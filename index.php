<?php
// --- CONFIGURACIÓN DE SESIÓN Y SEGURIDAD ROBUSTA (HTTPOnly, Secure, Strict Mode) ---
if (session_status() === PHP_SESSION_NONE) {
    ini_set('session.cookie_httponly', 1);
    ini_set('session.cookie_secure', 0); // Cambiar a 1 si usas HTTPS real
    ini_set('session.use_strict_mode', 1);
    ini_set('session.cookie_samesite', 'Strict');
    session_start();
}

// Cabeceras de seguridad HTTP Avanzadas
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Content-Security-Policy: default-src 'self' https://cdnjs.cloudflare.com https://fonts.googleapis.com https://fonts.gstatic.com 'unsafe-inline' 'unsafe-eval'");

// Generar Token CSRF por sesión si no existe
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// --- SISTEMA DE MITIGACIÓN ANTI-DDOS & RATE LIMITING GLOBAL ---
$client_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
$now_time = time();

if (!isset($_SESSION['ddos_tracker'])) {
    $_SESSION['ddos_tracker'] = ['count' => 0, 'start' => $now_time];
}

// Si pasan menos de 2 segundos y hay más de 15 peticiones, activar escudo Anti-DDoS temporal
if (($now_time - $_SESSION['ddos_tracker']['start']) < 2) {
    $_SESSION['ddos_tracker']['count']++;
    if ($_SESSION['ddos_tracker']['count'] > 15) {
        header("HTTP/1.1 530 Cloudflare / CyberGuard DDoS Mitigation Active");
        die("<!DOCTYPE html><html lang='es'><head><meta charset='UTF-8'><title>Anti-DDoS Shield Active</title><style>body{background:#030712;color:#ef4444;font-family:sans-serif;text-align:center;padding-top:20vh;}</style></head><body><h1>[!] ESCUDO ANTI-DDOS ACTIVADO</h1><p>Tráfico anómalo detectado desde tu IP ($client_ip). Espere unos segundos e intente nuevamente.</p></body></html>");
    }
} else {
    $_SESSION['ddos_tracker'] = ['count' => 1, 'start' => $now_time];
}

// Base de datos SQLite local para persistencia segura
$db_file = __DIR__ . '/cyberguard_secure.db';
try {
    $db = new PDO('sqlite:' . $db_file);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // Inicializar tablas necesarias con campos actualizados
    $db->exec("CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nombre TEXT NOT NULL,
        apellido TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        single_use_hash TEXT DEFAULT '',
        hash_type TEXT DEFAULT 'sha256',
        hash_used INTEGER DEFAULT 0,
        hash_security_active INTEGER DEFAULT 1,
        profile_pic TEXT DEFAULT '',
        theme_color TEXT DEFAULT '#06b6d4',
        ddos_protection INTEGER DEFAULT 1,
        sec_question_1 TEXT DEFAULT '',
        sec_answer_1 TEXT DEFAULT '',
        sec_question_2 TEXT DEFAULT '',
        sec_answer_2 TEXT DEFAULT '',
        sec_question_3 TEXT DEFAULT '',
        sec_answer_3 TEXT DEFAULT '',
        role TEXT DEFAULT 'analyst',
        status TEXT DEFAULT 'active',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");

    // Tabla para Consultas de Ciberseguridad con soporte de respuesta de administrador
    $db->exec("CREATE TABLE IF NOT EXISTS security_consultations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        admin_id INTEGER,
        email TEXT NOT NULL,
        subject TEXT NOT NULL,
        message TEXT NOT NULL,
        response TEXT DEFAULT NULL,
        ip_address TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");

    // Registrar administrador por defecto si no existe ninguno en la base de datos (con preguntas de seguridad robustas de admin por defecto)
    $stmt_check_admin = $db->query("SELECT id FROM users WHERE role = 'admin'");
    if (!$stmt_check_admin->fetch()) {
        $admin_pass = password_hash('AdminRoot999!', PASSWORD_BCRYPT);
        $adm_a1 = password_hash('CyberGuardRootMasterKey', PASSWORD_BCRYPT);
        $adm_a2 = password_hash('ZeroDayDefenseProtocol', PASSWORD_BCRYPT);
        $adm_a3 = password_hash('AES-256-GCM', PASSWORD_BCRYPT);
        
        $db->prepare("INSERT INTO users (nombre, apellido, email, password, sec_question_1, sec_answer_1, sec_question_2, sec_answer_2, sec_question_3, sec_answer_3, role) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
           ->execute([
               'Admin', 
               'Root', 
               'admin@cyberguard.com', 
               $admin_pass, 
               '¿Cuál es la clave maestra de inicialización del sistema?', 
               $adm_a1, 
               '¿Cuál es el protocolo de defensa ante brechas zero-day?', 
               $adm_a2, 
               '¿Cuál es el estándar de cifrado simétrico principal?', 
               $adm_a3, 
               'admin'
           ]);
    }

} catch (Exception $e) {
    die("Error crítico de conexión a la base de datos de alta seguridad.");
}

$message = '';
$message_type = '';
$action = isset($_GET['view']) ? $_GET['view'] : 'home';

// --- CONTROL DE BLOQUEO POR FUERZA BRUTA (BRUTE FORCE LOCKOUT) ---
function check_brute_force($action_name) {
    $key = 'bf_' . $action_name;
    if (!isset($_SESSION[$key])) {
        $_SESSION[$key] = ['attempts' => 0, 'lock_until' => 0];
    }
    
    if (time() < $_SESSION[$key]['lock_until']) {
        $remaining = $_SESSION[$key]['lock_until'] - time();
        return $remaining;
    }
    return 0;
}

function register_failed_attempt($action_name) {
    $key = 'bf_' . $action_name;
    if (!isset($_SESSION[$key])) {
        $_SESSION[$key] = ['attempts' => 0, 'lock_until' => 0];
    }
    $_SESSION[$key]['attempts']++;
    
    if ($_SESSION[$key]['attempts'] >= 3) {
        $lock_time = 30 * pow(2, $_SESSION[$key]['attempts'] - 3);
        $_SESSION[$key]['lock_until'] = time() + min($lock_time, 300);
    }
}

function reset_brute_force($action_name) {
    $key = 'bf_' . $action_name;
    $_SESSION[$key] = ['attempts' => 0, 'lock_until' => 0];
}

// --- PROCESAMIENTO DE ACCIONES BACKEND & PROTECCIÓN IDOR/CSRF ---
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $form_action = isset($_POST['action']) ? $_POST['action'] : '';

    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die("Error de validación de seguridad (CSRF Token inválido o expirado).");
    }

    // Lógica para que el Administrador responda consultas
    if ($form_action === 'respond_consultation') {
        if (!isset($_SESSION['user_id'])) {
            header("Location: ?view=login");
            exit;
        }
        
        $stmt_rol = $db->prepare("SELECT role FROM users WHERE id = ?");
        $stmt_rol->execute([$_SESSION['user_id']]);
        $current_user_check = $stmt_rol->fetch(PDO::FETCH_ASSOC);

        if ($current_user_check && $current_user_check['role'] === 'admin') {
            $consultation_id = $_POST['consultation_id'];
            $response_text = trim($_POST['response']);

            if (!empty($response_text)) {
                $stmt_resp = $db->prepare("UPDATE security_consultations SET response = ?, admin_id = ? WHERE id = ?");
                $stmt_resp->execute([$response_text, $_SESSION['user_id'], $consultation_id]);
                $message = "Respuesta enviada y registrada correctamente al usuario.";
                $message_type = "success";
                $action = 'profile';
            } else {
                $message = "La respuesta no puede estar vacía.";
                $message_type = "error";
                $action = 'profile';
            }
        } else {
            die("Acceso no autorizado.");
        }
    } elseif ($form_action === 'register') {
        $nombre = trim($_POST['nombre']);
        $apellido = trim($_POST['apellido']);
        $email = trim($_POST['email']);
        $password = password_hash($_POST['password'], PASSWORD_BCRYPT);
        
        $hash_type = $_POST['hash_type'] ?? 'sha256';
        $raw_hash_data = random_bytes(32);
        if ($hash_type === 'whirlpool') {
            $single_use_hash = hash('whirlpool', $raw_hash_data);
        } elseif ($hash_type === 'md5') {
            $single_use_hash = md5($raw_hash_data);
        } else {
            $single_use_hash = hash('sha256', $raw_hash_data);
        }

        $sec_q1 = trim($_POST['sec_question_1']);
        $sec_a1 = password_hash(trim($_POST['sec_answer_1']), PASSWORD_BCRYPT);
        $sec_q2 = trim($_POST['sec_question_2']);
        $sec_a2 = password_hash(trim($_POST['sec_answer_2']), PASSWORD_BCRYPT);
        $sec_q3 = trim($_POST['sec_question_3']);
        $sec_a3 = password_hash(trim($_POST['sec_answer_3']), PASSWORD_BCRYPT);

        try {
            $stmt = $db->prepare("INSERT INTO users (nombre, apellido, email, password, single_use_hash, hash_type, hash_used, hash_security_active, sec_question_1, sec_answer_1, sec_question_2, sec_answer_2, sec_question_3, sec_answer_3, role) VALUES (?, ?, ?, ?, ?, ?, 0, 1, ?, ?, ?, ?, ?, ?, 'analyst')");
            $stmt->execute([$nombre, $apellido, $email, $password, $single_use_hash, $hash_type, $sec_q1, $sec_a1, $sec_q2, $sec_a2, $sec_q3, $sec_a3]);

            $_SESSION['temp_new_hash'] = $single_use_hash;
            header("Location: ?view=login&registered=1");
            exit;
        } catch (Exception $e) {
            $message = "El correo electrónico ya se encuentra registrado en el sistema.";
            $message_type = "error";
            $action = 'register';
        }
    } elseif ($form_action === 'login') {
        $lockout = check_brute_force('login');
        if ($lockout > 0) {
            $message = "Demasiados intentos fallidos. Acceso bloqueado temporalmente. Espere {$lockout} segundos.";
            $message_type = "error";
            $action = 'login';
        } else {
            $login_id = trim($_POST['login_id']);
            $password = $_POST['password'];
            $answer_1 = trim($_POST['sec_answer_1'] ?? '');
            $answer_2 = trim($_POST['sec_answer_2'] ?? '');
            $answer_3 = trim($_POST['sec_answer_3'] ?? '');

            $stmt = $db->prepare("SELECT * FROM users WHERE email = ?");
            $stmt->execute([$login_id]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($user && password_verify($password, $user['password'])) {
                // Validación estricta de preguntas según el rol
                $auth_passed = true;
                if ($user['role'] === 'admin') {
                    // El admin requiere validación de sus 3 preguntas de seguridad robustas para entrar
                    if (!password_verify($answer_1, $user['sec_answer_1']) || 
                        !password_verify($answer_2, $user['sec_answer_2']) || 
                        !password_verify($answer_3, $user['sec_answer_3'])) {
                        $auth_passed = false;
                        $message = "Acceso root denegado: Las respuestas a las preguntas de seguridad del administrador son incorrectas.";
                    }
                } else {
                    // Usuarios analistas requieren la pregunta 1
                    if (!empty($user['sec_answer_1']) && !password_verify($answer_1, $user['sec_answer_1'])) {
                        $auth_passed = false;
                        $message = "Acceso denegado: La respuesta a la pregunta de seguridad es incorrecta.";
                    }
                }

                if (!$auth_passed) {
                    register_failed_attempt('login');
                    $message_type = "error";
                    $action = 'login';
                } else {
                    reset_brute_force('login');
                    session_regenerate_id(true);
                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['user_email'] = $user['email'];
                    $_SESSION['user_nombre'] = $user['nombre'];
                    
                    header("Location: ?view=profile");
                    exit;
                }
            } else {
                register_failed_attempt('login');
                $message = "Credenciales de acceso incorrectas.";
                $message_type = "error";
                $action = 'login';
            }
        }
    } elseif ($form_action === 'recover_hash') {
        $lockout = check_brute_force('recover');
        if ($lockout > 0) {
            $message = "Demasiados intentos de recuperación. Espere {$lockout} segundos.";
            $message_type = "error";
            $action = 'recover';
        } else {
            $recovery_hash = trim($_POST['recovery_hash']);

            if (empty($recovery_hash)) {
                $message = "Por favor ingrese el Hash de seguridad de su perfil.";
                $message_type = "error";
                $action = 'recover';
            } else {
                $stmt = $db->prepare("SELECT * FROM users WHERE single_use_hash = ?");
                $stmt->execute([$recovery_hash]);
                $user = $stmt->fetch(PDO::FETCH_ASSOC);

                if ($user) {
                    reset_brute_force('recover');
                    $_SESSION['recovery_user_id'] = $user['id'];
                    header("Location: ?view=reset_password");
                    exit;
                } else {
                    register_failed_attempt('recover');
                    $message = "El Hash ingresado es inválido o no pertenece a ningún perfil activo.";
                    $message_type = "error";
                    $action = 'recover';
                }
            }
        }
    } elseif ($form_action === 'reset_password_new') {
        if (!isset($_SESSION['recovery_user_id'])) {
            header("Location: ?view=home");
            exit;
        }
        $rec_user_id = $_SESSION['recovery_user_id'];
        $new_pass = $_POST['new_password'];

        if (!empty($new_pass)) {
            $hashed_pass = password_hash($new_pass, PASSWORD_BCRYPT);
            
            $stmt_u = $db->prepare("SELECT hash_type FROM users WHERE id = ?");
            $stmt_u->execute([$rec_user_id]);
            $u_data = $stmt_u->fetch(PDO::FETCH_ASSOC);
            $htype = $u_data['hash_type'] ?? 'sha256';

            $raw_data = random_bytes(32);
            if ($htype === 'whirlpool') {
                $new_hash = hash('whirlpool', $raw_data);
            } elseif ($htype === 'md5') {
                $new_hash = md5($raw_data);
            } else {
                $new_hash = hash('sha256', $raw_data);
            }

            $stmt_update = $db->prepare("UPDATE users SET password = ?, single_use_hash = ?, hash_used = 0 WHERE id = ?");
            $stmt_update->execute([$hashed_pass, $new_hash, $rec_user_id]);

            unset($_SESSION['recovery_user_id']);
            $message = "Contraseña restablecida exitosamente. Se ha generado un nuevo hash para tu perfil. Inicia sesión.";
            $message_type = "success";
            $action = 'login';
        } else {
            $message = "La contraseña no puede estar vacía.";
            $message_type = "error";
            $action = 'reset_password';
        }
    } elseif ($form_action === 'generate_new_hash') {
        if (!isset($_SESSION['user_id'])) {
            header("Location: ?view=login");
            exit;
        }
        $user_id = $_SESSION['user_id'];
        $desired_type = $_POST['hash_type'] ?? 'sha256';
        
        $raw_data = random_bytes(32);
        if ($desired_type === 'whirlpool') {
            $nuevo_hash = hash('whirlpool', $raw_data);
        } elseif ($desired_type === 'md5') {
            $nuevo_hash = md5($raw_data);
        } else {
            $nuevo_hash = hash('sha256', $raw_data);
        }

        $stmt = $db->prepare("UPDATE users SET single_use_hash = ?, hash_type = ?, hash_used = 0 WHERE id = ?");
        $stmt->execute([$nuevo_hash, $desired_type, $user_id]);

        $message = "Se ha generado un nuevo Hash de seguridad único con el algoritmo seleccionado.";
        $message_type = "success";
        $action = 'profile';
    } elseif ($form_action === 'update_profile') {
        if (!isset($_SESSION['user_id'])) {
            header("Location: ?view=login");
            exit;
        }
        $user_id = $_SESSION['user_id'];
        
        // Comprobar rol actual para verificar si es admin
        $stmt_check_rol = $db->prepare("SELECT role, password FROM users WHERE id = ?");
        $stmt_check_rol->execute([$user_id]);
        $current_db_user = $stmt_check_rol->fetch(PDO::FETCH_ASSOC);
        $is_admin_user = ($current_db_user['role'] === 'admin');

        $new_nombre = trim($_POST['nombre']);
        $new_apellido = trim($_POST['apellido']);
        $new_password = $_POST['password'];
        $theme_color = trim($_POST['theme_color'] ?? '#06b6d4');
        $ddos_toggle = isset($_POST['ddos_protection']) ? 1 : 0;
        
        // Si es admin, exigimos verificación estricta de la contraseña actual para permitir cambios de seguridad o credenciales
        if ($is_admin_user) {
            $current_admin_password = $_POST['current_admin_password'] ?? '';
            if (empty($current_admin_password) || !password_verify($current_admin_password, $current_db_user['password'])) {
                $message = "Error de Hardening: Debe ingresar su contraseña de Administrador actual para autorizar cambios en el perfil root.";
                $message_type = "error";
                $action = 'profile';
                goto profile_update_skip;
            }
        }
        
        $q1 = trim($_POST['sec_question_1']);
        $a1 = trim($_POST['sec_answer_1']);
        $q2 = trim($_POST['sec_question_2']);
        $a2 = trim($_POST['sec_answer_2']);
        $q3 = trim($_POST['sec_question_3']);
        $a3 = trim($_POST['sec_answer_3']);
        
        $profile_pic_path = null;
        if (isset($_FILES['profile_pic']) && $_FILES['profile_pic']['error'] === UPLOAD_ERR_OK) {
            $file_tmp = $_FILES['profile_pic']['tmp_name'];
            $file_ext = strtolower(pathinfo($_FILES['profile_pic']['name'], PATHINFO_EXTENSION));
            $allowed = ['jpg', 'jpeg', 'png', 'webp'];
            
            $finfo = finfo_open(FILEINFO_MIME_TYPE);
            $mime_type = finfo_file($finfo, $file_tmp);
            $allowed_mimes = ['image/jpeg', 'image/png', 'image/webp'];

            if (in_array($file_ext, $allowed) && in_array($mime_type, $allowed_mimes)) {
                $upload_dir = __DIR__ . '/uploads/';
                if (!is_dir($upload_dir)) { mkdir($upload_dir, 0755, true); }
                $profile_pic_path = 'uploads/profile_' . $user_id . '_' . time() . '.' . $file_ext;
                move_uploaded_file($file_tmp, __DIR__ . '/' . $profile_pic_path);
            }
        }

        $stmt_old = $db->prepare("SELECT profile_pic FROM users WHERE id = ?");
        $stmt_old->execute([$user_id]);
        $old_data = $stmt_old->fetch(PDO::FETCH_ASSOC);
        if (!$profile_pic_path) {
            $profile_pic_path = $old_data['profile_pic'];
        }

        $q_update_extras = "";
        $params_extras = [];

        if (!empty($a1)) {
            $hashed_a1 = password_hash($a1, PASSWORD_BCRYPT);
            $q_update_extras .= ", sec_question_1 = ?, sec_answer_1 = ?";
            $params_extras[] = $q1;
            $params_extras[] = $hashed_a1;
        }
        if (!empty($a2)) {
            $hashed_a2 = password_hash($a2, PASSWORD_BCRYPT);
            $q_update_extras .= ", sec_question_2 = ?, sec_answer_2 = ?";
            $params_extras[] = $q2;
            $params_extras[] = $hashed_a2;
        }
        if (!empty($a3)) {
            $hashed_a3 = password_hash($a3, PASSWORD_BCRYPT);
            $q_update_extras .= ", sec_question_3 = ?, sec_answer_3 = ?";
            $params_extras[] = $q3;
            $params_extras[] = $hashed_a3;
        }

        if (!empty($new_password)) {
            $hashed_pass = password_hash($new_password, PASSWORD_BCRYPT);
            $sql = "UPDATE users SET nombre = ?, apellido = ?, password = ?, profile_pic = ?, theme_color = ?, ddos_protection = ?" . $q_update_extras . " WHERE id = ?";
            $params = array_merge([$new_nombre, $new_apellido, $hashed_pass, $profile_pic_path, $theme_color, $ddos_toggle], $params_extras, [$user_id]);
            $stmt = $db->prepare($sql);
            $stmt->execute($params);
        } else {
            $sql = "UPDATE users SET nombre = ?, apellido = ?, profile_pic = ?, theme_color = ?, ddos_protection = ?" . $q_update_extras . " WHERE id = ?";
            $params = array_merge([$new_nombre, $new_apellido, $profile_pic_path, $theme_color, $ddos_toggle], $params_extras, [$user_id]);
            $stmt = $db->prepare($sql);
            $stmt->execute($params);
        }

        $_SESSION['user_nombre'] = $new_nombre;
        $message = "Perfil y capas de seguridad actualizadas de forma exitosa.";
        $message_type = "success";
        $action = 'profile';

        profile_update_skip:
    } elseif ($form_action === 'consultation') {
        $lockout = check_brute_force('consultation');
        if ($lockout > 0) {
            $message = "Demasiadas consultas enviadas. Espere {$lockout} segundos para enviar otra solicitud.";
            $message_type = "error";
            $action = 'consultation';
        } else {
            $c_email = trim($_POST['email']);
            $c_subject = trim($_POST['subject']);
            $c_message = trim($_POST['message']);
            $c_uid = isset($_SESSION['user_id']) ? $_SESSION['user_id'] : null;

            if (!empty($c_email) && !empty($c_subject) && !empty($c_message)) {
                $stmt = $db->prepare("INSERT INTO security_consultations (user_id, email, subject, message, ip_address) VALUES (?, ?, ?, ?, ?)");
                $stmt->execute([$c_uid, $c_email, $c_subject, $c_message, $client_ip]);
                
                register_failed_attempt('consultation');
                $message = "Consulta de ciberseguridad enviada y protegida con éxito contra flood/DDoS.";
                $message_type = "success";
                $action = 'consultation';
            } else {
                $message = "Por favor complete todos los campos de la consulta.";
                $message_type = "error";
                $action = 'consultation';
            }
        }
    }
}

// Manejo explícito de Cierre de Sesión (Logout)
if ($action === 'logout') {
    $_SESSION = array();
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $params["path"], $params["domain"],
            $params["secure"], $params["httponly"]
        );
    }
    session_destroy();
    header("Location: ?view=home");
    exit;
}

// Obtener datos globales del usuario autenticado de forma segura
$logged_user = null;
if (isset($_SESSION['user_id'])) {
    $stmt_nav = $db->prepare("SELECT * FROM users WHERE id = ?");
    $stmt_nav->execute([$_SESSION['user_id']]);
    $logged_user = $stmt_nav->fetch(PDO::FETCH_ASSOC);
}

$active_theme_color = $logged_user['theme_color'] ?? '#06b6d4';
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberGuard Offensive | Seguridad & Hardening 3D</title>
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&family=Inter:wght@300;400;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --theme-color: <?php echo htmlspecialchars($active_theme_color); ?>;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background-color: #030712; color: #f3f4f6; font-family: 'Inter', sans-serif; overflow-x: hidden; width: 100vw; min-height: 100vh; }
        #canvas-container { position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; z-index: 1; pointer-events: none; transition: transform 1.2s ease-in-out; }
        body.transitioning #canvas-container { transform: scale(1.1) rotate(180deg); filter: hue-rotate(45deg); }
        .ui-layer { position: relative; z-index: 2; width: 100%; min-height: 100vh; display: flex; flex-direction: column; justify-content: space-between; padding: 2rem 4rem; }
        header { display: flex; justify-content: space-between; align-items: center; width: 100%; max-width: 1200px; margin: 0 auto; }
        .logo { font-family: 'Orbitron', sans-serif; font-size: 1.5rem; font-weight: 700; color: var(--theme-color); letter-spacing: 2px; text-shadow: 0 0 10px rgba(6, 182, 212, 0.4); text-decoration: none; }
        nav { display: flex; align-items: center; gap: 1.8rem; }
        nav a { color: #9ca3af; text-decoration: none; font-size: 0.9rem; transition: color 0.3s ease; cursor: pointer; }
        nav a:hover { color: var(--theme-color); }
        .nav-avatar { width: 32px; height: 32px; border-radius: 50%; object-fit: cover; border: 1px solid var(--theme-color); vertical-align: middle; margin-left: 0.5rem; }
        .hero, .content-section { max-width: 800px; margin: auto 0; padding: 3rem 0; }
        .badge-status { display: inline-block; background: rgba(6, 182, 212, 0.1); border: 1px solid rgba(6, 182, 212, 0.3); color: var(--theme-color); padding: 0.4rem 1rem; border-radius: 50px; font-size: 0.8rem; font-family: 'Orbitron', sans-serif; margin-bottom: 1.5rem; text-transform: uppercase; letter-spacing: 1px; }
        h1 { font-family: 'Orbitron', sans-serif; font-size: 3rem; line-height: 1.1; margin-bottom: 1.5rem; color: #ffffff; }
        h1 span { color: var(--theme-color); }
        p.subtitle, .content-section p { font-size: 1.05rem; color: #9ca3af; line-height: 1.6; margin-bottom: 2rem; max-width: 700px; }
        
        .glass-card { background: rgba(15, 23, 42, 0.88); border: 1px solid rgba(6, 182, 212, 0.3); padding: 2.5rem; border-radius: 12px; backdrop-filter: blur(12px); box-shadow: 0 0 30px rgba(0, 0, 0, 0.7); max-width: 500px; transform-style: preserve-3d; transition: transform 0.3s ease, box-shadow 0.3s ease; }
        .glass-card:hover { transform: perspective(1000px) rotateX(1deg) rotateY(-1deg) translateZ(5px); box-shadow: 0 10px 40px rgba(6, 182, 212, 0.25); }
        
        .form-group { margin-bottom: 1.2rem; transform: translateZ(10px); }
        .form-group label { display: block; font-size: 0.85rem; color: var(--theme-color); font-family: 'Orbitron', sans-serif; margin-bottom: 0.5rem; }
        .form-control { width: 100%; padding: 0.8rem 1rem; background: rgba(3, 7, 18, 0.9); border: 1px solid rgba(255, 255, 255, 0.15); border-radius: 6px; color: #fff; font-size: 0.95rem; }
        .form-control:focus { outline: none; border-color: var(--theme-color); box-shadow: 0 0 10px rgba(6, 182, 212, 0.4); }
        
        .file-upload-wrapper { position: relative; width: 100%; overflow: hidden; display: inline-block; background: rgba(3, 7, 18, 0.9); border: 1px dashed var(--theme-color); border-radius: 6px; padding: 0.8rem; text-align: center; cursor: pointer; transition: all 0.3s; }
        .file-upload-wrapper:hover { background: rgba(6, 182, 212, 0.1); box-shadow: 0 0 10px rgba(6,182,212,0.3); }
        .file-upload-wrapper input[type=file] { font-size: 100px; position: absolute; left: 0; top: 0; opacity: 0; cursor: pointer; }
        .file-upload-text { font-size: 0.85rem; color: var(--theme-color); font-family: 'Orbitron', sans-serif; }

        .avatar-3d-box { width: 130px; height: 130px; border-radius: 50%; background: var(--theme-color); margin: 0 auto 1.2rem; display: flex; align-items: center; justify-content: center; font-size: 2.5rem; color: #030712; font-family: 'Orbitron'; font-weight: bold; overflow: hidden; border: 3px solid var(--theme-color); box-shadow: 0 0 20px var(--theme-color), inset 0 0 15px rgba(0,0,0,0.5); transform: perspective(600px) rotateY(15deg) rotateX(10deg); transition: transform 0.5s ease; }
        .avatar-3d-box:hover { transform: perspective(600px) rotateY(0deg) rotateX(0deg) scale(1.05); }

        .cta-group { display: flex; gap: 1rem; flex-wrap: wrap; }
        .btn { padding: 0.9rem 2rem; border-radius: 6px; font-weight: 600; text-decoration: none; transition: all 0.3s ease; cursor: pointer; font-size: 0.95rem; display: inline-block; text-align: center; }
        .btn-primary { background-color: var(--theme-color); color: #030712; border: none; box-shadow: 0 0 20px rgba(6, 182, 212, 0.3); }
        .btn-primary:hover { filter: brightness(1.2); box-shadow: 0 0 30px rgba(6, 182, 212, 0.6); }
        .btn-outline { background: transparent; color: #f3f4f6; border: 1px solid rgba(255, 255, 255, 0.2); }
        .btn-outline:hover { border-color: var(--theme-color); color: var(--theme-color); }
        .btn-warning { background: rgba(234, 179, 8, 0.2); border: 1px solid #eab308; color: #fde047; }
        .link-sub { display: block; margin-top: 1rem; color: #9ca3af; font-size: 0.85rem; text-decoration: none; }
        .link-sub:hover { color: var(--theme-color); }
        .hash-display { background: rgba(3, 7, 18, 0.95); border: 1px dashed var(--theme-color); padding: 0.7rem; font-family: monospace; font-size: 0.8rem; color: var(--theme-color); word-break: break-all; border-radius: 4px; margin-top: 0.3rem; }
        .alert { padding: 1rem; margin-bottom: 1.5rem; border-radius: 6px; font-size: 0.9rem; }
        .alert-error { background: rgba(239, 68, 68, 0.2); border: 1px solid #ef4444; color: #fca5a5; }
        .alert-success { background: rgba(16, 185, 129, 0.2); border: 1px solid #10b981; color: #a7f3d0; }
        footer { text-align: center; padding: 1.5rem 0; color: #4b5563; font-size: 0.85rem; border-top: 1px solid rgba(255, 255, 255, 0.05); max-width: 1200px; margin: 0 auto; width: 100%; }
        @media (max-width: 768px) { .ui-layer { padding: 1.5rem; } h1 { font-size: 2.2rem; } nav { display: none; } }
    </style>
</head>
<body>

    <div id="canvas-container"></div>

    <div class="ui-layer">
        <header>
            <a href="?view=home" class="logo transition-link">CYBERGUARD//OFFENSIVE</a>
            <nav>
                <a href="?view=about" class="transition-link">Nosotros</a>
                <a href="?view=consultation" class="transition-link">Consulta de Ciberseguridad</a>
                <?php if (isset($_SESSION['user_id'])): ?>
                    <a href="?view=profile" class="transition-link" style="color: var(--theme-color); font-weight: 600; display: flex; align-items: center;">
                        Mi Perfil Blindado
                        <?php if (!empty($logged_user['profile_pic']) && file_exists(__DIR__ . '/' . $logged_user['profile_pic'])): ?>
                            <img src="<?php echo htmlspecialchars($logged_user['profile_pic']); ?>" class="nav-avatar" alt="Avatar">
                        <?php endif; ?>
                    </a>
                    <a href="?view=logout" class="transition-link" style="color: #ef4444;">Salir</a>
                <?php else: ?>
                    <a href="?view=login" class="transition-link" style="color: var(--theme-color); font-weight: 600;">Iniciar Sesión</a>
                    <a href="?view=recover" class="transition-link" style="color: #eab308; font-weight: 600;">Recuperar por Hash</a>
                <?php endif; ?>
            </nav>
        </header>

        <?php if (!empty($message)): ?>
            <div style="max-width: 600px; margin: 1rem auto 0 auto; width: 100%;">
                <div class="alert alert-<?php echo $message_type === 'success' ? 'success' : 'error'; ?>">
                    <?php echo htmlspecialchars($message); ?>
                </div>
            </div>
        <?php endif; ?>

        <?php if ($action == 'home'): ?>
            <main class="hero">
                <div class="badge-status">Sistema de Autenticación Criptográfica & Anti-DDoS</div>
                <h1>Arquitectura de Acceso <span>Blindado 3D</span></h1>
                <p class="subtitle">Plataforma protegida con tokens criptográficos, protección avanzada contra fuerza bruta y DDoS, múltiples preguntas de seguridad y colores personalizables libres.</p>
                <div class="cta-group">
                    <a href="?view=register" class="btn btn-primary transition-link">Crear Cuenta Segura</a>
                    <a href="?view=login" class="btn btn-outline transition-link">Acceder al Sistema</a>
                    <a href="?view=consultation" class="btn btn-outline transition-link" style="border-color: var(--theme-color);">Consulta de Ciberseguridad</a>
                </div>
            </main>

        <?php elseif ($action == 'about'): ?>
            <main class="content-section" style="max-width: 800px; width: 100%;">
                <div class="badge-status">Acerca de CyberGuard Offensive</div>
                <h1>Ingeniería en <span>Ciberseguridad y Hardening</span></h1>
                <p class="subtitle">CyberGuard Offensive protege identidades digitales mediante algoritmos avanzados de hashing, control de intentos fallidos con bloqueos exponenciales, mitigación de ataques volumétricos y entornos visuales tridimensionales.</p>
            </main>

        <?php elseif ($action == 'consultation'): ?>
            <main class="hero">
                <div class="glass-card" style="max-width: 600px;">
                    <div class="badge-status">Área de Consultas Protegida</div>
                    <h2 style="font-family:'Orbitron'; font-size:1.8rem; margin-bottom:1.5rem; color:#fff;">Consulta de Ciberseguridad</h2>
                    <p style="font-size: 0.9rem; color: #9ca3af; margin-bottom: 1.5rem;">Envía tu consulta técnica. Este canal cuenta con mitigación DDoS activa y límites estrictos de reintentos por IP.</p>
                    <form action="?view=consultation" method="POST">
                        <input type="hidden" name="action" value="consultation">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <div class="form-group">
                            <label>Correo Electrónico de Contacto</label>
                            <input type="email" name="email" class="form-control" required value="<?php echo htmlspecialchars($_SESSION['user_email'] ?? ''); ?>">
                        </div>
                        <div class="form-group">
                            <label>Asunto del Reporte / Consulta</label>
                            <input type="text" name="subject" class="form-control" placeholder="Ej: Auditoría de vulnerabilidad web" required>
                        </div>
                        <div class="form-group">
                            <label>Mensaje Detallado</label>
                            <textarea name="message" class="form-control" rows="4" placeholder="Describa su consulta de seguridad..." required></textarea>
                        </div>
                        <button type="submit" class="btn btn-primary" style="width:100%; margin-top:1rem;">Enviar Consulta Segura</button>
                    </form>
                </div>
            </main>

        <?php elseif ($action == 'register'): ?>
            <main class="hero">
                <div class="glass-card" style="max-width: 600px;">
                    <div class="badge-status">Registro de Credenciales Criptográficas</div>
                    <h2 style="font-family:'Orbitron'; font-size:1.8rem; margin-bottom:1.5rem; color:#fff;">Nuevo Registro Blindado</h2>
                    <form action="?view=register" method="POST">
                        <input type="hidden" name="action" value="register">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <div class="form-group">
                            <label>Nombre</label>
                            <input type="text" name="nombre" class="form-control" required autocomplete="off">
                        </div>
                        <div class="form-group">
                            <label>Apellido</label>
                            <input type="text" name="apellido" class="form-control" required autocomplete="off">
                        </div>
                        <div class="form-group">
                            <label>Correo Electrónico</label>
                            <input type="email" name="email" class="form-control" required autocomplete="off">
                        </div>
                        <div class="form-group">
                            <label>Contraseña</label>
                            <input type="password" name="password" class="form-control" required autocomplete="new-password">
                        </div>
                        <div class="form-group">
                            <label>Tipo de Hash para el Perfil</label>
                            <select name="hash_type" class="form-control">
                                <option value="sha256">SHA-256 (Recomendado)</option>
                                <option value="whirlpool">Whirlpool</option>
                                <option value="md5">MD5</option>
                            </select>
                        </div>
                        <hr style="border: 0; border-top: 1px solid rgba(255,255,255,0.1); margin: 1.5rem 0;">
                        <h4 style="font-family:'Orbitron'; font-size: 1rem; color: var(--theme-color); margin-bottom: 1rem;">Múltiples Preguntas de Seguridad</h4>
                        
                        <div class="form-group">
                            <label>Pregunta 1: ¿Cuál es el nombre de tu primera mascota?</label>
                            <input type="text" name="sec_question_1" value="¿Cuál es el nombre de tu primera mascota?" class="form-control" readonly>
                            <input type="text" name="sec_answer_1" class="form-control" placeholder="Tu respuesta secreta 1" required style="margin-top: 5px;">
                        </div>
                        <div class="form-group">
                            <label>Pregunta 2: ¿En qué ciudad naciste?</label>
                            <input type="text" name="sec_question_2" value="¿En qué ciudad naciste?" class="form-control" readonly>
                            <input type="text" name="sec_answer_2" class="form-control" placeholder="Tu respuesta secreta 2" required style="margin-top: 5px;">
                        </div>
                        <div class="form-group">
                            <label>Pregunta 3: ¿Cuál es tu lenguaje de programación favorito?</label>
                            <input type="text" name="sec_question_3" value="¿Cuál es tu lenguaje de programación favorito?" class="form-control" readonly>
                            <input type="text" name="sec_answer_3" class="form-control" placeholder="Tu respuesta secreta 3" required style="margin-top: 5px;">
                        </div>

                        <button type="submit" class="btn btn-primary" style="width:100%; margin-top:1rem;">Registrar Cuenta y Generar Hash</button>
                    </form>
                    <a href="?view=login" class="link-sub transition-link">¿Ya tienes cuenta? Inicia sesión</a>
                </div>
            </main>

        <?php elseif ($action == 'login'): ?>
            <main class="hero">
                <div class="glass-card">
                    <div class="badge-status">Autenticación con Protección Anti-Fuerza Bruta</div>
                    <h2 style="font-family:'Orbitron'; font-size:1.8rem; margin-bottom:1.5rem; color:#fff;">Iniciar Sesión</h2>
                    
                    <?php if (isset($_GET['registered'])): ?>
                        <div class="alert alert-success">
                            ¡Cuenta creada exitosamente! Tu Hash de perfil único es:<br>
                            <div class="hash-display"><?php echo htmlspecialchars($_SESSION['temp_new_hash'] ?? ''); ?></div>
                            <span style="font-size: 0.8rem; display: block; margin-top: 5px;">Guárdalo de forma segura. Te servirá para recuperar el acceso si olvidas tus credenciales.</span>
                        </div>
                    <?php endif; ?>

                    <form action="?view=login" method="POST" onsubmit="if(document.getElementById('roleCheckNotice') && document.getElementById('roleCheckNotice').value === 'admin')">
                        <input type="hidden" name="action" value="login">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <div class="form-group">
                            <label>Correo Electrónico</label>
                            <input type="text" id="loginEmailInput" name="login_id" class="form-control" required autocomplete="off" onblur="if(this.value.includes('admin')) { document.getElementById('adminQuestionsBox').style.display='block'; document.getElementById('analystQuestionBox').style.display='none'; } else { document.getElementById('adminQuestionsBox').style.display='none'; document.getElementById('analystQuestionBox').style.display='block'; }">
                        </div>
                        <div class="form-group">
                            <label>Contraseña</label>
                            <input type="password" name="password" class="form-control" required autocomplete="current-password">
                        </div>

                        <!-- Pregunta para Analista / Estándar -->
                        <div class="form-group" id="analystQuestionBox">
                            <label style="color: #eab308;">Pregunta de Seguridad 1: ¿Cuál es el nombre de tu primera mascota?</label>
                            <input type="text" name="sec_answer_1" class="form-control" placeholder="Respuesta secreta" autocomplete="off">
                        </div>

                        <!-- Preguntas Robusta múltiples para Administrador Root -->
                        <div id="adminQuestionsBox" style="display:none; background: rgba(16,185,129,0.08); border: 1px solid #10b981; padding: 12px; border-radius: 6px; margin-bottom: 1.2rem;">
                            <label style="color: #10b981; font-size: 0.8rem; font-family:'Orbitron'; margin-bottom:0.8rem; display:block;">[!] AUTENTICACIÓN ROOT MULTI-FASE REQUERIDA</label>
                            
                            <div class="form-group" style="margin-bottom:0.8rem;">
                                <label style="font-size:0.75rem; color:#10b981;">1. ¿Cuál es la clave maestra de inicialización del sistema?</label>
                                <input type="password" name="sec_answer_1" class="form-control" placeholder="Respuesta maestra 1" autocomplete="off">
                            </div>
                            <div class="form-group" style="margin-bottom:0.8rem;">
                                <label style="font-size:0.75rem; color:#10b981;">2. ¿Cuál es el protocolo de defensa ante brechas zero-day?</label>
                                <input type="password" name="sec_answer_2" class="form-control" placeholder="Respuesta maestra 2" autocomplete="off">
                            </div>
                            <div class="form-group" style="margin-bottom:0;">
                                <label style="font-size:0.75rem; color:#10b981;">3. ¿Cuál es el estándar de cifrado simétrico principal?</label>
                                <input type="password" name="sec_answer_3" class="form-control" placeholder="Respuesta maestra 3" autocomplete="off">
                            </div>
                        </div>

                        <button type="submit" class="btn btn-primary" style="width:100%; margin-top:1rem;">Entrar al Sistema</button>
                    </form>
                    <div style="display: flex; justify-content: space-between; margin-top: 1rem;">
                        <a href="?view=register" class="link-sub transition-link">Registrarse</a>
                        <a href="?view=recover" class="link-sub transition-link" style="color: #eab308;">Recuperar por Hash</a>
                    </div>
                </div>
            </main>

        <?php elseif ($action == 'recover'): ?>
            <main class="hero">
                <div class="glass-card" style="border-color: rgba(234, 179, 8, 0.4);">
                    <div class="badge-status" style="color: #eab308; background: rgba(234, 179, 8, 0.1); border-color: rgba(234, 179, 8, 0.3);">Recuperación Blindada por Hash</div>
                    <h2 style="font-family:'Orbitron'; font-size:1.8rem; margin-bottom:1.5rem; color:#fff;">Restablecer con Hash</h2>
                    <p style="font-size: 0.9rem; color: #9ca3af; margin-bottom: 1.5rem;">Ingrese el Hash único correspondiente a su perfil. Cuenta con bloqueo progresivo anti-intentos.</p>
                    <form action="?view=recover" method="POST">
                        <input type="hidden" name="action" value="recover_hash">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <div class="form-group">
                            <label style="color: #eab308;">Hash de Perfil Activo</label>
                            <input type="text" name="recovery_hash" class="form-control" required autocomplete="off">
                        </div>
                        <button type="submit" class="btn btn-warning" style="width:100%; margin-top:1rem;">Validar Hash de Perfil</button>
                    </form>
                    <a href="?view=login" class="link-sub transition-link">Volver al login estándar</a>
                </div>
            </main>

        <?php elseif ($action == 'reset_password'): ?>
            <main class="hero">
                <div class="glass-card" style="border-color: rgba(16, 185, 129, 0.4);">
                    <div class="badge-status" style="color: #10b981; background: rgba(16, 185, 129, 0.1); border-color: rgba(16, 185, 129, 0.3);">Identidad Verificada</div>
                    <h2 style="font-family:'Orbitron'; font-size:1.8rem; margin-bottom:1.5rem; color:#fff;">Nueva Contraseña</h2>
                    <form action="?view=reset_password" method="POST">
                        <input type="hidden" name="action" value="reset_password_new">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <div class="form-group">
                            <label style="color: #10b981;">Ingrese su Nueva Contraseña</label>
                            <input type="password" name="new_password" class="form-control" required autocomplete="new-password">
                        </div>
                        <button type="submit" class="btn btn-primary" style="width:100%; margin-top:1rem;">Actualizar Credenciales</button>
                    </form>
                </div>
            </main>

        <?php elseif ($action == 'profile'): ?>
            <?php
            if (!isset($_SESSION['user_id'])) {
                header("Location: ?view=home");
                exit;
            }
            $stmt = $db->prepare("SELECT * FROM users WHERE id = ?");
            $stmt->execute([$_SESSION['user_id']]);
            $current_user = $stmt->fetch(PDO::FETCH_ASSOC);

            $active_hash = $current_user['single_use_hash'];
            $is_admin = ($current_user['role'] === 'admin');
            ?>
            <main class="content-section" style="max-width: 950px; width: 100%;">
                <div class="badge-status">Panel de Perfil Avanzado con Capas de Seguridad</div>
                <h1 style="font-size: 2.2rem;">Gestión de <span>Perfil y Hardening</span></h1>
                
                <div style="display: grid; grid-template-columns: 1fr 2fr; gap: 2rem; align-items: start;">
                    
                    <!-- Tarjeta Izquierda: Avatar 3D y Hash -->
                    <div class="glass-card" style="text-align: center; max-width: 100%;">
                        <div class="avatar-3d-box">
                            <?php if (!empty($current_user['profile_pic']) && file_exists(__DIR__ . '/' . $current_user['profile_pic'])): ?>
                                <img src="<?php echo htmlspecialchars($current_user['profile_pic']); ?>" alt="Avatar" style="width: 100%; height: 100%; object-fit: cover;">
                            <?php else: ?>
                                <?php echo strtoupper(substr($current_user['nombre'], 0, 1) . substr($current_user['apellido'], 0, 1)); ?>
                            <?php endif; ?>
                        </div>
                        <h3 style="color: #fff; font-size: 1.3rem; margin-bottom: 0.3rem; font-family: 'Orbitron';"><?php echo htmlspecialchars($current_user['nombre'] . ' ' . $current_user['apellido']); ?></h3>
                        <p style="font-size: 0.85rem; color: var(--theme-color); margin-bottom: 1rem;"><?php echo htmlspecialchars($current_user['email']); ?></p>
                        
                        <?php if ($is_admin): ?>
                            <div style="background: rgba(16, 185, 129, 0.15); border: 1px solid #10b981; color: #10b981; padding: 0.5rem; border-radius: 6px; font-family: 'Orbitron'; font-size: 0.8rem; margin-bottom: 1rem;">
                                ROL: ADMINISTRADOR ROOT
                            </div>
                        <?php endif; ?>

                        <div style="text-align: left; margin-bottom: 1.5rem; background: rgba(3,7,18,0.5); padding: 10px; border-radius: 6px;">
                            <label style="font-size: 0.75rem; color: var(--theme-color); font-family: 'Orbitron';">Hash de Recuperación (Tipo: <?php echo strtoupper($current_user['hash_type']); ?>):</label>
                            <div class="hash-display"><?php echo htmlspecialchars($active_hash); ?></div>
                        </div>

                        <!-- Generador de nuevo Hash con selección de tipo -->
                        <form action="?view=profile" method="POST" style="margin-bottom: 0.8rem;">
                            <input type="hidden" name="action" value="generate_new_hash">
                            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                            <div style="margin-bottom: 0.5rem; text-align: left;">
                                <label style="font-size: 0.75rem; color: var(--theme-color);">Nuevo Algoritmo de Hash:</label>
                                <select name="hash_type" class="form-control" style="font-size: 0.8rem; padding: 0.4rem;">
                                    <option value="sha256" <?php echo $current_user['hash_type'] === 'sha256' ? 'selected' : ''; ?>>SHA-256</option>
                                    <option value="whirlpool" <?php echo $current_user['hash_type'] === 'whirlpool' ? 'selected' : ''; ?>>Whirlpool</option>
                                    <option value="md5" <?php echo $current_user['hash_type'] === 'md5' ? 'selected' : ''; ?>>MD5</option>
                                </select>
                            </div>
                            <button type="submit" class="btn btn-warning" style="width: 100%; padding: 0.5rem; font-size: 0.8rem;">Generar Nuevo Hash</button>
                        </form>
                    </div>

                    <!-- Tarjeta Derecha: Editor de Datos o Panel de Administración de Consultas -->
                    <div class="glass-card" style="max-width: 100%;">
                        <?php if ($is_admin): ?>
                            <h3 style="font-family: 'Orbitron'; color: #10b981; margin-bottom: 1.5rem;">Panel Root: Gestión de Consultas y Hardening</h3>
                            <p style="font-size: 0.85rem; color: #9ca3af; margin-bottom: 1.5rem;">Desde aquí puedes revisar reportes de usuarios y actualizar tu contraseña o preguntas de seguridad robustas.</p>
                            
                            <!-- Sección de Edición de Credenciales y Preguntas del Administrador -->
                            <div style="background: rgba(3, 7, 18, 0.9); border: 1px solid rgba(16, 185, 129, 0.3); padding: 1.5rem; border-radius: 8px; margin-bottom: 2rem;">
                                <h4 style="font-family:'Orbitron'; font-size: 0.95rem; color: #10b981; margin-bottom: 1rem;">Actualizar Contraseña y Preguntas Root</h4>
                                <form action="?view=profile" method="POST">
                                    <input type="hidden" name="action" value="update_profile">
                                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                                    <input type="hidden" name="nombre" value="<?php echo htmlspecialchars($current_user['nombre']); ?>">
                                    <input type="hidden" name="apellido" value="<?php echo htmlspecialchars($current_user['apellido']); ?>">
                                    
                                    <div class="form-group">
                                        <label style="color: #ef4444;">Contraseña de Administrador Actual (Obligatoria para cambios)</label>
                                        <input type="password" name="current_admin_password" class="form-control" required placeholder="Contraseña actual root">
                                    </div>
                                    <div class="form-group">
                                        <label>Nueva Contraseña (Opcional)</label>
                                        <input type="password" name="password" class="form-control" placeholder="Dejar en blanco para mantener actual">
                                    </div>

                                    <hr style="border: 0; border-top: 1px solid rgba(255,255,255,0.1); margin: 1.2rem 0;">
                                    <label style="font-size:0.8rem; color:#10b981; font-family:'Orbitron'; margin-bottom:0.5rem; display:block;">Preguntas de Seguridad Root Maestras</label>
                                    
                                    <div class="form-group">
                                        <label style="font-size:0.75rem;">1. ¿Cuál es la clave maestra de inicialización del sistema?</label>
                                        <input type="hidden" name="sec_question_1" value="¿Cuál es la clave maestra de inicialización del sistema?">
                                        <input type="password" name="sec_answer_1" class="form-control" placeholder="Nueva respuesta maestra 1 (opcional)">
                                    </div>
                                    <div class="form-group">
                                        <label style="font-size:0.75rem;">2. ¿Cuál es el protocolo de defensa ante brechas zero-day?</label>
                                        <input type="hidden" name="sec_question_2" value="¿Cuál es el protocolo de defensa ante brechas zero-day?">
                                        <input type="password" name="sec_answer_2" class="form-control" placeholder="Nueva respuesta maestra 2 (opcional)">
                                    </div>
                                    <div class="form-group">
                                        <label style="font-size:0.75rem;">3. ¿Cuál es el estándar de cifrado simétrico principal?</label>
                                        <input type="hidden" name="sec_question_3" value="¿Cuál es el estándar de cifrado simétrico principal?">
                                        <input type="password" name="sec_answer_3" class="form-control" placeholder="Nueva respuesta maestra 3 (opcional)">
                                    </div>

                                    <button type="submit" class="btn btn-primary" style="background: #10b981; color: #030712; width: 100%; margin-top: 1rem;">Actualizar Configuración Root</button>
                                </form>
                            </div>

                            <h4 style="font-family: 'Orbitron'; color: #10b981; margin-bottom: 1rem; font-size:1.1rem;">Bandeja de Consultas Recibidas</h4>
                            <?php
                            $stmt_consultas = $db->query("SELECT * FROM security_consultations ORDER BY created_at DESC");
                            $consultas_list = $stmt_consultas->fetchAll(PDO::FETCH_ASSOC);
                            ?>

                            <?php if (empty($consultas_list)): ?>
                                <p style="color: #9ca3af; font-size: 0.9rem;">No hay consultas de seguridad registradas en este momento.</p>
                            <?php else: ?>
                                <div style="display: flex; flex-direction: column; gap: 1.5rem; max-height: 600px; overflow-y: auto; padding-right: 5px;">
                                    <?php foreach ($consultas_list as $cons): ?>
                                        <div style="background: rgba(3, 7, 18, 0.8); border: 1px solid rgba(255,255,255,0.1); padding: 1.2rem; border-radius: 8px;">
                                            <div style="font-size: 0.75rem; color: var(--theme-color); margin-bottom: 0.3rem;">De: <?php echo htmlspecialchars($cons['email']); ?> | IP: <?php echo htmlspecialchars($cons['ip_address'] ?? 'N/A'); ?></div>
                                            <h4 style="color: #fff; font-size: 1rem; margin-bottom: 0.5rem; font-family:'Orbitron';"><?php echo htmlspecialchars($cons['subject']); ?></h4>
                                            <p style="font-size: 0.9rem; color: #d1d5db; margin-bottom: 1rem; background: rgba(0,0,0,0.3); padding: 8px; border-radius: 4px;"><?php echo nl2br(htmlspecialchars($cons['message'])); ?></p>
                                            
                                            <?php if (!empty($cons['response'])): ?>
                                                <div style="background: rgba(16, 185, 129, 0.1); border-left: 3px solid #10b981; padding: 0.8rem; font-size: 0.85rem; color: #a7f3d0;">
                                                    <strong>Respuesta oficial dada:</strong><br>
                                                    <?php echo nl2br(htmlspecialchars($cons['response'])); ?>
                                                </div>
                                            <?php else: ?>
                                                <form action="?view=profile" method="POST">
                                                    <input type="hidden" name="action" value="respond_consultation">
                                                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                                                    <input type="hidden" name="consultation_id" value="<?php echo $cons['id']; ?>">
                                                    <div class="form-group" style="margin-bottom: 0.8rem;">
                                                        <textarea name="response" class="form-control" rows="3" placeholder="Escribe tu respuesta de resolución..." required style="font-size: 0.85rem;"></textarea>
                                                    </div>
                                                    <button type="submit" class="btn btn-primary" style="padding: 0.5rem 1rem; font-size: 0.8rem;">Enviar Respuesta al Usuario</button>
                                                </form>
                                            <?php endif; ?>
                                        </div>
                                    <?php endforeach; ?>
                                </div>
                            <?php endif; ?>

                        <?php else: ?>
                            <h3 style="font-family: 'Orbitron'; color: var(--theme-color); margin-bottom: 1.5rem;">Configuración de Estilo y Seguridad</h3>
                            <form action="?view=profile" method="POST" enctype="multipart/form-data">
                                <input type="hidden" name="action" value="update_profile">
                                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                                <div class="form-group">
                                    <label>Nombre</label>
                                    <input type="text" name="nombre" value="<?php echo htmlspecialchars($current_user['nombre']); ?>" class="form-control" required>
                                </div>
                                <div class="form-group">
                                    <label>Apellido</label>
                                    <input type="text" name="apellido" value="<?php echo htmlspecialchars($current_user['apellido']); ?>" class="form-control" required>
                                </div>
                                <div class="form-group">
                                    <label>Nueva Contraseña (Opcional)</label>
                                    <input type="password" name="password" class="form-control" placeholder="Dejar en blanco para mantener la actual">
                                </div>

                                <div class="form-group">
                                    <label>Color Personalizado del Tema (Escribe o Selecciona)</label>
                                    <div style="display: flex; gap: 10px; align-items: center;">
                                        <input type="color" name="theme_color_picker" id="colorPickerInput" value="<?php echo htmlspecialchars($active_theme_color); ?>" style="width: 50px; height: 40px; background: transparent; border: 1px solid var(--theme-color); border-radius: 6px; cursor: pointer;" oninput="document.getElementById('themeColorText').value = this.value;">
                                        <input type="text" name="theme_color" id="themeColorText" value="<?php echo htmlspecialchars($active_theme_color); ?>" class="form-control" placeholder="#HEX o color CSS" required>
                                    </div>
                                </div>

                                <div class="form-group">
                                    <label>Subir Foto de Perfil (Moderno)</label>
                                    <div class="file-upload-wrapper">
                                        <span class="file-upload-text" id="fileNameLabel">📂 Seleccionar imagen en alta definición...</span>
                                        <input type="file" name="profile_pic" accept="image/png, image/jpeg, image/webp" onchange="document.getElementById('fileNameLabel').innerText = '✓ ' + this.files[0].name;">
                                    </div>
                                </div>

                                <div class="form-group" style="background: rgba(3,7,18,0.6); padding: 12px; border-radius: 6px; border: 1px solid rgba(255,255,255,0.1);">
                                    <label style="display: flex; align-items: center; justify-content: cursor; cursor: pointer; margin: 0;">
                                        <span style="color: #fff; font-family: 'Orbitron'; font-size: 0.85rem;">Activar Escudo Anti-DDoS en Sesión</span>
                                        <input type="checkbox" name="ddos_protection" value="1" <?php echo ($current_user['ddos_protection'] ?? 1) == 1 ? 'checked' : ''; ?> style="width: 18px; height: 18px; accent-color: var(--theme-color); cursor: pointer;">
                                    </label>
                                </div>

                                <hr style="border: 0; border-top: 1px solid rgba(255,255,255,0.1); margin: 1.5rem 0;">
                                <h4 style="font-family:'Orbitron'; font-size: 0.95rem; color: var(--theme-color); margin-bottom: 1rem;">Gestión de Preguntas de Seguridad</h4>
                                
                                <div class="form-group">
                                    <label>Pregunta 1: ¿Cuál es el nombre de tu primera mascota?</label>
                                    <input type="text" name="sec_question_1" value="¿Cuál es el nombre de tu primera mascota?" class="form-control" readonly>
                                    <input type="text" name="sec_answer_1" class="form-control" placeholder="Nueva respuesta (dejar en blanco para no cambiar)" style="margin-top: 5px;">
                                </div>
                                <div class="form-group">
                                    <label>Pregunta 2: ¿En qué ciudad naciste?</label>
                                    <input type="text" name="sec_question_2" value="¿En qué ciudad naciste?" class="form-control" readonly>
                                    <input type="text" name="sec_answer_2" class="form-control" placeholder="Nueva respuesta (dejar en blanco para no cambiar)" style="margin-top: 5px;">
                                </div>
                                <div class="form-group">
                                    <label>Pregunta 3: ¿Cuál es tu lenguaje de programación favorito?</label>
                                    <input type="text" name="sec_question_3" value="¿Cuál es tu lenguaje de programación favorito?" class="form-control" readonly>
                                    <input type="text" name="sec_answer_3" class="form-control" placeholder="Nueva respuesta (dejar en blanco para no cambiar)" style="margin-top: 5px;">
                                </div>

                                <button type="submit" class="btn btn-primary" style="width: 100%; margin-top: 1rem;">Guardar Todos los Cambios</button>
                            </form>
                        <?php endif; ?>
                    </div>
                </div>
            </main>
        <?php endif; ?>

        <footer>
            <p>&copy; 2026 CyberGuard Offensive. Arquitectura Criptográfica y Hardening Avanzado con Protección Anti-DDoS.</p>
        </footer>
    </div>

    <!-- Three.js para la animación interactiva 3D -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
    <script>
        const container = document.getElementById('canvas-container');
        const scene = new THREE.Scene();
        const camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
        const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true });
        
        renderer.setSize(window.innerWidth, window.innerHeight);
        container.appendChild(renderer.domElement);

        const currentThemeColor = getComputedStyle(document.documentElement).getPropertyValue('--theme-color').trim() || '#06b6d4';

        const geometry = new THREE.IcosahedronGeometry(2, 2);
        const material = new THREE.MeshBasicMaterial({ 
            color: currentThemeColor, 
            wireframe: true,
            transparent: true,
            opacity: 0.25
        });
        const sphere = new THREE.Mesh(geometry, material);
        scene.add(scene.add ? sphere : sphere); // Compatible

        camera.position.z = 5;

        function animate() {
            requestAnimationFrame(animate);
            sphere.rotation.x += 0.002;
            sphere.rotation.y += 0.003;
            renderer.render(scene, camera);
        }
        animate();

        window.addEventListener('resize', () => {
            camera.aspect = window.innerWidth / window.innerHeight;
            camera.updateProjectionMatrix();
            renderer.setSize(window.innerWidth, window.innerHeight);
        });

        document.querySelectorAll('.transition-link').forEach(link => {
            link.addEventListener('click', function(e) {
                const href = this.getAttribute('href');
                if (href && href.startsWith('?')) {
                    e.preventDefault();
                    document.body.classList.add('transitioning');
                    setTimeout(() => {
                        window.location.href = href;
                    }, 800);
                }
            });
        });
    </script>
</body>
</html>
