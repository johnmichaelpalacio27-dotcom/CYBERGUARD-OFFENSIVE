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

    // Tabla para Consultas de Ciberseguridad con soporte de respuesta de administrador y adjuntos
    $db->exec("CREATE TABLE IF NOT EXISTS security_consultations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        admin_id INTEGER,
        email TEXT NOT NULL,
        subject TEXT NOT NULL,
        message TEXT NOT NULL,
        attachment TEXT DEFAULT NULL,
        response TEXT DEFAULT NULL,
        response_attachment TEXT DEFAULT NULL,
        ip_address TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");

    // Tabla para Mensajería Global / Chat entre Usuarios y Administrador
    $db->exec("CREATE TABLE IF NOT EXISTS global_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        receiver_id INTEGER DEFAULT NULL,
        message TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");

    // Registrar administrador por defecto si no existe ninguno
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
        return $_SESSION[$key]['lock_until'] - time();
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

    // 1. Administrador responde consulta y adjunta archivo opcional (PDF, Word, etc.)
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
            $resp_attachment_path = null;

            // Procesar archivo adjunto del administrador (PDF, Word, etc.)
            if (isset($_FILES['response_attachment']) && $_FILES['response_attachment']['error'] === UPLOAD_ERR_OK) {
                $file_tmp = $_FILES['response_attachment']['tmp_name'];
                $file_ext = strtolower(pathinfo($_FILES['response_attachment']['name'], PATHINFO_EXTENSION));
                $allowed = ['pdf', 'doc', 'docx', 'txt', 'zip', 'rar'];
                
                $finfo = finfo_open(FILEINFO_MIME_TYPE);
                $mime_type = finfo_file($finfo, $file_tmp);
                $allowed_mimes = [
                    'application/pdf', 
                    'application/msword', 
                    'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 
                    'text/plain', 
                    'application/zip', 
                    'application/x-rar-compressed'
                ];

                if (in_array($file_ext, $allowed)) {
                    $upload_dir = __DIR__ . '/uploads/';
                    if (!is_dir($upload_dir)) { mkdir($upload_dir, 0755, true); }
                    $resp_attachment_path = 'uploads/resp_' . $consultation_id . '_' . time() . '.' . $file_ext;
                    move_uploaded_file($file_tmp, __DIR__ . '/' . $resp_attachment_path);
                }
            }

            if (!empty($response_text) || $resp_attachment_path) {
                if ($resp_attachment_path) {
                    $stmt_resp = $db->prepare("UPDATE security_consultations SET response = ?, admin_id = ?, response_attachment = ? WHERE id = ?");
                    $stmt_resp->execute([$response_text, $_SESSION['user_id'], $resp_attachment_path, $consultation_id]);
                } else {
                    $stmt_resp = $db->prepare("UPDATE security_consultations SET response = ?, admin_id = ? WHERE id = ?");
                    $stmt_resp->execute([$response_text, $_SESSION['user_id'], $consultation_id]);
                }
                $message = "Respuesta y reporte adjunto enviados correctamente al usuario.";
                $message_type = "success";
                $action = 'profile';
            } else {
                $message = "La respuesta no puede estar vacía si no se adjunta ningún archivo.";
                $message_type = "error";
                $action = 'profile';
            }
        } else {
            die("Acceso no autorizado.");
        }
    } 
    // 2. Registro de Usuario
    elseif ($form_action === 'register') {
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
    } 
    // 3. Inicio de Sesión
    elseif ($form_action === 'login') {
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
                $auth_passed = true;
                
                if ($user['role'] === 'admin') {
                    if (!password_verify($answer_1, $user['sec_answer_1']) || 
                        !password_verify($answer_2, $user['sec_answer_2']) || 
                        !password_verify($answer_3, $user['sec_answer_3'])) {
                        $auth_passed = false;
                        $message = "Acceso root denegado: Las respuestas a las preguntas de seguridad del administrador son incorrectas.";
                    }
                } else {
                    if (!empty($user['sec_answer_1']) && !empty($answer_1) && !password_verify($answer_1, $user['sec_answer_1'])) {
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
    } 
    // 4. Envío de Consulta de Ciberseguridad con Archivo Adjunto (Reporte PDF/Word)
    elseif ($form_action === 'consultation') {
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
            $attachment_path = null;

            // Procesar subida de reporte o archivo del usuario (PDF, Word, etc.)
            if (isset($_FILES['attachment']) && $_FILES['attachment']['error'] === UPLOAD_ERR_OK) {
                $file_tmp = $_FILES['attachment']['tmp_name'];
                $file_ext = strtolower(pathinfo($_FILES['attachment']['name'], PATHINFO_EXTENSION));
                $allowed = ['pdf', 'doc', 'docx', 'txt', 'zip', 'rar'];
                
                $finfo = finfo_open(FILEINFO_MIME_TYPE);
                $mime_type = finfo_file($finfo, $file_tmp);
                $allowed_mimes = [
                    'application/pdf', 
                    'application/msword', 
                    'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 
                    'text/plain', 
                    'application/zip', 
                    'application/x-rar-compressed'
                ];

                if (in_array($file_ext, $allowed)) {
                    $upload_dir = __DIR__ . '/uploads/';
                    if (!is_dir($upload_dir)) { mkdir($upload_dir, 0755, true); }
                    $attachment_path = 'uploads/consultation_' . time() . '_' . mt_rand(1000, 9999) . '.' . $file_ext;
                    move_uploaded_file($file_tmp, __DIR__ . '/' . $attachment_path);
                }
            }

            if (!empty($c_email) && !empty($c_subject) && (!empty($c_message) || $attachment_path)) {
                $stmt = $db->prepare("INSERT INTO security_consultations (user_id, email, subject, message, attachment, ip_address) VALUES (?, ?, ?, ?, ?, ?)");
                $stmt->execute([$c_uid, $c_email, $c_subject, $c_message, $attachment_path, $client_ip]);
                
                register_failed_attempt('consultation');
                $message = "Consulta y archivo de ciberseguridad enviados con éxito.";
                $message_type = "success";
                $action = 'consultation';
            } else {
                $message = "Por favor complete el correo, asunto y mensaje o adjunte un archivo de reporte válido.";
                $message_type = "error";
                $action = 'consultation';
            }
        }
    }
    // 5. Envío de Mensajes en el Chat Directo (Global o a Usuario Específico)
    elseif ($form_action === 'send_chat_message') {
        if (!isset($_SESSION['user_id'])) {
            header("Location: ?view=login");
            exit;
        }
        $sender_id = $_SESSION['user_id'];
        $receiver_id = !empty($_POST['receiver_id']) ? intval($_POST['receiver_id']) : null;
        $chat_msg = trim($_POST['chat_message']);

        if (!empty($chat_msg)) {
            $stmt_chat = $db->prepare("INSERT INTO global_messages (sender_id, receiver_id, message) VALUES (?, ?, ?)");
            $stmt_chat->execute([$sender_id, $receiver_id, $chat_msg]);
            $message = "Mensaje enviado correctamente.";
            $message_type = "success";
            $action = 'profile';
        } else {
            $message = "El mensaje no puede estar vacío.";
            $message_type = "error";
            $action = 'profile';
        }
    }
    // 6. Actualización de Perfil y Preferencias
    elseif ($form_action === 'update_profile') {
        if (!isset($_SESSION['user_id'])) {
            header("Location: ?view=login");
            exit;
        }
        $user_id = $_SESSION['user_id'];
        
        $stmt_check_rol = $db->prepare("SELECT role, password FROM users WHERE id = ?");
        $stmt_check_rol->execute([$user_id]);
        $current_db_user = $stmt_check_rol->fetch(PDO::FETCH_ASSOC);
        $is_admin_user = ($current_db_user['role'] === 'admin');

        $new_nombre = trim($_POST['nombre']);
        $new_apellido = trim($_POST['apellido']);
        $new_password = $_POST['password'];
        $theme_color = trim($_POST['theme_color'] ?? '#06b6d4');
        $ddos_toggle = isset($_POST['ddos_protection']) ? 1 : 0;
        
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
        
        $profile_pic_path = null;
        if (isset($_FILES['profile_pic']) && $_FILES['profile_pic']['error'] === UPLOAD_ERR_OK) {
            $file_tmp = $_FILES['profile_pic']['tmp_name'];
            $file_ext = strtolower(pathinfo($_FILES['profile_pic']['name'], PATHINFO_EXTENSION));
            $allowed = ['jpg', 'jpeg', 'png', 'webp'];
            
            $finfo = finfo_open(FILEINFO_MIME_TYPE);
            $mime_type = finfo_file($finfo, $file_tmp);

            if (in_array($file_ext, $allowed)) {
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

        if (!empty($new_password)) {
            $hashed_pass = password_hash($new_password, PASSWORD_BCRYPT);
            $sql = "UPDATE users SET nombre = ?, apellido = ?, password = ?, profile_pic = ?, theme_color = ?, ddos_protection = ?" . $q_update_extras . " WHERE id = ?";
            $params = array_merge([$new_nombre, $new_apellido, $hashed_pass, $profile_pic_path, $theme_color, $ddos_toggle], $params_extras, [$user_id]);
        } else {
            $sql = "UPDATE users SET nombre = ?, apellido = ?, profile_pic = ?, theme_color = ?, ddos_protection = ?" . $q_update_extras . " WHERE id = ?";
            $params = array_merge([$new_nombre, $new_apellido, $profile_pic_path, $theme_color, $ddos_toggle], $params_extras, [$user_id]);
        }
        $stmt = $db->prepare($sql);
        $stmt->execute($params);

        $_SESSION['user_nombre'] = $new_nombre;
        $message = "Perfil y capas de seguridad actualizadas de forma exitosa.";
        $message_type = "success";
        $action = 'profile';

        profile_update_skip:
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
    <title>CyberGuard Offensive | Seguridad & Hardening</title>
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&family=Inter:wght@300;400;600&display=swap" rel="stylesheet">
    <style>
        :root { --theme-color: <?php echo htmlspecialchars($active_theme_color); ?>; }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background-color: #030712; color: #f3f4f6; font-family: 'Inter', sans-serif; overflow-x: hidden; width: 100vw; min-height: 100vh; }
        .ui-layer { position: relative; z-index: 2; width: 100%; min-height: 100vh; display: flex; flex-direction: column; justify-content: space-between; padding: 2rem 4rem; }
        header { display: flex; justify-content: space-between; align-items: center; width: 100%; max-width: 1200px; margin: 0 auto; }
        .logo { font-family: 'Orbitron', sans-serif; font-size: 1.5rem; font-weight: 700; color: var(--theme-color); letter-spacing: 2px; text-decoration: none; }
        nav { display: flex; align-items: center; gap: 1.8rem; }
        nav a { color: #9ca3af; text-decoration: none; font-size: 0.9rem; transition: color 0.3s ease; cursor: pointer; }
        nav a:hover { color: var(--theme-color); }
        .nav-avatar { width: 32px; height: 32px; border-radius: 50%; object-fit: cover; border: 1px solid var(--theme-color); vertical-align: middle; margin-left: 0.5rem; }
        .hero, .content-section { max-width: 900px; margin: 2rem auto; width: 100%; }
        h1 { font-family: 'Orbitron', sans-serif; font-size: 2.5rem; line-height: 1.1; margin-bottom: 1.5rem; color: #ffffff; }
        h1 span { color: var(--theme-color); }
        .glass-card { background: rgba(15, 23, 42, 0.9); border: 1px solid rgba(6, 182, 212, 0.3); padding: 2.5rem; border-radius: 12px; box-shadow: 0 0 30px rgba(0, 0, 0, 0.7); margin-bottom: 2rem; }
        .form-group { margin-bottom: 1.2rem; }
        .form-group label { display: block; font-size: 0.85rem; color: var(--theme-color); font-family: 'Orbitron', sans-serif; margin-bottom: 0.5rem; }
        .form-control { width: 100%; padding: 0.8rem 1rem; background: rgba(3, 7, 18, 0.9); border: 1px solid rgba(255, 255, 255, 0.15); border-radius: 6px; color: #fff; font-size: 0.95rem; }
        .form-control:focus { outline: none; border-color: var(--theme-color); box-shadow: 0 0 10px rgba(6, 182, 212, 0.4); }
        .btn { padding: 0.9rem 2rem; border-radius: 6px; font-weight: 600; text-decoration: none; transition: all 0.3s ease; cursor: pointer; font-size: 0.95rem; display: inline-block; text-align: center; }
        .btn-primary { background-color: var(--theme-color); color: #030712; border: none; box-shadow: 0 0 20px rgba(6, 182, 212, 0.3); }
        .btn-primary:hover { filter: brightness(1.2); }
        .btn-outline { background: transparent; color: #f3f4f6; border: 1px solid rgba(255, 255, 255, 0.2); }
        .btn-outline:hover { border-color: var(--theme-color); color: var(--theme-color); }
        .alert { padding: 1rem; margin-bottom: 1.5rem; border-radius: 6px; font-size: 0.9rem; }
        .alert-error { background: rgba(239, 68, 68, 0.2); border: 1px solid #ef4444; color: #fca5a5; }
        .alert-success { background: rgba(16, 185, 129, 0.2); border: 1px solid #10b981; color: #a7f3d0; }
        table { width: 100%; border-collapse: collapse; margin-top: 1rem; background: rgba(3,7,18,0.5); }
        th, td { padding: 10px; border: 1px solid rgba(255,255,255,0.1); text-align: left; font-size: 0.9rem; }
        th { color: var(--theme-color); font-family: 'Orbitron'; }
        footer { text-align: center; padding: 1.5rem 0; color: #4b5563; font-size: 0.85rem; border-top: 1px solid rgba(255, 255, 255, 0.05); }
    </style>
</head>
<body>

    <div class="ui-layer">
        <header>
            <a href="?view=home" class="logo">CYBERGUARD//OFFENSIVE</a>
            <nav>
                <a href="?view=home">Inicio</a>
                <a href="?view=consultation">Consulta de Ciberseguridad</a>
                <?php if (isset($_SESSION['user_id'])): ?>
                    <a href="?view=profile" style="color: var(--theme-color); font-weight: 600;">Mi Perfil Blindado</a>
                    <a href="?view=logout" style="color: #ef4444;">Salir</a>
                <?php else: ?>
                    <a href="?view=login" style="color: var(--theme-color); font-weight: 600;">Iniciar Sesión</a>
                    <a href="?view=register" style="font-weight: 600;">Registrarse</a>
                <?php endif; ?>
            </nav>
        </header>

        <div class="hero">
            <?php if (!empty($message)): ?>
                <div class="alert alert-<?php echo $message_type === 'success' ? 'success' : 'error'; ?>">
                    <?php echo htmlspecialchars($message); ?>
                </div>
            <?php endif; ?>

            <?php if ($action === 'home'): ?>
                <div class="glass-card" style="text-align: center;">
                    <h1>SISTEMA DE DEFENSA <span>CYBERGUARD</span></h1>
                    <p style="color: #9ca3af; margin-bottom: 2rem;">Plataforma integral de ciberseguridad ofensiva y defensiva con gestión de reportes técnicos, análisis forense, archivos adjuntos (PDF/Word) y mensajería directa.</p>
                    <a href="?view=consultation" class="btn btn-primary">Enviar Consulta o Reporte Técnico</a>
                </div>

            <?php elseif ($action === 'consultation'): ?>
                <div class="glass-card">
                    <h1>Enviar Consulta o <span>Reporte de Vulnerabilidad</span></h1>
                    <p style="color: #9ca3af; margin-bottom: 1.5rem;">Adjunte archivos de reporte (PDF, Word, TXT, ZIP) para su análisis por el equipo de administración.</p>
                    <form method="POST" enctype="multipart/form-data">
                        <input type="hidden" name="action" value="consultation">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        
                        <div class="form-group">
                            <label>Correo Electrónico de Contacto</label>
                            <input type="email" name="email" class="form-control" required value="<?php echo isset($_SESSION['user_email']) ? htmlspecialchars($_SESSION['user_email']) : ''; ?>">
                        </div>
                        <div class="form-group">
                            <label>Asunto del Reporte o Consulta</label>
                            <input type="text" name="subject" class="form-control" placeholder="Ej: Auditoría de Bug Bounty o Brecha IDOR" required>
                        </div>
                        <div class="form-group">
                            <label>Mensaje / Descripción Detallada</label>
                            <textarea name="message" class="form-control" rows="5" placeholder="Describa el hallazgo técnico..."></textarea>
                        </div>
                        <div class="form-group">
                            <label>Adjuntar Reporte (PDF, Word, TXT, ZIP)</label>
                            <input type="file" name="attachment" class="form-control" accept=".pdf,.doc,.docx,.txt,.zip,.rar">
                        </div>
                        <button type="submit" class="btn btn-primary">Enviar Consulta Protegida</button>
                    </form>
                </div>

            <?php elseif ($action === 'login'): ?>
                <div class="glass-card" style="max-width: 450px; margin: 0 auto;">
                    <h1>Iniciar <span>Sesión</span></h1>
                    <form method="POST">
                        <input type="hidden" name="action" value="login">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <div class="form-group">
                            <label>Correo Electrónico</label>
                            <input type="email" name="login_id" class="form-control" required>
                        </div>
                        <div class="form-group">
                            <label>Contraseña</label>
                            <input type="password" name="password" class="form-control" required>
                        </div>
                        <button type="submit" class="btn btn-primary" style="width: 100%;">Acceder</button>
                    </form>
                </div>

            <?php elseif ($action === 'register'): ?>
                <div class="glass-card" style="max-width: 500px; margin: 0 auto;">
                    <h1>Registro de <span>Analista</span></h1>
                    <form method="POST">
                        <input type="hidden" name="action" value="register">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <div class="form-group">
                            <label>Nombre</label>
                            <input type="text" name="nombre" class="form-control" required>
                        </div>
                        <div class="form-group">
                            <label>Apellido</label>
                            <input type="text" name="apellido" class="form-control" required>
                        </div>
                        <div class="form-group">
                            <label>Correo Electrónico</label>
                            <input type="email" name="email" class="form-control" required>
                        </div>
                        <div class="form-group">
                            <label>Contraseña</label>
                            <input type="password" name="password" class="form-control" required>
                        </div>
                        <button type="submit" class="btn btn-primary" style="width: 100%;">Registrarse</button>
                    </form>
                </div>

            <?php elseif ($action === 'profile' && isset($logged_user)): ?>
                <div class="glass-card">
                    <h1>Panel de <span><?php echo htmlspecialchars($logged_user['role'] === 'admin' ? 'Administrador Root' : 'Analista'); ?></span></h1>
                    <p>Bienvenido, <strong><?php echo htmlspecialchars($logged_user['nombre'] . ' ' . $logged_user['apellido']); ?></strong> (<?php echo htmlspecialchars($logged_user['email']); ?>)</p>

                    <?php if ($logged_user['role'] === 'admin'): ?>
                        <h3 style="color: var(--theme-color); margin-top: 2rem; margin-bottom: 1rem; font-family:'Orbitron';">Bandeja de Consultas y Reportes de Usuarios</h3>
                        <table>
                            <tr>
                                <th>ID</th>
                                <th>Usuario / Email</th>
                                <th>Asunto & Mensaje</th>
                                <th>Reporte Adjunto</th>
                                <th>Respuesta Admin & Adjunto Respuesta</th>
                            </tr>
                            <?php
                            $stmt_all_c = $db->query("SELECT * FROM security_consultations ORDER BY id DESC");
                            while ($c_row = $stmt_all_c->fetch(PDO::FETCH_ASSOC)):
                            ?>
                            <tr>
                                <td>#<?php echo $c_row['id']; ?></td>
                                <td><?php echo htmlspecialchars($c_row['email']); ?></td>
                                <td>
                                    <strong><?php echo htmlspecialchars($c_row['subject']); ?></strong><br>
                                    <?php echo htmlspecialchars($c_row['message']); ?>
                                </td>
                                <td>
                                    <?php if (!empty($c_row['attachment']) && file_exists(__DIR__ . '/' . $c_row['attachment'])): ?>
                                        <a href="<?php echo htmlspecialchars($c_row['attachment']); ?>" target="_blank" style="color: var(--theme-color);">Descargar Reporte</a>
                                    <?php else: ?>
                                        <span style="color: #6b7280;">Sin archivo</span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <?php if (!empty($c_row['response'])): ?>
                                        <p style="color: #10b981; font-size: 0.85rem;"><?php echo htmlspecialchars($c_row['response']); ?></p>
                                        <?php if (!empty($c_row['response_attachment']) && file_exists(__DIR__ . '/' . $c_row['response_attachment'])): ?>
                                            <a href="<?php echo htmlspecialchars($c_row['response_attachment']); ?>" target="_blank" style="color: #10b981; font-size: 0.8rem;">Ver Archivo Admin</a>
                                        <?php endif; ?>
                                    <?php endif; ?>
                                    
                                    <form method="POST" enctype="multipart/form-data" style="margin-top: 0.5rem;">
                                        <input type="hidden" name="action" value="respond_consultation">
                                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                                        <input type="hidden" name="consultation_id" value="<?php echo $c_row['id']; ?>">
                                        <textarea name="response" class="form-control" rows="2" placeholder="Escribir respuesta..." required style="font-size: 0.8rem; margin-bottom: 0.3rem;"></textarea>
                                        <input type="file" name="response_attachment" class="form-control" style="font-size: 0.75rem; padding: 0.3rem; margin-bottom: 0.3rem;" accept=".pdf,.doc,.docx,.txt,.zip">
                                        <button type="submit" class="btn btn-primary" style="padding: 0.4rem 1rem; font-size: 0.8rem;">Responder y Enviar</button>
                                    </form>
                                </td>
                            </tr>
                            <?php endwhile; ?>
                        </table>
                    <?php else: ?>
                        <!-- VISTA DE CONSULTAS Y RESPUESTAS PARA EL USUARIO COMÚN -->
                        <h3 style="color: var(--theme-color); margin-top: 2rem; margin-bottom: 1rem; font-family:'Orbitron';">Mis Consultas y Respuestas del Administrador</h3>
                        <table>
                            <tr>
                                <th>Asunto</th>
                                <th>Mi Mensaje / Reporte</th>
                                <th>Respuesta del Administrador</th>
                            </tr>
                            <?php
                            $stmt_user_c = $db->prepare("SELECT * FROM security_consultations WHERE user_id = ? OR email = ? ORDER BY id DESC");
                            $stmt_user_c->execute([$logged_user['id'], $logged_user['email']]);
                            while ($uc_row = $stmt_user_c->fetch(PDO::FETCH_ASSOC)):
                            ?>
                            <tr>
                                <td><strong><?php echo htmlspecialchars($uc_row['subject']); ?></strong></td>
                                <td>
                                    <?php echo htmlspecialchars($uc_row['message']); ?><br>
                                    <?php if (!empty($uc_row['attachment']) && file_exists(__DIR__ . '/' . $uc_row['attachment'])): ?>
                                        <a href="<?php echo htmlspecialchars($uc_row['attachment']); ?>" target="_blank" style="color: var(--theme-color); font-size: 0.8rem;">[Descargar mi archivo]</a>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <?php if (!empty($uc_row['response'])): ?>
                                        <p style="color: #10b981;"><?php echo htmlspecialchars($uc_row['response']); ?></p>
                                        <?php if (!empty($uc_row['response_attachment']) && file_exists(__DIR__ . '/' . $uc_row['response_attachment'])): ?>
                                            <a href="<?php echo htmlspecialchars($uc_row['response_attachment']); ?>" target="_blank" style="color: var(--theme-color); font-size: 0.8rem;">[Descargar Archivo/Reporte del Admin]</a>
                                        <?php endif; ?>
                                    <?php else: ?>
                                        <span style="color: #9ca3af;">Pendiente de revisión...</span>
                                    <?php endif; ?>
                                </td>
                            </tr>
                            <?php endwhile; ?>
                        </table>
                    <?php endif; ?>

                    <!-- SECCIÓN DE MENSAJERÍA / CHAT DIRECTO ENTRE USUARIO Y ADMIN U OTROS -->
                    <h3 style="color: var(--theme-color); margin-top: 2.5rem; margin-bottom: 1rem; font-family:'Orbitron';">Mensajería Directa con el Administrador y Usuarios</h3>
                    <div style="background: rgba(3,7,18,0.7); padding: 1rem; border-radius: 8px; max-height: 250px; overflow-y: auto; margin-bottom: 1rem;">
                        <?php
                        $stmt_msgs = $db->query("SELECT gm.*, u.nombre as sender_name, u.role as sender_role FROM global_messages gm JOIN users u ON gm.sender_id = u.id ORDER BY gm.id ASC");
                        while ($m_row = $stmt_msgs->fetch(PDO::FETCH_ASSOC)):
                        ?>
                            <div style="margin-bottom: 0.8rem; border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 0.5rem;">
                                <strong style="color: <?php echo $m_row['sender_role'] === 'admin' ? '#ef4444' : 'var(--theme-color)'; ?>;">
                                    <?php echo htmlspecialchars($m_row['sender_name']); ?> (<?php echo $m_row['sender_role']; ?>):
                                </strong>
                                <span><?php echo htmlspecialchars($m_row['message']); ?></span>
                                <span style="font-size: 0.75rem; color: #6b7280; float: right;"><?php echo $m_row['created_at']; ?></span>
                            </div>
                        <?php endwhile; ?>
                    </div>

                    <form method="POST">
                        <input type="hidden" name="action" value="send_chat_message">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <div style="display: flex; gap: 1rem;">
                            <input type="text" name="chat_message" class="form-control" placeholder="Escribir mensaje al administrador o comunidad..." required>
                            <button type="submit" class="btn btn-primary" style="white-space: nowrap;">Enviar Mensaje</button>
                        </div>
                    </form>

                </div>
            <?php endif; ?>
        </div>

        <footer>
            <p>&copy; 2026 CyberGuard Offensive. Todos los derechos reservados.</p>
        </footer>
    </div>
</body>
</html>
