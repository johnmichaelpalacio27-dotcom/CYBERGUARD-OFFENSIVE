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

    // Tabla para Consultas de Ciberseguridad con soporte de archivos de usuario y administrador
    $db->exec("CREATE TABLE IF NOT EXISTS security_consultations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        admin_id INTEGER,
        email TEXT NOT NULL,
        subject TEXT NOT NULL,
        message TEXT NOT NULL,
        user_file_name TEXT DEFAULT NULL,
        user_file_path TEXT DEFAULT NULL,
        response TEXT DEFAULT NULL,
        admin_file_name TEXT DEFAULT NULL,
        admin_file_path TEXT DEFAULT NULL,
        ip_address TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");
    
    // Tabla para Chat en Vivo de Seguridad
    $db->exec("CREATE TABLE IF NOT EXISTS live_chat (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        message TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");

    // Tabla para Archivos de Usuario (Subidas y Descargas)
    $db->exec("CREATE TABLE IF NOT EXISTS user_files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        file_name TEXT NOT NULL,
        file_path TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");

    // Registrar administrador por defecto si no existe ninguno en la base de datos
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
        // Enviar cabecera 403 Forbidden
        header("HTTP/1.1 403 Forbidden");
        die("<h1>403 Forbidden</h1><p>Demasiados intentos. Acceso bloqueado temporalmente por seguridad.</p>");
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
            
            $admin_file_name = null;
            $admin_file_path = null;

            if (isset($_FILES['admin_file']) && $_FILES['admin_file']['error'] === UPLOAD_ERR_OK) {
                $file_tmp = $_FILES['admin_file']['tmp_name'];
                $original_name = basename($_FILES['admin_file']['name']);
                $file_ext = strtolower(pathinfo($original_name, PATHINFO_EXTENSION));
                
                $allowed_exts = ['pdf', 'doc', 'docx'];
                $finfo = finfo_open(FILEINFO_MIME_TYPE);
                $mime_type = finfo_file($finfo, $file_tmp);
                $allowed_mimes = [
                    'application/pdf', 
                    'application/msword', 
                    'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
                ];

                if (in_array($file_ext, $allowed_exts) && in_array($mime_type, $allowed_mimes)) {
                    $upload_dir = __DIR__ . '/uploads/';
                    if (!is_dir($upload_dir)) { mkdir($upload_dir, 0755, true); }
                    
                    $admin_file_name = $original_name;
                    $admin_file_path = 'uploads/resp_' . $consultation_id . '_' . time() . '.' . $file_ext;
                    move_uploaded_file($file_tmp, __DIR__ . '/' . $admin_file_path);
                }
            }

            if (!empty($response_text)) {
                $stmt_resp = $db->prepare("UPDATE security_consultations SET response = ?, admin_id = ?, admin_file_name = ?, admin_file_path = ? WHERE id = ?");
                $stmt_resp->execute([$response_text, $_SESSION['user_id'], $admin_file_name, $admin_file_path, $consultation_id]);
                
                $message = "Respuesta y archivo adjunto enviados correctamente.";
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
                $auth_passed = true;
                if ($user['role'] === 'admin') {
                    if (!password_verify($answer_1, $user['sec_answer_1']) || 
                        !password_verify($answer_2, $user['sec_answer_2']) || 
                        !password_verify($answer_3, $user['sec_answer_3'])) {
                        $auth_passed = false;
                        $message = "Acceso root denegado: Las respuestas a las preguntas de seguridad del administrador son incorrectas.";
                    }
                } else {
                    if (!empty($user['sec_answer_1']) && !password_verify($answer_1, $user['sec_answer_1'])) {
                        $auth_passed = false;
                        $message = "Acceso denegado: La respuesta a la pregunta de seguridad es incorrecta.";
                    }
                }

              // Dentro del bloque 'login'
                if (!$auth_passed) {
                    register_failed_attempt('login');
                    
                    // Verificamos si acabamos de entrar en bloqueo
                    $key = 'bf_login';
                    if ($_SESSION[$key]['attempts'] >= 3) {
                        header("HTTP/1.1 403 Forbidden");
                        die("<h1>403 Forbidden</h1><p>Has superado el límite de intentos. Acceso bloqueado.</p>");
                    }

                    $message = "Credenciales de acceso incorrectas.";
                    $message_type = "error";
                    $action = 'login';
                } else {
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

            $user_file_name = null;
            $user_file_path = null;

            if (isset($_FILES['user_file']) && $_FILES['user_file']['error'] === UPLOAD_ERR_OK) {
                $file_tmp = $_FILES['user_file']['tmp_name'];
                $original_name = basename($_FILES['user_file']['name']);
                $file_ext = strtolower(pathinfo($original_name, PATHINFO_EXTENSION));
                
                $allowed_exts = ['pdf', 'doc', 'docx'];
                $finfo = finfo_open(FILEINFO_MIME_TYPE);
                $mime_type = finfo_file($finfo, $file_tmp);
                $allowed_mimes = [
                    'application/pdf', 
                    'application/msword', 
                    'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
                ];

                if (in_array($file_ext, $allowed_exts) && in_array($mime_type, $allowed_mimes)) {
                    $upload_dir = __DIR__ . '/uploads/';
                    if (!is_dir($upload_dir)) { mkdir($upload_dir, 0755, true); }
                    
                    $user_file_name = $original_name;
                    $user_file_path = 'uploads/user_consulta_' . time() . '_' . mt_rand(1000,9999) . '.' . $file_ext;
                    move_uploaded_file($file_tmp, __DIR__ . '/' . $user_file_path);
                }
            }

            if (!empty($c_email) && !empty($c_subject) && !empty($c_message)) {
                $stmt = $db->prepare("INSERT INTO security_consultations (user_id, email, subject, message, user_file_name, user_file_path, ip_address) VALUES (?, ?, ?, ?, ?, ?, ?)");
                $stmt->execute([$c_uid, $c_email, $c_subject, $c_message, $user_file_name, $user_file_path, $client_ip]);
                
                register_failed_attempt('consultation');
                $message = "Consulta de ciberseguridad y archivo adjunto enviados con éxito.";
                $message_type = "success";
                $action = 'consultation';
            } else {
                $message = "Por favor complete todos los campos obligatorios de la consulta.";
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
                        Mi Perfil 
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

        <main style="max-width: 1200px; margin: 0 auto; width: 100%; display: flex; align-items: center; justify-content: center; flex: 1;">
            <?php if ($action === 'home'): ?>
                <div class="hero">
                    <div class="badge-status">[+] Sistema Operativo Activo &bull; Ciberseguridad Ofensiva</div>
                    <h1>Seguridad Web Avanzada y <span>Hardening 3D</span></h1>
                    <p class="subtitle">Plataforma integral orientada al análisis de vulnerabilidades, mitigación proactiva contra ataques de denegación de servicio (DDoS), y gestión de identidades protegidas bajo estándares criptográficos robustos.</p>
                    <div class="cta-group">
                        <a href="?view=consultation" class="btn btn-primary transition-link">Iniciar Consulta de Seguridad</a>
                        <?php if (!isset($_SESSION['user_id'])): ?>
                            <a href="?view=register" class="btn btn-outline transition-link">Registrar Analista</a>
                        <?php else: ?>
                            <a href="?view=profile" class="btn btn-outline transition-link">Ir a Mi Perfil</a>
                        <?php endif; ?>
                    </div>
                </div>
            <?php elseif ($action === 'about'): ?>
                <div class="content-section">
                    <div class="badge-status">Sobre CyberGuard</div>
                    <h1>Arquitectura de <span>Defensa Total</span></h1>
                    <p>CyberGuard Offensive es un entorno simulado de pruebas de penetración y control de accesos diseñado bajo los más estrictos lineamientos de seguridad defensiva. Nuestro motor integra contramedidas frente a inyecciones SQL, ataques de fuerza bruta con retardos exponenciales, protección contra falsificación de peticiones en sitios cruzados (CSRF) y gestión cifrada de contraseñas.</p>
                    <p>Contamos con herramientas automatizadas de auditoría y un panel centralizado para administradores y analistas de seguridad enfocados en la mitigación de vectores de ataque complejos.</p>
                    <div class="cta-group" style="margin-top: 2rem;">
                        <a href="?view=home" class="btn btn-outline transition-link">Volver al Inicio</a>
                    </div>
                </div>
            <?php elseif ($action === 'consultation'): ?>
                <div class="glass-card" style="margin: 0 auto; width: 100%;">
                    <div class="badge-status">Centro de Reportes</div>
                    <h2 style="font-family: 'Orbitron'; font-size: 1.8rem; margin-bottom: 1rem; color: #fff;">Consulta de Ciberseguridad</h2>
                    <p style="font-size: 0.9rem; color: #9ca3af; margin-bottom: 1.5rem;">Reporta anomalías, brechas o solicita asesoría técnica especializada. Esta sección cuenta con rate-limiting activo contra flood.</p>
                    <form action="?view=consultation" method="POST" enctype="multipart/form-data">
                        <input type="hidden" name="action" value="consultation">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        
                        <div class="form-group">
                            <label>Correo Electrónico de Contacto</label>
                            <input type="email" name="email" class="form-control" required value="<?php echo isset($_SESSION['user_email']) ? htmlspecialchars($_SESSION['user_email']) : ''; ?>">
                        </div>
                        <div class="form-group">
                            <label>Asunto / Vector Analizado</label>
                            <input type="text" name="subject" class="form-control" required placeholder="">
                        </div>
                        <div class="form-group">
                            <label>Descripción Detallada del Incidente</label>
                            <textarea name="message" class="form-control" rows="4" required placeholder=""></textarea>
                        </div>
                        <div class="form-group">
                            <label>Adjuntar Archivo de Soporte (PDF, Word)</label>
                            <div class="file-upload-wrapper">
                                <span class="file-upload-text">[+] Seleccionar Documento</span>
                                <input type="file" name="user_file" accept=".pdf, .doc, .docx">
                            </div>
                        </div>
                        <button type="submit" class="btn btn-primary" style="width: 100%;">Enviar Consulta Segura</button>
                    </form>
                </div>
            <?php elseif ($action === 'login'): ?>
                <div class="glass-card" style="margin: 0 auto; width: 100%;">
                    <div class="badge-status">Autenticación de Acceso</div>
                    <h2 style="font-family: 'Orbitron'; font-size: 1.8rem; margin-bottom: 1.5rem; color: #fff;">Login Seguro</h2>
                    
                    <?php if (isset($_GET['registered']) && !empty($_SESSION['temp_new_hash'])): ?>
                        <div class="alert alert-success">
                            ¡Registro completado con éxito! <strong>Guarde su Hash de Recuperación de un solo uso:</strong>
                            <div class="hash-display"><?php echo htmlspecialchars($_SESSION['temp_new_hash']); ?></div>
                        </div>
                        <?php unset($_SESSION['temp_new_hash']); ?>
                    <?php endif; ?>

                    <form action="?view=login" method="POST">
                        <input type="hidden" name="action" value="login">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        
                        <div class="form-group">
                            <label>Correo Electrónico</label>
                           <input type="email" name="login_id" class="form-control" required placeholder="">
                        </div>
                        <div class="form-group">
                            <label>Contraseña de Acceso</label>
                           <input type="password" name="password" class="form-control" required placeholder="">
                        </div>
                        <div class="form-group">
                            <label>Pregunta de Seguridad (Verificación)</label>
                            <input type="text" name="sec_answer_1" class="form-control" placeholder="">
                        </div>
                        <div class="form-group" id="admin-extra-q" style="display:none;">
                            <label style="color: #eab308;">[Admin Root] Pregunta 2 y 3</label>
                            <input type="text" name="sec_answer_2" class="form-control" placeholder="Respuesta 2 (Solo Root)" style="margin-bottom:0.8rem;">
                            <input type="text" name="sec_answer_3" class="form-control" placeholder="Respuesta 3 (Solo Root)">
                        </div>
                        <button type="submit" class="btn btn-primary" style="width: 100%; margin-top: 1rem;">Autenticarse</button>
                    </form>
                    <a href="?view=recover" class="link-sub" style="text-align: center;">¿Olvidó su contraseña? Recupérela con su Hash</a>
                </div>
                <script>
                    document.querySelector('input[name="login_id"]').addEventListener('blur', function() {
                        if(this.value === 'admin@cyberguard.com') {
                            document.getElementById('admin-extra-q').style.display = 'block';
                        }
                    });
                </script>
            <?php elseif ($action === 'register'): ?>
                <div class="glass-card" style="margin: 0 auto; width: 100%; max-width: 600px;">
                    <div class="badge-status">Nuevo Analista</div>
                    <h2 style="font-family: 'Orbitron'; font-size: 1.8rem; margin-bottom: 1.5rem; color: #fff;">Registro del Sistema</h2>
                    <form action="?view=register" method="POST">
                        <input type="hidden" name="action" value="register">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        
                        <div style="display: flex; gap: 1rem;">
                            <div class="form-group" style="flex: 1;">
                                <label>Nombre</label>
                              <input type="text" name="nombre" class="form-control" required placeholder="">
                            </div>
                            <div class="form-group" style="flex: 1;">
                                <label>Apellido</label>
                                <input type="text" name="apellido" class="form-control" required placeholder="">
                            </div>
                        </div>
                        <div class="form-group">
                            <label>Correo Electrónico</label>
                            <input type="email" name="email" class="form-control" required placeholder="john@cyberguard.com">
                        </div>
                        <div class="form-group">
                            <label>Contraseña Maestra</label>
                            <input type="password" name="password" class="form-control" required placeholder="••••••••">
                        </div>
                        <div class="form-group">
                            <label>Algoritmo de Hash de Recuperación</label>
                            <select name="hash_type" class="form-control">
                                <option value="sha256">SHA-256 (Recomendado)</option>
                                <option value="whirlpool">Whirlpool</option>
                                <option value="md5">MD5 (Legacy)</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label>Pregunta de Seguridad 1</label>
                            <input type="text" name="sec_question_1" class="form-control" required value="¿Cuál es tu ciudad de operaciones de ciberseguridad?">
                        </div>
                        <div class="form-group">
                            <label>Respuesta de Seguridad 1</label>
                            <input type="text" name="sec_answer_1" class="form-control" required placeholder="Respuesta secreta">
                        </div>
                        <input type="hidden" name="sec_question_2" value="">
                        <input type="hidden" name="sec_answer_2" value="">
                        <input type="hidden" name="sec_question_3" value="">
                        <input type="hidden" name="sec_answer_3" value="">

                        <button type="submit" class="btn btn-primary" style="width: 100%; margin-top: 1rem;">Registrar Cuenta y Generar Hash</button>
                    </form>
                </div>
            <?php elseif ($action === 'recover'): ?>
                <div class="glass-card" style="margin: 0 auto; width: 100%;">
                    <div class="badge-status">Recuperación Criptográfica</div>
                    <h2 style="font-family: 'Orbitron'; font-size: 1.8rem; margin-bottom: 1.5rem; color: #fff;">Recuperar por Hash</h2>
                    <p style="font-size: 0.9rem; color: #9ca3af; margin-bottom: 1.5rem;">Ingrese el Hash de un solo uso que se le proporcionó al momento de registrar su cuenta.</p>
                    <form action="?view=recover" method="POST">
                        <input type="hidden" name="action" value="recover_hash">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        
                        <div class="form-group">
                            <label>Hash de Seguridad Único</label>
                            <input type="text" name="recovery_hash" class="form-control" required placeholder="">
                        </div>
                        <button type="submit" class="btn btn-warning" style="width: 100%; margin-top: 1rem;">Validar Hash y Continuar</button>
                    </form>
                </div>
            <?php elseif ($action === 'reset_password'): ?>
                <div class="glass-card" style="margin: 0 auto; width: 100%;">
                    <div class="badge-status">Restablecimiento</div>
                    <h2 style="font-family: 'Orbitron'; font-size: 1.8rem; margin-bottom: 1.5rem; color: #fff;">Nueva Contraseña</h2>
                    <form action="?view=reset_password" method="POST">
                        <input type="hidden" name="action" value="reset_password_new">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        
                        <div class="form-group">
                            <label>Nueva Contraseña</label>
                            <input type="password" name="new_password" class="form-control" required placeholder="••••••••">
                        </div>
                        <button type="submit" class="btn btn-primary" style="width: 100%; margin-top: 1rem;">Actualizar Credenciales</button>
                    </form>
                </div>
            <?php elseif ($action === 'profile'): ?>
                <?php if (!isset($_SESSION['user_id'])) { header("Location: ?view=login"); exit; } ?>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; width: 100%; max-width: 1100px; margin: 2rem auto;">
                    
                    <!-- Tarjeta Izquierda: Información de Perfil & Hash -->
                    <div class="glass-card" style="max-width: 100%;">
                        <div class="avatar-3d-box">
                            <?php if (!empty($logged_user['profile_pic']) && file_exists(__DIR__ . '/' . $logged_user['profile_pic'])): ?>
                                <img src="<?php echo htmlspecialchars($logged_user['profile_pic']); ?>" style="width:100%; height:100%; object-fit:cover;" alt="Avatar">
                            <?php else: ?>
                                <?php echo strtoupper(substr($logged_user['nombre'], 0, 1)); ?>
                            <?php endif; ?>
                        </div>
                        <h2 style="font-family: 'Orbitron'; text-align: center; margin-bottom: 0.5rem; color: #fff;"><?php echo htmlspecialchars($logged_user['nombre'] . ' ' . $logged_user['apellido']); ?></h2>
                        <p style="text-align: center; color: var(--theme-color); font-size: 0.9rem; margin-bottom: 1.5rem;"><?php echo htmlspecialchars($logged_user['email']); ?> &bull; <span style="text-transform: uppercase;"><?php echo htmlspecialchars($logged_user['role']); ?></span></p>
                        
                        <div style="background: rgba(3, 7, 18, 0.6); padding: 1rem; border-radius: 8px; border: 1px solid rgba(6,182,212,0.2); margin-bottom: 1.5rem;">
                            <label style="font-size: 0.75rem; color: var(--theme-color); font-family: 'Orbitron'; display: block; margin-bottom: 0.3rem;">Hash de Recuperación Activo (<?php echo strtoupper($logged_user['hash_type']); ?>):</label>
                            <div class="hash-display"><?php echo htmlspecialchars($logged_user['single_use_hash']); ?></div>
                        </div>

                        <form action="?view=profile" method="POST">
                            <input type="hidden" name="action" value="generate_new_hash">
                            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                            <div class="form-group">
                                <label>Regenerar Hash con Algoritmo:</label>
                                <select name="hash_type" class="form-control" style="margin-bottom: 0.8rem;">
                                    <option value="sha256">SHA-256</option>
                                    <option value="whirlpool">Whirlpool</option>
                                    <option value="sha512">SHA-512</option>
                                </select>
                            </div>
                            <button type="submit" class="btn btn-outline" style="width: 100%; font-size: 0.85rem;">Generar Nuevo Hash de Perfil</button>
                        </form>

                        <!-- Panel de Administración de Consultas / Historial de Usuario -->
                        <?php if ($logged_user['role'] === 'admin'): ?>
                            <hr style="border:0; border-top:1px solid rgba(255,255,255,0.1); margin: 2rem 0;">
                            <h3 style="font-family: 'Orbitron'; font-size: 1.1rem; color: var(--theme-color); margin-bottom: 1rem;">Gestión de Consultas Admin Root </h3>
                            <div style="max-height: 450px; overflow-y: auto; display: flex; flex-direction: column; gap: 1rem;">
                                <?php 
                                $consultas = $db->query("SELECT * FROM security_consultations ORDER BY created_at DESC");
                                while($c = $consultas->fetch(PDO::FETCH_ASSOC)):
                                ?>
                                    <div style="background: rgba(3,7,18,0.8); padding: 1rem; border-radius: 6px; border: 1px solid rgba(255,255,255,0.1);">
                                        <p style="font-size: 0.8rem; color: #eab308;">De: <?php echo htmlspecialchars($c['email']); ?> [IP: <?php echo htmlspecialchars($c['ip_address']); ?>]</p>
                                        <p style="font-size: 0.85rem; font-weight: 600; color: #fff; margin: 0.2rem 0;"><?php echo htmlspecialchars($c['subject']); ?></p>
                                        <p style="font-size: 0.8rem; color: #9ca3af; margin-bottom: 0.5rem;"><?php echo htmlspecialchars($c['message']); ?></p>
                                        
                                        <!-- Previsualización del archivo enviado por el usuario -->
                                        <?php if (!empty($c['user_file_path']) && file_exists(__DIR__ . '/' . $c['user_file_path'])): ?>
                                            <div style="margin: 0.8rem 0; background: rgba(0,0,0,0.5); padding: 0.5rem; border-radius: 4px;">
                                                <p style="font-size: 0.75rem; color: var(--theme-color); margin-bottom: 0.3rem;">Archivo del usuario: <?php echo htmlspecialchars($c['user_file_name']); ?></p>
                                                <div style="display: flex; gap: 0.5rem; margin-bottom: 0.5rem;">
                                                    <a href="<?php echo htmlspecialchars($c['user_file_path']); ?>" download="<?php echo htmlspecialchars($c['user_file_name']); ?>" class="btn btn-primary" style="font-size: 0.7rem; padding: 0.3rem 0.6rem; text-decoration: none;">[↓] Descargar</a>
                                                </div>
                                                <iframe src="<?php echo htmlspecialchars($c['user_file_path']); ?>" style="width: 100%; height: 180px; border: 1px solid rgba(255,255,255,0.2); border-radius: 4px;" title="Previsualización documento"></iframe>
                                            </div>
                                        <?php endif; ?>

                                        <?php if (!empty($c['response'])): ?>
                                            <p style="font-size: 0.8rem; color: #10b981; background: rgba(16,185,129,0.1); padding: 0.4rem; border-radius: 4px; margin-bottom: 0.5rem;"><strong>Respuesta Admin:</strong> <?php echo htmlspecialchars($c['response']); ?></p>
                                            <?php if (!empty($c['admin_file_path']) && file_exists(__DIR__ . '/' . $c['admin_file_path'])): ?>
                                                <div style="margin-bottom: 0.5rem;">
                                                    <a href="<?php echo htmlspecialchars($c['admin_file_path']); ?>" download="<?php echo htmlspecialchars($c['admin_file_name']); ?>" class="btn btn-primary" style="font-size: 0.75rem; padding: 0.4rem 0.8rem; text-decoration: none;">
                                                        [↓] Descargar Adjunto Admin: <?php echo htmlspecialchars($c['admin_file_name']); ?>
                                                    </a>
                                                </div>
                                            <?php endif; ?>
                                        <?php else: ?>
                                            <form action="?view=profile" method="POST" enctype="multipart/form-data" style="margin-top: 0.8rem;">
                                                <input type="hidden" name="action" value="respond_consultation">
                                                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                                                <input type="hidden" name="consultation_id" value="<?php echo $c['id']; ?>">
                                                
                                                <textarea name="response" class="form-control" placeholder="Escribir respuesta oficial..." style="font-size: 0.8rem; padding: 0.4rem; margin-bottom: 0.4rem;" required></textarea>
                                                
                                                <div class="form-group" style="margin-bottom: 0.5rem;">
                                                    <label style="font-size: 0.75rem;">Adjuntar Archivo de Respuesta (PDF, Word):</label>
                                                    <input type="file" name="admin_file" class="form-control" accept=".pdf, .doc, .docx" style="font-size: 0.75rem; padding: 0.3rem;">
                                                </div>

                                                <button type="submit" class="btn btn-primary" style="padding: 0.3rem 0.8rem; font-size: 0.75rem;">Enviar Respuesta y Archivo</button>
                                            </form>
                                        <?php endif; ?>
                                    </div>
                                <?php endwhile; ?>
                            </div>
                        <?php else: ?>
                            <hr style="border:0; border-top:1px solid rgba(255,255,255,0.1); margin: 2rem 0;">
                            <h3 style="font-family: 'Orbitron'; font-size: 1.1rem; color: var(--theme-color); margin-bottom: 1rem;">Mis Consultas y Archivos Compartidos</h3>
                            <div style="max-height: 400px; overflow-y: auto; display: flex; flex-direction: column; gap: 1rem;">
                                <?php 
                                $stmt_mis_consultas = $db->prepare("SELECT * FROM security_consultations WHERE user_id = ? OR email = ? ORDER BY created_at DESC");
                                $stmt_mis_consultas->execute([$logged_user['id'], $logged_user['email']]);
                                while($mc = $stmt_mis_consultas->fetch(PDO::FETCH_ASSOC)):
                                ?>
                                    <div style="background: rgba(3,7,18,0.8); padding: 1rem; border-radius: 6px; border: 1px solid rgba(6,182,212,0.2);">
                                        <p style="font-size: 0.8rem; color: #9ca3af;">Asunto: <strong><?php echo htmlspecialchars($mc['subject']); ?></strong></p>
                                        <p style="font-size: 0.85rem; color: #fff; margin: 0.3rem 0;">Tu consulta: <?php echo htmlspecialchars($mc['message']); ?></p>
                                        
                                        <?php if (!empty($mc['user_file_path']) && file_exists(__DIR__ . '/' . $mc['user_file_path'])): ?>
                                            <div style="margin: 0.5rem 0; font-size: 0.75rem; color: var(--theme-color);">
                                                Tu archivo adjunto: <a href="<?php echo htmlspecialchars($mc['user_file_path']); ?>" download="<?php echo htmlspecialchars($mc['user_file_name']); ?>" style="color: #fff; text-decoration: underline;"><?php echo htmlspecialchars($mc['user_file_name']); ?></a>
                                            </div>
                                        <?php endif; ?>

                                        <?php if (!empty($mc['response'])): ?>
                                            <div style="margin-top: 0.8rem; background: rgba(16,185,129,0.1); border: 1px solid #10b981; padding: 0.6rem; border-radius: 4px;">
                                                <p style="font-size: 0.85rem; color: #10b981; margin-bottom: 0.5rem;"><strong>Respuesta del Administrador:</strong> <?php echo htmlspecialchars($mc['response']); ?></p>
                                                
                                                <?php if (!empty($mc['admin_file_path']) && file_exists(__DIR__ . '/' . $mc['admin_file_path'])): ?>
                                                    <div style="margin-top: 0.5rem;">
                                                        <a href="<?php echo htmlspecialchars($mc['admin_file_path']); ?>" download="<?php echo htmlspecialchars($mc['admin_file_name']); ?>" class="btn btn-primary" style="font-size: 0.75rem; padding: 0.4rem 0.8rem; text-decoration: none; margin-bottom: 0.5rem; display: inline-block;">
                                                            [↓] Descargar Archivo del Admin: <?php echo htmlspecialchars($mc['admin_file_name']); ?>
                                                        </a>
                                                        <iframe src="<?php echo htmlspecialchars($mc['admin_file_path']); ?>" style="width: 100%; height: 180px; border: 1px solid rgba(255,255,255,0.2); border-radius: 4px;" title="Previsualizador documento admin"></iframe>
                                                    </div>
                                                <?php endif; ?>
                                            </div>
                                        <?php else: ?>
                                            <p style="font-size: 0.75rem; color: #eab308; margin-top: 0.5rem;">[⏳] Estado: Pendiente de respuesta por el equipo de analistas.</p>
                                        <?php endif; ?>
                                    </div>
                                <?php endwhile; ?>
                            </div>
                        <?php endif; ?>

                    </div>

                    <!-- Tarjeta Derecha: Editor de Datos y Configuración -->
                    <div class="glass-card" style="max-width: 100%;">
                        <div class="badge-status">Hardening de Cuenta</div>
                        <h2 style="font-family: 'Orbitron'; font-size: 1.5rem; margin-bottom: 1.5rem; color: #fff;">Configuración de Perfil</h2>
                        
                        <form action="?view=profile" method="POST" enctype="multipart/form-data">
                            <input type="hidden" name="action" value="update_profile">
                            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                            
                            <div style="display: flex; gap: 1rem;">
                                <div class="form-group" style="flex: 1;">
                                    <label>Nombre</label>
                                    <input type="text" name="nombre" class="form-control" required value="<?php echo htmlspecialchars($logged_user['nombre']); ?>">
                                </div>
                                <div class="form-group" style="flex: 1;">
                                    <label>Apellido</label>
                                    <input type="text" name="apellido" class="form-control" required value="<?php echo htmlspecialchars($logged_user['apellido']); ?>">
                                </div>
                            </div>
                            
                            <div class="form-group">
                                <label>Nueva Contraseña (Opcional)</label>
                                <input type="password" name="password" class="form-control" placeholder="Dejar en blanco para mantener actual">
                            </div>

                            <?php if ($logged_user['role'] === 'admin'): ?>
                                <div class="form-group" style="background: rgba(239, 68, 68, 0.1); border: 1px solid #ef4444; padding: 1rem; border-radius: 6px;">
                                    <label style="color: #ef4444;">Contraseña de Administrador Actual (Obligatoria)</label>
                                    <input type="password" name="current_admin_password" class="form-control" required placeholder="Ingrese su contraseña root actual">
                                </div>
                            <?php endif; ?>

                            <div class="form-group">
                                <label>Color Temático de la Interfaz (CSS Var)</label>
                                <input type="color" name="theme_color" class="form-control" style="height: 45px; cursor: pointer;" value="<?php echo htmlspecialchars($active_theme_color); ?>">
                            </div>

                            <div class="form-group">
                                <label>Fotografía de Perfil (Avatar)</label>
                                <div class="file-upload-wrapper">
                                    <span class="file-upload-text">[+] Seleccionar Imagen (JPG, PNG, WEBP)</span>
                                    <input type="file" name="profile_pic" accept=".jpg, .jpeg, .png, .webp">
                                </div>
                            </div>

                            <div class="form-group">
                                <label>Pregunta de Seguridad 1</label>
                                <input type="text" name="sec_question_1" class="form-control" value="<?php echo htmlspecialchars($logged_user['sec_question_1']); ?>">
                            </div>
                            <div class="form-group">
                                <label>Nueva Respuesta 1 (Opcional)</label>
                                <input type="text" name="sec_answer_1" class="form-control" placeholder="Nueva respuesta secreta">
                            </div>

                            <div class="form-group" style="display: flex; align-items: center; gap: 0.8rem; margin-top: 1rem;">
                                <input type="checkbox" name="ddos_protection" id="ddos_toggle" value="1" <?php echo $logged_user['ddos_protection'] ? 'checked' : ''; ?> style="width: 18px; height: 18px; accent-color: var(--theme-color);">
                                <label for="ddos_toggle" style="margin-bottom: 0; cursor: pointer; color: #fff;">Activar Escudo Anti-DDoS Avanzado en Sesión</label>
                            </div>

                            <button type="submit" class="btn btn-primary" style="width: 100%; margin-top: 1.5rem;">Guardar Cambios y Blindaje</button>
                        </form>

                        <hr style="border: 0; border-top: 1px solid rgba(255,255,255,0.1); margin: 2rem 0;">
                        
                        <h3 style="font-family: 'Orbitron'; color: var(--theme-color); margin-bottom: 1rem;">Chat en Vivo de Seguridad</h3>
                        <div id="chat-box" style="height:250px; overflow-y:auto; background:rgba(3, 7, 18, 0.6); border: 1px solid rgba(6, 182, 212, 0.2); padding:1rem; border-radius:8px; margin-bottom:1rem; font-size: 0.9rem;">
                        </div>
                        <div style="display: flex; gap: 10px;">
                            <input type="text" id="chat-input" class="form-control" placeholder="Escribe un mensaje de seguridad...">
                            <button onclick="enviarMensaje()" class="btn btn-primary">Enviar</button>
                        </div>

                    </div>

                </div>
            <?php endif; ?>
        </main>

        <footer>
            <p>&copy; 2026 CyberGuard Offensive Systems. Todos los derechos reservados. Entorno Protegido.</p>
        </footer>
    </div>

    <!-- Script 3D Three.js para Fondo Animado de Ciberseguridad -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
    <script>
        const container = document.getElementById('canvas-container');
        const scene = new THREE.Scene();
        const camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
        const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true });
        renderer.setSize(window.innerWidth, window.innerHeight);
        container.appendChild(renderer.domElement);

        const particlesGeometry = new THREE.BufferGeometry();
        const particlesCount = 700;
        const posArray = new Float32Array(particlesCount * 3);

        for(let i = 0; i < particlesCount * 3; i++) {
            posArray[i] = (Math.random() - 0.5) * 15;
        }

        particlesGeometry.setAttribute('position', new THREE.BufferAttribute(posArray, 3));
        
        const material = new THREE.PointsMaterial({
            size: 0.03,
            color: getComputedStyle(document.documentElement).getPropertyValue('--theme-color').trim() || '#06b6d4',
            transparent: true,
            opacity: 0.8
        });

        const particlesMesh = new THREE.Points(particlesGeometry, material);
        scene.add(particlesMesh);

        camera.position.z = 4;

        let mouseX = 0;
        let mouseY = 0;
        document.addEventListener('mousemove', (event) => {
            mouseX = event.clientX / window.innerWidth - 0.5;
            mouseY = event.clientY / window.innerHeight - 0.5;
        });

        function animate() {
            requestAnimationFrame(animate);
            particlesMesh.rotation.y += 0.0015 + (mouseX * 0.05);
            particlesMesh.rotation.x += 0.001 + (mouseY * 0.05);
            renderer.render(scene, camera);
        }
        animate();

        window.addEventListener('resize', () => {
            camera.aspect = window.innerWidth / window.innerHeight;
            camera.updateProjectionMatrix();
            renderer.setSize(window.innerWidth, window.innerHeight);
        });

        function cargarChat() {
            fetch('chat_backend.php')
                .then(response => response.text())
                .then(data => { 
                    const chatBox = document.getElementById('chat-box');
                    if(chatBox) {
                        chatBox.innerHTML = data; 
                        chatBox.scrollTop = chatBox.scrollHeight;
                    }
                }).catch(err => {});
        }

        function enviarMensaje() {
            let inputElem = document.getElementById('chat-input');
            if(!inputElem) return;
            let msg = inputElem.value;
            if(!msg) return;
            let formData = new FormData();
            formData.append('message', msg);
            formData.append('csrf_token', '<?php echo $_SESSION['csrf_token']; ?>');
            
            fetch('chat_backend.php', { method: 'POST', body: formData })
                .then(() => {
                    inputElem.value = '';
                    cargarChat();
                }).catch(err => {});
        }

        if(document.getElementById('chat-box')) {
            setInterval(cargarChat, 3000);
            cargarChat();
        }
    </script>
</body>
</html>
