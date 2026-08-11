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

    // Inicializar tablas necesarias
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

    // Tabla para Consultas de Ciberseguridad con soporte de archivos adjuntos y respuestas
    $db->exec("CREATE TABLE IF NOT EXISTS security_consultations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        admin_id INTEGER,
        email TEXT NOT NULL,
        subject TEXT NOT NULL,
        message TEXT NOT NULL,
        attachment_path TEXT DEFAULT NULL,
        response TEXT DEFAULT NULL,
        response_attachment TEXT DEFAULT NULL,
        ip_address TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");

    // Tabla para el Chat Global de Usuarios y Administrador
    $db->exec("CREATE TABLE IF NOT EXISTS global_chat (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        message TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");

    // Registrar administrador por defecto si no existe
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

// --- CONTROL DE BLOQUEO POR FUERZA BRUTA ---
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

// --- PROCESAMIENTO DE ACCIONES BACKEND ---
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $form_action = isset($_POST['action']) ? $_POST['action'] : '';

    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die("Error de validación de seguridad (CSRF Token inválido o expirado).");
    }

    // Enviar mensaje al Chat Global
    if ($form_action === 'send_chat_message') {
        if (!isset($_SESSION['user_id'])) {
            header("Location: ?view=login");
            exit;
        }
        $chat_msg = trim($_POST['chat_message']);
        if (!empty($chat_msg)) {
            $stmt_chat = $db->prepare("INSERT INTO global_chat (user_id, message) VALUES (?, ?)");
            $stmt_chat->execute([$_SESSION['user_id'], $chat_msg]);
            header("Location: ?view=chat");
            exit;
        }
    }

    // Lógica para que el Administrador responda consultas con archivos adjuntos opcionales (Word, PDF, imágenes)
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

            // Manejo de archivo adjunto en la respuesta del admin
            if (isset($_FILES['response_file']) && $_FILES['response_file']['error'] === UPLOAD_ERR_OK) {
                $file_tmp = $_FILES['response_file']['tmp_name'];
                $file_ext = strtolower(pathinfo($_FILES['response_file']['name'], PATHINFO_EXTENSION));
                $allowed_exts = ['pdf', 'doc', 'docx', 'jpg', 'jpeg', 'png', 'webp'];
                
                if (in_array($file_ext, $allowed_exts)) {
                    $upload_dir = __DIR__ . '/uploads/';
                    if (!is_dir($upload_dir)) { mkdir($upload_dir, 0755, true); }
                    $resp_attachment_path = 'uploads/resp_' . $consultation_id . '_' . time() . '.' . $file_ext;
                    move_uploaded_file($file_tmp, __DIR__ . '/' . $resp_attachment_path);
                }
            }

            if (!empty($response_text)) {
                $stmt_resp = $db->prepare("UPDATE security_consultations SET response = ?, admin_id = ?, response_attachment = COALESCE(?, response_attachment) WHERE id = ?");
                $stmt_resp->execute([$response_text, $_SESSION['user_id'], $resp_attachment_path, $consultation_id]);
                $message = "Respuesta y archivo enviados correctamente al usuario.";
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
        $single_use_hash = ($hash_type === 'whirlpool') ? hash('whirlpool', $raw_hash_data) : (($hash_type === 'md5') ? md5($raw_hash_data) : hash('sha256', $raw_hash_data));

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
                        $message = "Acceso root denegado: Las respuestas de seguridad son incorrectas.";
                    }
                } else {
                    if (!empty($user['sec_answer_1']) && !empty($answer_1) && !password_verify($answer_1, $user['sec_answer_1'])) {
                        $auth_passed = false;
                        $message = "Acceso denegado: Respuesta de seguridad incorrecta.";
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
        $recovery_hash = trim($_POST['recovery_hash']);
        $stmt = $db->prepare("SELECT * FROM users WHERE single_use_hash = ?");
        $stmt->execute([$recovery_hash]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user) {
            $_SESSION['recovery_user_id'] = $user['id'];
            header("Location: ?view=reset_password");
            exit;
        } else {
            $message = "El Hash ingresado es inválido.";
            $message_type = "error";
            $action = 'recover';
        }
    } elseif ($form_action === 'reset_password_new') {
        if (!isset($_SESSION['recovery_user_id'])) { header("Location: ?view=home"); exit; }
        $rec_user_id = $_SESSION['recovery_user_id'];
        $new_pass = $_POST['new_password'];

        if (!empty($new_pass)) {
            $hashed_pass = password_hash($new_pass, PASSWORD_BCRYPT);
            $stmt_u = $db->prepare("SELECT hash_type FROM users WHERE id = ?");
            $stmt_u->execute([$rec_user_id]);
            $u_data = $stmt_u->fetch(PDO::FETCH_ASSOC);
            $htype = $u_data['hash_type'] ?? 'sha256';

            $raw_data = random_bytes(32);
            $new_hash = ($htype === 'whirlpool') ? hash('whirlpool', $raw_data) : (($htype === 'md5') ? md5($raw_data) : hash('sha256', $raw_data));

            $stmt_update = $db->prepare("UPDATE users SET password = ?, single_use_hash = ?, hash_used = 0 WHERE id = ?");
            $stmt_update->execute([$hashed_pass, $new_hash, $rec_user_id]);

            unset($_SESSION['recovery_user_id']);
            $message = "Contraseña restablecida exitosamente. Inicia sesión.";
            $message_type = "success";
            $action = 'login';
        }
    } elseif ($form_action === 'generate_new_hash') {
        if (!isset($_SESSION['user_id'])) { header("Location: ?view=login"); exit; }
        $user_id = $_SESSION['user_id'];
        $desired_type = $_POST['hash_type'] ?? 'sha256';
        $raw_data = random_bytes(32);
        $nuevo_hash = ($desired_type === 'whirlpool') ? hash('whirlpool', $raw_data) : (($desired_type === 'md5') ? md5($raw_data) : hash('sha256', $raw_data));

        $stmt = $db->prepare("UPDATE users SET single_use_hash = ?, hash_type = ?, hash_used = 0 WHERE id = ?");
        $stmt->execute([$nuevo_hash, $desired_type, $user_id]);

        $message = "Nuevo Hash de seguridad generado exitosamente.";
        $message_type = "success";
        $action = 'profile';
    } elseif ($form_action === 'update_profile') {
        if (!isset($_SESSION['user_id'])) { header("Location: ?view=login"); exit; }
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
                $message = "Debe ingresar su contraseña de Administrador actual para autorizar cambios.";
                $message_type = "error";
                $action = 'profile';
                goto profile_update_skip;
            }
        }
        
        $profile_pic_path = null;
        if (isset($_FILES['profile_pic']) && $_FILES['profile_pic']['error'] === UPLOAD_ERR_OK) {
            $file_tmp = $_FILES['profile_pic']['tmp_name'];
            $file_ext = strtolower(pathinfo($_FILES['profile_pic']['name'], PATHINFO_EXTENSION));
            $allowed = ['jpg', 'jpeg', 'png', 'webp'];
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
        if (!$profile_pic_path) { $profile_pic_path = $old_data['profile_pic']; }

        if (!empty($new_password)) {
            $hashed_pass = password_hash($new_password, PASSWORD_BCRYPT);
            $stmt = $db->prepare("UPDATE users SET nombre = ?, apellido = ?, password = ?, profile_pic = ?, theme_color = ?, ddos_protection = ? WHERE id = ?");
            $stmt->execute([$new_nombre, $new_apellido, $hashed_pass, $profile_pic_path, $theme_color, $ddos_toggle, $user_id]);
        } else {
            $stmt = $db->prepare("UPDATE users SET nombre = ?, apellido = ?, profile_pic = ?, theme_color = ?, ddos_protection = ? WHERE id = ?");
            $stmt->execute([$new_nombre, $new_apellido, $profile_pic_path, $theme_color, $ddos_toggle, $user_id]);
        }

        $_SESSION['user_nombre'] = $new_nombre;
        $message = "Perfil actualizado exitosamente.";
        $message_type = "success";
        $action = 'profile';

        profile_update_skip:
    } elseif ($form_action === 'consultation') {
        $c_email = trim($_POST['email']);
        $c_subject = trim($_POST['subject']);
        $c_message = trim($_POST['message']);
        $c_uid = isset($_SESSION['user_id']) ? $_SESSION['user_id'] : null;
        $attachment_path = null;

        // Manejo de archivo adjunto enviado por el usuario en su consulta/reporte (PDF, Word, imágenes)
        if (isset($_FILES['attachment']) && $_FILES['attachment']['error'] === UPLOAD_ERR_OK) {
            $file_tmp = $_FILES['attachment']['tmp_name'];
            $file_ext = strtolower(pathinfo($_FILES['attachment']['name'], PATHINFO_EXTENSION));
            $allowed_exts = ['pdf', 'doc', 'docx', 'jpg', 'jpeg', 'png', 'webp'];
            
            if (in_array($file_ext, $allowed_exts)) {
                $upload_dir = __DIR__ . '/uploads/';
                if (!is_dir($upload_dir)) { mkdir($upload_dir, 0755, true); }
                $attachment_path = 'uploads/report_' . time() . '_' . rand(1000, 9999) . '.' . $file_ext;
                move_uploaded_file($file_tmp, __DIR__ . '/' . $attachment_path);
            }
        }

        if (!empty($c_email) && !empty($c_subject) && !empty($c_message)) {
            $stmt = $db->prepare("INSERT INTO security_consultations (user_id, email, subject, message, attachment_path, ip_address) VALUES (?, ?, ?, ?, ?, ?)");
            $stmt->execute([$c_uid, $c_email, $c_subject, $c_message, $attachment_path, $client_ip]);
            
            $message = "Reporte o consulta enviada con éxito (incluyendo archivo adjunto si fue proporcionado).";
            $message_type = "success";
            $action = 'consultation';
        } else {
            $message = "Por favor complete todos los campos obligatorios.";
            $message_type = "error";
            $action = 'consultation';
        }
    }
}

// Manejo de Logout
if ($action === 'logout') {
    $_SESSION = array();
    session_destroy();
    header("Location: ?view=home");
    exit;
}

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
        :root { --theme-color: <?php echo htmlspecialchars($active_theme_color); ?>; }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background-color: #030712; color: #f3f4f6; font-family: 'Inter', sans-serif; overflow-x: hidden; width: 100vw; min-height: 100vh; }
        #canvas-container { position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; z-index: 1; pointer-events: none; transition: transform 1.2s ease-in-out; }
        body.transitioning #canvas-container { transform: scale(1.1) rotate(180deg); filter: hue-rotate(45deg); }
        .ui-layer { position: relative; z-index: 2; width: 100%; min-height: 100vh; display: flex; flex-direction: column; justify-content: space-between; padding: 2rem 4rem; }
        header { display: flex; justify-content: space-between; align-items: center; width: 100%; max-width: 1200px; margin: 0 auto; }
        .logo { font-family: 'Orbitron', sans-serif; font-size: 1.5rem; font-weight: 700; color: var(--theme-color); letter-spacing: 2px; text-decoration: none; }
        nav { display: flex; align-items: center; gap: 1.8rem; }
        nav a { color: #9ca3af; text-decoration: none; font-size: 0.9rem; transition: color 0.3s ease; cursor: pointer; }
        nav a:hover { color: var(--theme-color); }
        .nav-avatar { width: 32px; height: 32px; border-radius: 50%; object-fit: cover; border: 1px solid var(--theme-color); vertical-align: middle; margin-left: 0.5rem; }
        .hero, .content-section { max-width: 800px; margin: auto 0; padding: 3rem 0; }
        .badge-status { display: inline-block; background: rgba(6, 182, 212, 0.1); border: 1px solid rgba(6, 182, 212, 0.3); color: var(--theme-color); padding: 0.4rem 1rem; border-radius: 50px; font-size: 0.8rem; font-family: 'Orbitron', sans-serif; margin-bottom: 1.5rem; text-transform: uppercase; }
        h1 { font-family: 'Orbitron', sans-serif; font-size: 3rem; line-height: 1.1; margin-bottom: 1.5rem; color: #ffffff; }
        h1 span { color: var(--theme-color); }
        p.subtitle, .content-section p { font-size: 1.05rem; color: #9ca3af; line-height: 1.6; margin-bottom: 2rem; }
        
        .glass-card { background: rgba(15, 23, 42, 0.88); border: 1px solid rgba(6, 182, 212, 0.3); padding: 2.5rem; border-radius: 12px; backdrop-filter: blur(12px); box-shadow: 0 0 30px rgba(0, 0, 0, 0.7); max-width: 500px; }
        .form-group { margin-bottom: 1.2rem; }
        .form-group label { display: block; font-size: 0.85rem; color: var(--theme-color); font-family: 'Orbitron', sans-serif; margin-bottom: 0.5rem; }
        .form-control { width: 100%; padding: 0.8rem 1rem; background: rgba(3, 7, 18, 0.9); border: 1px solid rgba(255, 255, 255, 0.15); border-radius: 6px; color: #fff; font-size: 0.95rem; }
        .form-control:focus { outline: none; border-color: var(--theme-color); box-shadow: 0 0 10px rgba(6, 182, 212, 0.4); }
        
        .file-upload-wrapper { position: relative; width: 100%; overflow: hidden; display: inline-block; background: rgba(3, 7, 18, 0.9); border: 1px dashed var(--theme-color); border-radius: 6px; padding: 0.8rem; text-align: center; cursor: pointer; }
        .file-upload-wrapper input[type=file] { font-size: 100px; position: absolute; left: 0; top: 0; opacity: 0; cursor: pointer; }
        .file-upload-text { font-size: 0.85rem; color: var(--theme-color); font-family: 'Orbitron', sans-serif; }

        .avatar-3d-box { width: 130px; height: 130px; border-radius: 50%; background: var(--theme-color); margin: 0 auto 1.2rem; display: flex; align-items: center; justify-content: center; font-size: 2.5rem; color: #030712; font-family: 'Orbitron'; font-weight: bold; overflow: hidden; border: 3px solid var(--theme-color); }
        .cta-group { display: flex; gap: 1rem; flex-wrap: wrap; }
        .btn { padding: 0.9rem 2rem; border-radius: 6px; font-weight: 600; text-decoration: none; transition: all 0.3s ease; cursor: pointer; font-size: 0.95rem; display: inline-block; text-align: center; border: none; }
        .btn-primary { background-color: var(--theme-color); color: #030712; box-shadow: 0 0 20px rgba(6, 182, 212, 0.3); }
        .btn-primary:hover { filter: brightness(1.2); }
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
                <a href="?view=consultation" class="transition-link">Enviar Reporte / Consulta</a>
                <?php if (isset($_SESSION['user_id'])): ?>
                    <a href="?view=chat" class="transition-link" style="color: #10b981; font-weight: 600;">Chat Global</a>
                    <a href="?view=profile" class="transition-link" style="color: var(--theme-color); font-weight: 600; display: flex; align-items: center;">
                        Mi Perfil
                        <?php if (!empty($logged_user['profile_pic']) && file_exists(__DIR__ . '/' . $logged_user['profile_pic'])): ?>
                            <img src="<?php echo htmlspecialchars($logged_user['profile_pic']); ?>" class="nav-avatar" alt="Avatar">
                        <?php endif; ?>
                    </a>
                    <a href="?view=logout" class="transition-link" style="color: #ef4444;">Salir</a>
                <?php else: ?>
                    <a href="?view=login" class="transition-link" style="color: var(--theme-color); font-weight: 600;">Iniciar Sesión</a>
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
                <div class="badge-status">Sistema de Seguridad, Reportes & Chat Multi-Usuario</div>
                <h1>Arquitectura con <span>Chat y Archivos</span></h1>
                <p class="subtitle">Plataforma con chat integrado en tiempo real para usuarios y administradores, soporte completo para subir archivos (Word, PDF), y respuestas directas desde el panel root.</p>
                <div class="cta-group">
                    <a href="?view=register" class="btn btn-primary transition-link">Crear Cuenta</a>
                    <a href="?view=login" class="btn btn-outline transition-link">Acceder</a>
                    <a href="?view=consultation" class="btn btn-outline transition-link" style="border-color: var(--theme-color);">Enviar Consulta con Archivo</a>
                </div>
            </main>

        <?php elseif ($action == 'about'): ?>
            <main class="content-section" style="max-width: 800px; width: 100%;">
                <div class="badge-status">Acerca de CyberGuard Offensive</div>
                <h1>Ingeniería y <span>Comunicación Directa</span></h1>
                <p class="subtitle">Permite el intercambio de reportes técnicos adjuntando archivos Word y PDF, comunicación interactiva mediante chat global, y trazabilidad total entre administradores y analistas.</p>
            </main>

        <?php elseif ($action == 'chat'): ?>
            <?php
            if (!isset($_SESSION['user_id'])) { header("Location: ?view=login"); exit; }
            $stmt_chat_all = $db->query("SELECT global_chat.*, users.nombre, users.apellido, users.role FROM global_chat JOIN users ON global_chat.user_id = users.id ORDER BY global_chat.created_at ASC");
            $chat_messages = $stmt_chat_all->fetchAll(PDO::FETCH_ASSOC);
            ?>
            <main class="content-section" style="max-width: 800px; width: 100%;">
                <div class="badge-status">Chat Global de Usuarios y Administrador</div>
                <h1 style="font-size: 2.2rem;">Canal de <span>Comunicación en Vivo</span></h1>
                
                <div class="glass-card" style="max-width: 100%; display: flex; flex-direction: column; height: 500px;">
                    <div style="flex: 1; overflow-y: auto; padding-right: 10px; display: flex; flex-direction: column; gap: 1rem; margin-bottom: 1rem;">
                        <?php if (empty($chat_messages)): ?>
                            <p style="color: #9ca3af; text-align: center; margin-top: auto; margin-bottom: auto;">No hay mensajes en el chat global aún. ¡Sé el primero en escribir!</p>
                        <?php else: ?>
                            <?php foreach ($chat_messages as $cm): ?>
                                <div style="background: rgba(3, 7, 18, 0.8); border: 1px solid <?php echo $cm['role'] === 'admin' ? '#10b981' : 'rgba(255,255,255,0.1)'; ?>; padding: 10px 15px; border-radius: 8px; max-width: 80%;">
                                    <div style="display: flex; justify-content: space-between; font-size: 0.75rem; color: <?php echo $cm['role'] === 'admin' ? '#10b981' : 'var(--theme-color)'; ?>; margin-bottom: 4px;">
                                        <span><?php echo htmlspecialchars($cm['nombre'] . ' ' . $cm['apellido']); ?> <?php echo $cm['role'] === 'admin' ? '[ADMIN ROOT]' : ''; ?></span>
                                        <span style="color: #6b7280;"><?php echo $cm['created_at']; ?></span>
                                    </div>
                                    <p style="font-size: 0.9rem; color: #e5e7eb; word-break: break-word;"><?php echo nl2br(htmlspecialchars($cm['message'])); ?></p>
                                </div>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </div>

                    <form action="?view=chat" method="POST" style="display: flex; gap: 10px;">
                        <input type="hidden" name="action" value="send_chat_message">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <input type="text" name="chat_message" class="form-control" placeholder="Escribe un mensaje al chat..." required autocomplete="off" style="flex: 1;">
                        <button type="submit" class="btn btn-primary" style="padding: 0.8rem 1.5rem;">Enviar</button>
                    </form>
                </div>
            </main>

        <?php elseif ($action == 'consultation'): ?>
            <main class="hero">
                <div class="glass-card" style="max-width: 600px;">
                    <div class="badge-status">Área de Consultas & Reportes con Archivos</div>
                    <h2 style="font-family:'Orbitron'; font-size:1.8rem; margin-bottom:1.5rem; color:#fff;">Enviar Reporte o Consulta</h2>
                    <p style="font-size: 0.9rem; color: #9ca3af; margin-bottom: 1.5rem;">Puedes adjuntar archivos Word (.doc, .docx), PDF o imágenes con tu reporte técnico.</p>
                    
                    <form action="?view=consultation" method="POST" enctype="multipart/form-data">
                        <input type="hidden" name="action" value="consultation">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <div class="form-group">
                            <label>Correo Electrónico</label>
                            <input type="email" name="email" class="form-control" required value="<?php echo htmlspecialchars($_SESSION['user_email'] ?? ''); ?>">
                        </div>
                        <div class="form-group">
                            <label>Asunto</label>
                            <input type="text" name="subject" class="form-control" placeholder="Ej: Reporte de vulnerabilidad o duda" required>
                        </div>
                        <div class="form-group">
                            <label>Mensaje Detallado</label>
                            <textarea name="message" class="form-control" rows="4" placeholder="Describe tu consulta..." required></textarea>
                        </div>
                        <div class="form-group">
                            <label>Adjuntar Reporte (PDF, Word, Imagen)</label>
                            <div class="file-upload-wrapper">
                                <span class="file-upload-text" id="reportFileLabel">📎 Seleccionar archivo (PDF, Word)...</span>
                                <input type="file" name="attachment" accept=".pdf,.doc,.docx,image/*" onchange="document.getElementById('reportFileLabel').innerText = '✓ ' + this.files[0].name;">
                            </div>
                        </div>
                        <button type="submit" class="btn btn-primary" style="width:100%; margin-top:1rem;">Enviar Consulta Completa</button>
                    </form>
                </div>
            </main>

        <?php elseif ($action == 'register'): ?>
            <main class="hero">
                <div class="glass-card" style="max-width: 600px;">
                    <div class="badge-status">Nuevo Registro</div>
                    <h2 style="font-family:'Orbitron'; font-size:1.8rem; margin-bottom:1.5rem; color:#fff;">Crear Cuenta</h2>
                    <form action="?view=register" method="POST">
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
                        <div class="form-group">
                            <label>Pregunta de Seguridad: Mascota</label>
                            <input type="hidden" name="sec_question_1" value="¿Cuál es el nombre de tu primera mascota?">
                            <input type="text" name="sec_answer_1" class="form-control" placeholder="Respuesta secreta" required>
                        </div>
                        <button type="submit" class="btn btn-primary" style="width:100%; margin-top:1rem;">Registrar Cuenta</button>
                    </form>
                    <a href="?view=login" class="link-sub transition-link">¿Ya tienes cuenta? Inicia sesión</a>
                </div>
            </main>

        <?php elseif ($action == 'login'): ?>
            <main class="hero">
                <div class="glass-card">
                    <div class="badge-status">Iniciar Sesión</div>
                    <h2 style="font-family:'Orbitron'; font-size:1.8rem; margin-bottom:1.5rem; color:#fff;">Acceder</h2>
                    
                    <?php if (isset($_GET['registered'])): ?>
                        <div class="alert alert-success">
                            ¡Cuenta creada! Hash único:<br>
                            <div class="hash-display"><?php echo htmlspecialchars($_SESSION['temp_new_hash'] ?? ''); ?></div>
                        </div>
                    <?php endif; ?>

                    <form action="?view=login" method="POST">
                        <input type="hidden" name="action" value="login">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <div class="form-group">
                            <label>Correo Electrónico</label>
                            <input type="text" id="loginEmailInput" name="login_id" class="form-control" required onblur="if(this.value.includes('admin')) { document.getElementById('adminQuestionsBox').style.display='block'; document.getElementById('analystQuestionBox').style.display='none'; } else { document.getElementById('adminQuestionsBox').style.display='none'; document.getElementById('analystQuestionBox').style.display='block'; }">
                        </div>
                        <div class="form-group">
                            <label>Contraseña</label>
                            <input type="password" name="password" class="form-control" required>
                        </div>

                        <div class="form-group" id="analystQuestionBox">
                            <label style="color: #eab308;">Pregunta de Seguridad (Opcional)</label>
                            <input type="text" name="sec_answer_1" class="form-control" placeholder="Respuesta secreta">
                        </div>

                        <div id="adminQuestionsBox" style="display:none; background: rgba(16,185,129,0.08); border: 1px solid #10b981; padding: 12px; border-radius: 6px; margin-bottom: 1.2rem;">
                            <label style="color: #10b981; font-size: 0.8rem; font-family:'Orbitron'; margin-bottom:0.8rem; display:block;">[!] AUTENTICACIÓN ROOT</label>
                            <div class="form-group" style="margin-bottom:0.8rem;">
                                <input type="password" name="sec_answer_1" class="form-control" placeholder="Clave maestra 1">
                            </div>
                            <div class="form-group" style="margin-bottom:0.8rem;">
                                <input type="password" name="sec_answer_2" class="form-control" placeholder="Protocolo zero-day 2">
                            </div>
                            <div class="form-group" style="margin-bottom:0;">
                                <input type="password" name="sec_answer_3" class="form-control" placeholder="Estándar cifrado 3">
                            </div>
                        </div>

                        <button type="submit" class="btn btn-primary" style="width:100%; margin-top:1rem;">Entrar</button>
                    </form>
                    <a href="?view=register" class="link-sub transition-link">Registrarse</a>
                </div>
            </main>

        <?php elseif ($action == 'profile'): ?>
            <?php
            if (!isset($_SESSION['user_id'])) { header("Location: ?view=home"); exit; }
            $stmt = $db->prepare("SELECT * FROM users WHERE id = ?");
            $stmt->execute([$_SESSION['user_id']]);
            $current_user = $stmt->fetch(PDO::FETCH_ASSOC);
            $is_admin = ($current_user['role'] === 'admin');
            ?>
            <main class="content-section" style="max-width: 950px; width: 100%;">
                <div class="badge-status">Panel de Usuario y Respuestas con Archivos</div>
                <h1 style="font-size: 2.2rem;">Mi <span>Perfil</span></h1>
                
                <div style="display: grid; grid-template-columns: 1fr 2fr; gap: 2rem; align-items: start;">
                    
                    <div class="glass-card" style="text-align: center; max-width: 100%;">
                        <div class="avatar-3d-box">
                            <?php if (!empty($current_user['profile_pic']) && file_exists(__DIR__ . '/' . $current_user['profile_pic'])): ?>
                                <img src="<?php echo htmlspecialchars($current_user['profile_pic']); ?>" alt="Avatar" style="width: 100%; height: 100%; object-fit: cover;">
                            <?php else: ?>
                                <?php echo strtoupper(substr($current_user['nombre'], 0, 1)); ?>
                            <?php endif; ?>
                        </div>
                        <h3 style="color: #fff; font-size: 1.3rem; margin-bottom: 0.3rem; font-family: 'Orbitron';"><?php echo htmlspecialchars($current_user['nombre'] . ' ' . $current_user['apellido']); ?></h3>
                        <p style="font-size: 0.85rem; color: var(--theme-color); margin-bottom: 1rem;"><?php echo htmlspecialchars($current_user['email']); ?></p>
                        
                        <?php if ($is_admin): ?>
                            <div style="background: rgba(16, 185, 129, 0.15); border: 1px solid #10b981; color: #10b981; padding: 0.5rem; border-radius: 6px; font-family: 'Orbitron'; font-size: 0.8rem; margin-bottom: 1rem;">
                                ROL: ADMINISTRADOR ROOT
                            </div>
                        <?php endif; ?>
                    </div>

                    <div class="glass-card" style="max-width: 100%;">
                        <?php if ($is_admin): ?>
                            <h3 style="font-family: 'Orbitron'; color: #10b981; margin-bottom: 1.5rem;">Panel Root: Responder Consultas y Subir Archivos</h3>
                            
                            <?php
                            $stmt_consultas = $db->query("SELECT * FROM security_consultations ORDER BY created_at DESC");
                            $consultas_list = $stmt_consultas->fetchAll(PDO::FETCH_ASSOC);
                            ?>

                            <?php if (empty($consultas_list)): ?>
                                <p style="color: #9ca3af; font-size: 0.9rem;">No hay reportes o consultas registradas.</p>
                            <?php else: ?>
                                <div style="display: flex; flex-direction: column; gap: 1.5rem; max-height: 600px; overflow-y: auto; padding-right: 5px;">
                                    <?php foreach ($consultas_list as $cons): ?>
                                        <div style="background: rgba(3, 7, 18, 0.8); border: 1px solid rgba(255,255,255,0.1); padding: 1.2rem; border-radius: 8px;">
                                            <div style="font-size: 0.75rem; color: var(--theme-color); margin-bottom: 0.3rem;">De: <?php echo htmlspecialchars($cons['email']); ?></div>
                                            <h4 style="color: #fff; font-size: 1rem; margin-bottom: 0.5rem; font-family:'Orbitron';"><?php echo htmlspecialchars($cons['subject']); ?></h4>
                                            <p style="font-size: 0.9rem; color: #d1d5db; margin-bottom: 0.8rem; background: rgba(0,0,0,0.3); padding: 8px; border-radius: 4px;"><?php echo nl2br(htmlspecialchars($cons['message'])); ?></p>
                                            
                                            <?php if (!empty($cons['attachment_path']) && file_exists(__DIR__ . '/' . $cons['attachment_path'])): ?>
                                                <div style="margin-bottom: 1rem;">
                                                    <a href="<?php echo htmlspecialchars($cons['attachment_path']); ?>" download class="btn btn-outline" style="padding: 0.4rem 0.8rem; font-size: 0.75rem;">📥 Descargar Reporte del Usuario (Word/PDF)</a>
                                                </div>
                                            <?php endif; ?>

                                            <?php if (!empty($cons['response'])): ?>
                                                <div style="background: rgba(16, 185, 129, 0.1); border-left: 3px solid #10b981; padding: 0.8rem; font-size: 0.85rem; color: #a7f3d0;">
                                                    <strong>Respuesta enviada:</strong><br><?php echo nl2br(htmlspecialchars($cons['response'])); ?>
                                                    <?php if (!empty($cons['response_attachment']) && file_exists(__DIR__ . '/' . $cons['response_attachment'])): ?>
                                                        <br><a href="<?php echo htmlspecialchars($cons['response_attachment']); ?>" download style="color: #34d399; text-decoration: underline; font-size: 0.8rem;">📥 Archivo adjunto de respuesta</a>
                                                    <?php endif; ?>
                                                </div>
                                            <?php else: ?>
                                                <form action="?view=profile" method="POST" enctype="multipart/form-data">
                                                    <input type="hidden" name="action" value="respond_consultation">
                                                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                                                    <input type="hidden" name="consultation_id" value="<?php echo $cons['id']; ?>">
                                                    
                                                    <div class="form-group" style="margin-bottom: 0.8rem;">
                                                        <textarea name="response" class="form-control" rows="3" placeholder="Escribe tu respuesta..." required style="font-size: 0.85rem;"></textarea>
                                                    </div>
                                                    <div class="form-group" style="margin-bottom: 0.8rem;">
                                                        <label style="font-size: 0.75rem;">Adjuntar archivo de resolución (Word, PDF, etc.)</label>
                                                        <input type="file" name="response_file" class="form-control" style="font-size: 0.8rem; padding: 0.4rem;" accept=".pdf,.doc,.docx,image/*">
                                                    </div>
                                                    <button type="submit" class="btn btn-primary" style="padding: 0.5rem 1rem; font-size: 0.8rem; background: #10b981; color: #030712;">Enviar Respuesta y Archivo</button>
                                                </form>
                                            <?php endif; ?>
                                        </div>
                                    <?php endforeach; ?>
                                </div>
                            <?php endif; ?>

                        <?php else: ?>
                            <h3 style="font-family: 'Orbitron'; color: var(--theme-color); margin-bottom: 1.5rem;">Mis Consultas y Respuestas Recibidas</h3>
                            <?php
                            $stmt_user_cons = $db->prepare("SELECT * FROM security_consultations WHERE email = ? ORDER BY created_at DESC");
                            $stmt_user_cons->execute([$current_user['email']]);
                            $user_cons_list = $stmt_user_cons->fetchAll(PDO::FETCH_ASSOC);
                            ?>

                            <?php if (empty($user_cons_list)): ?>
                                <p style="color: #9ca3af; font-size: 0.9rem;">No has enviado ningún reporte o consulta todavía.</p>
                            <?php else: ?>
                                <div style="display: flex; flex-direction: column; gap: 1.2rem;">
                                    <?php foreach ($user_cons_list as $uc): ?>
                                        <div style="background: rgba(3, 7, 18, 0.8); border: 1px solid rgba(255,255,255,0.1); padding: 1rem; border-radius: 8px;">
                                            <h4 style="color: #fff; font-size: 0.95rem; font-family:'Orbitron';"><?php echo htmlspecialchars($uc['subject']); ?></h4>
                                            <p style="font-size: 0.85rem; color: #9ca3af; margin: 5px 0;"><?php echo nl2br(htmlspecialchars($uc['message'])); ?></p>
                                            
                                            <?php if (!empty($uc['attachment_path']) && file_exists(__DIR__ . '/' . $uc['attachment_path'])): ?>
                                                <a href="<?php echo htmlspecialchars($uc['attachment_path']); ?>" download style="font-size: 0.75rem; color: var(--theme-color); text-decoration: underline; display: block; margin-bottom: 5px;">📥 Mi archivo adjunto enviado</a>
                                            <?php endif; ?>

                                            <?php if (!empty($uc['response'])): ?>
                                                <div style="background: rgba(16, 185, 129, 0.1); border-left: 3px solid #10b981; padding: 8px; font-size: 0.85rem; color: #a7f3d0; margin-top: 8px;">
                                                    <strong>Respuesta del Administrador:</strong><br><?php echo nl2br(htmlspecialchars($uc['response'])); ?>
                                                    <?php if (!empty($uc['response_attachment']) && file_exists(__DIR__ . '/' . $uc['response_attachment'])): ?>
                                                        <br><a href="<?php echo htmlspecialchars($uc['response_attachment']); ?>" download style="color: #34d399; font-weight: bold; text-decoration: underline; font-size: 0.8rem; margin-top: 4px; display: inline-block;">📥 Descargar archivo enviado por el Administrador (Word/PDF)</a>
                                                    <?php endif; ?>
                                                </div>
                                            <?php else: ?>
                                                <span style="font-size: 0.75rem; color: #eab308; display: block; margin-top: 5px;">⏳ Pendiente de respuesta por el administrador...</span>
                                            <?php endif; ?>
                                        </div>
                                    <?php endforeach; ?>
                                </div>
                            <?php endif; ?>
                        <?php endif; ?>
                    </div>
                </div>
            </main>
        <?php endif; ?>

        <footer>
            <p>&copy; 2026 CyberGuard Offensive. Chat y Gestión de Archivos Adjuntos.</p>
        </footer>
    </div>

    <!-- Three.js para animación 3D -->
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
        const material = new THREE.MeshBasicMaterial({ color: currentThemeColor, wireframe: true, transparent: true, opacity: 0.25 });
        const sphere = new THREE.Mesh(geometry, material);
        scene.add(sphere);
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
                    setTimeout(() => { window.location.href = href; }, 800);
                }
            });
        });
    </script>
</body>
</html>
