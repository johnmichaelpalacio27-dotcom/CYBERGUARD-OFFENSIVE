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

    // Tabla para Consultas de Ciberseguridad con soporte de respuestas y remitente/destinatario
    $db->exec("CREATE TABLE IF NOT EXISTS security_consultations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        email TEXT NOT NULL,
        subject TEXT NOT NULL,
        message TEXT NOT NULL,
        admin_reply TEXT DEFAULT '',
        status TEXT DEFAULT 'pending',
        ip_address TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");

    // Tabla para Mensajería Directa entre Usuarios
    $db->exec("CREATE TABLE IF NOT EXISTS direct_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        receiver_id INTEGER NOT NULL,
        message TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");

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

    if ($form_action === 'register') {
        // Verificar si ya existe un administrador en el sistema
        $stmt_check_admin = $db->prepare("SELECT COUNT(*) FROM users WHERE role = 'admin'");
        $stmt_check_admin->execute();
        $admin_exists = $stmt_check_admin->fetchColumn() > 0;

        $role = 'analyst';
        if (isset($_POST['register_as_admin']) && $_POST['register_as_admin'] === '1') {
            if ($admin_exists) {
                $message = "El puesto de Administrador único ya se encuentra ocupado en este sistema seguro.";
                $message_type = "error";
                $action = 'register';
                goto skip_registration;
            } else {
                $role = 'admin';
            }
        }

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
            $stmt = $db->prepare("INSERT INTO users (nombre, apellido, email, password, single_use_hash, hash_type, hash_used, hash_security_active, sec_question_1, sec_answer_1, sec_question_2, sec_answer_2, sec_question_3, sec_answer_3, role) VALUES (?, ?, ?, ?, ?, ?, 0, 1, ?, ?, ?, ?, ?, ?, ?)");
            $stmt->execute([$nombre, $apellido, $email, $password, $single_use_hash, $hash_type, $sec_q1, $sec_a1, $sec_q2, $sec_a2, $sec_q3, $sec_a3, $role]);

            $_SESSION['temp_new_hash'] = $single_use_hash;
            header("Location: ?view=login&registered=1");
            exit;
        } catch (Exception $e) {
            $message = "El correo electrónico ya se encuentra registrado en el sistema.";
            $message_type = "error";
            $action = 'register';
        }
        skip_registration:;

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

            $stmt = $db->prepare("SELECT * FROM users WHERE email = ?");
            $stmt->execute([$login_id]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($user && password_verify($password, $user['password'])) {
                if (!empty($user['sec_answer_1']) && !password_verify($answer_1, $user['sec_answer_1'])) {
                    register_failed_attempt('login');
                    $message = "Acceso denegado: La respuesta a la pregunta de seguridad es incorrecta.";
                    $message_type = "error";
                    $action = 'login';
                } else {
                    reset_brute_force('login');
                    session_regenerate_id(true);
                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['user_email'] = $user['email'];
                    $_SESSION['user_nombre'] = $user['nombre'];
                    $_SESSION['user_role'] = $user['role'];
                    
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
            $message = "Contraseña restablecida exitosamente. Inicia sesión.";
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

        $message = "Se ha generado un nuevo Hash de seguridad único.";
        $message_type = "success";
        $action = 'profile';
    } elseif ($form_action === 'update_profile') {
        if (!isset($_SESSION['user_id'])) {
            header("Location: ?view=login");
            exit;
        }
        $user_id = $_SESSION['user_id'];
        
        $new_nombre = trim($_POST['nombre']);
        $new_apellido = trim($_POST['apellido']);
        $new_password = $_POST['password'];
        $theme_color = trim($_POST['theme_color'] ?? '#06b6d4');
        $ddos_toggle = isset($_POST['ddos_protection']) ? 1 : 0;
        
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

    } elseif ($form_action === 'consultation') {
        $c_email = trim($_POST['email']);
        $c_subject = trim($_POST['subject']);
        $c_message = trim($_POST['message']);
        $c_uid = isset($_SESSION['user_id']) ? $_SESSION['user_id'] : null;

        if (!empty($c_email) && !empty($c_subject) && !empty($c_message)) {
            $stmt = $db->prepare("INSERT INTO security_consultations (user_id, email, subject, message, ip_address) VALUES (?, ?, ?, ?, ?)");
            $stmt->execute([$c_uid, $c_email, $c_subject, $c_message, $client_ip]);
            
            // Simular envío de notificación al correo del administrador vía web interna
            $message = "Consulta enviada con éxito al panel del administrador y registrada vía web.";
            $message_type = "success";
            $action = 'consultation';
        } else {
            $message = "Complete todos los campos de la consulta.";
            $message_type = "error";
            $action = 'consultation';
        }

    } elseif ($form_action === 'admin_reply_consultation') {
        if (!isset($_SESSION['user_id'])) {
            header("Location: ?view=login");
            exit;
        }
        $stmt_chk = $db->prepare("SELECT role FROM users WHERE id = ?");
        $stmt_chk->execute([$_SESSION['user_id']]);
        $u_role = $stmt_chk->fetchColumn();

        if ($u_role === 'admin') {
            $consult_id = $_POST['consult_id'];
            $reply_text = trim($_POST['admin_reply']);
            
            $stmt_rep = $db->prepare("UPDATE security_consultations SET admin_reply = ?, status = 'resolved' WHERE id = ?");
            $stmt_rep->execute([$reply_text, $consult_id]);
            
            $message = "Respuesta enviada y registrada en el perfil del usuario.";
            $message_type = "success";
            $action = 'profile';
        }

    } elseif ($form_action === 'send_direct_message') {
        if (!isset($_SESSION['user_id'])) {
            header("Location: ?view=login");
            exit;
        }
        $sender_id = $_SESSION['user_id'];
        $receiver_id = $_POST['receiver_id'];
        $dm_message = trim($_POST['message']);

        if (!empty($dm_message) && !empty($receiver_id)) {
            $stmt_dm = $db->prepare("INSERT INTO direct_messages (sender_id, receiver_id, message) VALUES (?, ?, ?)");
            $stmt_dm->execute([$sender_id, $receiver_id, $dm_message]);
            $message = "Mensaje enviado a otro usuario correctamente.";
            $message_type = "success";
            $action = 'profile';
        }
    }
}

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

// Comprobar si ya hay un administrador registrado globalmente
$stmt_admin_check = $db->prepare("SELECT COUNT(*) FROM users WHERE role = 'admin'");
$stmt_admin_check->execute();
$admin_registered_global = $stmt_admin_check->fetchColumn() > 0;

$active_theme_color = $logged_user['theme_color'] ?? '#06b6d4';
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberGuard Offensive | Gestión Integral y Mensajería</title>
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&family=Inter:wght@300;400;600&display=swap" rel="stylesheet">
    <style>
        :root { --theme-color: <?php echo htmlspecialchars($active_theme_color); ?>; }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background-color: #030712; color: #f3f4f6; font-family: 'Inter', sans-serif; overflow-x: hidden; width: 100vw; min-height: 100vh; }
        #canvas-container { position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; z-index: 1; pointer-events: none; }
        .ui-layer { position: relative; z-index: 2; width: 100%; min-height: 100vh; display: flex; flex-direction: column; justify-content: space-between; padding: 2rem 4rem; }
        header { display: flex; justify-content: space-between; align-items: center; width: 100%; max-width: 1200px; margin: 0 auto; }
        .logo { font-family: 'Orbitron', sans-serif; font-size: 1.5rem; font-weight: 700; color: var(--theme-color); letter-spacing: 2px; text-decoration: none; }
        nav { display: flex; align-items: center; gap: 1.8rem; }
        nav a { color: #9ca3af; text-decoration: none; font-size: 0.9rem; transition: color 0.3s ease; cursor: pointer; }
        nav a:hover { color: var(--theme-color); }
        .nav-avatar { width: 32px; height: 32px; border-radius: 50%; object-fit: cover; border: 1px solid var(--theme-color); vertical-align: middle; margin-left: 0.5rem; }
        .hero, .content-section { max-width: 900px; margin: auto 0; padding: 3rem 0; width: 100%; }
        .badge-status { display: inline-block; background: rgba(6, 182, 212, 0.1); border: 1px solid rgba(6, 182, 212, 0.3); color: var(--theme-color); padding: 0.4rem 1rem; border-radius: 50px; font-size: 0.8rem; font-family: 'Orbitron', sans-serif; margin-bottom: 1.5rem; text-transform: uppercase; }
        h1 { font-family: 'Orbitron', sans-serif; font-size: 3rem; line-height: 1.1; margin-bottom: 1.5rem; color: #ffffff; }
        h1 span { color: var(--theme-color); }
        p.subtitle { font-size: 1.05rem; color: #9ca3af; line-height: 1.6; margin-bottom: 2rem; }
        .glass-card { background: rgba(15, 23, 42, 0.88); border: 1px solid rgba(6, 182, 212, 0.3); padding: 2.5rem; border-radius: 12px; backdrop-filter: blur(12px); box-shadow: 0 0 30px rgba(0, 0, 0, 0.7); max-width: 100%; width: 100%; margin-bottom: 2rem; }
        .form-group { margin-bottom: 1.2rem; }
        .form-group label { display: block; font-size: 0.85rem; color: var(--theme-color); font-family: 'Orbitron', sans-serif; margin-bottom: 0.5rem; }
        .form-control { width: 100%; padding: 0.8rem 1rem; background: rgba(3, 7, 18, 0.9); border: 1px solid rgba(255, 255, 255, 0.15); border-radius: 6px; color: #fff; font-size: 0.95rem; }
        .form-control:focus { outline: none; border-color: var(--theme-color); box-shadow: 0 0 10px rgba(6, 182, 212, 0.4); }
        .cta-group { display: flex; gap: 1rem; flex-wrap: wrap; }
        .btn { padding: 0.9rem 2rem; border-radius: 6px; font-weight: 600; text-decoration: none; transition: all 0.3s ease; cursor: pointer; font-size: 0.95rem; display: inline-block; text-align: center; border: none; }
        .btn-primary { background-color: var(--theme-color); color: #030712; box-shadow: 0 0 20px rgba(6, 182, 212, 0.3); }
        .btn-primary:hover { filter: brightness(1.2); }
        .btn-outline { background: transparent; color: #f3f4f6; border: 1px solid rgba(255, 255, 255, 0.2); }
        .btn-outline:hover { border-color: var(--theme-color); color: var(--theme-color); }
        .alert { padding: 1rem; margin-bottom: 1.5rem; border-radius: 6px; font-size: 0.9rem; }
        .alert-error { background: rgba(239, 68, 68, 0.2); border: 1px solid #ef4444; color: #fca5a5; }
        .alert-success { background: rgba(16, 185, 129, 0.2); border: 1px solid #10b981; color: #a7f3d0; }
        table { width: 100%; border-collapse: collapse; margin-top: 1rem; font-size: 0.9rem; }
        th, td { padding: 0.8rem; border-bottom: 1px solid rgba(255,255,255,0.1); text-align: left; }
        th { color: var(--theme-color); font-family: 'Orbitron'; font-size: 0.8rem; }
        footer { text-align: center; padding: 1.5rem 0; color: #4b5563; font-size: 0.85rem; border-top: 1px solid rgba(255, 255, 255, 0.05); max-width: 1200px; margin: 0 auto; width: 100%; }
    </style>
</head>
<body>

    <div id="canvas-container"></div>

    <div class="ui-layer">
        <header>
            <a href="?view=home" class="logo">CYBERGUARD//OFFENSIVE</a>
            <nav>
                <a href="?view=consultation">Consultas de Seguridad</a>
                <?php if (isset($_SESSION['user_id'])): ?>
                    <a href="?view=profile" style="color: var(--theme-color); font-weight: 600;">Mi Perfil (<?php echo htmlspecialchars($logged_user['role']); ?>)</a>
                    <a href="?view=logout" style="color: #ef4444;">Salir</a>
                <?php else: ?>
                    <a href="?view=login" style="color: var(--theme-color); font-weight: 600;">Iniciar Sesión</a>
                    <a href="?view=register" style="color: #10b981; font-weight: 600;">Registro Único Admin / Usuario</a>
                <?php endif; ?>
            </nav>
        </header>

        <?php if (!empty($message)): ?>
            <div style="max-width: 800px; margin: 1rem auto 0 auto; width: 100%;">
                <div class="alert alert-<?php echo $message_type === 'success' ? 'success' : 'error'; ?>">
                    <?php echo htmlspecialchars($message); ?>
                </div>
            </div>
        <?php endif; ?>

        <?php if ($action == 'home'): ?>
            <main class="hero">
                <div class="badge-status">Sistema de Control con Único Administrador y Mensajería</div>
                <h1>Plataforma de <span>Gestión y Auditoría</span></h1>
                <p class="subtitle">Administra consultas de usuarios, recibe respuestas directas en tu perfil, comunícate con otros analistas y protege el sistema con un único administrador registrado.</p>
                <div class="cta-group">
                    <a href="?view=register" class="btn btn-primary">Registrar Cuenta o Administrador</a>
                    <a href="?view=login" class="btn btn-outline">Acceder</a>
                </div>
            </main>

        <?php elseif ($action == 'register'): ?>
            <main class="hero">
                <div class="glass-card">
                    <div class="badge-status">Registro Protegido</div>
                    <h2>Crear Cuenta de Usuario o Administrador Único</h2>
                    <form action="?view=register" method="POST">
                        <input type="hidden" name="action" value="register">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        
                        <?php if (!$admin_registered_global): ?>
                            <div class="form-group" style="background: rgba(16, 185, 129, 0.1); border: 1px solid #10b981; padding: 1rem; border-radius: 6px;">
                                <label style="color: #10b981;">¿Desea registrarse como el ÚNICO Administrador del Sistema?</label>
                                <input type="checkbox" name="register_as_admin" value="1" style="transform: scale(1.2); margin-top: 0.5rem;"> 
                                <span style="font-size: 0.85rem; color: #a7f3d0;">(Sólo se permite un administrador supremo protegido en este servidor).</span>
                            </div>
                        <?php else: ?>
                            <p style="font-size: 0.85rem; color: #eab308; margin-bottom: 1rem;">[i] El rol de Administrador ya ha sido reclamado. Las nuevas cuentas se registrarán automáticamente como Analistas/Usuarios.</p>
                        <?php endif; ?>

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
                        <!-- Preguntas de seguridad básicas -->
                        <div class="form-group">
                            <label>Pregunta de Seguridad 1</label>
                            <input type="text" name="sec_question_1" class="form-control" placeholder="Ej: ¿Ciudad de nacimiento?" required>
                            <input type="text" name="sec_answer_1" class="form-control" placeholder="Respuesta" style="margin-top:0.5rem;" required>
                        </div>
                        <button type="submit" class="btn btn-primary" style="width: 100%; margin-top: 1rem;">Registrarse de Forma Segura</button>
                    </form>
                </div>
            </main>

        <?php elseif ($action == 'login'): ?>
            <main class="hero">
                <div class="glass-card" style="max-width: 500px; margin: 0 auto;">
                    <div class="badge-status">Acceso Autenticado</div>
                    <h2>Iniciar Sesión</h2>
                    <form action="?view=login" method="POST">
                        <input type="hidden" name="action" value="login">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <div class="form-group">
                            <label>Correo Electrónico</label>
                            <input type="text" name="login_id" class="form-control" required>
                        </div>
                        <div class="form-group">
                            <label>Contraseña</label>
                            <input type="password" name="password" class="form-control" required>
                        </div>
                        <div class="form-group">
                            <label>Respuesta a Pregunta de Seguridad 1</label>
                            <input type="text" name="sec_answer_1" class="form-control" required>
                        </div>
                        <button type="submit" class="btn btn-primary" style="width: 100%; margin-top: 1rem;">Ingresar al Sistema</button>
                    </form>
                </div>
            </main>

        <?php elseif ($action == 'consultation'): ?>
            <main class="hero">
                <div class="glass-card">
                    <div class="badge-status">Envío de Consultas vía Web al Administrador</div>
                    <h2>Consulta de Ciberseguridad</h2>
                    <form action="?view=consultation" method="POST">
                        <input type="hidden" name="action" value="consultation">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <div class="form-group">
                            <label>Correo Electrónico</label>
                            <input type="email" name="email" class="form-control" required value="<?php echo htmlspecialchars($logged_user['email'] ?? ''); ?>">
                        </div>
                        <div class="form-group">
                            <label>Asunto</label>
                            <input type="text" name="subject" class="form-control" required>
                        </div>
                        <div class="form-group">
                            <label>Mensaje / Consulta</label>
                            <textarea name="message" class="form-control" rows="4" required></textarea>
                        </div>
                        <button type="submit" class="btn btn-primary" style="width: 100%;">Enviar Consulta al Administrador</button>
                    </form>
                </div>
            </main>

        <?php elseif ($action == 'profile'): ?>
            <?php if (!isset($_SESSION['user_id'])) { header("Location: ?view=login"); exit; } ?>
            <main class="hero" style="max-width: 1000px;">
                <div class="glass-card">
                    <div class="badge-status">Panel de Control de Perfil // Rol: <?php echo htmlspecialchars($logged_user['role']); ?></div>
                    <h2>Bienvenido, <?php echo htmlspecialchars($logged_user['nombre'] . ' ' . $logged_user['apellido']); ?></h2>

                    <?php if ($logged_user['role'] === 'admin'): ?>
                        <hr style="border: 0; border-top: 1px solid rgba(255,255,255,0.1); margin: 2rem 0;">
                        <h3 style="color: var(--theme-color); margin-bottom: 1rem; font-family: 'Orbitron';">Panel de Administración: Consultas Recibidas</h3>
                        <?php
                            $stmt_all_c = $db->query("SELECT * FROM security_consultations ORDER BY id DESC");
                            $consultations = $stmt_all_c->fetchAll(PDO::FETCH_ASSOC);
                        ?>
                        <?php if (count($consultations) > 0): ?>
                            <?php foreach($consultations as $c): ?>
                                <div style="background: rgba(3,7,18,0.7); padding: 1rem; border-radius: 6px; margin-bottom: 1rem; border: 1px solid rgba(255,255,255,0.1);">
                                    <p><strong>De:</strong> <?php echo htmlspecialchars($c['email']); ?> | <strong>Asunto:</strong> <?php echo htmlspecialchars($c['subject']); ?></p>
                                    <p style="margin: 0.5rem 0; color: #9ca3af;"><?php echo htmlspecialchars($c['message']); ?></p>
                                    <form action="?view=profile" method="POST" style="margin-top: 0.8rem;">
                                        <input type="hidden" name="action" value="admin_reply_consultation">
                                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                                        <input type="hidden" name="consult_id" value="<?php echo $c['id']; ?>">
                                        <div class="form-group" style="margin-bottom:0.5rem;">
                                            <input type="text" name="admin_reply" class="form-control" placeholder="Escribir respuesta para que llegue al perfil del usuario..." required value="<?php echo htmlspecialchars($c['admin_reply']); ?>">
                                        </div>
                                        <button type="submit" class="btn btn-primary" style="padding: 0.5rem 1rem; font-size: 0.8rem;">Enviar Respuesta al Usuario</button>
                                    </form>
                                </div>
                            <?php endforeach; ?>
                        <?php else: ?>
                            <p style="color: #9ca3af;">No hay consultas de usuarios registradas.</p>
                        <?php endif; ?>

                    <?php else: ?>
                        <!-- VISTA DE PERFIL PARA USUARIOS NORMALES: VER CONSULTAS Y RESPUESTAS DEL ADMIN -->
                        <hr style="border: 0; border-top: 1px solid rgba(255,255,255,0.1); margin: 2rem 0;">
                        <h3 style="color: var(--theme-color); margin-bottom: 1rem; font-family: 'Orbitron';">Mis Consultas y Respuestas Recibidas del Administrador</h3>
                        <?php
                            $stmt_my_c = $db->prepare("SELECT * FROM security_consultations WHERE email = ? OR user_id = ? ORDER BY id DESC");
                            $stmt_my_c->execute([$logged_user['email'], $logged_user['id']]);
                            $my_consultations = $stmt_my_c->fetchAll(PDO::FETCH_ASSOC);
                        ?>
                        <?php if (count($my_consultations) > 0): ?>
                            <?php foreach($my_consultations as $mc): ?>
                                <div style="background: rgba(3,7,18,0.7); padding: 1rem; border-radius: 6px; margin-bottom: 1rem; border: 1px solid rgba(255,255,255,0.1);">
                                    <p><strong>Mi Consulta (<?php echo htmlspecialchars($mc['subject']); ?>):</strong> <?php echo htmlspecialchars($mc['message']); ?></p>
                                    <?php if (!empty($mc['admin_reply'])): ?>
                                        <p style="margin-top: 0.5rem; color: #10b981;"><strong>Respuesta del Administrador:</strong> <?php echo htmlspecialchars($mc['admin_reply']); ?></p>
                                    <?php else: ?>
                                        <p style="margin-top: 0.5rem; color: #eab308; font-size: 0.85rem;">[Pendiente de respuesta por el administrador]</p>
                                    <?php endif; ?>
                                </div>
                            <?php endforeach; ?>
                        <?php else: ?>
                            <p style="color: #9ca3af;">No has realizado consultas de seguridad aún.</p>
                        <?php endif; ?>

                        <!-- MENSAJERÍA ENTRE OTROS USUARIOS -->
                        <hr style="border: 0; border-top: 1px solid rgba(255,255,255,0.1); margin: 2rem 0;">
                        <h3 style="color: var(--theme-color); margin-bottom: 1rem; font-family: 'Orbitron';">Enviar Mensajes a Otros Usuarios</h3>
                        <form action="?view=profile" method="POST">
                            <input type="hidden" name="action" value="send_direct_message">
                            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                            <div class="form-group">
                                <label>Seleccionar Usuario Destinatario</label>
                                <select name="receiver_id" class="form-control" required>
                                    <?php
                                        $stmt_users = $db->prepare("SELECT id, nombre, apellido, email FROM users WHERE id != ?");
                                        $stmt_users->execute([$logged_user['id']]);
                                        $other_users = $stmt_users->fetchAll(PDO::FETCH_ASSOC);
                                    ?>
                                    <?php foreach($other_users as $ou): ?>
                                        <option value="<?php echo $ou['id']; ?>"><?php echo htmlspecialchars($ou['nombre'] . ' ' . $ou['apellido'] . ' (' . $ou['email'] . ')'); ?></option>
                                    <?php endforeach; ?>
                                </select>
                            </div>
                            <div class="form-group">
                                <label>Mensaje Directo</label>
                                <textarea name="message" class="form-control" rows="3" required></textarea>
                            </div>
                            <button type="submit" class="btn btn-primary" style="padding: 0.6rem 1.5rem; font-size: 0.85rem;">Enviar Mensaje</button>
                        </form>

                        <h3 style="color: var(--theme-color); margin: 2rem 0 1rem 0; font-family: 'Orbitron';">Bandeja de Mensajes Recibidos de Otros Usuarios</h3>
                        <?php
                            $stmt_inbox = $db->prepare("SELECT dm.*, u.nombre, u.apellido FROM direct_messages dm JOIN users u ON dm.sender_id = u.id WHERE dm.receiver_id = ? ORDER BY dm.id DESC");
                            $stmt_inbox->execute([$logged_user['id']]);
                            $inbox_msgs = $stmt_inbox->fetchAll(PDO::FETCH_ASSOC);
                        ?>
                        <?php if (count($inbox_msgs) > 0): ?>
                            <?php foreach($inbox_msgs as $im): ?>
                                <div style="background: rgba(3,7,18,0.7); padding: 0.8rem; border-radius: 6px; margin-bottom: 0.8rem; border: 1px solid rgba(255,255,255,0.05);">
                                    <p style="font-size: 0.85rem; color: #eab308;">De: <?php echo htmlspecialchars($im['nombre'] . ' ' . $im['apellido']); ?></p>
                                    <p style="margin-top: 0.3rem;"><?php echo htmlspecialchars($im['message']); ?></p>
                                </div>
                            <?php endforeach; ?>
                        <?php else: ?>
                            <p style="color: #9ca3af;">No tienes mensajes de otros usuarios.</p>
                        <?php endif; ?>

                    <?php endif; ?>
                </div>
            </main>
        <?php endif; ?>

        <footer>
            <p>&copy; 2026 CyberGuard Offensive. Sistema Blindado con Registro Único de Administrador y Mensajería Integrada.</p>
        </footer>
    </div>
</body>
</html>
