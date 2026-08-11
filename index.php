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

    // Tabla de Consultas con soporte para respuestas del administrador
    $db->exec("CREATE TABLE IF NOT EXISTS security_consultations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        email TEXT NOT NULL,
        subject TEXT NOT NULL,
        message TEXT NOT NULL,
        admin_response TEXT DEFAULT '',
        status TEXT DEFAULT 'pending',
        ip_address TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");

    // Crear cuenta de Administrador por defecto si no existe
    $stmt_check_admin = $db->query("SELECT COUNT(*) FROM users WHERE role = 'admin'");
    if ($stmt_check_admin->fetchColumn() == 0) {
        $admin_pass = password_hash('AdminCyber2026*', PASSWORD_BCRYPT);
        $admin_hash = hash('sha256', random_bytes(32));
        $stmt_admin = $db->prepare("INSERT INTO users (nombre, apellido, email, password, single_use_hash, role, status) VALUES (?, ?, ?, ?, ?, 'admin', 'active')");
        $stmt_admin->execute(['Admin', 'Master', 'admin@cyberguard.local', $admin_pass, $admin_hash]);
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

    if ($form_action === 'register') {
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
            $new_hash = ($htype === 'whirlpool') ? hash('whirlpool', $raw_data) : (($htype === 'md5') ? md5($raw_data) : hash('sha256', $raw_data));

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
        if (!isset($_SESSION['user_id'])) { header("Location: ?view=login"); exit; }
        $user_id = $_SESSION['user_id'];
        $desired_type = $_POST['hash_type'] ?? 'sha256';
        $raw_data = random_bytes(32);
        $nuevo_hash = ($desired_type === 'whirlpool') ? hash('whirlpool', $raw_data) : (($desired_type === 'md5') ? md5($raw_data) : hash('sha256', $raw_data));

        $stmt = $db->prepare("UPDATE users SET single_use_hash = ?, hash_type = ?, hash_used = 0 WHERE id = ?");
        $stmt->execute([$nuevo_hash, $desired_type, $user_id]);

        $message = "Se ha generado un nuevo Hash de seguridad único.";
        $message_type = "success";
        $action = 'profile';
    } elseif ($form_action === 'update_profile') {
        if (!isset($_SESSION['user_id'])) { header("Location: ?view=login"); exit; }
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
    } elseif ($form_action === 'consultation') {
        $lockout = check_brute_force('consultation');
        if ($lockout > 0) {
            $message = "Demasiadas consultas enviadas. Espere {$lockout} segundos.";
            $message_type = "error";
            $action = 'consultation';
        } else {
            $c_email = trim($_POST['email']);
            $c_subject = trim($_POST['subject']);
            $c_message = trim($_POST['message']);
            $c_uid = isset($_SESSION['user_id']) ? $_SESSION['user_id'] : null;

            if (!empty($c_email) && !empty($c_subject) && !empty($c_message)) {
                // Guarda la consulta vinculada al ID del usuario para que la respuesta llegue a su perfil
                $stmt = $db->prepare("INSERT INTO security_consultations (user_id, email, subject, message, ip_address, status) VALUES (?, ?, ?, ?, ?, 'pending')");
                $stmt->execute([$c_uid, $c_email, $c_subject, $c_message, $client_ip]);
                
                register_failed_attempt('consultation');
                $message = "Consulta enviada con éxito al Administrador. Recibirás respuesta en tu sección de Perfil.";
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

// Manejo explícito de Cierre de Sesión
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
        h1 { font-family: 'Orbitron', sans-serif; font-size: 2.8rem; line-height: 1.1; margin-bottom: 1.5rem; color: #ffffff; }
        h1 span { color: var(--theme-color); }
        .glass-card { background: rgba(15, 23, 42, 0.9); border: 1px solid rgba(6, 182, 212, 0.3); padding: 2.5rem; border-radius: 12px; backdrop-filter: blur(12px); box-shadow: 0 0 30px rgba(0, 0, 0, 0.7); width: 100%; max-width: 700px; margin: 0 auto; }
        .form-group { margin-bottom: 1.2rem; }
        .form-group label { display: block; font-size: 0.85rem; color: var(--theme-color); font-family: 'Orbitron', sans-serif; margin-bottom: 0.5rem; }
        .form-control { width: 100%; padding: 0.8rem 1rem; background: rgba(3, 7, 18, 0.9); border: 1px solid rgba(255, 255, 255, 0.15); border-radius: 6px; color: #fff; font-size: 0.95rem; }
        .form-control:focus { outline: none; border-color: var(--theme-color); }
        .btn { padding: 0.8rem 2rem; border-radius: 6px; font-weight: 600; text-decoration: none; transition: all 0.3s ease; cursor: pointer; font-size: 0.95rem; display: inline-block; text-align: center; border: none; }
        .btn-primary { background-color: var(--theme-color); color: #030712; box-shadow: 0 0 20px rgba(6, 182, 212, 0.3); }
        .btn-primary:hover { filter: brightness(1.2); }
        .btn-outline { background: transparent; color: #f3f4f6; border: 1px solid rgba(255, 255, 255, 0.2); }
        .btn-outline:hover { border-color: var(--theme-color); color: var(--theme-color); }
        .alert { padding: 1rem; margin-bottom: 1.5rem; border-radius: 6px; font-size: 0.9rem; }
        .alert-error { background: rgba(239, 68, 68, 0.2); border: 1px solid #ef4444; color: #fca5a5; }
        .alert-success { background: rgba(16, 185, 129, 0.2); border: 1px solid #10b981; color: #a7f3d0; }
        footer { text-align: center; padding: 1.5rem 0; color: #4b5563; font-size: 0.85rem; border-top: 1px solid rgba(255, 255, 255, 0.05); max-width: 1200px; margin: 0 auto; width: 100%; }
    </style>
</head>
<body>

    <div id="canvas-container"></div>

    <div class="ui-layer">
        <header>
            <a href="?view=home" class="logo">CYBERGUARD//OFFENSIVE</a>
            <nav>
                <a href="?view=consultation">Consulta de Ciberseguridad</a>
                <?php if (isset($_SESSION['user_id'])): ?>
                    <a href="?view=profile" style="color: var(--theme-color); font-weight: 600;">Mi Perfil</a>
                    <a href="?view=logout" style="color: #ef4444;">Salir</a>
                <?php else: ?>
                    <a href="?view=login" style="color: var(--theme-color);">Iniciar Sesión</a>
                    <a href="?view=register">Registrarse</a>
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
                <p style="color: #9ca3af; margin-bottom: 2rem;">Plataforma protegida con tokens criptográficos, protección avanzada contra fuerza bruta y buzón de consultas integrado con respuestas en perfil.</p>
                <div>
                    <a href="?view=register" class="btn btn-primary">Crear Cuenta Segura</a>
                    <a href="?view=login" class="btn btn-outline" style="margin-left: 1rem;">Acceder al Sistema</a>
                </div>
            </main>

        <?php elseif ($action == 'consultation'): ?>
            <main class="hero">
                <div class="glass-card">
                    <div class="badge-status">Buzón de Consultas Protegido</div>
                    <h2 style="font-family:'Orbitron'; font-size:1.6rem; margin-bottom:1rem; color:#fff;">Enviar Consulta al Administrador</h2>
                    <p style="color:#9ca3af; font-size:0.9rem; margin-bottom:1.5rem;">Envía tu duda o reporte. Una vez que el administrador responda, verás la respuesta directamente en tu sección de <strong>Mi Perfil</strong>.</p>
                    <form action="?view=consultation" method="POST">
                        <input type="hidden" name="action" value="consultation">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <div class="form-group">
                            <label>Correo Electrónico</label>
                            <input type="email" name="email" class="form-control" required value="<?php echo htmlspecialchars($_SESSION['user_email'] ?? ''); ?>">
                        </div>
                        <div class="form-group">
                            <label>Asunto</label>
                            <input type="text" name="subject" class="form-control" placeholder="Ej: Análisis de vulnerabilidad en API" required>
                        </div>
                        <div class="form-group">
                            <label>Mensaje Detallado</label>
                            <textarea name="message" class="form-control" rows="4" placeholder="Describa su duda..." required></textarea>
                        </div>
                        <button type="submit" class="btn btn-primary" style="width:100%; margin-top:1rem;">Enviar Consulta Segura</button>
                    </form>
                </div>
            </main>

        <?php elseif ($action == 'register'): ?>
            <main class="hero">
                <div class="glass-card">
                    <div class="badge-status">Nuevo Registro</div>
                    <h2 style="font-family:'Orbitron'; font-size:1.6rem; margin-bottom:1.5rem; color:#fff;">Crear Cuenta de Analista</h2>
                    <form action="?view=register" method="POST">
                        <input type="hidden" name="action" value="register">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
                            <div class="form-group"><label>Nombre</label><input type="text" name="nombre" class="form-control" required></div>
                            <div class="form-group"><label>Apellido</label><input type="text" name="apellido" class="form-control" required></div>
                        </div>
                        <div class="form-group"><label>Correo Electrónico</label><input type="email" name="email" class="form-control" required></div>
                        <div class="form-group"><label>Contraseña</label><input type="password" name="password" class="form-control" required></div>
                        <div class="form-group">
                            <label>Algoritmo Criptográfico de Hash</label>
                            <select name="hash_type" class="form-control">
                                <option value="sha256">SHA-256 (Estándar)</option>
                                <option value="whirlpool">Whirlpool (Avanzado)</option>
                                <option value="md5">MD5 (Legacy)</option>
                            </select>
                        </div>
                        <hr style="border-color:rgba(255,255,255,0.1); margin:1.5rem 0;">
                        <div class="form-group"><label>Pregunta de Seguridad 1</label><input type="text" name="sec_question_1" class="form-control" placeholder="Ej: ¿Nombre de tu primera mascota?" required></div>
                        <div class="form-group"><label>Respuesta 1</label><input type="text" name="sec_answer_1" class="form-control" required></div>
                        <button type="submit" class="btn btn-primary" style="width:100%; margin-top:1rem;">Registrar Cuenta Segura</button>
                    </form>
                </div>
            </main>

        <?php elseif ($action == 'login'): ?>
            <main class="hero">
                <div class="glass-card" style="max-width: 450px;">
                    <div class="badge-status">Autenticación</div>
                    <h2 style="font-family:'Orbitron'; font-size:1.6rem; margin-bottom:1.5rem; color:#fff;">Iniciar Sesión</h2>
                    <form action="?view=login" method="POST">
                        <input type="hidden" name="action" value="login">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <div class="form-group"><label>Correo Electrónico</label><input type="email" name="login_id" class="form-control" required></div>
                        <div class="form-group"><label>Contraseña</label><input type="password" name="password" class="form-control" required></div>
                        <div class="form-group"><label>Respuesta Pregunta Seguridad 1</label><input type="text" name="sec_answer_1" class="form-control" placeholder="Verificación 2FA"></div>
                        <button type="submit" class="btn btn-primary" style="width:100%; margin-top:1rem;">Ingresar</button>
                    </form>
                </div>
            </main>

        <?php elseif ($action == 'profile'): ?>
            <?php
            if (!isset($logged_user)) { header("Location: ?view=login"); exit; }
            // Obtener consultas enviadas por este usuario y sus respectivas respuestas del admin
            $stmt_my_q = $db->prepare("SELECT * FROM security_consultations WHERE user_id = ? OR email = ? ORDER BY created_at DESC");
            $stmt_my_q->execute([$logged_user['id'], $logged_user['email']]);
            $my_consultations = $stmt_my_q->fetchAll(PDO::FETCH_ASSOC);
            ?>
            <main class="content-section" style="max-width: 900px;">
                <div class="badge-status">Panel de Analista & Perfil Blindado</div>
                <h1>Bienvenido, <span><?php echo htmlspecialchars($logged_user['nombre']); ?></span></h1>
                
                <div class="glass-card" style="max-width: 100%; margin-bottom: 2rem;">
                    <h3 style="font-family:'Orbitron'; color:#fff; margin-bottom:1.5rem;">Mis Consultas y Respuestas del Administrador</h3>
                    <?php if (empty($my_consultations)): ?>
                        <p style="color:#9ca3af;">Aún no has enviado ninguna consulta. Dirígete a <a href="?view=consultation" style="color:var(--theme-color);">Consulta de Ciberseguridad</a> para crear una.</p>
                    <?php else: ?>
                        <div style="display:flex; flex-direction:column; gap:1rem;">
                            <?php foreach ($my_consultations as $mc): ?>
                                <div style="background:rgba(3,7,18,0.7); border:1px solid rgba(255,255,255,0.1); padding:1.2rem; border-radius:8px;">
                                    <div style="display:flex; justify-content:space-between; margin-bottom:0.5rem;">
                                        <strong style="color:var(--theme-color);"><?php echo htmlspecialchars($mc['subject']); ?></strong>
                                        <span style="font-size:0.8rem; color:#9ca3af;"><?php echo $mc['created_at']; ?></span>
                                    </div>
                                    <p style="font-size:0.9rem; color:#d1d5db; margin-bottom:1rem;"><?php echo nl2br(htmlspecialchars($mc['message'])); ?></p>
                                    
                                    <div style="background:rgba(6,182,212,0.05); border-left:3px solid var(--theme-color); padding:0.8rem; border-radius:4px;">
                                        <strong style="font-size:0.85rem; color:#fff; font-family:'Orbitron';">Respuesta Oficial del Administrador:</strong>
                                        <?php if ($mc['status'] === 'resolved' && !empty($mc['admin_response'])): ?>
                                            <p style="font-size:0.9rem; color:#a7f3d0; margin-top:0.4rem;"><?php echo nl2br(htmlspecialchars($mc['admin_response'])); ?></p>
                                        <?php else: ?>
                                            <p style="font-size:0.85rem; color:#f59e0b; margin-top:0.4rem;">Estado: Pendiente de revisión por el equipo de administración.</p>
                                        <?php endif; ?>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>
                </div>

                <div class="glass-card" style="max-width: 100%;">
                    <h3 style="font-family:'Orbitron'; color:#fff; margin-bottom:1rem;">Configuración de Perfil & Apariencia</h3>
                    <form action="?view=profile" method="POST" enctype="multipart/form-data">
                        <input type="hidden" name="action" value="update_profile">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <div style="display:grid; grid-template-columns: 1fr 1fr; gap:1rem;">
                            <div class="form-group"><label>Nombre</label><input type="text" name="nombre" class="form-control" value="<?php echo htmlspecialchars($logged_user['nombre']); ?>" required></div>
                            <div class="form-group"><label>Apellido</label><input type="text" name="apellido" class="form-control" value="<?php echo htmlspecialchars($logged_user['apellido']); ?>" required></div>
                        </div>
                        <div class="form-group"><label>Color Temático de Interfaz</label><input type="color" name="theme_color" value="<?php echo htmlspecialchars($active_theme_color); ?>" style="width:100%; height:40px; background:none; border:none; cursor:pointer;"></div>
                        <button type="submit" class="btn btn-primary" style="margin-top:1rem;">Guardar Cambios</button>
                    </form>
                </div>
            </main>
        <?php endif; ?>

        <footer>
            <p>&copy; 2026 CyberGuard Offensive. Hardened Security Systems.</p>
        </footer>
    </div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
    <script>
        const container = document.getElementById('canvas-container');
        const scene = new THREE.Scene();
        const camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
        const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true });
        renderer.setSize(window.innerWidth, window.innerHeight);
        container.appendChild(renderer.domElement);

        const geometry = new THREE.SphereGeometry(2.2, 32, 32);
        const material = new THREE.MeshBasicMaterial({ color: '<?php echo $active_theme_color; ?>', wireframe: true, transparent: true, opacity: 0.35 });
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
    </script>
</body>
</html>
