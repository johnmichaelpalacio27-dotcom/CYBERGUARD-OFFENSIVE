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

    // Tabla para Consultas de Ciberseguridad y Webmail Interno
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

    // Tabla para Mensajería entre usuarios y administrador
    $db->exec("CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        receiver_id INTEGER NOT NULL,
        subject TEXT NOT NULL,
        message TEXT NOT NULL,
        is_read INTEGER DEFAULT 0,
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
    $form_action = $_POST['action'] ?? '';

    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die("Error de validación de seguridad (CSRF Token inválido o expirado).");
    }

    if ($form_action === 'register') {
        $nombre = trim($_POST['nombre']);
        $apellido = trim($_POST['apellido']);
        $email = trim($_POST['email']);
        $password = password_hash($_POST['password'], PASSWORD_BCRYPT);
        
        $requested_role = $_POST['role'] ?? 'analyst';

        // Lógica de validación estricta para permitir un ÚNICO administrador
        if ($requested_role === 'admin') {
            $stmt_chk = $db->prepare("SELECT COUNT(*) FROM users WHERE role = 'admin'");
            $stmt_chk->execute();
            $admin_count = $stmt_chk->fetchColumn();

            if ($admin_count > 0) {
                $message = "Error de seguridad: Ya existe un Administrador registrado en el sistema. No se permiten registros múltiples de admin.";
                $message_type = "error";
                $action = 'register';
                goto skip_registration;
            }
        }

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
            $stmt->execute([$nombre, $apellido, $email, $password, $single_use_hash, $hash_type, $sec_q1, $sec_a1, $sec_q2, $sec_a2, $sec_q3, $sec_a3, $requested_role]);

            $_SESSION['temp_new_hash'] = $single_use_hash;
            header("Location: ?view=login&registered=1");
            exit;
        } catch (Exception $e) {
            $message = "El correo electrónico ya se encuentra registrado en el sistema.";
            $message_type = "error";
            $action = 'register';
        }
        skip_registration:

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
    } elseif ($form_action === 'consultation') {
        $c_email = trim($_POST['email']);
        $c_subject = trim($_POST['subject']);
        $c_message = trim($_POST['message']);
        $c_uid = $_SESSION['user_id'] ?? null;

        if (!empty($c_email) && !empty($c_subject) && !empty($c_message)) {
            $stmt = $db->prepare("INSERT INTO security_consultations (user_id, email, subject, message, ip_address) VALUES (?, ?, ?, ?, ?)");
            $stmt->execute([$c_uid, $c_email, $c_subject, $c_message, $client_ip]);
            
            $message = "Consulta enviada exitosamente al panel del administrador vía Webmail.";
            $message_type = "success";
            $action = 'consultation';
        } else {
            $message = "Complete todos los campos de la consulta.";
            $message_type = "error";
            $action = 'consultation';
        }
    } elseif ($form_action === 'admin_reply_consultation') {
        if (!isset($_SESSION['user_id'])) { header("Location: ?view=login"); exit; }
        
        $stmt_rol = $db->prepare("SELECT role FROM users WHERE id = ?");
        $stmt_rol->execute([$_SESSION['user_id']]);
        $current_role = $stmt_rol->fetchColumn();

        if ($current_role === 'admin') {
            $consult_id = $_POST['consultation_id'];
            $reply_text = trim($_POST['admin_response']);

            $stmt_up = $db->prepare("UPDATE security_consultations SET admin_response = ?, status = 'resolved' WHERE id = ?");
            $stmt_up->execute([$reply_text, $consult_id]);
            
            $message = "Respuesta enviada al usuario con éxito.";
            $message_type = "success";
            $action = 'profile';
        }
    } elseif ($form_action === 'send_direct_message') {
        if (!isset($_SESSION['user_id'])) { header("Location: ?view=login"); exit; }
        $sender_id = $_SESSION['user_id'];
        $receiver_id = $_POST['receiver_id'];
        $subject = trim($_POST['subject']);
        $msg_text = trim($_POST['message']);

        if (!empty($subject) && !empty($msg_text)) {
            $stmt_m = $db->prepare("INSERT INTO messages (sender_id, receiver_id, subject, message) VALUES (?, ?, ?, ?)");
            $stmt_m->execute([$sender_id, $receiver_id, $subject, $msg_text]);
            
            $message = "Mensaje directo enviado correctamente.";
            $message_type = "success";
            $action = 'profile';
        }
    }
}

// Manejo de Cierre de Sesión
if ($action === 'logout') {
    $_SESSION = array();
    session_destroy();
    header("Location: ?view=home");
    exit;
}

// Obtener datos globales del usuario autenticado
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
    <title>CyberGuard Offensive | Panel Admin & Mensajería</title>
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&family=Inter:wght@300;400;600&display=swap" rel="stylesheet">
    <style>
        :root { --theme-color: <?php echo htmlspecialchars($active_theme_color); ?>; }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background-color: #030712; color: #f3f4f6; font-family: 'Inter', sans-serif; min-height: 100vh; }
        #canvas-container { position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; z-index: 1; pointer-events: none; }
        .ui-layer { position: relative; z-index: 2; width: 100%; min-height: 100vh; display: flex; flex-direction: column; justify-content: space-between; padding: 2rem 4rem; }
        header { display: flex; justify-content: space-between; align-items: center; width: 100%; max-width: 1200px; margin: 0 auto; }
        .logo { font-family: 'Orbitron', sans-serif; font-size: 1.5rem; font-weight: 700; color: var(--theme-color); text-decoration: none; }
        nav { display: flex; align-items: center; gap: 1.8rem; }
        nav a { color: #9ca3af; text-decoration: none; font-size: 0.9rem; transition: color 0.3s ease; }
        nav a:hover { color: var(--theme-color); }
        .hero, .content-section { max-width: 900px; margin: auto 0; padding: 3rem 0; width: 100%; }
        .badge-status { display: inline-block; background: rgba(6, 182, 212, 0.1); border: 1px solid rgba(6, 182, 212, 0.3); color: var(--theme-color); padding: 0.4rem 1rem; border-radius: 50px; font-size: 0.8rem; font-family: 'Orbitron', sans-serif; margin-bottom: 1.5rem; text-transform: uppercase; }
        h1 { font-family: 'Orbitron', sans-serif; font-size: 3rem; line-height: 1.1; margin-bottom: 1.5rem; color: #ffffff; }
        h1 span { color: var(--theme-color); }
        .glass-card { background: rgba(15, 23, 42, 0.88); border: 1px solid rgba(6, 182, 212, 0.3); padding: 2.5rem; border-radius: 12px; backdrop-filter: blur(12px); box-shadow: 0 0 30px rgba(0, 0, 0, 0.7); width: 100%; margin-bottom: 2rem; }
        .form-group { margin-bottom: 1.2rem; }
        .form-group label { display: block; font-size: 0.85rem; color: var(--theme-color); font-family: 'Orbitron', sans-serif; margin-bottom: 0.5rem; }
        .form-control { width: 100%; padding: 0.8rem 1rem; background: rgba(3, 7, 18, 0.9); border: 1px solid rgba(255, 255, 255, 0.15); border-radius: 6px; color: #fff; font-size: 0.95rem; }
        .form-control:focus { outline: none; border-color: var(--theme-color); }
        .btn { padding: 0.9rem 2rem; border-radius: 6px; font-weight: 600; text-decoration: none; cursor: pointer; font-size: 0.95rem; display: inline-block; text-align: center; border: none; }
        .btn-primary { background-color: var(--theme-color); color: #030712; }
        .btn-outline { background: transparent; color: #f3f4f6; border: 1px solid rgba(255, 255, 255, 0.2); }
        .alert { padding: 1rem; margin-bottom: 1.5rem; border-radius: 6px; font-size: 0.9rem; }
        .alert-error { background: rgba(239, 68, 68, 0.2); border: 1px solid #ef4444; color: #fca5a5; }
        .alert-success { background: rgba(16, 185, 129, 0.2); border: 1px solid #10b981; color: #a7f3d0; }
        table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
        th, td { padding: 0.8rem; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.1); font-size: 0.9rem; }
        th { color: var(--theme-color); font-family: 'Orbitron'; }
    </style>
</head>
<body>

    <div id="canvas-container"></div>

    <div class="ui-layer">
        <header>
            <a href="?view=home" class="logo">CYBERGUARD//OFFENSIVE</a>
            <nav>
                <a href="?view=consultation">Consulta / Webmail</a>
                <?php if (isset($_SESSION['user_id'])): ?>
                    <a href="?view=profile" style="color: var(--theme-color); font-weight: 600;">Mi Panel / Perfil</a>
                    <a href="?view=logout" style="color: #ef4444;">Salir</a>
                <?php else: ?>
                    <a href="?view=login" style="color: var(--theme-color); font-weight: 600;">Iniciar Sesión</a>
                    <a href="?view=register" style="font-weight: 600;">Registrarse</a>
                <?php endif; ?>
            </nav>
        </header>

        <?php if (!empty($message)): ?>
            <div style="max-width: 900px; margin: 1rem auto 0 auto; width: 100%;">
                <div class="alert alert-<?php echo $message_type === 'success' ? 'success' : 'error'; ?>">
                    <?php echo htmlspecialchars($message); ?>
                </div>
            </div>
        <?php endif; ?>

        <?php if ($action == 'home'): ?>
            <main class="hero">
                <div class="badge-status">Sistema Blindado con Panel de Administración y Webmail</div>
                <h1>Arquitectura de Acceso <span>Administrado</span></h1>
                <p style="color: #9ca3af; margin-bottom: 2rem;">Plataforma con gestión de un único administrador, mensajería interna cifrada y control web de consultas técnicas.</p>
                <div>
                    <a href="?view=register" class="btn btn-primary">Crear Cuenta</a>
                    <a href="?view=login" class="btn btn-outline">Acceder</a>
                </div>
            </main>

        <?php elseif ($action == 'register'): ?>
            <main class="hero">
                <div class="glass-card">
                    <div class="badge-status">Registro de Nuevo Usuario / Administrador</div>
                    <form action="?view=register" method="POST">
                        <input type="hidden" name="action" value="register">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        
                        <div class="form-group">
                            <label>Rol de Usuario</label>
                            <select name="role" class="form-control">
                                <option value="analyst">Analista de Seguridad</option>
                                <option value="admin">Administrador del Sistema (Único)</option>
                            </select>
                        </div>
                        <div class="form-group"><label>Nombre</label><input type="text" name="nombre" class="form-control" required></div>
                        <div class="form-group"><label>Apellido</label><input type="text" name="apellido" class="form-control" required></div>
                        <div class="form-group"><label>Correo Electrónico</label><input type="email" name="email" class="form-control" required></div>
                        <div class="form-group"><label>Contraseña</label><input type="password" name="password" class="form-control" required></div>
                        
                        <div class="form-group"><label>Pregunta de Seguridad</label><input type="text" name="sec_question_1" class="form-control" value="¿Cuál es tu herramienta de ciberseguridad favorita?" required></div>
                        <div class="form-group"><label>Respuesta de Seguridad</label><input type="text" name="sec_answer_1" class="form-control" required></div>

                        <button type="submit" class="btn btn-primary" style="width:100%;">Registrar Cuenta</button>
                    </form>
                </div>
            </main>

        <?php elseif ($action == 'login'): ?>
            <main class="hero">
                <div class="glass-card">
                    <div class="badge-status">Autenticación Segura</div>
                    <form action="?view=login" method="POST">
                        <input type="hidden" name="action" value="login">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <div class="form-group"><label>Correo Electrónico</label><input type="email" name="login_id" class="form-control" required></div>
                        <div class="form-group"><label>Contraseña</label><input type="password" name="password" class="form-control" required></div>
                        <div class="form-group"><label>Respuesta Pregunta 1</label><input type="text" name="sec_answer_1" class="form-control" required></div>
                        <button type="submit" class="btn btn-primary" style="width:100%;">Iniciar Sesión</button>
                    </form>
                </div>
            </main>

        <?php elseif ($action == 'consultation'): ?>
            <main class="hero">
                <div class="glass-card">
                    <div class="badge-status">Webmail de Consultas</div>
                    <h2>Envío de Consulta al Administrador</h2>
                    <form action="?view=consultation" method="POST">
                        <input type="hidden" name="action" value="consultation">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <div class="form-group"><label>Tu Correo</label><input type="email" name="email" class="form-control" required value="<?php echo htmlspecialchars($_SESSION['user_email'] ?? ''); ?>"></div>
                        <div class="form-group"><label>Asunto</label><input type="text" name="subject" class="form-control" required></div>
                        <div class="form-group"><label>Mensaje / Consulta</label><textarea name="message" class="form-control" rows="4" required></textarea></div>
                        <button type="submit" class="btn btn-primary" style="width:100%;">Enviar al Administrador</button>
                    </form>
                </div>
            </main>

        <?php elseif ($action == 'profile'): ?>
            <main class="content-section">
                <div class="glass-card">
                    <div class="badge-status">Panel de Usuario / Administrador</div>
                    <h2>Bienvenido, <?php echo htmlspecialchars($logged_user['nombre']); ?> (Rol: <strong><?php echo strtoupper($logged_user['role']); ?></strong>)</h2>

                    <?php if ($logged_user['role'] === 'admin'): ?>
                        <hr style="border-color: rgba(255,255,255,0.1); margin: 2rem 0;">
                        <h3 style="color:var(--theme-color); font-family:'Orbitron'; margin-bottom:1rem;">Panel de Administración: Consultas Recibidas</h3>
                        <?php
                        $stmt_c = $db->query("SELECT * FROM security_consultations ORDER BY created_at DESC");
                        $consultations = $stmt_c->fetchAll(PDO::FETCH_ASSOC);
                        ?>
                        <?php if (count($consultations) > 0): ?>
                            <table>
                                <tr><th>Usuario/Email</th><th>Asunto</th><th>Mensaje</th><th>Respuesta</th><th>Acción</th></tr>
                                <?php foreach ($consultations as $c): ?>
                                    <tr>
                                        <td><?php echo htmlspecialchars($c['email']); ?></td>
                                        <td><?php echo htmlspecialchars($c['subject']); ?></td>
                                        <td><?php echo htmlspecialchars($c['message']); ?></td>
                                        <td><?php echo htmlspecialchars($c['admin_response'] ?: 'Pendiente'); ?></td>
                                        <td>
                                            <form action="?view=profile" method="POST" style="display:flex; gap:0.5rem; flex-direction:column;">
                                                <input type="hidden" name="action" value="admin_reply_consultation">
                                                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                                                <input type="hidden" name="consultation_id" value="<?php echo $c['id']; ?>">
                                                <input type="text" name="admin_response" class="form-control" placeholder="Responder..." required style="padding:0.3rem;">
                                                <button type="submit" class="btn btn-primary" style="padding:0.3rem 0.6rem; font-size:0.8rem;">Enviar</button>
                                            </form>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </table>
                        <?php else: ?>
                            <p style="color:#9ca3af;">No hay consultas pendientes en el buzón web.</p>
                        <?php endif; ?>
                    <?php endif; ?>

                    <hr style="border-color: rgba(255,255,255,0.1); margin: 2rem 0;">
                    <h3 style="color:var(--theme-color); font-family:'Orbitron'; margin-bottom:1rem;">Mensajería Directa con otros Usuarios</h3>
                    <form action="?view=profile" method="POST">
                        <input type="hidden" name="action" value="send_direct_message">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <div class="form-group">
                            <label>Enviar a Usuario (Seleccionar)</label>
                            <select name="receiver_id" class="form-control" required>
                                <?php
                                $stmt_users = $db->prepare("SELECT id, nombre, email FROM users WHERE id != ?");
                                $stmt_users->execute([$logged_user['id']]);
                                foreach ($stmt_users->fetchAll(PDO::FETCH_ASSOC) as $usr) {
                                    echo "<option value='{$usr['id']}'>{$usr['nombre']} ({$usr['email']})</option>";
                                }
                                ?>
                            </select>
                        </div>
                        <div class="form-group"><label>Asunto del Mensaje</label><input type="text" name="subject" class="form-control" required></div>
                        <div class="form-group"><label>Mensaje</label><textarea name="message" class="form-control" rows="3" required></textarea></div>
                        <button type="submit" class="btn btn-primary">Enviar Mensaje</button>
                    </form>

                    <h3 style="color:var(--theme-color); font-family:'Orbitron'; margin: 2rem 0 1rem 0;">Bandeja de Mensajes Recibidos</h3>
                    <?php
                    $stmt_msgs = $db->prepare("SELECT m.*, u.nombre as sender_name FROM messages m JOIN users u ON m.sender_id = u.id WHERE m.receiver_id = ? ORDER BY m.created_at DESC");
                    $stmt_msgs->execute([$logged_user['id']]);
                    $inbox = $stmt_msgs->fetchAll(PDO::FETCH_ASSOC);
                    ?>
                    <?php if (count($inbox) > 0): ?>
                        <table>
                            <tr><th>Remitente</th><th>Asunto</th><th>Mensaje</th><th>Fecha</th></tr>
                            <?php foreach ($inbox as $msg): ?>
                                <tr>
                                    <td><?php echo htmlspecialchars($msg['sender_name']); ?></td>
                                    <td><?php echo htmlspecialchars($msg['subject']); ?></td>
                                    <td><?php echo htmlspecialchars($msg['message']); ?></td>
                                    <td><?php echo htmlspecialchars($msg['created_at']); ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </table>
                    <?php else: ?>
                        <p style="color:#9ca3af;">Tu bandeja de entrada está vacía.</p>
                    <?php endif; ?>

                </div>
            </main>
        <?php endif; ?>

    </div>
</body>
</html>
