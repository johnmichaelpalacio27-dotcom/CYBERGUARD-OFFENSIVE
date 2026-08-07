<?php
// ====================================================================
// INCLUSIÓN DEL MÓDULO DE NOTIFICACIONES SMTP / AUDITORÍA DE SEGURIDAD
// ====================================================================
require_once __DIR__ . '/mailer_mail.php';

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

    // Tabla para Consultas de Ciberseguridad ajustada sin campos incompatibles
    $db->exec("CREATE TABLE IF NOT EXISTS security_consultations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        email TEXT NOT NULL,
        subject TEXT NOT NULL,
        message TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");
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

    if ($form_action === 'register') {
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
            $stmt = $db->prepare("INSERT INTO users (nombre, apellido, email, password, single_use_hash, hash_type, hash_used, hash_security_active, sec_question_1, sec_answer_1, sec_question_2, sec_answer_2, sec_question_3, sec_answer_3) VALUES (?, ?, ?, ?, ?, ?, 0, 1, ?, ?, ?, ?, ?, ?)");
            $stmt->execute([$nombre, $apellido, $email, $password, $single_use_hash, $hash_type, $sec_q1, $sec_a1, $sec_q2, $sec_a2, $sec_q3, $sec_a3]);

            registrarYNotificarEvento($db, null, $email, $nombre, 'REGISTRO DE USUARIO', 'Cuenta creada exitosamente con token criptográfico.');

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
                    
                    registrarYNotificarEvento($db, $user['id'], $user['email'], $user['nombre'], 'INICIO DE SESIÓN', 'Acceso autenticado correctamente desde IP: ' . $client_ip);

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
                $stmt = $db->prepare("INSERT INTO security_consultations (user_id, email, subject, message) VALUES (?, ?, ?, ?)");
                $stmt->execute([$c_uid, $c_email, $c_subject, $c_message]);
                
                registrarYNotificarEvento($db, $c_uid, $c_email, $_SESSION['user_nombre'] ?? 'Visitante', 'CONSULTA DE CIBERSEGURIDAD', 'Asunto: ' . $c_subject);

                register_failed_attempt('consultation');
                $message = "Consulta de ciberseguridad enviada y protegida con éxito.";
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
        #canvas-container { position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; z-index: 1; pointer-events: none; }
        .ui-layer { position: relative; z-index: 2; width: 100%; min-height: 100vh; display: flex; flex-direction: column; justify-content: space-between; padding: 2rem 4rem; }
        header { display: flex; justify-content: space-between; align-items: center; width: 100%; max-width: 1200px; margin: 0 auto; }
        .logo { font-family: 'Orbitron', sans-serif; font-size: 1.5rem; font-weight: 700; color: var(--theme-color); letter-spacing: 2px; text-decoration: none; }
        nav { display: flex; align-items: center; gap: 1.8rem; }
        nav a { color: #9ca3af; text-decoration: none; font-size: 0.9rem; }
        .hero, .content-section { max-width: 800px; margin: auto 0; padding: 3rem 0; }
        .badge-status { display: inline-block; background: rgba(6, 182, 212, 0.1); border: 1px solid rgba(6, 182, 212, 0.3); color: var(--theme-color); padding: 0.4rem 1rem; border-radius: 50px; font-size: 0.8rem; font-family: 'Orbitron', sans-serif; margin-bottom: 1.5rem; }
        h1 { font-family: 'Orbitron', sans-serif; font-size: 3rem; line-height: 1.1; margin-bottom: 1.5rem; color: #ffffff; }
        h1 span { color: var(--theme-color); }
        .subtitle { font-size: 1.05rem; color: #9ca3af; line-height: 1.6; margin-bottom: 2rem; }
        .glass-card { background: rgba(15, 23, 42, 0.88); border: 1px solid rgba(6, 182, 212, 0.3); padding: 2.5rem; border-radius: 12px; backdrop-filter: blur(12px); max-width: 500px; }
        .form-group { margin-bottom: 1.2rem; }
        .form-group label { display: block; font-size: 0.85rem; color: var(--theme-color); font-family: 'Orbitron', sans-serif; margin-bottom: 0.5rem; }
        .form-control { width: 100%; padding: 0.8rem 1rem; background: rgba(3, 7, 18, 0.9); border: 1px solid rgba(255, 255, 255, 0.15); border-radius: 6px; color: #fff; font-size: 0.95rem; }
        .btn { padding: 0.9rem 2rem; border-radius: 6px; font-weight: 600; text-decoration: none; cursor: pointer; font-size: 0.95rem; display: inline-block; text-align: center; border: none; }
        .btn-primary { background-color: var(--theme-color); color: #030712; }
        .btn-outline { background: transparent; color: #f3f4f6; border: 1px solid rgba(255, 255, 255, 0.2); }
        .alert { padding: 1rem; margin-bottom: 1.5rem; border-radius: 6px; font-size: 0.9rem; }
        .alert-error { background: rgba(239, 68, 68, 0.2); border: 1px solid #ef4444; color: #fca5a5; }
        .alert-success { background: rgba(16, 185, 129, 0.2); border: 1px solid #10b981; color: #a7f3d0; }
        footer { text-align: center; padding: 1.5rem 0; color: #4b5563; font-size: 0.85rem; border-top: 1px solid rgba(255, 255, 255, 0.05); }
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
                    <a href="?view=login" style="color: var(--theme-color); font-weight: 600;">Iniciar Sesión</a>
                    <a href="?view=register" style="color: #f3f4f6;">Registrarse</a>
                <?php endif; ?>
            </nav>
        </header>

        <?php if (!empty($message)): ?>
            <div style="max-width: 600px; margin: 1rem auto; width: 100%;">
                <div class="alert alert-<?php echo $message_type === 'success' ? 'success' : 'error'; ?>">
                    <?php echo htmlspecialchars($message); ?>
                </div>
            </div>
        <?php endif; ?>

        <?php if ($action == 'home'): ?>
            <main class="hero">
                <div class="badge-status">Sistema de Autenticación Criptográfica & Anti-DDoS</div>
                <h1>Arquitectura de Acceso <span>Blindado 3D</span></h1>
                <p class="subtitle">Plataforma protegida con tokens criptográficos, protección avanzada contra fuerza bruta y notificaciones SMTP en tiempo real.</p>
                <div style="display: flex; gap: 1rem;">
                    <a href="?view=register" class="btn btn-primary">Crear Cuenta Segura</a>
                    <a href="?view=login" class="btn btn-outline">Acceder al Sistema</a>
                </div>
            </main>
        <?php elseif ($action == 'consultation'): ?>
            <main class="hero">
                <div class="glass-card" style="max-width: 600px;">
                    <div class="badge-status">Área de Consultas Protegida</div>
                    <h2 style="font-family:'Orbitron'; font-size:1.8rem; margin-bottom:1.5rem; color:#fff;">Consulta de Ciberseguridad</h2>
                    <form action="?view=consultation" method="POST">
                        <input type="hidden" name="action" value="consultation">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <div class="form-group">
                            <label>Correo Electrónico</label>
                            <input type="email" name="email" class="form-control" required value="<?php echo htmlspecialchars($_SESSION['user_email'] ?? ''); ?>">
                        </div>
                        <div class="form-group">
                            <label>Asunto</label>
                            <input type="text" name="subject" class="form-control" required>
                        </div>
                        <div class="form-group">
                            <label>Mensaje</label>
                            <textarea name="message" class="form-control" rows="4" required></textarea>
                        </div>
                        <button type="submit" class="btn btn-primary" style="width:100%;">Enviar Consulta</button>
                    </form>
                </div>
            </main>
        <?php elseif ($action == 'register'): ?>
            <main class="hero">
                <div class="glass-card" style="max-width: 600px;">
                    <div class="badge-status">Nuevo Registro</div>
                    <form action="?view=register" method="POST">
                        <input type="hidden" name="action" value="register">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <div class="form-group"><label>Nombre</label><input type="text" name="nombre" class="form-control" required></div>
                        <div class="form-group"><label>Apellido</label><input type="text" name="apellido" class="form-control" required></div>
                        <div class="form-group"><label>Correo Electrónico</label><input type="email" name="email" class="form-control" required></div>
                        <div class="form-group"><label>Contraseña</label><input type="password" name="password" class="form-control" required></div>
                        <div class="form-group"><label>Pregunta 1: Nombre de tu primera mascota?</label><input type="text" name="sec_answer_1" class="form-control" required></div>
                        <input type="hidden" name="sec_question_1" value="Mascota">
                        <input type="hidden" name="sec_question_2" value="Ciudad">
                        <input type="hidden" name="sec_question_3" value="Lenguaje">
                        <input type="hidden" name="sec_answer_2" value="default">
                        <input type="hidden" name="sec_answer_3" value="default">
                        <button type="submit" class="btn btn-primary" style="width:100%;">Registrar Cuenta</button>
                    </form>
                </div>
            </main>
        <?php elseif ($action == 'login'): ?>
            <main class="hero">
                <div class="glass-card">
                    <div class="badge-status">Iniciar Sesión</div>
                    <form action="?view=login" method="POST">
                        <input type="hidden" name="action" value="login">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <div class="form-group"><label>Correo Electrónico</label><input type="text" name="login_id" class="form-control" required></div>
                        <div class="form-group"><label>Contraseña</label><input type="password" name="password" class="form-control" required></div>
                        <div class="form-group"><label>Pregunta de Seguridad 1</label><input type="text" name="sec_answer_1" class="form-control" required></div>
                        <button type="submit" class="btn btn-primary" style="width:100%;">Entrar</button>
                    </form>
                </div>
            </main>
        <?php elseif ($action == 'profile'): ?>
            <main class="hero">
                <div class="glass-card" style="max-width: 600px;">
                    <div class="badge-status">Panel de Control</div>
                    <h2>Bienvenido, <?php echo htmlspecialchars($logged_user['nombre'] ?? ''); ?></h2>
                    <p style="color: #9ca3af; margin-top: 1rem;">Tu sesión está activa y protegida con éxito.</p>
                    <a href="?view=logout" class="btn btn-outline" style="margin-top: 1.5rem; display:inline-block; color:#ef4444; border-color:#ef4444;">Cerrar Sesión</a>
                </div>
            </main>
        <?php endif; ?>

        <footer><p>&copy; 2026 CyberGuard Offensive. Hardening Avanzado.</p></footer>
    </div>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
    <script>
        const container = document.getElementById('canvas-container');
        const scene = new THREE.Scene();
        const camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
        const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true });
        renderer.setSize(window.innerWidth, window.innerHeight);
        container.appendChild(renderer.domElement);
        const geometry = new THREE.IcosahedronGeometry(2, 2);
        const material = new THREE.MeshBasicMaterial({ color: '#06b6d4', wireframe: true, transparent: true, opacity: 0.25 });
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
    </script>
</body>
</html>
