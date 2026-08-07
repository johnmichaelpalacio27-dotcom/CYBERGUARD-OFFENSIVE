<?php
// --- CONFIGURACIÓN DE SESIÓN Y SEGURIDAD ROBUSTA (HTTPOnly, Secure, Strict Mode) ---
if (session_status() === PHP_SESSION_NONE) {
    ini_set('session.cookie_httponly', 1);
    ini_set('session.cookie_secure', 0); // Cambiar a 1 si usas HTTPS real
    ini_set('session.use_strict_mode', 1);
    ini_set('session.cookie_samesite', 'Strict');
    session_start();
}

// Cabeceras de seguridad HTTP
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Content-Security-Policy: default-src 'self' https://cdnjs.cloudflare.com https://fonts.googleapis.com https://fonts.gstatic.com 'unsafe-inline' 'unsafe-eval'");

// Generar Token CSRF por sesión si no existe
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Base de datos SQLite local para persistencia segura
$db_file = __DIR__ . '/cyberguard_secure.db';
try {
    $db = new PDO('sqlite:' . $db_file);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // Inicializar tablas necesarias con campos actualizados para Hash, Preguntas de Seguridad y Personalización
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
        sec_question_1 TEXT DEFAULT '',
        sec_answer_1 TEXT DEFAULT '',
        sec_question_2 TEXT DEFAULT '',
        sec_answer_2 TEXT DEFAULT '',
        role TEXT DEFAULT 'analyst',
        status TEXT DEFAULT 'active',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");
} catch (Exception $e) {
    die("Error de conexión a la base de datos de alta seguridad.");
}

$message = '';
$message_type = '';
$action = isset($_GET['view']) ? $_GET['view'] : 'home';

// --- PROCESAMIENTO DE ACCIONES BACKEND & PROTECCIÓN IDOR/CSRF ---
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $form_action = isset($_POST['action']) ? $_POST['action'] : '';

    // Validación CSRF global para peticiones POST
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die("Error de validación de seguridad (CSRF Token inválido).");
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

        try {
            $stmt = $db->prepare("INSERT INTO users (nombre, apellido, email, password, single_use_hash, hash_type, hash_used, hash_security_active, sec_question_1, sec_answer_1, sec_question_2, sec_answer_2) VALUES (?, ?, ?, ?, ?, ?, 0, 1, ?, ?, ?, ?)");
            $stmt->execute([$nombre, $apellido, $email, $password, $single_use_hash, $hash_type, $sec_q1, $sec_a1, $sec_q2, $sec_a2]);

            $_SESSION['temp_new_hash'] = $single_use_hash;

            header("Location: ?view=login&registered=1");
            exit;
        } catch (Exception $e) {
            $message = "El correo electrónico ya se encuentra registrado en el sistema.";
            $message_type = "error";
            $action = 'register';
        }
     
    } elseif ($form_action === 'login') {
        $login_id = trim($_POST['login_id']);
        $password = $_POST['password'];
        $answer_1 = trim($_POST['sec_answer_1'] ?? '');

        $stmt = $db->prepare("SELECT * FROM users WHERE email = ?");
        $stmt->execute([$login_id]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && password_verify($password, $user['password'])) {
            // Validar pregunta de seguridad 1 obligatoria
            if (!empty($user['sec_answer_1']) && !password_verify($answer_1, $user['sec_answer_1'])) {
                $message = "Acceso denegado: La respuesta a la pregunta de seguridad es incorrecta.";
                $message_type = "error";
                $action = 'login';
            } else {
                session_regenerate_id(true);
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['user_email'] = $user['email'];
                $_SESSION['user_nombre'] = $user['nombre'];
                
                header("Location: ?view=profile");
                exit;
            }
        } else {
            $message = "Credenciales de acceso incorrectas.";
            $message_type = "error";
            $action = 'login';
        }
    } elseif ($form_action === 'recover_hash') {
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
                // Guardamos temporalmente el ID en sesión para el cambio obligatorio de contraseña por recuperación
                $_SESSION['recovery_user_id'] = $user['id'];
                header("Location: ?view=reset_password");
                exit;
            } else {
                $message = "El Hash ingresado es inválido o no pertenece a ningún perfil activo.";
                $message_type = "error";
                $action = 'recover';
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
            
            // Generar nuevo hash automáticamente por seguridad y actualizar contraseña
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
        
        $new_nombre = trim($_POST['nombre']);
        $new_apellido = trim($_POST['apellido']);
        $new_password = $_POST['password'];
        $theme_color = trim($_POST['theme_color'] ?? '#06b6d4');
        $q1 = trim($_POST['sec_question_1']);
        $a1 = trim($_POST['sec_answer_1']);
        $q2 = trim($_POST['sec_question_2']);
        $a2 = trim($_POST['sec_answer_2']);
        
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

        // Construir consulta dinámica para actualizar preguntas si se suministran
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

        if (!empty($new_password)) {
            $hashed_pass = password_hash($new_password, PASSWORD_BCRYPT);
            $sql = "UPDATE users SET nombre = ?, apellido = ?, password = ?, profile_pic = ?, theme_color = ?" . $q_update_extras . " WHERE id = ?";
            $params = array_merge([$new_nombre, $new_apellido, $hashed_pass, $profile_pic_path, $theme_color], $params_extras, [$user_id]);
            $stmt = $db->prepare($sql);
            $stmt->execute($params);
        } else {
            $sql = "UPDATE users SET nombre = ?, apellido = ?, profile_pic = ?, theme_color = ?" . $q_update_extras . " WHERE id = ?";
            $params = array_merge([$new_nombre, $new_apellido, $profile_pic_path, $theme_color], $params_extras, [$user_id]);
            $stmt = $db->prepare($sql);
            $stmt->execute($params);
        }

        $_SESSION['user_nombre'] = $new_nombre;

        $message = "Perfil y configuración actualizados de forma segura.";
        $message_type = "success";
        $action = 'profile';
    }
}

// Manejo explícito de Cierre de Sesión (Logout) redirigiendo a inicio
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
        nav { display: flex; align-items: center; gap: 2rem; }
        nav a { color: #9ca3af; text-decoration: none; font-size: 0.9rem; transition: color 0.3s ease; cursor: pointer; }
        nav a:hover { color: var(--theme-color); }
        .nav-avatar { width: 32px; height: 32px; border-radius: 50%; object-fit: cover; border: 1px solid var(--theme-color); vertical-align: middle; margin-left: 0.5rem; }
        .hero, .content-section { max-width: 800px; margin: auto 0; padding: 3rem 0; }
        .badge-status { display: inline-block; background: rgba(6, 182, 212, 0.1); border: 1px solid rgba(6, 182, 212, 0.3); color: var(--theme-color); padding: 0.4rem 1rem; border-radius: 50px; font-size: 0.8rem; font-family: 'Orbitron', sans-serif; margin-bottom: 1.5rem; text-transform: uppercase; letter-spacing: 1px; }
        h1 { font-family: 'Orbitron', sans-serif; font-size: 3rem; line-height: 1.1; margin-bottom: 1.5rem; color: #ffffff; }
        h1 span { color: var(--theme-color); }
        p.subtitle, .content-section p { font-size: 1.05rem; color: #9ca3af; line-height: 1.6; margin-bottom: 2rem; max-width: 700px; }
        
        .glass-card { background: rgba(15, 23, 42, 0.85); border: 1px solid rgba(6, 182, 212, 0.3); padding: 2.5rem; border-radius: 12px; backdrop-filter: blur(12px); box-shadow: 0 0 30px rgba(0, 0, 0, 0.7); max-width: 500px; transform-style: preserve-3d; transition: transform 0.3s ease, box-shadow 0.3s ease; }
        .glass-card:hover { transform: perspective(1000px) rotateX(2deg) rotateY(-2deg) translateZ(10px); box-shadow: 0 10px 40px rgba(6, 182, 212, 0.2); }
        
        .form-group { margin-bottom: 1.2rem; transform: translateZ(15px); }
        .form-group label { display: block; font-size: 0.85rem; color: var(--theme-color); font-family: 'Orbitron', sans-serif; margin-bottom: 0.5rem; }
        .form-control { width: 100%; padding: 0.8rem 1rem; background: rgba(3, 7, 18, 0.9); border: 1px solid rgba(255, 255, 255, 0.15); border-radius: 6px; color: #fff; font-size: 0.95rem; }
        .form-control:focus { outline: none; border-color: var(--theme-color); box-shadow: 0 0 10px rgba(6, 182, 212, 0.4); }
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
                <div class="badge-status">Sistema de Autenticación Criptográfica Avanzada</div>
                <h1>Arquitectura de Acceso <span>Blindado 3D</span></h1>
                <p class="subtitle">Plataforma protegida con tokens criptográficos de perfil, preguntas de seguridad avanzadas y panel de personalización cromática dinámica en 3D.</p>
                <div class="cta-group">
                    <a href="?view=register" class="btn btn-primary transition-link">Crear Cuenta Segura</a>
                    <a href="?view=login" class="btn btn-outline transition-link">Acceder al Sistema</a>
                    <a href="?view=recover" class="btn btn-warning transition-link">Recuperar por Hash</a>
                </div>
            </main>

        <?php elseif ($action == 'about'): ?>
            <main class="content-section" style="max-width: 800px; width: 100%;">
                <div class="badge-status">Acerca de CyberGuard Offensive</div>
                <h1>Ingeniería en <span>Ciberseguridad y Hardening</span></h1>
                <p class="subtitle">CyberGuard Offensive es una plataforma de vanguardia diseñada para la gestión segura de accesos, análisis de vulnerabilidades y protección de datos con múltiples capas criptográficas.</p>
            </main>

        <?php elseif ($action == 'register'): ?>
            <main class="hero">
                <div class="glass-card" style="max-width: 600px;">
                    <div class="badge-status">Registro de Credenciales</div>
                    <h2 style="font-family:'Orbitron'; font-size:1.8rem; margin-bottom:1.5rem; color:#fff;">Nuevo Registro</h2>
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
                        <h4 style="font-family:'Orbitron'; font-size: 1rem; color: var(--theme-color); margin-bottom: 1rem;">Preguntas de Seguridad</h4>
                        <div class="form-group">
                            <label>Pregunta 1: ¿Cuál es el nombre de tu primera mascota?</label>
                            <input type="text" name="sec_question_1" value="¿Cuál es el nombre de tu primera mascota?" class="form-control" readonly>
                            <input type="text" name="sec_answer_1" class="form-control" placeholder="Tu respuesta secreta" required style="margin-top: 5px;">
                        </div>
                        <div class="form-group">
                            <label>Pregunta 2: ¿En qué ciudad naciste?</label>
                            <input type="text" name="sec_question_2" value="¿En qué ciudad naciste?" class="form-control" readonly>
                            <input type="text" name="sec_answer_2" class="form-control" placeholder="Tu respuesta secreta" required style="margin-top: 5px;">
                        </div>
                        <button type="submit" class="btn btn-primary" style="width:100%; margin-top:1rem;">Registrar Cuenta y Generar Hash</button>
                    </form>
                    <a href="?view=login" class="link-sub transition-link">¿Ya tienes cuenta? Inicia sesión</a>
                </div>
            </main>

        <?php elseif ($action == 'login'): ?>
            <main class="hero">
                <div class="glass-card">
                    <div class="badge-status">Autenticación de Acceso</div>
                    <h2 style="font-family:'Orbitron'; font-size:1.8rem; margin-bottom:1.5rem; color:#fff;">Iniciar Sesión</h2>
                    
                    <?php if (isset($_GET['registered'])): ?>
                        <div class="alert alert-success">
                            ¡Cuenta creada exitosamente! Tu Hash de perfil único es:<br>
                            <div class="hash-display"><?php echo htmlspecialchars($_SESSION['temp_new_hash'] ?? ''); ?></div>
                            <span style="font-size: 0.8rem; display: block; margin-top: 5px;">Guárdalo en un lugar seguro. Solo te servirá para recuperar el acceso a tu cuenta si olvidas tus credenciales.</span>
                        </div>
                    <?php endif; ?>

                    <form action="?view=login" method="POST">
                        <input type="hidden" name="action" value="login">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <div class="form-group">
                            <label>Correo Electrónico</label>
                            <input type="text" name="login_id" class="form-control" required autocomplete="off">
                        </div>
                        <div class="form-group">
                            <label>Contraseña</label>
                            <input type="password" name="password" class="form-control" required autocomplete="current-password">
                        </div>
                        <div class="form-group">
                            <label style="color: #eab308;">Pregunta de Seguridad 1: ¿Cuál es el nombre de tu primera mascota?</label>
                            <input type="text" name="sec_answer_1" class="form-control" placeholder="Respuesta secreta" required autocomplete="off">
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
                    <div class="badge-status" style="color: #eab308; background: rgba(234, 179, 8, 0.1); border-color: rgba(234, 179, 8, 0.3);">Recuperación Exclusiva por Hash</div>
                    <h2 style="font-family:'Orbitron'; font-size:1.8rem; margin-bottom:1.5rem; color:#fff;">Restablecer con Hash</h2>
                    <p style="font-size: 0.9rem; color: #9ca3af; margin-bottom: 1.5rem;">Ingrese el Hash único correspondiente a su perfil para validar su identidad y asignar una nueva contraseña.</p>
                    <form action="?view=recover" method="POST">
                        <input type="hidden" name="action" value="recover_hash">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <div class="form-group">
                            <label style="color: #eab308;">Hash de Perfil Activo</label>
                            <input type="text" name="recovery_hash" class="form-control" placeholder="" required autocomplete="off">
                        </div>
                        <button type="submit" class="btn btn-warning" style="width:100%; margin-top:1rem;">Validar Hash de Perfil</button>
                    </form>
                    <a href="?view=login" class="link-sub transition-link">Volver al login estándar</a>
                </div>
            </main>

        <?php elseif ($action == 'reset_password'): ?>
            <main class="hero">
                <div class="glass-card" style="border-color: rgba(16, 185, 129, 0.4);">
                    <div class="badge-status" style="color: #10b981; background: rgba(16, 185, 129, 0.1); border-color: rgba(16, 185, 129, 0.3);">Seguridad Verificada</div>
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
            ?>
            <main class="content-section" style="max-width: 950px; width: 100%;">
                <div class="badge-status">Panel de Perfil Avanzado</div>
                <h1 style="font-size: 2.2rem;">Gestión de <span>Perfil y Seguridad</span></h1>
                
                <div style="display: grid; grid-template-columns: 1fr 2fr; gap: 2rem; align-items: start;">
                    <div class="glass-card" style="text-align: center; max-width: 100%;">
                        <div style="width: 120px; height: 120px; border-radius: 50%; background: var(--theme-color); margin: 0 auto 1rem; display: flex; align-items: center; justify-content: center; font-size: 2.5rem; color: #030712; font-family: 'Orbitron'; font-weight: bold; overflow: hidden; border: 3px solid var(--theme-color); box-shadow: 0 0 15px rgba(6,182,212,0.5);">
                            <?php if (!empty($current_user['profile_pic']) && file_exists(__DIR__ . '/' . $current_user['profile_pic'])): ?>
                                <img src="<?php echo htmlspecialchars($current_user['profile_pic']); ?>" alt="Avatar" style="width: 100%; height: 100%; object-fit: cover;">
                            <?php else: ?>
                                <?php echo strtoupper(substr($current_user['nombre'], 0, 1) . substr($current_user['apellido'], 0, 1)); ?>
                            <?php endif; ?>
                        </div>
                        <h3 style="color: #fff; font-size: 1.3rem; margin-bottom: 0.3rem; font-family: 'Orbitron';"><?php echo htmlspecialchars($current_user['nombre'] . ' ' . $current_user['apellido']); ?></h3>
                        <p style="font-size: 0.85rem; color: var(--theme-color); margin-bottom: 1rem;"><?php echo htmlspecialchars($current_user['email']); ?></p>
                        
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
                            <button type="submit" class="btn btn-warning" style="width: 100%; padding: 0.5rem; font-size: 0.8rem;">Generar Nuevo Hash de Perfil</button>
                        </form>
                    </div>

                    <!-- Formulario de Actualización de Datos y Preguntas de Seguridad -->
                    <div class="glass-card" style="max-width: 100%;">
                        <h3 style="font-family: 'Orbitron'; color: var(--theme-color); margin-bottom: 1.5rem;">Editar Perfil y Seguridad</h3>
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
                                <label>Color de Tema Visual</label>
                                <select name="theme_color" class="form-control">
                                    <option value="#06b6d4" <?php echo $active_theme_color === '#06b6d4' ? 'selected' : ''; ?>>Cian Cyber (Por defecto)</option>
                                    <option value="#10b981" <?php echo $active_theme_color === '#10b981' ? 'selected' : ''; ?>>Verde Matrix</option>
                                    <option value="#8b5cf6" <?php echo $active_theme_color === '#8b5cf6' ? 'selected' : ''; ?>>Púrpura Hacker</option>
                                    <option value="#f59e0b" <?php echo $active_theme_color === '#f59e0b' ? 'selected' : ''; ?>>Ámbar Táctico</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label>Foto de Perfil</label>
                                <input type="file" name="profile_pic" class="form-control" accept="image/png, image/jpeg, image/webp">
                            </div>
                            <hr style="border: 0; border-top: 1px solid rgba(255,255,255,0.1); margin: 1.5rem 0;">
                            <h4 style="font-family:'Orbitron'; font-size: 0.95rem; color: var(--theme-color); margin-bottom: 1rem;">Actualizar Preguntas de Seguridad</h4>
                            <div class="form-group">
                                <label>Pregunta 1: ¿Cuál es el nombre de tu primera mascota?</label>
                                <input type="text" name="sec_question_1" value="¿Cuál es el nombre de tu primera mascota?" class="form-control" readonly>
                                <input type="text" name="sec_answer_1" class="form-control" placeholder="Nueva respuesta (dejar en blanco para no cambiar)" style="margin-top: 5px;">
                            </div>
                            <button type="submit" class="btn btn-primary" style="width: 100%; margin-top: 1rem;">Guardar Cambios de Perfil</button>
                        </form>
                    </div>
                </div>
            </main>
        <?php endif; ?>

        <footer>
            <p>&copy; 2026 CyberGuard Offensive. Arquitectura Criptográfica y Hardening Avanzado.</p>
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

        // Efecto de transición suave al navegar
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
