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

    // Inicializar tablas necesarias con campos de seguridad de Hash Avanzado y Activación de Capas
    $db->exec("CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nombre TEXT NOT NULL,
        apellido TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        single_use_hash TEXT DEFAULT '',
        hash_used INTEGER DEFAULT 0,
        hash_security_active INTEGER DEFAULT 1,
        profile_pic TEXT DEFAULT '',
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
$registered_hash_display = ''; // Variable para mostrar el hash solo al registrarse

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
        
        // Generar Hash criptográfico real de un solo uso
        $single_use_hash = bin2hex(random_bytes(32));

        try {
            $stmt = $db->prepare("INSERT INTO users (nombre, apellido, email, password, single_use_hash, hash_used, hash_security_active) VALUES (?, ?, ?, ?, ?, 0, 1)");
            $stmt->execute([$nombre, $apellido, $email, $password, $single_use_hash]);

            // Guardamos temporalmente el hash en sesión para mostrarlo al usuario justo después del registro
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
        $login_hash = trim($_POST['login_hash'] ?? '');

        $stmt = $db->prepare("SELECT * FROM users WHERE email = ?");
        $stmt->execute([$login_id]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && password_verify($password, $user['password'])) {
            
            // Verificar si la capa de seguridad de Hash está activada en la cuenta
            if ($user['hash_security_active'] == 1) {
                // El hash ingresado DEBE coincidir con el hash actual del usuario y NO haber sido usado
                if (empty($login_hash) || $login_hash !== $user['single_use_hash'] || $user['hash_used'] == 1) {
                    $message = "Acceso denegado: El Hash de seguridad único es inválido, ya fue consumido o no corresponde a esta cuenta.";
                    $message_type = "error";
                    $action = 'login';
                } else {
                    // Consumir/Invalidar el hash inmediatamente para que no sirva más (One-Time Use estricto)
                    $stmt_invalidate = $db->prepare("UPDATE users SET hash_used = 1 WHERE id = ?");
                    $stmt_invalidate->execute([$user['id']]);

                    // Regenerar ID de sesión para prevenir Session Fixation
                    session_regenerate_id(true);

                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['user_email'] = $user['email'];
                    $_SESSION['user_nombre'] = $user['nombre'];
                    
                    header("Location: ?view=profile");
                    exit;
                }
            } else {
                // Si la capa está desactivada, entra de forma normal
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
        // Recuperar cuenta UNICAMENTE mediante el Hash único de perfil
        $recovery_hash = trim($_POST['recovery_hash']);

        if (empty($recovery_hash)) {
            $message = "Por favor ingrese el Hash de seguridad de su perfil.";
            $message_type = "error";
            $action = 'recover';
        } else {
            // Buscamos estrictamente al usuario cuyo single_use_hash coincida y que NO esté marcado como usado
            $stmt = $db->prepare("SELECT * FROM users WHERE single_use_hash = ? AND hash_used = 0");
            $stmt->execute([$recovery_hash]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($user) {
                // Invalida inmediatamente el hash actual para que nadie más pueda volver a usarlo
                $stmt_burn = $db->prepare("UPDATE users SET hash_used = 1 WHERE id = ?");
                $stmt_burn->execute([$user['id']]);

                session_regenerate_id(true);
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['user_email'] = $user['email'];
                $_SESSION['user_nombre'] = $user['nombre'];

                header("Location: ?view=profile");
                exit;
            } else {
                $message = "El Hash ingresado es inválido, ya fue utilizado anteriormente o no pertenece a ningún perfil activo.";
                $message_type = "error";
                $action = 'recover';
            }
        }
    } elseif ($form_action === 'generate_new_hash') {
        if (!isset($_SESSION['user_id'])) {
            header("Location: ?view=login");
            exit;
        }
        $user_id = $_SESSION['user_id'];
        
        // Generar un nuevo hash y marcar hash_used = 0, invalidando cualquier token anterior automáticamente
        $nuevo_hash = bin2hex(random_bytes(32));
        $stmt = $db->prepare("UPDATE users SET single_use_hash = ?, hash_used = 0 WHERE id = ?");
        $stmt->execute([$nuevo_hash, $user_id]);

        $message = "Se ha generado un nuevo Hash de seguridad único. El anterior ha quedado totalmente invalidado.";
        $message_type = "success";
        $action = 'profile';
    } elseif ($form_action === 'toggle_hash_security') {
        if (!isset($_SESSION['user_id'])) {
            header("Location: ?view=login");
            exit;
        }
        $user_id = $_SESSION['user_id'];
        $current_state = intval($_POST['current_state']);
        $new_state = ($current_state == 1) ? 0 : 1;

        $stmt = $db->prepare("UPDATE users SET hash_security_active = ? WHERE id = ?");
        $stmt->execute([$new_state, $user_id]);

        $message = $new_state == 1 ? "Capa de seguridad de Hash activada exitosamente." : "Capa de seguridad de Hash desactivada.";
        $message_type = "success";
        $action = 'profile';
    } elseif ($form_action === 'update_profile') {
        // Prevención estricta de IDOR: Forzamos el ID a través de la sesión cifrada y validada, ignorando cualquier parámetro externo.
        if (!isset($_SESSION['user_id'])) {
            header("Location: ?view=login");
            exit;
        }
        $user_id = $_SESSION['user_id'];
        
        $new_nombre = trim($_POST['nombre']);
        $new_apellido = trim($_POST['apellido']);
        $new_password = $_POST['password'];
        
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
            $stmt = $db->prepare("UPDATE users SET nombre = ?, apellido = ?, password = ?, profile_pic = ? WHERE id = ?");
            $stmt->execute([$new_nombre, $new_apellido, $hashed_pass, $profile_pic_path, $user_id]);
        } else {
            $stmt = $db->prepare("UPDATE users SET nombre = ?, apellido = ?, profile_pic = ? WHERE id = ?");
            $stmt->execute([$new_nombre, $new_apellido, $profile_pic_path, $user_id]);
        }

        $_SESSION['user_nombre'] = $new_nombre;

        $message = "Perfil actualizado de forma segura.";
        $message_type = "success";
        $action = 'profile';
    }
}

// Obtener datos globales del usuario autenticado de forma segura
$logged_user = null;
if (isset($_SESSION['user_id'])) {
    $stmt_nav = $db->prepare("SELECT * FROM users WHERE id = ?");
    $stmt_nav->execute([$_SESSION['user_id']]);
    $logged_user = $stmt_nav->fetch(PDO::FETCH_ASSOC);
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberGuard Offensive | Seguridad & Hardening</title>
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&family=Inter:wght@300;400;600&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background-color: #030712; color: #f3f4f6; font-family: 'Inter', sans-serif; overflow-x: hidden; width: 100vw; min-height: 100vh; }
        #canvas-container { position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; z-index: 1; pointer-events: none; transition: transform 1.2s ease-in-out; }
        body.transitioning #canvas-container { transform: scale(1.1) rotate(180deg); filter: hue-rotate(45deg); }
        .ui-layer { position: relative; z-index: 2; width: 100%; min-height: 100vh; display: flex; flex-direction: column; justify-content: space-between; padding: 2rem 4rem; }
        header { display: flex; justify-content: space-between; align-items: center; width: 100%; max-width: 1200px; margin: 0 auto; }
        .logo { font-family: 'Orbitron', sans-serif; font-size: 1.5rem; font-weight: 700; color: #06b6d4; letter-spacing: 2px; text-shadow: 0 0 10px rgba(6, 182, 212, 0.4); text-decoration: none; }
        nav { display: flex; align-items: center; gap: 2rem; }
        nav a { color: #9ca3af; text-decoration: none; font-size: 0.9rem; transition: color 0.3s ease; cursor: pointer; }
        nav a:hover { color: #06b6d4; }
        .nav-avatar { width: 32px; height: 32px; border-radius: 50%; object-fit: cover; border: 1px solid #06b6d4; vertical-align: middle; margin-left: 0.5rem; }
        .hero, .content-section { max-width: 800px; margin: auto 0; padding: 3rem 0; }
        .badge-status { display: inline-block; background: rgba(6, 182, 212, 0.1); border: 1px solid rgba(6, 182, 212, 0.3); color: #06b6d4; padding: 0.4rem 1rem; border-radius: 50px; font-size: 0.8rem; font-family: 'Orbitron', sans-serif; margin-bottom: 1.5rem; text-transform: uppercase; letter-spacing: 1px; }
        h1 { font-family: 'Orbitron', sans-serif; font-size: 3rem; line-height: 1.1; margin-bottom: 1.5rem; color: #ffffff; }
        h1 span { color: #06b6d4; }
        p.subtitle, .content-section p { font-size: 1.05rem; color: #9ca3af; line-height: 1.6; margin-bottom: 2rem; max-width: 700px; }
        
        /* Contenedores con animación 3D sutil */
        .glass-card { background: rgba(15, 23, 42, 0.85); border: 1px solid rgba(6, 182, 212, 0.3); padding: 2.5rem; border-radius: 12px; backdrop-filter: blur(12px); box-shadow: 0 0 30px rgba(0, 0, 0, 0.7); max-width: 500px; transform-style: preserve-3d; transition: transform 0.3s ease, box-shadow 0.3s ease; }
        .glass-card:hover { transform: perspective(1000px) rotateX(2deg) rotateY(-2deg) translateZ(10px); box-shadow: 0 10px 40px rgba(6, 182, 212, 0.2); }
        
        .form-group { margin-bottom: 1.2rem; transform: translateZ(15px); }
        .form-group label { display: block; font-size: 0.85rem; color: #06b6d4; font-family: 'Orbitron', sans-serif; margin-bottom: 0.5rem; }
        .form-control { width: 100%; padding: 0.8rem 1rem; background: rgba(3, 7, 18, 0.9); border: 1px solid rgba(255, 255, 255, 0.15); border-radius: 6px; color: #fff; font-size: 0.95rem; }
        .form-control:focus { outline: none; border-color: #06b6d4; box-shadow: 0 0 10px rgba(6, 182, 212, 0.4); }
        .form-control:disabled { background: rgba(255,255,255,0.05); color: #6b7280; cursor: not-allowed; }
        .cta-group { display: flex; gap: 1rem; flex-wrap: wrap; }
        .btn { padding: 0.9rem 2rem; border-radius: 6px; font-weight: 600; text-decoration: none; transition: all 0.3s ease; cursor: pointer; font-size: 0.95rem; display: inline-block; text-align: center; }
        .btn-primary { background-color: #06b6d4; color: #030712; border: none; box-shadow: 0 0 20px rgba(6, 182, 212, 0.3); }
        .btn-primary:hover { background-color: #0891b2; box-shadow: 0 0 30px rgba(6, 182, 212, 0.6); }
        .btn-outline { background: transparent; color: #f3f4f6; border: 1px solid rgba(255, 255, 255, 0.2); }
        .btn-outline:hover { border-color: #06b6d4; color: #06b6d4; }
        .btn-danger { background: rgba(239, 68, 68, 0.2); border: 1px solid #ef4444; color: #fca5a5; }
        .btn-danger:hover { background: rgba(239, 68, 68, 0.4); }
        .btn-warning { background: rgba(234, 179, 8, 0.2); border: 1px solid #eab308; color: #fde047; }
        .btn-warning:hover { background: rgba(234, 179, 8, 0.4); }
        .link-sub { display: block; margin-top: 1rem; color: #9ca3af; font-size: 0.85rem; text-decoration: none; }
        .link-sub:hover { color: #06b6d4; }
        .hash-display { background: rgba(3, 7, 18, 0.95); border: 1px dashed #06b6d4; padding: 0.7rem; font-family: monospace; font-size: 0.8rem; color: #06b6d4; word-break: break-all; border-radius: 4px; margin-top: 0.3rem; }
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
                    <a href="?view=profile" class="transition-link" style="color: #06b6d4; font-weight: 600; display: flex; align-items: center;">
                        Mi Perfil Blindado
                        <?php if (!empty($logged_user['profile_pic']) && file_exists(__DIR__ . '/' . $logged_user['profile_pic'])): ?>
                            <img src="<?php echo htmlspecialchars($logged_user['profile_pic']); ?>" class="nav-avatar" alt="Avatar">
                        <?php endif; ?>
                    </a>
                    <a href="?view=logout" class="transition-link" style="color: #ef4444;">Salir</a>
                <?php else: ?>
                    <a href="?view=login" class="transition-link" style="color: #06b6d4; font-weight: 600;">Iniciar Sesión</a>
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
                <div class="badge-status">Sistema de Autenticación Criptográfica Avanzada con Hash</div>
                <h1>Arquitectura de Acceso <span>Blindado 3D</span></h1>
                <p class="subtitle">Plataforma protegida con tokens de un solo uso (OTP Hash estricto), capas de seguridad activables por cuenta, recuperación exclusiva por hash de perfil y efectos visuales interactivos en 3D.</p>
                <div class="cta-group">
                    <a href="?view=register" class="btn btn-primary transition-link">Crear Cuenta Segura</a>
                    <a href="?view=login" class="btn btn-outline transition-link">Acceder al Sistema</a>
                    <a href="?view=recover" class="btn btn-warning transition-link">Recuperar por Hash</a>
                </div>
            </main>

        <?php elseif ($action == 'register'): ?>
            <main class="hero">
                <div class="glass-card">
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
                        <button type="submit" class="btn btn-primary" style="width:100%; margin-top:1rem;">Registrar y Generar Hash Único</button>
                    </form>
                    <a href="?view=login" class="link-sub transition-link">¿Ya tienes cuenta? Inicia sesión</a>
                </div>
            </main>

        <?php elseif ($action == 'login'): ?>
            <main class="hero">
                <div class="glass-card">
                    <div class="badge-status">Autenticación de Acceso con Hash</div>
                    <h2 style="font-family:'Orbitron'; font-size:1.8rem; margin-bottom:1.5rem; color:#fff;">Iniciar Sesión</h2>
                    
                    <?php if (isset($_GET['registered'])): ?>
                        <div class="alert alert-success">
                            ¡Cuenta creada exitosamente! Tu Hash de registro único es:<br>
                            <div class="hash-display"><?php echo htmlspecialchars($_SESSION['temp_new_hash'] ?? ''); ?></div>
                            <span style="font-size: 0.8rem; display: block; margin-top: 5px;">Cópialo ahora. Al usarlo para ingresar quedará invalidado y podrás cambiarlo luego desde tu perfil.</span>
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
                            <label style="color: #eab308;">Hash de Seguridad Activo</label>
                            <input type="text" name="login_hash" class="form-control" placeholder="" autocomplete="off">
                        </div>
                        <button type="submit" class="btn btn-primary" style="width:100%; margin-top:1rem;">Entrar al Sistema</button>
                    </form>
                    <div style="display: flex; justify-content: space-between; margin-top: 1rem;">
                        <a href="?view=register" class="link-sub transition-link">Registrarse</a>
                        <a href="?view=recover" class="link-sub transition-link" style="color: #eab308;">¿Olvidaste tu acceso? Recuperar por Hash</a>
                    </div>
                </div>
            </main>

        <?php elseif ($action == 'recover'): ?>
            <main class="hero">
                <div class="glass-card" style="border-color: rgba(234, 179, 8, 0.4);">
                    <div class="badge-status" style="color: #eab308; background: rgba(234, 179, 8, 0.1); border-color: rgba(234, 179, 8, 0.3);">Recuperación Exclusiva por Hash</div>
                    <h2 style="font-family:'Orbitron'; font-size:1.8rem; margin-bottom:1.5rem; color:#fff;">Acceso mediante Hash</h2>
                    <p style="font-size: 0.9rem; color: #9ca3af; margin-bottom: 1.5rem;">Ingrese el Hash único correspondiente a su perfil. Al usarlo, se le otorgará acceso inmediato a su cuenta y el hash quedará invalidado permanentemente por seguridad.</p>
                    <form action="?view=recover" method="POST">
                        <input type="hidden" name="action" value="recover_hash">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <div class="form-group">
                            <label style="color: #eab308;">Hash de Perfil Activo</label>
                            <input type="text" name="recovery_hash" class="form-control" placeholder="" required autocomplete="off">
                        </div>
                        <button type="submit" class="btn btn-warning" style="width:100%; margin-top:1rem;">Validar Hash y Acceder</button>
                    </form>
                    <a href="?view=login" class="link-sub transition-link">Volver al login estándar</a>
                </div>
            </main>

        <?php elseif ($action == 'profile'): ?>
            <?php
            if (!isset($_SESSION['user_id'])) {
                header("Location: ?view=login");
                exit;
            }
            $stmt = $db->prepare("SELECT * FROM users WHERE id = ?");
            $stmt->execute([$_SESSION['user_id']]);
            $current_user = $stmt->fetch(PDO::FETCH_ASSOC);

            // Mostrar el hash actual del usuario si existe
            $active_hash = $current_user['single_use_hash'];
            if (empty($active_hash)) {
                $active_hash = "No hay hash generado actualmente.";
            }
            ?>
            <main class="content-section" style="max-width: 950px; width: 100%;">
                <div class="badge-status">Panel de Perfil con Movimiento 3D</div>
                <h1 style="font-size: 2.2rem;">Gestión de <span>Perfil Avanzado</span></h1>
                
                <div style="display: grid; grid-template-columns: 1fr 2fr; gap: 2rem; align-items: start;">
                    <!-- Tarjeta Visual de Perfil en 3D -->
                    <div class="glass-card" style="text-align: center; max-width: 100%;">
                        <div style="width: 120px; height: 120px; border-radius: 50%; background: #06b6d4; margin: 0 auto 1rem; display: flex; align-items: center; justify-content: center; font-size: 2.5rem; color: #030712; font-family: 'Orbitron'; font-weight: bold; overflow: hidden; border: 3px solid #06b6d4; box-shadow: 0 0 15px rgba(6,182,212,0.5);">
                            <?php if (!empty($current_user['profile_pic']) && file_exists(__DIR__ . '/' . $current_user['profile_pic'])): ?>
                                <img src="<?php echo htmlspecialchars($current_user['profile_pic']); ?>" alt="Foto de perfil" style="width: 100%; height: 100%; object-fit: cover;">
                            <?php else: ?>
                                <?php echo strtoupper(substr($current_user['nombre'], 0, 1) . substr($current_user['apellido'], 0, 1)); ?>
                            <?php endif; ?>
                        </div>
                        <h3 style="color: #fff; font-size: 1.3rem; margin-bottom: 0.3rem; font-family: 'Orbitron';"><?php echo htmlspecialchars($current_user['nombre'] . ' ' . $current_user['apellido']); ?></h3>
                        <p style="font-size: 0.85rem; color: #06b6d4; margin-bottom: 1rem;"><?php echo htmlspecialchars($current_user['email']); ?></p>
                        
                        <!-- Panel de Control de Capas de Seguridad y Hash -->
                        <div style="text-align: left; margin-bottom: 1.5rem; background: rgba(3,7,18,0.5); padding: 10px; border-radius: 6px;">
                            <label style="font-size: 0.75rem; color: #06b6d4; font-family: 'Orbitron';">Hash de Seguridad Único:</label>
                            <div class="hash-display"><?php echo htmlspecialchars($active_hash); ?></div>
                            <p style="font-size: 0.7rem; color: #9ca3af; margin-top: 5px;">Estado: <?php echo $current_user['hash_used'] == 1 ? '<span style="color:#ef4444;">Consumido / Invalidado</span>' : '<span style="color:#10b981;">Activo y Válido</span>'; ?></p>
                        </div>

                        <!-- Botón para generar nuevo Hash -->
                        <form action="?view=profile" method="POST" style="margin-bottom: 0.8rem;">
                            <input type="hidden" name="action" value="generate_new_hash">
                            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                            <button type="submit" class="btn btn-warning" style="width: 100%; padding: 0.5rem; font-size: 0.8rem;">Generar Nuevo Hash (Invalidar Antiguo)</button>
                        </form>

                        <!-- Botón para activar/desactivar capa de seguridad de Hash -->
                        <form action="?view=profile" method="POST" style="margin-bottom: 1rem;">
                            <input type="hidden" name="action" value="toggle_hash_security">
                            <input type="hidden" name="current_state" value="<?php echo $current_user['hash_security_active']; ?>">
                            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                            <button type="submit" class="btn btn-outline" style="width: 100%; padding: 0.5rem; font-size: 0.8rem; border-color: <?php echo $current_user['hash_security_active'] == 1 ? '#10b981' : '#ef4444'; ?>;">
                                Capa Hash Login: <?php echo $current_user['hash_security_active'] == 1 ? 'ACTIVADA (ON)' : 'DESACTIVADA (OFF)'; ?>
                            </button>
                        </form>

                        <a href="?view=logout" class="btn btn-danger" style="width: 100%; padding: 0.6rem; font-size: 0.85rem;">Cerrar Sesión</a>
                    </div>

                    <!-- Formulario de Actualización en 3D -->
                    <div class="glass-card" style="max-width: 100%;">
                        <h3 style="font-family:'Orbitron'; font-size: 1.2rem; margin-bottom: 1rem; color: #fff;">Actualizar Datos Personales</h3>
                        <form action="?view=profile" method="POST" enctype="multipart/form-data">
                            <input type="hidden" name="action" value="update_profile">
                            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
                                <div class="form-group">
                                    <label>Nombre</label>
                                    <input type="text" name="nombre" class="form-control" value="<?php echo htmlspecialchars($current_user['nombre']); ?>" required autocomplete="off">
                                </div>
                                <div class="form-group">
                                    <label>Apellido</label>
                                    <input type="text" name="apellido" class="form-control" value="<?php echo htmlspecialchars($current_user['apellido']); ?>" required autocomplete="off">
                                </div>
                            </div>
                            <div class="form-group">
                                <label>Nueva Contraseña (Dejar en blanco para no cambiar)</label>
                                <input type="password" name="password" class="form-control" autocomplete="new-password">
                            </div>
                            <div class="form-group">
                                <label>Foto de Perfil (JPG, PNG, WEBP)</label>
                                <input type="file" name="profile_pic" class="form-control" accept="image/*">
                            </div>
                            <button type="submit" class="btn btn-primary" style="width: 100%; margin-top: 1rem;">Guardar Cambios</button>
                        </form>
                    </div>
                </div>
            </main>
        <?php endif; ?>

        <footer>
            <p>&copy; 2026 CyberGuard Offensive Systems. Todos los derechos reservados.</p>
        </footer>
    </div>

    <!-- Three.js Background Animation Script -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
    <script>
        const container = document.getElementById('canvas-container');
        const scene = new THREE.Scene();
        const camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
        const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true });
        
        renderer.setSize(window.innerWidth, window.innerHeight);
        container.appendChild(renderer.domElement);

        // Geometría de partículas de seguridad cibernética
        const particleCount = 700;
        const geometry = new THREE.BufferGeometry();
        const positions = new Float32Array(particleCount * 3);

        for (let i = 0; i < particleCount * 3; i++) {
            positions[i] = (Math.random() - 0.5) * 20;
        }

        geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));

        const material = new THREE.PointsMaterial({
            color: 0x06b6d4,
            size: 0.05,
            transparent: true,
            opacity: 0.7
        });

        const particles = new THREE.Points(geometry, material);
        scene.add(particles);

        camera.position.z = 5;

        // Animación fluida
        function animate() {
            requestAnimationFrame(animate);
            particles.rotation.x += 0.0005;
            particles.rotation.y += 0.001;
            renderer.render(scene, camera);
        }
        animate();

        window.addEventListener('resize', () => {
            camera.aspect = window.innerWidth / window.innerHeight;
            camera.updateProjectionMatrix();
            renderer.setSize(window.innerWidth, window.innerHeight);
        });

        // Efecto visual de transición en enlaces
        document.querySelectorAll('.transition-link').forEach(link => {
            link.addEventListener('click', function(e) {
                const href = this.getAttribute('href');
                if(href && href.startsWith('?')) {
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
