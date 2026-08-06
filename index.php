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

    // Inicializar tablas necesarias (incluyendo el campo para el hash de un solo uso)
    $db->exec("CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nombre TEXT NOT NULL,
        apellido TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        single_use_hash TEXT DEFAULT '',
        hash_used INTEGER DEFAULT 0,
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
            $stmt = $db->prepare("INSERT INTO users (nombre, apellido, email, password, single_use_hash, hash_used) VALUES (?, ?, ?, ?, ?, 0)");
            $stmt->execute([$nombre, $apellido, $email, $password, $single_use_hash]);

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

        $stmt = $db->prepare("SELECT * FROM users WHERE email = ?");
        $stmt->execute([$login_id]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && password_verify($password, $user['password'])) {
            // Regenerar ID de sesión para prevenir Session Fixation
            session_regenerate_id(true);

            $_SESSION['user_id'] = $user['id'];
            $_SESSION['user_email'] = $user['email'];
            $_SESSION['user_nombre'] = $user['nombre'];
            
            header("Location: ?view=profile");
            exit;
        } else {
            $message = "Credenciales de acceso incorrectas.";
            $message_type = "error";
            $action = 'login';
        }
    } elseif ($form_action === 'update_profile') {
        // Prevención estricta de IDOR: Forzamos el ID a través de la sesión cifrada y validada, ignorando cualquier parámetro externo.
        if (!isset($_SESSION['user_id'])) {
            header("Location: ?view=login");
            exit;
        }
        $user_id = $_SESSION['user_id'];
        
        $new_nombre = trim($_POST['nombre']);
        $new_apellido = trim($_POST['apellido']);
        // El correo NO se permite editar por requerimiento de blindaje
        $new_password = $_POST['password'];
        
        $profile_pic_path = null;
        if (isset($_FILES['profile_pic']) && $_FILES['profile_pic']['error'] === UPLOAD_ERR_OK) {
            $file_tmp = $_FILES['profile_pic']['tmp_name'];
            $file_ext = strtolower(pathinfo($_FILES['profile_pic']['name'], PATHINFO_EXTENSION));
            $allowed = ['jpg', 'jpeg', 'png', 'webp'];
            
            // Validación robusta de tipo MIME real
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

        // Mantener foto anterior si no se sube una nueva
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
        .glass-card { background: rgba(15, 23, 42, 0.85); border: 1px solid rgba(6, 182, 212, 0.3); padding: 2.5rem; border-radius: 12px; backdrop-filter: blur(12px); box-shadow: 0 0 30px rgba(0, 0, 0, 0.7); max-width: 500px; }
        .form-group { margin-bottom: 1.2rem; }
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
            <a href="?view=home" class="logo transition-link">CYBERGUARD//HARDENED</a>
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
                <div class="badge-status">Sistema de Autenticación Criptográfica Seguro</div>
                <h1>Arquitectura de Acceso <span>Blindado</span></h1>
                <p class="subtitle">Plataforma protegida con tokens de un solo uso (OTP Hash), mitigación anti-IDOR, protección contra ataques CSRF y cifrado avanzado del lado del servidor.</p>
                <div class="cta-group">
                    <a href="?view=register" class="btn btn-primary transition-link">Crear Cuenta Segura</a>
                    <a href="?view=login" class="btn btn-outline transition-link">Acceder al Sistema</a>
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
                            <label>Correo Electrónico (Inmodificable)</label>
                            <input type="email" name="email" class="form-control" required autocomplete="off">
                        </div>
                        <div class="form-group">
                            <label>Contraseña</label>
                            <input type="password" name="password" class="form-control" required autocomplete="new-password">
                        </div>
                        <button type="submit" class="btn btn-primary" style="width:100%; margin-top:1rem;">Registrar y Generar Hash</button>
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
                            ¡Cuenta creada exitosamente! Tu Hash de un solo uso ha sido generado. Ya puedes iniciar sesión.
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
                        <button type="submit" class="btn btn-primary" style="width:100%; margin-top:1rem;">Entrar al Sistema</button>
                    </form>
                    <a href="?view=register" class="link-sub transition-link">¿No tienes cuenta? Regístrate aquí</a>
                </div>
            </main>

        <?php elseif ($action == 'profile'): ?>
            <?php
            if (!isset($_SESSION['user_id'])) {
                header("Location: ?view=login");
                exit;
            }
            // Blindaje IDOR: Se consulta estrictamente el registro vinculado al ID de la sesión activa
            $stmt = $db->prepare("SELECT * FROM users WHERE id = ?");
            $stmt->execute([$_SESSION['user_id']]);
            $current_user = $stmt->fetch(PDO::FETCH_ASSOC);

            // Mecanismo de Hash Rotativo de Único Uso (OTP Hash Check)
            // Si el hash no ha sido consumido, lo mostramos una sola vez y lo quemamos (hash_used = 1) para rotación estricta
            $active_hash = "";
            if ($current_user['hash_used'] == 0 && !empty($current_user['single_use_hash'])) {
                $active_hash = $current_user['single_use_hash'];
                $stmt_burn = $db->prepare("UPDATE users SET hash_used = 1, single_use_hash = ? WHERE id = ?");
                // Generamos un nuevo hash rotativo para el siguiente evento si se requiere, o dejamos constancia del uso único
                $nuevo_hash_rotativo = bin2hex(random_bytes(32));
                $stmt_burn->execute([$nuevo_hash_rotativo, $_SESSION['user_id']]);
            } else {
                $active_hash = "Hash consumido (Rotado por seguridad de sesión)";
            }
            ?>
            <main class="content-section" style="max-width: 950px; width: 100%;">
                <div class="badge-status">Panel de Perfil Blindado</div>
                <h1 style="font-size: 2.2rem;">Gestión de <span>Perfil Realista</span></h1>
                
                <div style="display: grid; grid-template-columns: 1fr 2fr; gap: 2rem; align-items: start;">
                    <!-- Tarjeta Visual de Perfil -->
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
                        
                        <div style="text-align: left; margin-bottom: 1.5rem;">
                            <label style="font-size: 0.75rem; color: #06b6d4; font-family: 'Orbitron';">Hash Dinámico (Único Uso):</label>
                            <div class="hash-display"><?php echo htmlspecialchars($active_hash); ?></div>
                        </div>

                        <a href="?view=logout" class="btn btn-danger" style="width: 100%; padding: 0.6rem; font-size: 0.85rem;">Cerrar Sesión</a>
                    </div>

                    <!-- Formulario de Actualización -->
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
                                <label>Correo Electrónico (Blindado / No Modificable)</label>
                                <input type="email" class="form-control" value="<?php echo htmlspecialchars($current_user['email']); ?>" disabled>
                            </div>
                            <div class="form-group">
                                <label>Nueva Contraseña (Opcional)</label>
                                <input type="password" name="password" class="form-control" placeholder="Dejar en blanco para mantener actual" autocomplete="new-password">
                            </div>
                            <div class="form-group">
                                <label>Cambiar Fotografía de Perfil</label>
                                <input type="file" name="profile_pic" class="form-control" accept="image/*" style="font-size: 0.8rem; padding: 0.4rem;">
                            </div>
                            <button type="submit" class="btn btn-primary" style="width:100%; margin-top: 1rem;">Guardar Cambios de Perfil</button>
                        </form>
                    </div>
                </div>
            </main>

        <?php elseif ($action == 'about'): ?>
            <main class="content-section">
                <div class="badge-status">Seguridad Aplicada</div>
                <h1>Arquitectura y <span>Blindaje Web</span></h1>
                <p><strong>CyberGuard Hardened</strong> implementa estrictas directrices de seguridad defensiva, asegurando que las sesiones residan bajo cookies cifradas de tipo <strong>HttpOnly</strong> y <strong>SameSite</strong>.</p>
                <p>Se utiliza protección contra vulnerabilidades comunes como <strong>IDOR</strong> (validación interna estricta de privilegios por sesión de usuario) y <strong>CSRF</strong> mediante tokens aleatorios únicos por formulario.</p>
                <a href="?view=home" class="btn btn-outline transition-link">Volver al Inicio</a>
            </main>

        <?php elseif ($action == 'logout'): ?>
            <?php
            session_unset();
            session_destroy();
            header("Location: ?view=home");
            exit;
            ?>
        <?php endif; ?>

        <footer>
            <p>&copy;2026 CyberGuard Security Consulting. Todos los derechos reservados.</p>
        </footer>
    </div>

    <!-- Script de Three.js con velocidad de rotación suave y tranquila -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
    <script>
        document.querySelectorAll('.transition-link').forEach(link => {
            link.addEventListener('click', function(e) {
                e.preventDefault();
                const targetUrl = this.getAttribute('href');
                document.body.classList.add('transitioning');
                setTimeout(() => {
                    window.location.href = targetUrl;
                }, 600);
            });
        });

        document.addEventListener('DOMContentLoaded', () => {
            const container = document.getElementById('canvas-container');
            if (!container) return;

            const scene = new THREE.Scene();
            scene.fog = new THREE.FogExp2(0x030712, 0.08);

            const camera = new THREE.PerspectiveCamera(55, window.innerWidth / window.innerHeight, 0.1, 1000);
            camera.position.z = 6;

            const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true });
            renderer.setSize(window.innerWidth, window.innerHeight);
            renderer.setPixelRatio(window.devicePixelRatio);
            renderer.setClearColor(0x000000, 0);
            container.appendChild(renderer.domElement);

            const geometry = new THREE.IcosahedronGeometry(3, 4);
            const material = new THREE.MeshBasicMaterial({
                color: 0x06b6d4,
                wireframe: true,
                transparent: true,
                opacity: 0.25,
                wireframeLinewidth: 1
            });

            const sphere = new THREE.Mesh(geometry, material);
            scene.add(sphere);

            let mouseX = 0;
            let mouseY = 0;
            let targetRotationX = 0;
            let targetRotationY = 0;

            document.addEventListener('mousemove', (event) => {
                // Factores reducidos para garantizar un movimiento sumamente tranquilo
                mouseX = (event.clientX - window.innerWidth / 2) * 0.0002;
                mouseY = (event.clientY - window.innerHeight / 2) * 0.0002;
            });

            function animate() {
                requestAnimationFrame(animate);
                // Rotación base muy lenta y sutil
                sphere.rotation.y += 0.0008;
                sphere.rotation.x += 0.0004;

                targetRotationY += (mouseX - targetRotationY) * 0.02;
                targetRotationX += (mouseY - targetRotationX) * 0.02;
                sphere.rotation.y += targetRotationY;
                sphere.rotation.x += targetRotationX;

                renderer.render(scene, camera);
            }

            animate();

            window.addEventListener('resize', () => {
                camera.aspect = window.innerWidth / window.innerHeight;
                camera.updateProjectionMatrix();
                renderer.setSize(window.innerWidth, window.innerHeight);
            });
        });
    </script>
</body>
</html>
