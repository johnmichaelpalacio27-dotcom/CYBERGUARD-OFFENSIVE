<?php
// download.php - Control de acceso estricto anti-IDOR para archivos protegidos
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

if (!isset($_SESSION['user_id'])) {
    header("HTTP/1.1 403 Forbidden");
    die("Acceso denegado: Se requiere autenticación.");
}

require_once __DIR__ . '/cyberguard_secure.db'; // O la conexion PDO activa

$file_id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
$type = $_GET['type'] ?? 'consultation'; // 'consultation' o 'user_file'

if (!$file_id) {
    header("HTTP/1.1 400 Bad Request");
    die("ID de archivo inválido.");
}

try {
    $db = new PDO('sqlite:' . __DIR__ . '/cyberguard_secure.db');
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // Verificar rol del usuario actual
    $stmt_user = $db->prepare("SELECT role FROM users WHERE id = ?");
    $stmt_user->execute([$_SESSION['user_id']]);
    $current_user = $stmt_user->fetch(PDO::FETCH_ASSOC);
    $is_admin = ($current_user && $current_user['role'] === 'admin');

    $file_path = '';
    $file_name = '';

    if ($type === 'consultation') {
        $stmt = $db->prepare("SELECT user_id, user_file_path, user_file_name, admin_file_path, admin_file_name FROM security_consultations WHERE id = ?");
        $stmt->execute([$file_id]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$row) {
            header("HTTP/1.1 404 Not Found");
            die("El recurso solicitado no existe.");
        }

        // Protección IDOR: Validar si el usuario es el dueño de la consulta o es Admin Root
        if (!$is_admin && $row['user_id'] != $_SESSION['user_id']) {
            header("HTTP/1.1 403 Forbidden");
            die("Error IDOR Detectado: No tienes permisos para acceder a este archivo ajeno.");
        }

        $target = $_GET['target'] ?? 'user'; // 'user' o 'admin'
        if ($target === 'admin' && !empty($row['admin_file_path'])) {
            $file_path = __DIR__ . '/' . $row['admin_file_path'];
            $file_name = $row['admin_file_name'];
        } else {
            $file_path = __DIR__ . '/' . $row['user_file_path'];
            $file_name = $row['user_file_name'];
        }
    }

    if (!empty($file_path) && file_exists($file_path)) {
        header('Content-Description: File Transfer');
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($file_name) . '"');
        header('Expires: 0');
        header('Cache-Control: must-revalidate');
        header('Pragma: public');
        header('Content-Length: ' . filesize($file_path));
        flush();
        readfile($file_path);
        exit;
    } else {
        header("HTTP/1.1 404 Not Found");
        die("Archivo no encontrado en el servidor.");
    }

} catch (Exception $e) {
    header("HTTP/1.1 500 Internal Server Error");
    die("Error crítico procesando la descarga segura.");
}
?>
