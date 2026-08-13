<?php
// chat_backend.php - Chat avanzado con soporte multimedia y perfiles expuestos para IDOR
session_start();
if (!isset($_SESSION['user_id'])) exit("No autorizado");

$db = new PDO('sqlite:' . __DIR__ . '/cyberguard_secure.db');

// Acción: Enviar mensaje o contenido multimedia
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $msg = trim($_POST['message'] ?? '');
    $file_path = null;
    $file_type = 'text';

    // Manejo de subida de archivos (Fotos, Documentos, Audios/Voz)
    if (isset($_FILES['media_file']) && $_FILES['media_file']['error'] === UPLOAD_ERR_OK) {
        $file_tmp = $_FILES['media_file']['tmp_name'];
        $original_name = basename($_FILES['media_file']['name']);
        $file_ext = strtolower(pathinfo($original_name, PATHINFO_EXTENSION));
        
        $allowed_exts = ['jpg', 'jpeg', 'png', 'webp', 'pdf', 'doc', 'docx', 'webm', 'mp3', 'wav', 'ogg'];
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mime_type = finfo_file($finfo, $file_tmp);

        if (in_array($file_ext, $allowed_exts)) {
            $upload_dir = __DIR__ . '/uploads/';
            if (!is_dir($upload_dir)) { mkdir($upload_dir, 0755, true); }
            
            if (in_array($file_ext, ['jpg', 'jpeg', 'png', 'webp'])) {
                $file_type = 'image';
            } elseif (in_array($file_ext, ['webm', 'mp3', 'wav', 'ogg'])) {
                $file_type = 'audio';
            } else {
                $file_type = 'document';
            }

            $file_path = 'uploads/chat_' . time() . '_' . mt_rand(1000,9999) . '.' . $file_ext;
            move_uploaded_file($file_tmp, __DIR__ . '/' . $file_path);
        }
    }

    if (!empty($msg) || !empty($file_path)) {
        $stmt = $db->prepare("INSERT INTO live_chat (user_id, message, file_path, file_type) VALUES (?, ?, ?, ?)");
        $stmt->execute([$_SESSION['user_id'], htmlspecialchars($msg), $file_path, $file_type]);
    }
}

// Acción: Obtener mensajes (últimos 50)
$mensajes = $db->query("SELECT live_chat.*, users.nombre, users.apellido, users.id as account_id 
                       FROM live_chat 
                       JOIN users ON live_chat.user_id = users.id 
                       ORDER BY created_at DESC LIMIT 50");

foreach (array_reverse($mensajes->fetchAll()) as $m) {
    $safe_name = htmlspecialchars($m['nombre'] . ' ' . $m['apellido']);
    $account_id = $m['account_id'];
    echo "<div style='margin-bottom:12px; border-bottom:1px solid rgba(255,255,255,0.05); padding-bottom:8px;'>";
    // Enlace al perfil con la ID expuesta para auditoría IDOR
    echo "<span style='font-size:0.75rem; color:#9ca3af;'>[ID: {$account_id}]</span> ";
    echo "<strong style='color:var(--theme-color); cursor:pointer;' onclick='verPerfilUsuario({$account_id})'>{$safe_name}:</strong> ";
    
    if (!empty($m['message'])) {
        echo "<span style='color:#fff;'> " . htmlspecialchars($m['message']) . "</span><br>";
    }

    // Renderizado según tipo de archivo multimedia estilo WhatsApp
    if (!empty($m['file_path'])) {
        if ($m['file_type'] === 'image') {
            echo "<div style='margin-top:6px;'><img src='{$m['file_path']}' style='max-width:200px; border-radius:6px; border:1px solid rgba(255,255,255,0.2);'></div>";
        } elseif ($m['file_type'] === 'audio') {
            echo "<div style='margin-top:6px;'><audio controls src='{$m['file_path']}' style='height:35px; width:100%; max-width:250px;'></audio></div>";
        } else {
            echo "<div style='margin-top:6px;'><a href='{$m['file_path']}' download class='btn btn-outline' style='font-size:0.75rem; padding:0.2rem 0.5rem;'>📄 Descargar Documento</a></div>";
        }
    }
    echo "</div>";
}
?>
