<?php
// chat_backend.php - Chat avanzado con soporte multimedia y perfiles protegidos[cite: 11]
session_start();
if (!isset($_SESSION['user_id'])) {
    header("HTTP/1.1 403 Forbidden");
    exit("No autorizado");
}

$db = new PDO('sqlite:' . __DIR__ . '/cyberguard_secure.db');

// Acción: Enviar mensaje o contenido multimedia[cite: 11]
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        header("HTTP/1.1 403 Forbidden");
        exit("Error de validación CSRF.");
    }

    $msg = trim($_POST['message'] ?? '');
    $file_path = null;
    $file_type = 'text';

    // Manejo de subida de archivos (Fotos, Documentos, Audios/Voz)[cite: 11]
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

            $file_path = 'uploads/chat_' . time() . '_' . mt_rand(1000, 9999) . '.' . $file_ext;
            move_uploaded_file($file_tmp, __DIR__ . '/' . $file_path);
        }
    }

    // Acción de borrado de mensaje si se solicita por POST
    if (isset($_POST['action']) && $_POST['action'] === 'delete_chat_message' && isset($_POST['chat_id'])) {
        $chat_id = intval($_POST['chat_id']);
        // Opcional: validar propiedad del mensaje antes de borrar
        $stmt_del = $db->prepare("DELETE FROM live_chat WHERE id = ?");
        $stmt_del->execute([$chat_id]);
        exit;
    }

    if (!empty($msg) || !empty($file_path)) {
        $stmt = $db->prepare("INSERT INTO live_chat (user_id, message, file_path, file_type) VALUES (?, ?, ?, ?)");
        $stmt->execute([$_SESSION['user_id'], htmlspecialchars($msg), $file_path, $file_type]);
    }
    exit;
}

// Acción: Obtener y renderizar los mensajes (últimos 50 de forma cronológica)[cite: 7, 11]
$stmt_chat = $db->query("
    SELECT c.*, u.nombre, u.apellido, u.public_user_hash, u.role, u.id as account_id 
    FROM live_chat c 
    JOIN users u ON c.user_id = u.id 
    ORDER BY c.created_at ASC 
    LIMIT 50
");

while ($msg = $stmt_chat->fetch(PDO::FETCH_ASSOC)) {
    $nombre_completo = htmlspecialchars($msg['nombre'] . ' ' . $msg['apellido']);
    $hash_id = htmlspecialchars($msg['public_user_hash'] ?? 'hash_guest');
    $account_id = $msg['account_id'];
    
    echo '<div class="chat-message" style="margin-bottom: 12px; border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 8px;">';
    
    // Encabezado del mensaje con Hash público y opción de auditoría de perfil[cite: 7, 11]
    echo '<span style="font-size: 0.75rem; color: #9ca3af; font-family: Orbitron;">[' . $hash_id . ']</span> ';
    echo '<strong style="color: var(--theme-color); cursor: pointer;" onclick="verPerfilUsuario(' . $account_id . ')">' . $nombre_completo . ':</strong> ';
    
    // Contenido de texto[cite: 11]
    if (!empty($msg['message'])) {
        echo '<p style="color: #fff; font-size: 0.9rem; margin-top: 2px;">' . htmlspecialchars($msg['message']) . '</p>';
    }
    
    // Renderizado multimedia adaptado (Imagen, Audio/Voz o Documento)[cite: 7, 11]
    if (!empty($msg['file_path'])) {
        $ext = strtolower(pathinfo($msg['file_path'], PATHINFO_EXTENSION));
        if ($msg['file_type'] === 'image' || in_array($ext, ['jpg', 'jpeg', 'png', 'webp'])) {
            echo '<div style="margin-top: 6px;"><img src="' . htmlspecialchars($msg['file_path']) . '" style="max-width: 200px; border-radius: 6px; border: 1px solid rgba(255,255,255,0.2);" alt="Imagen adjunta"></div>';
        } elseif ($msg['file_type'] === 'audio' || in_array($ext, ['webm', 'mp3', 'wav', 'ogg'])) {
            echo '<div style="margin-top: 6px;"><audio controls style="height: 32px; width: 100%; max-width: 240px;"><source src="' . htmlspecialchars($msg['file_path']) . '" type="audio/' . $ext . '">Tu navegador no soporta audio.</audio></div>';
        } else {
            echo '<div style="margin-top: 6px;"><a href="' . htmlspecialchars($msg['file_path']) . '" download class="btn btn-outline" style="font-size: 0.75rem; padding: 0.2rem 0.5rem; text-decoration: none;">📄 Descargar Documento</a></div>';
        }
    }
    
    echo '</div>';
}
?>

<script>
// Función para eliminar un mensaje de chat con confirmación visual 3D[cite: 11]
function eliminarMensajeChat(chatId) {
    if(confirm("¿Deseas eliminar este chat/consulta en pantalla 3D?")) {
        let formData = new FormData();
        formData.append('action', 'delete_chat_message');
        formData.append('chat_id', chatId);
        formData.append('csrf_token', '<?php echo $_SESSION['csrf_token'] ?? ''; ?>');
        
        fetch('chat_backend.php', { method: 'POST', body: formData })
            .then(() => { if(typeof cargarChat === 'function') { cargarChat(); } else { location.reload(); } });
    }
}
</script>
