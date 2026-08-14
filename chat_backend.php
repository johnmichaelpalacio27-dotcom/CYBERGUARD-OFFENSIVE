<?php
// chat_backend.php - Chat avanzado con soporte multimedia, perfiles protegidos y avatares dinámicos[cite: 7]
session_start();
if (!isset($_SESSION['user_id'])) {
    header("HTTP/1.1 403 Forbidden");
    exit("No autorizado");
}

$db = new PDO('sqlite:' . __DIR__ . '/cyberguard_secure.db');

// Acción: Enviar mensaje o contenido multimedia
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'],$_POST['csrf_token'])) {
        header("HTTP/1.1 403 Forbidden");
        exit("Error de validación CSRF.");
    }

    $msg = trim($_POST['message'] ?? '');$file_path = null;
    $file_type = 'text';

    // Manejo de subida de archivos (Fotos, Documentos, Audios/Voz)
    if (isset($_FILES['media_file']) && $_FILES['media_file']['error'] === UPLOAD_ERR_OK) {$file_tmp = $_FILES['media_file']['tmp_name'];$original_name = basename($_FILES['media_file']['name']);$file_ext = strtolower(pathinfo($original_name, PATHINFO_EXTENSION));$allowed_exts = ['jpg', 'jpeg', 'png', 'webp', 'pdf', 'doc', 'docx', 'webm', 'mp3', 'wav', 'ogg'];
        $finfo = finfo_open(FILEINFO_MIME_TYPE);$mime_type = finfo_file($finfo,$file_tmp);

        if (in_array($file_ext, $allowed_exts)) {$upload_dir = __DIR__ . '/uploads/';
            if (!is_dir($upload_dir)) { mkdir($upload_dir, 0755, true); }
            
            if (in_array($file_ext, ['jpg', 'jpeg', 'png', 'webp'])) {$file_type = 'image';
            } elseif (in_array($file_ext, ['webm', 'mp3', 'wav', 'ogg'])) {$file_type = 'audio';
            } else {
                $file_type = 'document';
            }

            $file_path = 'uploads/chat_' . time() . '_' . mt_rand(1000, 9999) . '.' . $file_ext;
            move_uploaded_file($file_tmp, __DIR__ . '/' .$file_path);
        }
    }

    // Acción de borrado de mensaje si se solicita por POST
    if (isset($_POST['action']) && $_POST['action'] === 'delete_chat_message' && isset($_POST['chat_id'])) {
        $chat_id = intval($_POST['chat_id']);
        $stmt_del =$db->prepare("DELETE FROM live_chat WHERE id = ?");
        $stmt_del->execute([$chat_id]);
        exit;
    }

    if (!empty($msg) \vert{}\vert{} !empty($file_path)) {
        $stmt =$db->prepare("INSERT INTO live_chat (user_id, message, file_path, file_type) VALUES (?, ?, ?, ?)");
        $stmt->execute([$_SESSION['user_id'], htmlspecialchars($msg), $file_path,$file_type]);
    }
    exit;
}

// Acción: Obtener y renderizar los mensajes (últimos 50 de forma cronológica con avatares e información de auditoría)[cite: 7]
$stmt_chat =$db->query("
    SELECT c.*, u.nombre, u.apellido, u.public_user_hash, u.role, u.id as account_id, u.profile_pic 
    FROM live_chat c 
    JOIN users u ON c.user_id = u.id 
    ORDER BY c.created_at ASC 
    LIMIT 50
");

while ($msg = $stmt_chat->fetch(PDO::FETCH_ASSOC)) {$nombre_completo = htmlspecialchars($msg['nombre'] . ' ' .$msg['apellido']);
    $hash_id = htmlspecialchars($msg['public_user_hash'] ?? 'hash_guest');
    $account_id =$msg['account_id'];
    
    // Gestión del Avatar (Foto de perfil o inicial estilizada)
    $avatar = (!empty($msg['profile_pic']) && file_exists(__DIR__ . '/' .$msg['profile_pic'])) 
              ? htmlspecialchars($msg['profile_pic']) 
              : '';

    echo '<div class="chat-message" style="display: flex; align-items: flex-start; gap: 10px; margin-bottom: 12px; border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 8px;">';
    
    // Renderizado del Avatar Circular
    if (!empty($avatar)) {
        echo '<img src="' . $avatar . '" style="width: 32px; height: 32px; border-radius: 50%; object-fit: cover; border: 1px solid var(--theme-color); flex-shrink: 0; cursor: pointer;" onclick="verPerfilUsuario(' . $account_id . ')">';
    } else {
        $inicial = strtoupper(substr($msg['nombre'], 0, 1));
        echo '<div style="width: 32px; height: 32px; border-radius: 50%; background: var(--theme-color); color: #030712; display: flex; align-items: center; justify-content: center; font-weight: bold; font-size: 0.85rem; flex-shrink: 0; cursor: pointer;" onclick="verPerfilUsuario(' . $account_id . ')">' . $inicial . '</div>';
    }

    echo '<div style="flex: 1;">';
    
    // Encabezado con Hash público y nombre real activo (Sin corchetes vacíos genéricos)
    echo '<span style="font-size: 0.75rem; color: #9ca3af; font-family: Orbitron;">[' . $hash_id . ']</span> ';
    echo '<strong style="color: var(--theme-color); cursor: pointer;" onclick="verPerfilUsuario(' . $account_id . ')">' . $nombre_completo . ':</strong>';
    
    // Contenido de texto del mensaje
    if (!empty($msg['message'])) {
        echo '<p style="color: #f3f4f6; font-size: 0.9rem; margin-top: 2px;">' . htmlspecialchars($msg['message']) . '</p>';
    }
    
    // Renderizado multimedia adaptado (Imagen, Audio/Voz o Documento)[cite: 7]
    if (!empty($msg['file_path'])) {
        $ext = strtolower(pathinfo($msg['file_path'], PATHINFO_EXTENSION));
        if ($msg['file_type'] === 'image' \vert{}\vert{} in_array($ext, ['jpg', 'jpeg', 'png', 'webp'])) {
            echo '<div style="margin-top: 6px;"><img src="' . htmlspecialchars($msg['file_path']) . '" style="max-width: 200px; border-radius: 6px; border: 1px solid rgba(255,255,255,0.2);" alt="Imagen adjunta"></div>';
        } elseif ($msg['file_type'] === 'audio' \vert{}\vert{} in_array($ext, ['webm', 'mp3', 'wav', 'ogg'])) {
            echo '<div style="margin-top: 6px;"><audio controls style="height: 32px; width: 100%; max-width: 240px;"><source src="' . htmlspecialchars($msg['file_path']) . '" type="audio/' . $ext . '">Tu navegador no soporta audio.</audio></div>';
        } else {
            echo '<div style="margin-top: 6px;"><a href="' . htmlspecialchars($msg['file_path']) . '" target="_blank" class="btn btn-outline" style="font-size: 0.75rem; padding: 0.2rem 0.5rem; text-decoration: none;">📄 Descargar Archivo / Ver Adjunto</a></div>';
        }
    }
    
    echo '</div></div>';
}
?>

<script>
// Función para eliminar un mensaje de chat con confirmación visual 3D
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
