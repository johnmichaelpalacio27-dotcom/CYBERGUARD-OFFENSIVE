<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

if (!isset($_SESSION['user_id'])) {
    header("HTTP/1.1 403 Forbidden");
    exit("No autorizado");
}

$db_file = __DIR__ . '/cyberguard_secure.db';
$db = new PDO('sqlite:' . $db_file);
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

// Clave simétrica de cifrado para los mensajes (Hardcoded o derivada por usuario)
define('CHAT_ENCRYPTION_KEY', hash('sha256', 'CyberGuard_Master_Secret_Salt_2026', true));

function encrypt_chat_message($plaintext) {
    $ivlen = openssl_cipher_iv_length($cipher = "AES-256-GCM");
    $iv = openssl_random_pseudo_bytes($ivlen);
    $ciphertext = openssl_encrypt($plaintext, $cipher, CHAT_ENCRYPTION_KEY, $options=0, $iv, $tag);
    return base64_encode($iv . $tag . $ciphertext);
}

function decrypt_chat_message($iv_tag_ciphertext) {
    $c = base64_decode($iv_tag_ciphertext);
    $ivlen = openssl_cipher_iv_length($cipher = "AES-256-GCM");
    $iv = substr($c, 0, $ivlen);
    $ivlen_tag = $ivlen + 16; // GCM tag length is 16 bytes
    $tag = substr($c, $ivlen, 16);
    $ciphertext = substr($c, $ivlen_tag);
    return openssl_decrypt($ciphertext, $cipher, CHAT_ENCRYPTION_KEY, $options=0, $iv, $tag);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        exit("CSRF Error");
    }

    $raw_message = trim($_POST['message'] ?? '');
    if (!empty($raw_message)) {
        // Sanitizar contra XSS antes de cifrar o guardar
        $sanitized_msg = htmlspecialchars($raw_message, ENT_QUOTES, 'UTF-8');
        $encrypted_payload = encrypt_chat_message($sanitized_msg);

        $stmt = $db->prepare("INSERT INTO live_chat (user_id, message) VALUES (?, ?)");
        $stmt->execute([$_SESSION['user_id'], $encrypted_payload]);
    }
    exit("OK");
}

// Renderizar historial descifrando en tiempo de ejecución para el cliente autorizado
$query = $db->query("SELECT live_chat.*, users.nombre, users.role FROM live_chat JOIN users ON live_chat.user_id = users.id ORDER BY live_chat.created_at ASC LIMIT 50");
while ($row = $query->fetch(PDO::FETCH_ASSOC)) {
    $decrypted_text = decrypt_chat_message($row['message']);
    if ($decrypted_text === false) {
        $decrypted_text = "[Mensaje cifrado corrupto o ilegible]";
    }
    $badge_color = ($row['role'] === 'admin') ? '#eab308' : 'var(--theme-color)';
    echo "<div style='margin-bottom:0.6rem;'>";
    echo "<strong style='color: {$badge_color};'>[" . htmlspecialchars($row['nombre']) . "]:</strong> ";
    echo "<span style='color: #f3f4f6;'>" . $decrypted_text . "</span>";
    echo "<span style='font-size: 0.65rem; color: #6b7280; margin-left: 0.5rem;'>(" . $row['created_at'] . ")</span>";
    echo "</div>";
}
?>
