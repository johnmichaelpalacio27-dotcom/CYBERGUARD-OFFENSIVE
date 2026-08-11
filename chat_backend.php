<?php
// chat_backend.php - Requiere la sesión activa
session_start();
if (!isset($_SESSION['user_id'])) exit("No autorizado");

$db = new PDO('sqlite:' . __DIR__ . '/cyberguard_secure.db');

// Acción: Enviar mensaje
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $msg = trim($_POST['message']);
    if (!empty($msg)) {
        $stmt = $db->prepare("INSERT INTO live_chat (user_id, message) VALUES (?, ?)");
        $stmt->execute([$_SESSION['user_id'], htmlspecialchars($msg)]);
    }
}

// Acción: Obtener mensajes (últimos 50)
$mensajes = $db->query("SELECT live_chat.*, users.nombre 
                       FROM live_chat 
                       JOIN users ON live_chat.user_id = users.id 
                       ORDER BY created_at DESC LIMIT 50");

foreach (array_reverse($mensajes->fetchAll()) as $m) {
    echo "<div style='margin-bottom:10px;'><strong>{$m['nombre']}:</strong> {$m['message']}</div>";
}
