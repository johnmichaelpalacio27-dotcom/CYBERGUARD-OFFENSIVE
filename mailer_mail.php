<?php
// ====================================================================
// MÓDULO DE INTEGRACIÓN SMTP Y AUDITORÍA DE SEGURIDAD
// ====================================================================

// --- CONFIGURACIÓN SMTP GLOBAL PARA GMAIL ---
define('SMTP_HOST', 'smtp.gmail.com');
define('SMTP_USER', 'johnmichaelpalacio27@gmail.com');             
define('SMTP_PASS', 'essu rpel yghl xffu');           
define('SMTP_PORT', 587);
define('SMTP_FROM_NAME', 'CyberGuard Offensive SecOps');

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

function registrarYNotificarEvento($db, $user_id, $email, $nombre, $evento, $detalles) {
    // 1. Guardar auditoría interna en Base de Datos (Corregido sin ip_address para evitar fallos de esquema)
    try {
        $stmt_audit = $db->prepare("INSERT INTO security_consultations (user_id, email, subject, message) VALUES (?, ?, ?, ?)");
        $ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
        $stmt_audit->execute([$user_id, $email, "AUDITORÍA: " . $evento, "Usuario: $nombre | Detalles: $detalles | IP: " . $ip]);
    } catch (Exception $ex) {
        // Fallo silencioso de auditoría en BD para no romper el flujo principal
    }

    // 2. Envío de Notificación por Correo Electrónico (SMTP Gmail)
    if (!class_exists('PHPMailer\PHPMailer\PHPMailer')) {
        return; 
    }

    $mail = new PHPMailer(true);
    try {
        $mail->isSMTP();
        $mail->Host       = SMTP_HOST;
        $mail->SMTPAuth   = true;
        $mail->Username   = SMTP_USER;
        $mail->Password   = SMTP_PASS;
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port       = SMTP_PORT;

        $mail->setFrom(SMTP_USER, SMTP_FROM_NAME);
        $mail->addAddress($email, $nombre);

        $mail->isHTML(true);
        $mail->Subject = '[CyberGuard Security Alert] - ' . $evento;
        $mail->Body    = "
            <div style='background:#030712;color:#f3f4f6;padding:20px;font-family:sans-serif;border-radius:8px;'>
                <h2 style='color:#06b6d4;'>CyberGuard Offensive SecOps</h2>
                <p>Hola <b>{$nombre}</b>,</p>
                <p>Se ha registrado un evento de seguridad crítico en tu cuenta:</p>
                <div style='background:rgba(6,182,212,0.1);border:1px solid #06b6d4;padding:12px;border-radius:6px;margin:15px 0;'>
                    <b>Evento:</b> {$evento}<br>
                    <b>Detalles:</b> {$detalles}<br>
                    <b>Fecha/Hora:</b> " . date('Y-m-d H:i:s') . "
                </div>
                <p style='font-size:12px;color:#9ca3af;'>Si no reconoces esta actividad, por favor cambia tu contraseña y revisa tus hashes de seguridad de inmediato.</p>
            </div>
        ";

        $mail->send();
    } catch (Exception $e) {
        // Error de envío de correo capturado para evitar interrupciones
    }
}
