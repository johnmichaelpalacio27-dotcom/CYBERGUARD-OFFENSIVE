<?php
// ====================================================================
// MÓDULO DE NOTIFICACIONES PHPMailer / SMTP CON LOGUEO EN BASE DE DATOS
// ====================================================================
// Este script se integra con tu código actual (cyberguard_secure.db)
// para enviar correos electrónicos seguros ante cada acción crítica:
// Registro, Inicio de Sesión, Cambio/Recuperación de Clave y Consultas.
// ====================================================================

// Asegurar disponibilidad de PHPMailer (puedes instalarlo vía Composer: composer require phpmailer/phpmailer)
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

// Si estás usando un entorno local como XAMPP/LAMPP sin Composer autoload automático, 
// descomenta las siguientes líneas con la ruta a tus archivos de PHPMailer:
/*
require 'PHPMailer/src/Exception.php';
require 'PHPMailer/src/PHPMailer.php';
require 'PHPMailer/src/SMTP.php';
*/

// --- CONFIGURACIÓN SMTP GLOBAL (AJUSTA TUS CREDENCIALES AQUÍ) ---
define('SMTP_HOST', 'smtp.gmail.com');       // Servidor SMTP (ej: smtp.gmail.com, mail.tuproyectoseguro.com)
define('SMTP_USER', 'johnmichaelpalacio@gmail.com'); // Tu correo remitente o ProtonBridge/SMTP
define('SMTP_PASS', 'essu rpel yghl xffu');      // Contraseña de aplicación o SMTP
define('SMTP_PORT', 587);                      // Puerto (587 para TLS, 465 para SSL)
define('SMTP_FROM_NAME', 'CyberGuard Offensive SecOps');

/**
 * Función centralizada para enviar correos electrónicos de forma segura vía SMTP
 */
function enviarCorreoNotificacion($destinatario, $nombre_destinatario, $asunto, $mensaje_html) {
    // Si PHPMailer no está disponible, hace un fallback a mail() nativo o retorna falso
    if (!class_exists('PHPMailer\PHPMailer\PHPMailer')) {
        // Fallback nativo básico de PHP si no se cargó PHPMailer
        $headers  = "MIME-Version: 1.0" . "\r\n";
        $headers .= "Content-type:text/html;charset=UTF-8" . "\r\n";
        $headers .= "From: " . SMTP_FROM_NAME . " <" . SMTP_USER . ">" . "\r\n";
        return @mail($destinatario, $asunto, $mensaje_html, $headers);
    }

    $mail = new PHPMailer(true);
    try {
        // Configuración del servidor SMTP
        $mail->isSMTP();
        $mail->Host       = SMTP_HOST;
        $mail->SMTPAuth   = true;
        $mail->Username   = SMTP_USER;
        $mail->Password   = SMTP_PASS;
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port       = SMTP_PORT;
        $mail->CharSet    = 'UTF-8';

        // Remitente y Destinatario
        $mail->setFrom(SMTP_USER, SMTP_FROM_NAME);
        $mail->addAddress($destinatario, $nombre_destinatario);

        // Contenido del Correo
        $mail->isHTML(true);
        $mail->Subject = $asunto;
        $mail->Body    = $mensaje_html;
        $mail->AltBody = strip_tags($mensaje_html);

        $mail->send();
        return true;
    } catch (Exception $e) {
        // Error de envío SMTP registrado internamente sin romper el flujo de la aplicación
        error_log("Error de envío SMTP: {$mail->ErrorInfo}");
        return false;
    }
}

/**
 * Función para registrar cada evento de seguridad en la base de datos SQLite y disparar la alerta por correo
 */
function registrarYNotificarEvento($db, $user_id, $email, $nombre, $tipo_evento, $detalles) {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';

    // 1. Crear tabla de logs de auditoría si no existe en tu base de datos actual
    try {
        $db->exec("CREATE TABLE IF NOT EXISTS security_audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            email TEXT NOT NULL,
            event_type TEXT NOT NULL,
            details TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )");

        // Insertar registro de auditoría
        $stmt = $db->prepare("INSERT INTO security_audit_logs (user_id, email, event_type, details, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?)");
        $stmt->execute([$user_id, $email, $tipo_evento, $detalles, $ip, $user_agent]);
    } catch (Exception $e) {
        // Manejo silencioso de error en log para no interrumpir ejecución
    }

    // 2. Construir plantilla HTML profesional para la notificación por correo
    $asunto_email = "[CyberGuard Alerta] Actividad de Seguridad Registrada: " . strtoupper($tipo_evento);
    
    $cuerpo_html = '
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <style>
            body { background-color: #030712; color: #f3f4f6; font-family: Arial, sans-serif; padding: 20px; }
            .container { background: #0f172a; border: 1px solid #06b6d4; border-radius: 8px; padding: 30px; max-width: 600px; margin: 0 auto; }
            h2 { color: #06b6d4; font-family: monospace; }
            .info { background: rgba(3, 7, 18, 0.8); padding: 15px; border-left: 4px solid #06b6d4; margin: 15px 0; font-family: monospace; font-size: 0.9rem; }
            .footer { font-size: 0.75rem; color: #9ca3af; margin-top: 25px; border-top: 1px solid rgba(255,255,255,0.1); padding-top: 10px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>CYBERGUARD//SECURITY AUDIT</h2>
            <p>Hola <strong>' . htmlspecialchars($nombre) . '</strong>,</p>
            <p>Se ha registrado un evento crítico en tu cuenta dentro del sistema blindado:</p>
            <div class="info">
                <strong>Evento:</strong> ' . htmlspecialchars($tipo_evento) . '<br>
                <strong>Detalles:</strong> ' . htmlspecialchars($detalles) . '<br>
                <strong>Dirección IP:</strong> ' . htmlspecialchars($ip) . '<br>
                <strong>Fecha / Hora:</strong> ' . date('Y-m-d H:i:s') . '
            </div>
            <p>Si reconoces esta actividad, puedes ignorar este mensaje. De lo contrario, contacta de inmediato con el equipo de soporte de ciberseguridad.</p>
            <div class="footer">
                CyberGuard Offensive - Hardening & Criptografía 3D.<br>
                Este correo fue generado automáticamente, por favor no respondas a este mensaje.
            </div>
        </div>
    </body>
    </html>';

    // 3. Enviar correo al usuario afectado o administrador
    enviarCorreoNotificacion($email, $nombre, $asunto_email, $cuerpo_html);
}
?>
