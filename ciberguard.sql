-- ====================================================================
-- SISTEMA DE GESTIÓN DE BASE DE DATOS: CyberGuard Offensive (SQL Dump)
-- Motor: MySQL / MariaDB (Estructura 100% Real, Vacía y Lista para Producción)
-- Descripción: Base de datos limpia con hardening avanzado, encriptación
--              AES a nivel de columna y tablas vacías para registro real.
-- ====================================================================

SET FOREIGN_KEY_CHECKS = 0;
DROP DATABASE IF EXISTS `cyberguard_secure_db`;
CREATE DATABASE `cyberguard_secure_db` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `cyberguard_secure_db`;

-- --------------------------------------------------------------------
-- 1. TABLA DE USUARIOS (Estructura real para registros, perfiles y seguridad 3D)
-- --------------------------------------------------------------------
CREATE TABLE `users` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `nombre` VARCHAR(100) NOT NULL,
  `apellido` VARCHAR(100) NOT NULL,
  `email` VARCHAR(150) NOT NULL UNIQUE,
  `password` VARCHAR(255) NOT NULL,
  `single_use_hash` VARCHAR(255) DEFAULT '',
  `hash_type` ENUM('sha256', 'whirlpool', 'md5') DEFAULT 'sha256',
  `hash_used` TINYINT(1) DEFAULT 0,
  `hash_security_active` TINYINT(1) DEFAULT 1,
  `profile_pic` VARCHAR(255) DEFAULT '',
  `theme_color` VARCHAR(7) DEFAULT '#06b6d4',
  `ddos_protection` TINYINT(1) DEFAULT 1,
  `sec_question_1` VARCHAR(255) DEFAULT '',
  `sec_answer_1` VARCHAR(255) DEFAULT '',
  `sec_question_2` VARCHAR(255) DEFAULT '',
  `sec_answer_2` VARCHAR(255) DEFAULT '',
  `sec_question_3` VARCHAR(255) DEFAULT '',
  `sec_answer_3` VARCHAR(255) DEFAULT '',
  `role` ENUM('analyst', 'admin', 'operator') DEFAULT 'analyst',
  `status` ENUM('active', 'suspended', 'locked') DEFAULT 'active',
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_email` (`email`),
  KEY `idx_hash` (`single_use_hash`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------------------
-- 2. TABLA DE CONSULTAS DE CIBERSEGURIDAD (Vacía para datos reales)
-- --------------------------------------------------------------------
CREATE TABLE `security_consultations` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `user_id` INT(11) DEFAULT NULL,
  `email` VARCHAR(150) NOT NULL,
  `subject` VARCHAR(200) NOT NULL,
  `message` TEXT NOT NULL,
  `ip_address` VARCHAR(45) DEFAULT NULL,
  `status` ENUM('pending', 'in_review', 'resolved') DEFAULT 'pending',
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_user_consult` (`user_id`),
  CONSTRAINT `fk_consult_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------------------
-- 3. TABLA DE REGISTRO DE AUDITORÍA Y BLOQUEO POR FUERZA BRUTA
-- --------------------------------------------------------------------
CREATE TABLE `security_audit_logs` (
  `log_id` INT(11) NOT NULL AUTO_INCREMENT,
  `user_id` INT(11) DEFAULT NULL,
  `action_type` VARCHAR(50) NOT NULL,
  `ip_address` VARCHAR(45) NOT NULL,
  `status` VARCHAR(20) NOT NULL,
  `details` TEXT DEFAULT NULL,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`log_id`),
  KEY `idx_audit_ip` (`ip_address`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------------------
-- 4. RUTINAS DE SEGURIDAD Y ENCRIPTACIÓN A NIVEL DE BASE DE DATOS
-- --------------------------------------------------------------------

-- Llave simétrica interna para funciones AES (Asegúrese de cambiar la passphrase en producción)
SET @aes_secret_key = 'CyberGuard_Master_Encryption_Key_2026!#*';

DELIMITER //
-- Procedimiento almacenado para insertar consultas cifrando el contenido sensible automáticamente
CREATE PROCEDURE `sp_SecureInsertConsultation` (
    IN p_user_id INT,
    IN p_email VARCHAR(150),
    IN p_subject VARCHAR(200),
    IN p_message TEXT,
    IN p_ip VARCHAR(45)
)
BEGIN
    INSERT INTO `security_consultations` (`user_id`, `email`, `subject`, `message`, `ip_address`, `status`)
    VALUES (
        p_user_id, 
        p_email, 
        p_subject, 
        TO_BASE64(AES_ENCRYPT(p_message, @aes_secret_key)), 
        p_ip, 
        'pending'
    );
END//

-- Procedimiento almacenado para desencriptar y leer mensajes confidenciales de la base de datos
CREATE PROCEDURE `sp_SecureReadConsultation` (
    IN p_consult_id INT
)
BEGIN
    SELECT 
        id, 
        user_id, 
        email, 
        subject, 
        AES_DECRYPT(FROM_BASE64(message), @aes_secret_key) AS decrypted_message, 
        ip_address, 
        status, 
        created_at 
    FROM `security_consultations` 
    WHERE id = p_consult_id;
END//
DELIMITER ;

SET FOREIGN_KEY_CHECKS = 1;
