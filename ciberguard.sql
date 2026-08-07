-- =========================================================================
-- EXPANSIÓN DE BASE DE DATOS PARA CYBERGUARD OFFENSIVE V2
-- =========================================================================

-- 1. Tabla de Auditoría de Seguridad y Eventos del Sistema (SIEM Ligero)
CREATE TABLE IF NOT EXISTS security_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    event_type TEXT NOT NULL, -- Ej: 'LOGIN_SUCCESS', 'BRUTE_FORCE_TRIGGERED', 'DDOS_SHIELD', 'HASH_RESET'
    severity TEXT DEFAULT 'INFO', -- INFO, WARNING, CRITICAL
    ip_address TEXT,
    user_agent TEXT,
    details TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- 2. Tabla para Gestión de Sesiones Activas (Control de Concurrencia e IDOR)
CREATE TABLE IF NOT EXISTS active_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    session_identifier TEXT UNIQUE NOT NULL,
    ip_address TEXT,
    device_fingerprint TEXT,
    last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 3. Tabla de Reportes de Vulnerabilidades y Bug Bounty Internos
CREATE TABLE IF NOT EXISTS vulnerability_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    reporter_id INTEGER,
    target_asset TEXT NOT NULL,
    severity_level TEXT CHECK(severity_level IN ('Low', 'Medium', 'High', 'Critical')) DEFAULT 'Medium',
    description TEXT NOT NULL,
    proof_of_concept TEXT,
    status TEXT DEFAULT 'Pending Review', -- Pending Review, Verified, Patched, Rejected
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (reporter_id) REFERENCES users(id) ON DELETE SET NULL
);

-- 4. Tabla de Tokens de API para Analistas Avanzados
CREATE TABLE IF NOT EXISTS api_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash TEXT UNIQUE NOT NULL,
    token_name TEXT NOT NULL,
    scopes TEXT DEFAULT 'read', -- read, write, execute
    expires_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- =========================================================================
-- DATOS DE PRUEBA (SEEDERS) PARA ENTORNO DE DESARROLLO Y TESTING
-- =========================================================================

-- Insertar Usuario Administrador Maestro por defecto
-- Contraseña plana: 'CyberGuard2026*' (Hasheada con BCRYPT)
INSERT INTO users (nombre, apellido, email, password, single_use_hash, hash_type, hash_used, hash_security_active, theme_color, ddos_protection, sec_question_1, sec_answer_1, role, status)
VALUES (
    'Admin', 
    'CyberGuard', 
    'admin@cyberguard.internal', 
    '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 
    'sha256', 
    0, 
    1, 
    '#06b6d4', 
    1, 
    '¿Cuál es tu protocolo de cifrado favorito?', 
    '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 
    'administrator', 
    'active'
);

-- Insertar Registros Iniciales de Auditoría (Simulando ataques y accesos)
INSERT INTO security_logs (user_id, event_type, severity, ip_address, user_agent, details) VALUES
(1, 'SYSTEM_BOOT', 'INFO', '127.0.0.1', 'CyberGuard-Core-Engine/2.6', 'Base de datos inicializada correctamente con esquemas blindados 3D.'),
(NULL, 'DDOS_MITIGATION_TEST', 'WARNING', '192.168.1.105', 'Mozilla/5.0 (Anomalous Scanner)', 'Peticiones masivas interceptadas en el umbral de 2 segundos.');

-- Insertar Consultas de Ciberseguridad de Ejemplo
INSERT INTO security_consultations (user_id, email, subject, message, ip_address) VALUES
(1, 'admin@cyberguard.internal', 'Revisión de Cabeceras HTTP', 'Validar que la directiva Content-Security-Policy bloquee correctamente scripts inline no autorizados.', '127.0.0.1');
