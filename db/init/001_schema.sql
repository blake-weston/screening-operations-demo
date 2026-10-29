CREATE DATABASE IF NOT EXISTS airport_security;
USE airport_security;

CREATE TABLE IF NOT EXISTS operators (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) NOT NULL UNIQUE,
  display_name VARCHAR(100) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  role ENUM('admin', 'manager', 'lane') NOT NULL DEFAULT 'lane',
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS operator_lane_assignments (
  operator_id INT NOT NULL,
  terminal_name VARCHAR(50) NOT NULL,
  lane_number INT NOT NULL,
  PRIMARY KEY (operator_id, terminal_name, lane_number),
  CONSTRAINT fk_operator_lane_assignments_operator
    FOREIGN KEY (operator_id) REFERENCES operators(id)
    ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS login_throttles (
  throttle_key VARCHAR(191) PRIMARY KEY,
  failed_attempts INT NOT NULL DEFAULT 0,
  last_failed_at DATETIME NOT NULL,
  locked_until DATETIME DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS operator_audit_logs (
  id INT AUTO_INCREMENT PRIMARY KEY,
  actor_operator_id INT NOT NULL,
  target_operator_id INT DEFAULT NULL,
  action VARCHAR(50) NOT NULL,
  details JSON NOT NULL,
  ip_address VARCHAR(45) NOT NULL,
  occurred_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_operator_audit_logs_occurred_at (occurred_at),
  CONSTRAINT fk_operator_audit_logs_actor
    FOREIGN KEY (actor_operator_id) REFERENCES operators(id),
  CONSTRAINT fk_operator_audit_logs_target
    FOREIGN KEY (target_operator_id) REFERENCES operators(id)
    ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS scan_events (
  id INT AUTO_INCREMENT PRIMARY KEY,
  scan_time DATETIME NOT NULL,
  terminal_name VARCHAR(50) NOT NULL,
  lane_number INT NOT NULL,
  scanner_location VARCHAR(100) NOT NULL,
  risk_level ENUM('Low', 'Medium', 'High') NOT NULL,
  threat_category ENUM('firearm', 'grenade', 'knife', 'wrench', 'pliers', 'scissors', 'hammer') NOT NULL,
  notes TEXT NOT NULL,
  sixray_image_filename VARCHAR(255) DEFAULT NULL,
  thumbnail_filename VARCHAR(255) DEFAULT NULL,
  INDEX idx_scan_time (scan_time),
  INDEX idx_risk_level (risk_level),
  INDEX idx_scanner_location (scanner_location)
);

INSERT INTO operators (id, username, display_name, password_hash, role, is_active)
VALUES (
  1,
  'admin',
  'Administrator',
  '$2y$10$Z6Ro1.EhR4I/VF7euGEIb.TKPd2Vn5yL.sTyg0bmtNDtM0wb4EWVq',
  'admin',
  TRUE
),
(
  2,
  'manager.t2',
  'Terminal 2 Screening Manager',
  '$2y$10$v8zLwFOdFVL6Daagzx4Wa.d3YuJwJ7Vbls80OxAJSdF4VB.RFfvi6',
  'manager',
  TRUE
),
(
  3,
  'lane.t2.a',
  'Lane A Security Officer',
  '$2y$10$thAw9g363td7O.zmZ8JD3O5ztwHh7WyKWOw9WJK2.Eon1PA3qWSDu',
  'lane',
  TRUE
)
ON DUPLICATE KEY UPDATE
  display_name = VALUES(display_name),
  password_hash = VALUES(password_hash),
  role = VALUES(role),
  is_active = VALUES(is_active);

INSERT INTO operator_lane_assignments (operator_id, terminal_name, lane_number)
VALUES
  (3, 'Terminal 2', 1),
  (3, 'Terminal 2', 3)
ON DUPLICATE KEY UPDATE
  terminal_name = VALUES(terminal_name),
  lane_number = VALUES(lane_number);

INSERT INTO scan_events (
  id,
  scan_time,
  terminal_name,
  lane_number,
  scanner_location,
  risk_level,
  threat_category,
  notes,
  sixray_image_filename,
  thumbnail_filename
)
VALUES
  (1, '2026-04-15 08:12:43', 'Terminal 2', 1, 'Terminal 2 Lane 1', 'High', 'firearm', 'Passenger cabin bag flagged for probable compact firearm shape during CT review. Item diverted for immediate armed-response protocol.', NULL, NULL),
  (2, '2026-04-15 08:19:07', 'Terminal 2', 2, 'Terminal 2 Lane 2', 'High', 'knife', 'Bladed article consistent with a prohibited knife detected in hand luggage. Bag isolated and supervisor escalation initiated.', NULL, NULL),
  (3, '2026-04-15 08:44:51', 'Terminal 2', 3, 'Terminal 2 Lane 3', 'High', 'knife', 'Bladed article consistent with a prohibited knife identified in passenger hand baggage.', NULL, NULL),
  (4, '2026-04-15 09:03:16', 'Terminal 2', 1, 'Terminal 2 Lane 1', 'Medium', 'hammer', 'Heavy tool silhouette required secondary inspection due to strike-capable profile.', NULL, NULL),
  (5, '2026-04-15 09:17:28', 'Terminal 2', 2, 'Terminal 2 Lane 2', 'Medium', 'wrench', 'Dense metallic wrench identified among electronics and toiletries during manual image review.', NULL, NULL),
  (6, '2026-04-15 09:52:02', 'Terminal 2', 3, 'Terminal 2 Lane 3', 'Medium', 'pliers', 'Pliers detected in cabin baggage; bag retained for operator verification.', NULL, NULL),
  (7, '2026-04-15 10:11:39', 'Terminal 2', 4, 'Terminal 2 Lane 4', 'Low', 'scissors', 'Small scissors identified in an otherwise low-complexity tray image.', NULL, NULL),
  (8, '2026-04-15 10:34:55', 'Terminal 2', 1, 'Terminal 2 Lane 1', 'Low', 'knife', 'Secondary image review showed a small folding blade requiring standard prohibited-item handling.', NULL, NULL),
  (9, '2026-04-15 11:05:41', 'Terminal 2', 4, 'Terminal 2 Lane 4', 'Low', 'pliers', 'Resolved passenger bag contained compact pliers after post-alert tray search.', NULL, NULL)
ON DUPLICATE KEY UPDATE
  scan_time = VALUES(scan_time),
  terminal_name = VALUES(terminal_name),
  lane_number = VALUES(lane_number),
  scanner_location = VALUES(scanner_location),
  risk_level = VALUES(risk_level),
  threat_category = VALUES(threat_category),
  notes = VALUES(notes);
