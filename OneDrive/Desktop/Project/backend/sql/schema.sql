-- Create Database
CREATE DATABASE IF NOT EXISTS shorto_db;
USE shorto_db;

-- 1. Users Table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    fullname VARCHAR(100) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    failed_attempts INT DEFAULT 0,
    locked_until DATETIME NULL,
    is_verified BOOLEAN DEFAULT FALSE,
    otp_code VARCHAR(6),
    otp_expires_at DATETIME,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_email (email),
    INDEX idx_locked (locked_until),
    INDEX idx_created (created_at)
);

-- 2. Flying Messages Table
CREATE TABLE IF NOT EXISTS flying_messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    message_id VARCHAR(100) UNIQUE NOT NULL,
    text TEXT NOT NULL,
    sender_email VARCHAR(255) NOT NULL,
    sender_name VARCHAR(100),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    status ENUM('flying', 'caught', 'expired') DEFAULT 'flying',
    INDEX idx_status_expires (status, expires_at),
    INDEX idx_message_id (message_id),
    INDEX idx_sender (sender_email),
    FOREIGN KEY (sender_email) REFERENCES users(email) ON DELETE CASCADE
);

-- 3. Caught Messages Table
CREATE TABLE IF NOT EXISTS caught_messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    message_id VARCHAR(100) NOT NULL,
    caught_by_email VARCHAR(255) NOT NULL,
    caught_by_name VARCHAR(100),
    caught_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    action_taken ENUM('pending', 'requested', 'passed') DEFAULT 'pending',
    INDEX idx_message (message_id),
    INDEX idx_caught_by (caught_by_email),
    FOREIGN KEY (message_id) REFERENCES flying_messages(message_id) ON DELETE CASCADE,
    FOREIGN KEY (caught_by_email) REFERENCES users(email) ON DELETE CASCADE
);

-- 4. Requests Table
CREATE TABLE IF NOT EXISTS requests (
    id INT AUTO_INCREMENT PRIMARY KEY,
    request_id VARCHAR(100) UNIQUE NOT NULL,
    from_email VARCHAR(255) NOT NULL,
    to_email VARCHAR(255) NOT NULL,
    message_id VARCHAR(100),
    message_text TEXT,
    status ENUM('pending', 'accepted', 'declined') DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_to_email_status (to_email, status),
    INDEX idx_from_email (from_email),
    FOREIGN KEY (from_email) REFERENCES users(email) ON DELETE CASCADE,
    FOREIGN KEY (to_email) REFERENCES users(email) ON DELETE CASCADE
);

-- 5. Chats Table
CREATE TABLE IF NOT EXISTS chats (
    id INT AUTO_INCREMENT PRIMARY KEY,
    chat_id VARCHAR(255) UNIQUE NOT NULL,
    participant1 VARCHAR(255) NOT NULL,
    participant2 VARCHAR(255) NOT NULL,
    last_message TEXT,
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_participants (participant1, participant2),
    FOREIGN KEY (participant1) REFERENCES users(email) ON DELETE CASCADE,
    FOREIGN KEY (participant2) REFERENCES users(email) ON DELETE CASCADE
);

-- 6. Chat Messages Table
CREATE TABLE IF NOT EXISTS chat_messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    chat_id VARCHAR(255) NOT NULL,
    from_email VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    is_read BOOLEAN DEFAULT FALSE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_chat_id (chat_id),
    INDEX idx_created_at (created_at),
    INDEX idx_unread (chat_id, is_read),
    FOREIGN KEY (chat_id) REFERENCES chats(chat_id) ON DELETE CASCADE,
    FOREIGN KEY (from_email) REFERENCES users(email) ON DELETE CASCADE
);

-- 7. Failed Login Logs
CREATE TABLE IF NOT EXISTS failed_logins (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45),
    attempt_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_email_time (email, attempt_time),
    INDEX idx_time (attempt_time)
);

-- 8. OTP Logs (for audit)
CREATE TABLE IF NOT EXISTS otp_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    otp_code VARCHAR(6) NOT NULL,
    purpose ENUM('register', 'login', 'reset') DEFAULT 'register',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_email (email),
    INDEX idx_created (created_at)
);

-- Insert demo user (password: Demo@123)
INSERT INTO users (email, fullname, password_hash, is_verified) VALUES 
('demo@shorto.com', 'Demo User', '$2a$10$N9qo8uLOickgx2ZMRZoMy.Mr4qUqK7qQ6qQ6qQ6qQ6qQ6qQ6qQ6q', TRUE)
ON DUPLICATE KEY UPDATE email=email;

-- Insert sample flying message
INSERT INTO flying_messages (message_id, text, sender_email, sender_name, expires_at) VALUES 
('sample_001', 'Welcome to Shorto! Catch this flying message and start your journey! 🕊️', 'demo@shorto.com', 'Demo User', DATE_ADD(NOW(), INTERVAL 24 HOUR))
ON DUPLICATE KEY UPDATE message_id=message_id;

-- Create stored procedure to clean expired messages
DELIMITER //
CREATE PROCEDURE CleanExpiredMessages()
BEGIN
    UPDATE flying_messages 
    SET status = 'expired' 
    WHERE status = 'flying' AND expires_at < NOW();
END //
DELIMITER ;

-- Create event to run cleanup every hour (if event scheduler is on)
-- SET GLOBAL event_scheduler = ON;
-- CREATE EVENT IF NOT EXISTS CleanExpiredMessagesEvent
-- ON SCHEDULE EVERY 1 HOUR
-- DO CALL CleanExpiredMessages();