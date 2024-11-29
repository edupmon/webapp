DROP DATABASE IF EXISTS webapp;

DROP USER IF EXISTS 'webapp'@'localhost';

CREATE DATABASE webapp;

CREATE USER 'webapp'@'localhost' IDENTIFIED BY 'webapp';
GRANT SELECT, INSERT, UPDATE, DELETE ON webapp.* TO 'webapp'@'localhost';
FLUSH PRIVILEGES;

USE webapp;

CREATE TABLE audit_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    tablename VARCHAR(256) NOT NULL,
    operation_type ENUM('insert', 'update', 'delete') NOT NULL,
    changed_data JSON NOT NULL,
    change_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE users (
    username VARCHAR(12) NOT NULL PRIMARY KEY,
    user_admin BOOLEAN NOT NULL DEFAULT 0, -- Tracks if the user is an administrator
    user_password VARCHAR(255) NOT NULL,
    password_updated_at TIMESTAMP NULL, -- Tracks when the password was last updated
    enabled BOOLEAN NOT NULL DEFAULT 0, -- Tracks if the user is enabled
    failed_attempts INT DEFAULT 0, -- Tracks failed logins attempts
    locked_until DATETIME DEFAULT NULL, -- Account locked due to too many failed login attempts
    last_login TIMESTAMP NULL, -- Tracks user last login timestamp
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, -- Automatically set at creation
    created_by VARCHAR(12) NOT NULL, -- Tracks who created the user
    updated_at TIMESTAMP NULL ON UPDATE CURRENT_TIMESTAMP, -- Automatically updated timestamp
    updated_by VARCHAR(12) DEFAULT NULL -- Tracks who last updated the user
);

ALTER TABLE users
ADD CONSTRAINT fk_user_created_by FOREIGN KEY (created_by) REFERENCES users(username),
ADD CONSTRAINT fk_user_updated_by FOREIGN KEY (updated_by) REFERENCES users(username);

DELIMITER $$

CREATE TRIGGER users_insert_audit
AFTER INSERT ON users
FOR EACH ROW
BEGIN
    INSERT INTO audit_logs (tablename, operation_type, changed_data)
    VALUES (
        'users',
        'insert',
        JSON_OBJECT(
            'username', NEW.username,
            'user_admin', NEW.user_admin,
            'user_password', NEW.user_password,
            'password_updated_at', NEW.password_updated_at,
            'enabled', NEW.enabled,
            'failed_attempts', NEW.failed_attempts,
            'locked_until', NEW.locked_until,
            'last_login', NEW.last_login,
            'created_at', NEW.created_at,
            'created_by', NEW.created_by,
            'updated_by', NEW.updated_by
        )
    );
END$$

CREATE TRIGGER users_update_audit
AFTER UPDATE ON users
FOR EACH ROW
BEGIN
    INSERT INTO audit_logs (tablename, operation_type, changed_data)
    VALUES (
        'users',
        'update',
        JSON_OBJECT(
            'old_username', OLD.username,
            'new_username', NEW.username,
            'old_user_admin', OLD.user_admin,
            'new_user_admin', NEW.user_admin,
            'old_user_password', OLD.user_password,
            'new_user_password', NEW.user_password,
            'old_password_updated_at', OLD.password_updated_at,
            'new_password_updated_at', NEW.password_updated_at,
            'old_enabled', OLD.enabled,
            'new_enabled', NEW.enabled,
            'old_failed_attempts', OLD.failed_attempts,
            'new_failed_attempts', NEW.failed_attempts,
            'old_locked_until', OLD.locked_until,
            'new_locked_until', NEW.locked_until,
            'old_last_login', OLD.last_login,
            'new_last_login', NEW.last_login,
            'old_created_at', OLD.created_at,
            'new_created_at', NEW.created_at,
            'old_created_by', OLD.created_by,
            'new_created_by', NEW.created_by,
            'old_updated_by', OLD.updated_by,
            'new_updated_by', NEW.updated_by
        )
    );
END$$

CREATE TRIGGER users_delete_audit
AFTER DELETE ON users
FOR EACH ROW
BEGIN
    INSERT INTO audit_logs (tablename, operation_type, changed_data)
    VALUES (
        'users',
        'delete',
        JSON_OBJECT(
            'username', OLD.username,
            'user_admin', OLD.user_admin,
            'user_password', OLD.user_password,
            'password_updated_at', OLD.password_updated_at,
            'enabled', OLD.enabled,
            'failed_attempts', OLD.failed_attempts,
            'locked_until', OLD.locked_until,
            'last_login', OLD.last_login,
            'created_at', OLD.created_at,
            'created_by', OLD.created_by,
            'updated_by', OLD.updated_by
        )
    );
END$$

DELIMITER ;

-- Insert default admin user (Password: admin)
INSERT INTO users (username, user_admin, user_password, password_updated_at, enabled, created_by)
VALUES ('admin', 1, '$2y$10$cIaSdHJkkn/yo5nIaLaXF.z/EEHZMlqdcjfWq.zz8o.NdSNKeb0YS', NOW(), 1, 'admin');

-- Insert default staff user (Password: staff)
INSERT INTO users (username, user_admin, user_password, password_updated_at, enabled, created_by)
VALUES ('staff', 0, '$2y$10$20JJtiQmZ8fPOpFvBdljP.HAW9FXZFS4u2/0/lCGdYg.Kemv28g0.', NOW(), 1, 'staff');
