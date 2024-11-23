DROP DATABASE IF EXISTS webapp;

DROP USER IF EXISTS 'webapp'@'localhost';

CREATE DATABASE webapp;

CREATE USER 'webapp'@'localhost' IDENTIFIED BY 'webapp';
GRANT SELECT, INSERT, UPDATE, DELETE ON webapp.* TO 'webapp'@'localhost';
FLUSH PRIVILEGES;

USE webapp;

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

-- Insert default admin user (Password: admin)
INSERT INTO users (username, user_admin, user_password, password_updated_at, enabled, created_by)
VALUES ('admin', 1, '$2y$10$cIaSdHJkkn/yo5nIaLaXF.z/EEHZMlqdcjfWq.zz8o.NdSNKeb0YS', NOW(), 1, 'admin');

-- Insert default staff user (Password: staff)
INSERT INTO users (username, user_admin, user_password, password_updated_at, enabled, created_by)
VALUES ('staff', 0, '$2y$10$20JJtiQmZ8fPOpFvBdljP.HAW9FXZFS4u2/0/lCGdYg.Kemv28g0.', NOW(), 1, 'staff');
