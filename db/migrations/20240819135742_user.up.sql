-- Add up migration script here

CREATE TABLE IF NOT EXISTS user (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sub TEXT,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        enabled BOOLEAN DEFAULT TRUE,
        admin BOOLEAN DEFAULT FALSE,
        picture TEXT
);

INSERT INTO user (name, email, enabled, admin, picture)  VALUES ('admin@example.com', 'admin@example.com', 1, 1, '/img/admin_icon.webp');
INSERT INTO user (name, email, enabled, admin)  VALUES ('admin02', 'admin02@example.com','0','1');
INSERT INTO user (name, email, enabled, admin)  VALUES ('user01', 'user01@example.com','1','0');
INSERT INTO user (name, email, enabled, admin)  VALUES ('user02', 'user02@example.com','0','0');
