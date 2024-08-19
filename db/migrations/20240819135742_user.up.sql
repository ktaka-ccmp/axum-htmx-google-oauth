-- Add up migration script here

CREATE TABLE IF NOT EXISTS user (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        enabled BOOLEAN DEFAULT FALSE,
        admin BOOLEAN DEFAULT FALSE,
        password TEXT,
        picture TEXT
);

INSERT INTO user (name, email, enabled, admin, password, picture)  VALUES ('admin@example.com', 'admin@example.com', 1, 1, 'fakehashed_admin', '/img/admin_icon.webp');
INSERT INTO user (name, email, enabled, admin)  VALUES ('admin02', 'admin02@example.com','0','1');
INSERT INTO user (name, email, enabled, admin)  VALUES ('user01', 'user01@example.com','1','0');
INSERT INTO user (name, email, enabled, admin)  VALUES ('user02', 'user02@example.com','0','0');
