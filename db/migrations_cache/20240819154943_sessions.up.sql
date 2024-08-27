-- Add up migration script here
CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT NOT NULL,
        csrf_token TEXT,
        user_id INTEGER,
        email TEXT NOT NULL,
        expires INTEGER
);
