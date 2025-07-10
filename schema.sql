DROP TABLE IF EXISTS notes;
DROP TABLE IF EXISTS participants;
DROP TABLE IF EXISTS meetings;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL
);

CREATE TABLE meetings (
    id INTEGER PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    meeting_link TEXT,
    start_time TEXT NOT NULL,
    end_time TEXT,
    creator_id INTEGER NOT NULL,
    zoom_meeting_id TEXT,
    FOREIGN KEY (creator_id) REFERENCES users(id)
);

CREATE TABLE participants (
    id INTEGER PRIMARY KEY,
    meeting_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    UNIQUE(meeting_id, user_id),
    FOREIGN KEY (meeting_id) REFERENCES meetings(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE notes (
    id INTEGER PRIMARY KEY,
    meeting_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    content TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (meeting_id) REFERENCES meetings(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE zoom_tokens (
    user_id INTEGER PRIMARY KEY,
    access_token TEXT NOT NULL,
    refresh_token TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
