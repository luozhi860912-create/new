const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const DATA_DIR = path.join(__dirname, 'data');
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
const AUDIO_DIR = path.join(DATA_DIR, 'audio');
const VOICE_DIR = path.join(DATA_DIR, 'voice-samples');
const TTS_DIR = path.join(DATA_DIR, 'tts-cache');

[DATA_DIR, UPLOAD_DIR, AUDIO_DIR, VOICE_DIR, TTS_DIR].forEach(d => {
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
});

const db = new Database(path.join(DATA_DIR, 'inkwell.db'), {
  verbose: process.env.NODE_ENV === 'development' ? console.log : null
});

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    public_key TEXT,
    display_name TEXT DEFAULT '',
    avatar TEXT DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    encrypted_content TEXT NOT NULL,
    iv TEXT NOT NULL,
    reply_to INTEGER,
    msg_type TEXT DEFAULT 'text',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_id) REFERENCES users(id),
    FOREIGN KEY (reply_to) REFERENCES messages(id)
  );

  CREATE TABLE IF NOT EXISTS notes (
    id TEXT PRIMARY KEY,
    creator_id INTEGER NOT NULL,
    note_type TEXT NOT NULL DEFAULT 'personal',
    title_encrypted TEXT NOT NULL,
    title_iv TEXT NOT NULL,
    content_encrypted TEXT NOT NULL,
    content_iv TEXT NOT NULL,
    tags TEXT DEFAULT '[]',
    pinned INTEGER DEFAULT 0,
    archived INTEGER DEFAULT 0,
    color TEXT DEFAULT '',
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (creator_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS todos (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    encrypted_text TEXT NOT NULL,
    iv TEXT NOT NULL,
    done INTEGER DEFAULT 0,
    priority INTEGER DEFAULT 0,
    category TEXT DEFAULT '',
    due_date TEXT,
    completed_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS diary (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    encrypted_content TEXT NOT NULL,
    iv TEXT NOT NULL,
    encrypted_title TEXT DEFAULT '',
    title_iv TEXT DEFAULT '',
    entry_date TEXT NOT NULL,
    mood TEXT DEFAULT '',
    weather TEXT DEFAULT '',
    tags TEXT DEFAULT '[]',
    word_count INTEGER DEFAULT 0,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS books (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    encrypted_content TEXT NOT NULL,
    iv TEXT NOT NULL,
    total_chars INTEGER DEFAULT 0,
    read_position INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS audio_files (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    filepath TEXT NOT NULL,
    file_size INTEGER DEFAULT 0,
    duration REAL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS voice_profiles (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    voice_id TEXT NOT NULL,
    sample_paths TEXT DEFAULT '[]',
    is_custom INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS tts_cache (
    id TEXT PRIMARY KEY,
    text_hash TEXT NOT NULL,
    voice_id TEXT NOT NULL,
    filepath TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS pomodoro_records (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    duration INTEGER NOT NULL,
    session_type TEXT DEFAULT 'focus',
    label TEXT DEFAULT '',
    completed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS memos (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    encrypted_content TEXT NOT NULL,
    iv TEXT NOT NULL,
    remind_at DATETIME,
    is_reminded INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE INDEX IF NOT EXISTS idx_messages_created ON messages(created_at);
  CREATE INDEX IF NOT EXISTS idx_notes_type ON notes(note_type);
  CREATE INDEX IF NOT EXISTS idx_notes_creator ON notes(creator_id);
  CREATE INDEX IF NOT EXISTS idx_todos_user ON todos(user_id);
  CREATE INDEX IF NOT EXISTS idx_diary_user_date ON diary(user_id, entry_date);
  CREATE INDEX IF NOT EXISTS idx_books_user ON books(user_id);
  CREATE INDEX IF NOT EXISTS idx_pomodoro_user ON pomodoro_records(user_id);
  CREATE INDEX IF NOT EXISTS idx_memos_remind ON memos(remind_at);
`);

module.exports = { db, DATA_DIR, UPLOAD_DIR, AUDIO_DIR, VOICE_DIR, TTS_DIR };
