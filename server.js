const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const compression = require('compression');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const { execFile } = require('child_process');

const { db, DATA_DIR, UPLOAD_DIR, AUDIO_DIR, VOICE_DIR, TTS_DIR } = require('./db');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'inkwell-secret-change-me-' + crypto.randomBytes(16).toString('hex');
const MAX_USERS = parseInt(process.env.MAX_USERS) || 2;

// ─── Middleware ───
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "blob:"],
      mediaSrc: ["'self'", "blob:"],
      connectSrc: ["'self'", "ws:", "wss:"]
    }
  }
}));
app.use(compression());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// File upload config
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const field = req.route?.path || '';
    if (field.includes('audio')) cb(null, AUDIO_DIR);
    else if (field.includes('voice')) cb(null, VOICE_DIR);
    else cb(null, UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, uuidv4() + ext);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 100 * 1024 * 1024 } // 100MB
});

// ─── Auth Middleware ───
function authMiddleware(req, res, next) {
  const token = req.cookies?.token || req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: '未登录' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = db.prepare('SELECT id, username, display_name FROM users WHERE id = ?').get(decoded.userId);
    if (!user) return res.status(401).json({ error: '用户不存在' });
    req.user = user;
    next();
  } catch (e) {
    return res.status(401).json({ error: '登录已过期' });
  }
}

// ─── Auth Routes ───
app.post('/api/register', (req, res) => {
  const { username, password, displayName } = req.body;
  if (!username || !password) return res.status(400).json({ error: '用户名和密码不能为空' });
  if (username.length < 2 || password.length < 6) return res.status(400).json({ error: '用户名至少2位，密码至少6位' });

  const count = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
  if (count >= MAX_USERS) return res.status(403).json({ error: '已达到最大用户数限制' });

  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existing) return res.status(409).json({ error: '用户名已存在' });

  const hash = bcrypt.hashSync(password, 10);
  const result = db.prepare('INSERT INTO users (username, password_hash, display_name) VALUES (?, ?, ?)').run(username, hash, displayName || username);

  const token = jwt.sign({ userId: result.lastInsertRowid }, JWT_SECRET, { expiresIn: '30d' });
  res.cookie('token', token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000, sameSite: 'strict' });
  res.json({ success: true, userId: result.lastInsertRowid, username });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: '用户名或密码错误' });
  }
  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });
  res.cookie('token', token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000, sameSite: 'strict' });
  res.json({ success: true, userId: user.id, username: user.username, displayName: user.display_name });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ success: true });
});

app.get('/api/me', authMiddleware, (req, res) => {
  const user = db.prepare('SELECT id, username, display_name, public_key, created_at FROM users WHERE id = ?').get(req.user.id);
  res.json(user);
});

app.get('/api/partner', authMiddleware, (req, res) => {
  const partner = db.prepare('SELECT id, username, display_name, public_key, created_at FROM users WHERE id != ?').get(req.user.id);
  res.json(partner || null);
});

app.post('/api/public-key', authMiddleware, (req, res) => {
  const { publicKey } = req.body;
  db.prepare('UPDATE users SET public_key = ? WHERE id = ?').run(publicKey, req.user.id);
  res.json({ success: true });
});

// ─── Chat / Messages ───
app.get('/api/messages', authMiddleware, (req, res) => {
  const { before, limit = 50 } = req.query;
  let stmt;
  if (before) {
    stmt = db.prepare(`
      SELECT m.*, u.username as sender_name, u.display_name as sender_display
      FROM messages m JOIN users u ON m.sender_id = u.id
      WHERE m.id < ? ORDER BY m.id DESC LIMIT ?
    `);
    res.json(stmt.all(before, parseInt(limit)).reverse());
  } else {
    stmt = db.prepare(`
      SELECT m.*, u.username as sender_name, u.display_name as sender_display
      FROM messages m JOIN users u ON m.sender_id = u.id
      ORDER BY m.id DESC LIMIT ?
    `);
    res.json(stmt.all(parseInt(limit)).reverse());
  }
});

app.post('/api/messages', authMiddleware, (req, res) => {
  const { encrypted_content, iv, msg_type = 'text', reply_to } = req.body;
  const result = db.prepare(
    'INSERT INTO messages (sender_id, encrypted_content, iv, msg_type, reply_to) VALUES (?, ?, ?, ?, ?)'
  ).run(req.user.id, encrypted_content, iv, msg_type, reply_to || null);

  const msg = db.prepare(`
    SELECT m.*, u.username as sender_name, u.display_name as sender_display
    FROM messages m JOIN users u ON m.sender_id = u.id WHERE m.id = ?
  `).get(result.lastInsertRowid);

  broadcastWS({ type: 'new_message', data: msg });
  res.json(msg);
});

app.delete('/api/messages/:id', authMiddleware, (req, res) => {
  db.prepare('DELETE FROM messages WHERE id = ? AND sender_id = ?').run(req.params.id, req.user.id);
  broadcastWS({ type: 'delete_message', data: { id: parseInt(req.params.id) } });
  res.json({ success: true });
});

// ─── Notes ───
app.get('/api/notes', authMiddleware, (req, res) => {
  const { type } = req.query;
  let notes;
  if (type === 'shared') {
    notes = db.prepare(`
      SELECT n.*, u.username as creator_name FROM notes n
      JOIN users u ON n.creator_id = u.id
      WHERE n.note_type = 'shared' AND n.archived = 0
      ORDER BY n.pinned DESC, n.updated_at DESC
    `).all();
  } else {
    notes = db.prepare(`
      SELECT n.*, u.username as creator_name FROM notes n
      JOIN users u ON n.creator_id = u.id
      WHERE n.note_type = 'personal' AND n.creator_id = ? AND n.archived = 0
      ORDER BY n.pinned DESC, n.updated_at DESC
    `).all(req.user.id);
  }
  res.json(notes);
});

app.get('/api/notes/archived', authMiddleware, (req, res) => {
  const notes = db.prepare(`
    SELECT n.*, u.username as creator_name FROM notes n
    JOIN users u ON n.creator_id = u.id
    WHERE (n.creator_id = ? OR n.note_type = 'shared') AND n.archived = 1
    ORDER BY n.updated_at DESC
  `).all(req.user.id);
  res.json(notes);
});

app.post('/api/notes', authMiddleware, (req, res) => {
  const { id, note_type, title_encrypted, title_iv, content_encrypted, content_iv, tags, color } = req.body;
  const noteId = id || uuidv4();
  db.prepare(`
    INSERT OR REPLACE INTO notes (id, creator_id, note_type, title_encrypted, title_iv, content_encrypted, content_iv, tags, color, updated_at, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, COALESCE((SELECT created_at FROM notes WHERE id = ?), CURRENT_TIMESTAMP))
  `).run(noteId, req.user.id, note_type || 'personal', title_encrypted, title_iv, content_encrypted, content_iv, JSON.stringify(tags || []), color || '', noteId);

  const note = db.prepare('SELECT n.*, u.username as creator_name FROM notes n JOIN users u ON n.creator_id = u.id WHERE n.id = ?').get(noteId);
  if (note_type === 'shared') broadcastWS({ type: 'note_updated', data: note });
  res.json(note);
});

app.patch('/api/notes/:id/pin', authMiddleware, (req, res) => {
  const note = db.prepare('SELECT * FROM notes WHERE id = ?').get(req.params.id);
  if (!note) return res.status(404).json({ error: '笔记不存在' });
  db.prepare('UPDATE notes SET pinned = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(note.pinned ? 0 : 1, req.params.id);
  res.json({ success: true, pinned: !note.pinned });
});

app.patch('/api/notes/:id/archive', authMiddleware, (req, res) => {
  db.prepare('UPDATE notes SET archived = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

app.patch('/api/notes/:id/restore', authMiddleware, (req, res) => {
  db.prepare('UPDATE notes SET archived = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

app.delete('/api/notes/:id', authMiddleware, (req, res) => {
  db.prepare('DELETE FROM notes WHERE id = ?').run(req.params.id);
  broadcastWS({ type: 'note_deleted', data: { id: req.params.id } });
  res.json({ success: true });
});

// ─── TODO ───
app.get('/api/todos', authMiddleware, (req, res) => {
  const todos = db.prepare('SELECT * FROM todos WHERE user_id = ? ORDER BY done ASC, priority DESC, created_at DESC').all(req.user.id);
  res.json(todos);
});

app.post('/api/todos', authMiddleware, (req, res) => {
  const { encrypted_text, iv, priority = 0, category = '', due_date } = req.body;
  const id = uuidv4();
  db.prepare('INSERT INTO todos (id, user_id, encrypted_text, iv, priority, category, due_date) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .run(id, req.user.id, encrypted_text, iv, priority, category, due_date || null);
  const todo = db.prepare('SELECT * FROM todos WHERE id = ?').get(id);
  res.json(todo);
});

app.patch('/api/todos/:id', authMiddleware, (req, res) => {
  const { encrypted_text, iv, done, priority, category, due_date } = req.body;
  const todo = db.prepare('SELECT * FROM todos WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!todo) return res.status(404).json({ error: 'TODO不存在' });

  if (encrypted_text !== undefined) {
    db.prepare('UPDATE todos SET encrypted_text = ?, iv = ? WHERE id = ?').run(encrypted_text, iv, req.params.id);
  }
  if (done !== undefined) {
    db.prepare('UPDATE todos SET done = ?, completed_at = ? WHERE id = ?').run(done ? 1 : 0, done ? new Date().toISOString() : null, req.params.id);
  }
  if (priority !== undefined) db.prepare('UPDATE todos SET priority = ? WHERE id = ?').run(priority, req.params.id);
  if (category !== undefined) db.prepare('UPDATE todos SET category = ? WHERE id = ?').run(category, req.params.id);
  if (due_date !== undefined) db.prepare('UPDATE todos SET due_date = ? WHERE id = ?').run(due_date, req.params.id);

  res.json(db.prepare('SELECT * FROM todos WHERE id = ?').get(req.params.id));
});

app.delete('/api/todos/:id', authMiddleware, (req, res) => {
  db.prepare('DELETE FROM todos WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
  res.json({ success: true });
});

// ─── Diary ───
app.get('/api/diary', authMiddleware, (req, res) => {
  const { month, year } = req.query;
  let diaries;
  if (month && year) {
    const datePattern = `${year}-${String(month).padStart(2, '0')}%`;
    diaries = db.prepare('SELECT * FROM diary WHERE user_id = ? AND entry_date LIKE ? ORDER BY entry_date DESC').all(req.user.id, datePattern);
  } else {
    diaries = db.prepare('SELECT * FROM diary WHERE user_id = ? ORDER BY entry_date DESC LIMIT 60').all(req.user.id);
  }
  res.json(diaries);
});

app.get('/api/diary/:date', authMiddleware, (req, res) => {
  const entry = db.prepare('SELECT * FROM diary WHERE user_id = ? AND entry_date = ?').get(req.user.id, req.params.date);
  res.json(entry || null);
});

app.post('/api/diary', authMiddleware, (req, res) => {
  const { entry_date, encrypted_content, iv, encrypted_title, title_iv, mood, weather, tags, word_count } = req.body;
  const id = uuidv4();
  const existing = db.prepare('SELECT id FROM diary WHERE user_id = ? AND entry_date = ?').get(req.user.id, entry_date);

  if (existing) {
    db.prepare(`
      UPDATE diary SET encrypted_content = ?, iv = ?, encrypted_title = ?, title_iv = ?,
      mood = ?, weather = ?, tags = ?, word_count = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?
    `).run(encrypted_content, iv, encrypted_title || '', title_iv || '', mood || '', weather || '', JSON.stringify(tags || []), word_count || 0, existing.id);
    res.json(db.prepare('SELECT * FROM diary WHERE id = ?').get(existing.id));
  } else {
    db.prepare(`
      INSERT INTO diary (id, user_id, encrypted_content, iv, encrypted_title, title_iv, entry_date, mood, weather, tags, word_count)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id, req.user.id, encrypted_content, iv, encrypted_title || '', title_iv || '', entry_date, mood || '', weather || '', JSON.stringify(tags || []), word_count || 0);
    res.json(db.prepare('SELECT * FROM diary WHERE id = ?').get(id));
  }
});

app.delete('/api/diary/:id', authMiddleware, (req, res) => {
  db.prepare('DELETE FROM diary WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
  res.json({ success: true });
});

// ─── Books / TXT Reader ───
app.get('/api/books', authMiddleware, (req, res) => {
  const books = db.prepare('SELECT id, user_id, filename, total_chars, read_position, created_at FROM books WHERE user_id = ? ORDER BY created_at DESC').all(req.user.id);
  res.json(books);
});

app.get('/api/books/:id', authMiddleware, (req, res) => {
  const book = db.prepare('SELECT * FROM books WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!book) return res.status(404).json({ error: '书籍不存在' });
  res.json(book);
});

app.post('/api/books', authMiddleware, (req, res) => {
  const { filename, encrypted_content, iv, total_chars } = req.body;
  const id = uuidv4();
  db.prepare('INSERT INTO books (id, user_id, filename, encrypted_content, iv, total_chars) VALUES (?, ?, ?, ?, ?, ?)')
    .run(id, req.user.id, filename, encrypted_content, iv, total_chars || 0);
  res.json({ id, filename, total_chars });
});

app.patch('/api/books/:id/progress', authMiddleware, (req, res) => {
  const { read_position } = req.body;
  db.prepare('UPDATE books SET read_position = ? WHERE id = ? AND user_id = ?').run(read_position, req.params.id, req.user.id);
  res.json({ success: true });
});

app.delete('/api/books/:id', authMiddleware, (req, res) => {
  db.prepare('DELETE FROM books WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
  res.json({ success: true });
});

// ─── Audio Files ───
app.get('/api/audio', authMiddleware, (req, res) => {
  const files = db.prepare('SELECT * FROM audio_files WHERE user_id = ? ORDER BY created_at DESC').all(req.user.id);
  res.json(files);
});

app.post('/api/audio/upload', authMiddleware, upload.single('audio'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: '未选择文件' });
  const id = uuidv4();
  db.prepare('INSERT INTO audio_files (id, user_id, filename, filepath, file_size) VALUES (?, ?, ?, ?, ?)')
    .run(id, req.user.id, req.file.originalname, req.file.filename, req.file.size);
  res.json({ id, filename: req.file.originalname });
});

app.get('/api/audio/:id/stream', authMiddleware, (req, res) => {
  const file = db.prepare('SELECT * FROM audio_files WHERE id = ?').get(req.params.id);
  if (!file) return res.status(404).json({ error: '文件不存在' });
  const filepath = path.join(AUDIO_DIR, file.filepath);
  if (!fs.existsSync(filepath)) return res.status(404).json({ error: '文件已丢失' });
  res.sendFile(filepath);
});

app.delete('/api/audio/:id', authMiddleware, (req, res) => {
  const file = db.prepare('SELECT * FROM audio_files WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (file) {
    const filepath = path.join(AUDIO_DIR, file.filepath);
    if (fs.existsSync(filepath)) fs.unlinkSync(filepath);
    db.prepare('DELETE FROM audio_files WHERE id = ?').run(req.params.id);
  }
  res.json({ success: true });
});

// ─── TTS ───
app.get('/api/tts/voices', authMiddleware, (req, res) => {
  // Return built-in edge-tts voices
  const voices = [
    { id: 'zh-CN-XiaoxiaoNeural', name: '晓晓 (女)', lang: 'zh-CN' },
    { id: 'zh-CN-YunxiNeural', name: '云希 (男)', lang: 'zh-CN' },
    { id: 'zh-CN-YunjianNeural', name: '云健 (男)', lang: 'zh-CN' },
    { id: 'zh-CN-XiaoyiNeural', name: '晓艺 (女)', lang: 'zh-CN' },
    { id: 'zh-CN-YunyangNeural', name: '云扬 (男新闻)', lang: 'zh-CN' },
    { id: 'zh-TW-HsiaoChenNeural', name: '曉臻 (女台)', lang: 'zh-TW' },
    { id: 'en-US-JennyNeural', name: 'Jenny (Female)', lang: 'en-US' },
    { id: 'en-US-GuyNeural', name: 'Guy (Male)', lang: 'en-US' },
    { id: 'en-GB-SoniaNeural', name: 'Sonia (UK Female)', lang: 'en-GB' },
    { id: 'ja-JP-NanamiNeural', name: 'Nanami (日本語女)', lang: 'ja-JP' },
  ];
  // Add custom voice profiles
  const custom = db.prepare('SELECT * FROM voice_profiles WHERE user_id = ?').all(req.user.id);
  res.json({ builtin: voices, custom });
});

app.post('/api/tts/synthesize', authMiddleware, (req, res) => {
  const { text, voice = 'zh-CN-XiaoxiaoNeural', rate = '+0%', pitch = '+0Hz' } = req.body;
  if (!text || text.length > 5000) return res.status(400).json({ error: '文本为空或过长(最多5000字)' });

  const textHash = crypto.createHash('md5').update(text + voice + rate + pitch).digest('hex');
  const cached = db.prepare('SELECT * FROM tts_cache WHERE text_hash = ? AND voice_id = ?').get(textHash, voice);

  if (cached && fs.existsSync(path.join(TTS_DIR, cached.filepath))) {
    return res.sendFile(path.join(TTS_DIR, cached.filepath));
  }

  const outputFile = `${uuidv4()}.mp3`;
  const outputPath = path.join(TTS_DIR, outputFile);

  // Use edge-tts Python package
  const edgeTtsScript = `
import edge_tts, asyncio, sys
async def main():
    c = edge_tts.Communicate(sys.argv[1], sys.argv[2], rate=sys.argv[3], pitch=sys.argv[4])
    await c.save(sys.argv[5])
asyncio.run(main())
`;

  const tempScript = path.join(DATA_DIR, '_tts_temp.py');
  fs.writeFileSync(tempScript, edgeTtsScript);

  execFile('python3', [tempScript, text, voice, rate, pitch, outputPath], { timeout: 30000 }, (err) => {
    if (err) {
      console.error('TTS Error:', err.message);
      // Fallback: try with python instead of python3
      execFile('python', [tempScript, text, voice, rate, pitch, outputPath], { timeout: 30000 }, (err2) => {
        if (err2) return res.status(500).json({ error: 'TTS合成失败，请确保已安装 edge-tts: pip install edge-tts' });
        db.prepare('INSERT INTO tts_cache (id, text_hash, voice_id, filepath) VALUES (?, ?, ?, ?)').run(uuidv4(), textHash, voice, outputFile);
        res.sendFile(outputPath);
      });
      return;
    }
    db.prepare('INSERT INTO tts_cache (id, text_hash, voice_id, filepath) VALUES (?, ?, ?, ?)').run(uuidv4(), textHash, voice, outputFile);
    res.sendFile(outputPath);
  });
});

app.post('/api/tts/voice-sample', authMiddleware, upload.single('sample'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: '未选择文件' });
  const { profile_name } = req.body;
  const profileId = uuidv4();
  const voiceId = 'custom-' + profileId.slice(0, 8);

  db.prepare('INSERT INTO voice_profiles (id, user_id, name, voice_id, sample_paths, is_custom) VALUES (?, ?, ?, ?, ?, 1)')
    .run(profileId, req.user.id, profile_name || '自定义音色', voiceId, JSON.stringify([req.file.filename]));

  res.json({ id: profileId, name: profile_name, voice_id: voiceId });
});

// ─── Pomodoro ───
app.get('/api/pomodoro/records', authMiddleware, (req, res) => {
  const { days = 30 } = req.query;
  const records = db.prepare(`
    SELECT * FROM pomodoro_records WHERE user_id = ?
    AND completed_at >= datetime('now', '-${parseInt(days)} days')
    ORDER BY completed_at DESC
  `).all(req.user.id);
  res.json(records);
});

app.post('/api/pomodoro/records', authMiddleware, (req, res) => {
  const { duration, session_type = 'focus', label = '' } = req.body;
  const id = uuidv4();
  db.prepare('INSERT INTO pomodoro_records (id, user_id, duration, session_type, label) VALUES (?, ?, ?, ?, ?)')
    .run(id, req.user.id, duration, session_type, label);
  res.json({ id, success: true });
});

app.get('/api/pomodoro/stats', authMiddleware, (req, res) => {
  const today = db.prepare(`
    SELECT COUNT(*) as count, COALESCE(SUM(duration), 0) as total_minutes
    FROM pomodoro_records WHERE user_id = ? AND session_type = 'focus'
    AND date(completed_at) = date('now')
  `).get(req.user.id);

  const week = db.prepare(`
    SELECT COUNT(*) as count, COALESCE(SUM(duration), 0) as total_minutes
    FROM pomodoro_records WHERE user_id = ? AND session_type = 'focus'
    AND completed_at >= datetime('now', '-7 days')
  `).get(req.user.id);

  const month = db.prepare(`
    SELECT COUNT(*) as count, COALESCE(SUM(duration), 0) as total_minutes
    FROM pomodoro_records WHERE user_id = ? AND session_type = 'focus'
    AND completed_at >= datetime('now', '-30 days')
  `).get(req.user.id);

  res.json({ today, week, month });
});

// ─── Memos ───
app.get('/api/memos', authMiddleware, (req, res) => {
  const memos = db.prepare('SELECT * FROM memos WHERE user_id = ? ORDER BY created_at DESC').all(req.user.id);
  res.json(memos);
});

app.post('/api/memos', authMiddleware, (req, res) => {
  const { encrypted_content, iv, remind_at } = req.body;
  const id = uuidv4();
  db.prepare('INSERT INTO memos (id, user_id, encrypted_content, iv, remind_at) VALUES (?, ?, ?, ?, ?)')
    .run(id, req.user.id, encrypted_content, iv, remind_at || null);
  res.json(db.prepare('SELECT * FROM memos WHERE id = ?').get(id));
});

app.patch('/api/memos/:id', authMiddleware, (req, res) => {
  const { encrypted_content, iv, remind_at } = req.body;
  db.prepare('UPDATE memos SET encrypted_content = ?, iv = ?, remind_at = ? WHERE id = ? AND user_id = ?')
    .run(encrypted_content, iv, remind_at || null, req.params.id, req.user.id);
  res.json({ success: true });
});

app.delete('/api/memos/:id', authMiddleware, (req, res) => {
  db.prepare('DELETE FROM memos WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
  res.json({ success: true });
});

app.get('/api/memos/pending', authMiddleware, (req, res) => {
  const memos = db.prepare(`
    SELECT * FROM memos WHERE user_id = ? AND remind_at IS NOT NULL
    AND remind_at <= datetime('now') AND is_reminded = 0
  `).all(req.user.id);
  res.json(memos);
});

app.patch('/api/memos/:id/reminded', authMiddleware, (req, res) => {
  db.prepare('UPDATE memos SET is_reminded = 1 WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// ─── WebSocket ───
const wsClients = new Map(); // userId -> ws

function broadcastWS(message) {
  const data = JSON.stringify(message);
  wsClients.forEach((ws) => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(data);
    }
  });
}

function sendToUser(userId, message) {
  const ws = wsClients.get(userId);
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(message));
  }
}

wss.on('connection', (ws, req) => {
  let userId = null;

  ws.on('message', (raw) => {
    try {
      const msg = JSON.parse(raw);

      if (msg.type === 'auth') {
        try {
          const decoded = jwt.verify(msg.token, JWT_SECRET);
          userId = decoded.userId;
          wsClients.set(userId, ws);
          ws.send(JSON.stringify({ type: 'auth_ok', userId }));

          // Notify partner
          const partner = db.prepare('SELECT id FROM users WHERE id != ?').get(userId);
          if (partner) {
            sendToUser(partner.id, { type: 'partner_online', userId });
          }
        } catch (e) {
          ws.send(JSON.stringify({ type: 'auth_error' }));
        }
      }

      if (msg.type === 'typing' && userId) {
        const partner = db.prepare('SELECT id FROM users WHERE id != ?').get(userId);
        if (partner) sendToUser(partner.id, { type: 'typing', userId });
      }

      if (msg.type === 'ping') {
        ws.send(JSON.stringify({ type: 'pong' }));
      }
    } catch (e) { }
  });

  ws.on('close', () => {
    if (userId) {
      wsClients.delete(userId);
      const partner = db.prepare('SELECT id FROM users WHERE id != ?').get(userId);
      if (partner) sendToUser(partner.id, { type: 'partner_offline', userId });
    }
  });
});

// ─── SPA Fallback ───
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─── Start ───
server.listen(PORT, () => {
  console.log(`\n  ╔══════════════════════════════════════╗`);
  console.log(`  ║   墨 韵 · InkWell  已启动            ║`);
  console.log(`  ║   端口: ${PORT}                          ║`);
  console.log(`  ║   地址: http://localhost:${PORT}         ║`);
  console.log(`  ╚══════════════════════════════════════╝\n`);
});
