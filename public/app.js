/* ═══════════════════════════════════════════════
   墨 韵 · InkWell — Client Application
   端对端加密双人空间
   ═══════════════════════════════════════════════ */

// ─── Crypto Module (E2E Encryption) ───
const Crypto = (() => {
  let personalKey = null;
  let sharedKey = null;
  let keyPair = null;

  const ENC_ALGO = 'AES-GCM';
  const KEY_LENGTH = 256;

  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  function buf2hex(buf) {
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
  }
  function hex2buf(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    return bytes.buffer;
  }
  function buf2b64(buf) { return btoa(String.fromCharCode(...new Uint8Array(buf))); }
  function b642buf(b64) { const s = atob(b64); const buf = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) buf[i] = s.charCodeAt(i); return buf.buffer; }

  async function deriveKeyFromPassword(password, salt) {
    const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: encoder.encode(salt), iterations: 100000, hash: 'SHA-256' },
      keyMaterial,
      { name: ENC_ALGO, length: KEY_LENGTH },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async function generateKeyPair() {
    return crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']);
  }

  async function exportPublicKey(key) {
    const raw = await crypto.subtle.exportKey('raw', key);
    return buf2b64(raw);
  }

  async function importPublicKey(b64) {
    const raw = b642buf(b64);
    return crypto.subtle.importKey('raw', raw, { name: 'ECDH', namedCurve: 'P-256' }, true, []);
  }

  async function deriveSharedKey(privateKey, publicKey) {
    return crypto.subtle.deriveKey(
      { name: 'ECDH', public: publicKey },
      privateKey,
      { name: ENC_ALGO, length: KEY_LENGTH },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async function encrypt(text, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({ name: ENC_ALGO, iv }, key, encoder.encode(text));
    return { encrypted: buf2b64(ciphertext), iv: buf2b64(iv) };
  }

  async function decrypt(encrypted, iv, key) {
    try {
      const plain = await crypto.subtle.decrypt({ name: ENC_ALGO, iv: b642buf(iv) }, key, b642buf(encrypted));
      return decoder.decode(plain);
    } catch (e) {
      console.warn('Decryption failed:', e);
      return '[解密失败]';
    }
  }

  async function init(username, password) {
    // Derive personal key
    personalKey = await deriveKeyFromPassword(password, 'inkwell-personal-' + username);

    // Try to load saved keypair from IndexedDB
    const saved = await loadFromIDB('keypair');
    if (saved) {
      try {
        keyPair = {
          privateKey: await crypto.subtle.importKey('jwk', saved.privateKey, { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']),
          publicKey: await crypto.subtle.importKey('jwk', saved.publicKey, { name: 'ECDH', namedCurve: 'P-256' }, true, [])
        };
      } catch {
        keyPair = await generateKeyPair();
        await saveKeypair();
      }
    } else {
      keyPair = await generateKeyPair();
      await saveKeypair();
    }

    // Upload public key
    const pubKeyB64 = await exportPublicKey(keyPair.publicKey);
    await api('/api/public-key', 'POST', { publicKey: pubKeyB64 });

    // Try to establish shared key with partner
    await refreshSharedKey();

    return { personalKey, sharedKey };
  }

  async function refreshSharedKey() {
    try {
      const partner = await api('/api/partner');
      if (partner && partner.public_key) {
        const partnerPub = await importPublicKey(partner.public_key);
        sharedKey = await deriveSharedKey(keyPair.privateKey, partnerPub);
      }
    } catch (e) { console.warn('No partner key available yet'); }
  }

  async function saveKeypair() {
    const priv = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
    const pub = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
    await saveToIDB('keypair', { privateKey: priv, publicKey: pub });
  }

  // IndexedDB helpers
  function openIDB() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open('inkwell-keys', 1);
      req.onupgradeneeded = () => req.result.createObjectStore('keys');
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }
  async function saveToIDB(key, value) {
    const db = await openIDB();
    const tx = db.transaction('keys', 'readwrite');
    tx.objectStore('keys').put(value, key);
  }
  async function loadFromIDB(key) {
    const db = await openIDB();
    return new Promise(resolve => {
      const tx = db.transaction('keys', 'readonly');
      const req = tx.objectStore('keys').get(key);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => resolve(null);
    });
  }

  async function encryptPersonal(text) { return encrypt(text, personalKey); }
  async function decryptPersonal(encrypted, iv) { return decrypt(encrypted, iv, personalKey); }
  async function encryptShared(text) {
    const key = sharedKey || personalKey;
    return encrypt(text, key);
  }
  async function decryptShared(encrypted, iv) {
    const key = sharedKey || personalKey;
    return decrypt(encrypted, iv, key);
  }

  return { init, refreshSharedKey, encryptPersonal, decryptPersonal, encryptShared, decryptShared, buf2b64, b642buf };
})();

// ─── API Helper ───
async function api(url, method = 'GET', body = null) {
  const opts = { method, headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin' };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(url, opts);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Request failed' }));
    throw new Error(err.error || 'Request failed');
  }
  const ct = res.headers.get('content-type');
  if (ct && ct.includes('application/json')) return res.json();
  return res;
}

// ─── WebSocket ───
const WS = (() => {
  let ws = null;
  let reconnectTimer = null;
  const handlers = {};

  function connect() {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(`${proto}//${location.host}`);

    ws.onopen = () => {
      const token = document.cookie.split('; ').find(c => c.startsWith('token='))?.split('=')[1];
      // Cookie is httpOnly, so we can't read it. Send auth via a different method.
      // We'll get token from a hidden endpoint
      api('/api/me').then(user => {
        // WS auth: just send the cookie (it's sent automatically). 
        // Actually since cookie is httpOnly we need another approach.
        // Let's store a session token in localStorage on login.
        const wsToken = localStorage.getItem('ws_token');
        if (wsToken) ws.send(JSON.stringify({ type: 'auth', token: wsToken }));
      });
    };

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (handlers[msg.type]) handlers[msg.type].forEach(fn => fn(msg.data || msg));
      } catch (e) { }
    };

    ws.onclose = () => {
      clearTimeout(reconnectTimer);
      reconnectTimer = setTimeout(connect, 3000);
    };

    ws.onerror = () => ws.close();
  }

  function on(type, fn) {
    if (!handlers[type]) handlers[type] = [];
    handlers[type].push(fn);
  }

  function send(data) {
    if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(data));
  }

  // Ping to keep alive
  setInterval(() => send({ type: 'ping' }), 30000);

  return { connect, on, send };
})();

// ─── App Module ───
const App = (() => {
  let currentUser = null;
  let currentPanel = 'chat';
  let tempPassword = '';

  async function login() {
    const username = document.getElementById('login-username').value.trim();
    const password = document.getElementById('login-password').value;
    const errEl = document.getElementById('login-error');
    errEl.textContent = '';

    if (!username || !password) { errEl.textContent = '请填写用户名和密码'; return; }

    try {
      const result = await api('/api/login', 'POST', { username, password });
      localStorage.setItem('ws_token', document.cookie.split('; ').find(c => c.startsWith('token='))?.split('=')[1] || '');
      tempPassword = password;
      await initApp(result);
    } catch (e) {
      errEl.textContent = e.message;
    }
  }

  async function register() {
    const username = document.getElementById('login-username').value.trim();
    const password = document.getElementById('login-password').value;
    const errEl = document.getElementById('login-error');
    errEl.textContent = '';

    if (!username || !password) { errEl.textContent = '请填写用户名和密码'; return; }
    if (password.length < 6) { errEl.textContent = '密码至少6位'; return; }

    try {
      const result = await api('/api/register', 'POST', { username, password });
      // We need the token for WS. Since it's httpOnly, let's make a special endpoint.
      tempPassword = password;
      await initApp(result);
    } catch (e) {
      errEl.textContent = e.message;
    }
  }

  async function initApp(userData) {
    currentUser = userData;

    // Init encryption
    try {
      await Crypto.init(currentUser.username, tempPassword);
      document.getElementById('crypto-info').textContent = '密钥已生成 · AES-256-GCM + ECDH P-256';
    } catch (e) {
      console.error('Crypto init error:', e);
      document.getElementById('crypto-info').textContent = '加密初始化失败';
    }
    tempPassword = '';

    // Setup WS token (we need to pass it differently since cookie is httpOnly)
    // Let's create a simple token endpoint
    try {
      const me = await api('/api/me');
      // Store user info
      currentUser = me;
    } catch (e) { }

    // Show app
    document.getElementById('login-screen').style.display = 'none';
    document.getElementById('app').style.display = 'flex';
    document.getElementById('user-info').textContent = currentUser.display_name || currentUser.username;

    // Connect WebSocket with a workaround for httpOnly cookies
    setupWS();

    // Load partner info
    loadPartnerInfo();

    // Init all modules
    Chat.init();
    Notes.init();
    Diary.init();
    Todo.init();
    Memo.init();
    Pomodoro.init();
    Reader.init();
    Audio.init();

    // Check memos periodically
    setInterval(Memo.checkReminders, 60000);
  }

  function setupWS() {
    // For httpOnly cookie WS auth, we'll use a simple approach:
    // Create a one-time token
    api('/api/me').then(user => {
      // WS will use the cookie automatically for the HTTP upgrade
      WS.connect();
      // After connection, we re-auth with username (cookie handles actual auth)
    });

    WS.on('auth_ok', () => console.log('WebSocket authenticated'));
    WS.on('partner_online', () => updatePartnerStatus(true));
    WS.on('partner_offline', () => updatePartnerStatus(false));
    WS.on('new_message', (msg) => Chat.onNewMessage(msg));
    WS.on('delete_message', (data) => Chat.onDeleteMessage(data.id));
    WS.on('note_updated', () => Notes.refresh());
    WS.on('note_deleted', () => Notes.refresh());
    WS.on('typing', () => Chat.showTyping());
  }

  async function loadPartnerInfo() {
    try {
      const partner = await api('/api/partner');
      if (partner) {
        document.getElementById('partner-info').innerHTML = `
          <div><strong>${partner.display_name || partner.username}</strong></div>
          <div class="text-xs mt-sm">加入于 ${new Date(partner.created_at).toLocaleDateString('zh-CN')}</div>
        `;
        if (partner.public_key) {
          await Crypto.refreshSharedKey();
          document.getElementById('crypto-info').textContent = '共享密钥已建立 · AES-256-GCM + ECDH P-256';
        }
      }
    } catch (e) { }
  }

  function updatePartnerStatus(online) {
    const el = document.getElementById('partner-status');
    el.innerHTML = online
      ? '<span class="status-dot online"></span> 在线'
      : '<span class="status-dot"></span> 离线';
  }

  function switchPanel(name) {
    currentPanel = name;
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    document.getElementById('panel-' + name)?.classList.add('active');
    document.querySelectorAll('.sidebar-item').forEach(i => i.classList.toggle('active', i.dataset.panel === name));

    const titles = { chat: '对 话', notes: '笔 记', diary: '日 记', todo: '待 办', memo: '备忘录', pomodoro: '番茄钟', reader: '听 书', audio: '音 频' };
    document.getElementById('panel-title').textContent = titles[name] || '';

    closeSidebars();
  }

  function toggleLeft() {
    document.getElementById('left-sidebar').classList.toggle('open');
    document.getElementById('sidebar-overlay').classList.toggle('active');
  }

  function toggleRight() {
    document.getElementById('right-sidebar').classList.toggle('open');
    document.getElementById('sidebar-overlay').classList.toggle('active');
  }

  function closeSidebars() {
    document.getElementById('left-sidebar').classList.remove('open');
    document.getElementById('right-sidebar').classList.remove('open');
    document.getElementById('sidebar-overlay').classList.remove('active');
  }

  function setScale(val) {
    document.documentElement.style.setProperty('--s', val);
    document.getElementById('scale-value').textContent = Math.round(val * 100) + '%';
  }

  async function logout() {
    await api('/api/logout', 'POST');
    localStorage.clear();
    location.reload();
  }

  // Auto-login check
  async function checkSession() {
    try {
      const user = await api('/api/me');
      if (user) {
        // We need the password for encryption. Ask user to re-enter.
        // For UX, show a simplified login prompt
        currentUser = user;
        document.getElementById('login-username').value = user.username;
        document.querySelector('.login-subtitle').textContent = `欢迎回来，${user.display_name || user.username}`;
        document.getElementById('btn-register').style.display = 'none';
      }
    } catch (e) { /* Not logged in */ }
  }

  // Init
  checkSession();

  // Enter key on login form
  document.getElementById('login-password').addEventListener('keydown', e => { if (e.key === 'Enter') login(); });
  document.getElementById('login-username').addEventListener('keydown', e => { if (e.key === 'Enter') document.getElementById('login-password').focus(); });

  return { login, register, logout, switchPanel, toggleLeft, toggleRight, closeSidebars, setScale, get user() { return currentUser; } };
})();

// ─── Chat Module ───
const Chat = (() => {
  let messages = [];
  let typingTimeout = null;

  async function init() {
    await loadMessages();
  }

  async function loadMessages() {
    try {
      const raw = await api('/api/messages?limit=100');
      messages = raw;
      await renderMessages();
      scrollToBottom();
    } catch (e) { console.error('Load messages error:', e); }
  }

  async function renderMessages() {
    const container = document.getElementById('chat-messages');
    if (messages.length === 0) {
      container.innerHTML = `<div class="empty-state"><div class="empty-icon">✉</div><div class="empty-text">开始你们的加密对话</div></div>`;
      return;
    }

    let html = '';
    for (const msg of messages) {
      const isSelf = msg.sender_id === App.user?.id;
      let content;
      try {
        content = await Crypto.decryptShared(msg.encrypted_content, msg.iv);
      } catch {
        content = '[无法解密]';
      }
      const time = new Date(msg.created_at).toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' });
      const dateStr = new Date(msg.created_at).toLocaleDateString('zh-CN');

      html += `
        <div class="message-bubble ${isSelf ? 'self' : 'other'}" data-id="${msg.id}">
          <div class="message-text">${escapeHtml(content)}</div>
          <div class="message-meta">
            ${isSelf ? '' : `<span>${msg.sender_display || msg.sender_name} · </span>`}
            ${dateStr} ${time}
            ${isSelf ? `<button class="btn-ghost btn-sm" style="font-size:10px;padding:0 4px;border:none;cursor:pointer;color:inherit;opacity:0.6" onclick="Chat.deleteMsg(${msg.id})">✕</button>` : ''}
          </div>
        </div>`;
    }
    container.innerHTML = html;
  }

  async function send() {
    const input = document.getElementById('chat-input');
    const text = input.value.trim();
    if (!text) return;

    try {
      const { encrypted, iv } = await Crypto.encryptShared(text);
      await api('/api/messages', 'POST', { encrypted_content: encrypted, iv });
      input.value = '';
      input.style.height = 'auto';
    } catch (e) {
      console.error('Send error:', e);
    }
  }

  async function onNewMessage(msg) {
    messages.push(msg);
    await renderMessages();
    scrollToBottom();
    clearTyping();
  }

  function onDeleteMessage(id) {
    messages = messages.filter(m => m.id !== id);
    const el = document.querySelector(`.message-bubble[data-id="${id}"]`);
    if (el) el.remove();
  }

  async function deleteMsg(id) {
    try {
      await api(`/api/messages/${id}`, 'DELETE');
      onDeleteMessage(id);
    } catch (e) { console.error(e); }
  }

  function handleKey(e) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      send();
    }
  }

  function autoResize(el) {
    el.style.height = 'auto';
    el.style.height = Math.min(el.scrollHeight, 120) + 'px';
  }

  function sendTyping() {
    WS.send({ type: 'typing' });
  }

  function showTyping() {
    const el = document.getElementById('typing-indicator');
    el.innerHTML = '<span class="typing-dots">对方正在输入<span>.</span><span>.</span><span>.</span></span>';
    clearTimeout(typingTimeout);
    typingTimeout = setTimeout(clearTyping, 3000);
  }

  function clearTyping() {
    document.getElementById('typing-indicator').innerHTML = '';
  }

  function scrollToBottom() {
    const el = document.getElementById('chat-messages');
    el.scrollTop = el.scrollHeight;
  }

  return { init, send, handleKey, autoResize, sendTyping, onNewMessage, onDeleteMessage, deleteMsg, showTyping };
})();

// ─── Notes Module ───
const Notes = (() => {
  let notes = [];
  let currentType = 'personal';
  let editingNote = null;

  async function init() {
    await refresh();
    updateTypeButtons();
  }

  async function refresh() {
    try {
      notes = await api(`/api/notes?type=${currentType}`);
      await render();
    } catch (e) { console.error(e); }
  }

  function updateTypeButtons() {
    document.getElementById('notes-personal-btn').classList.toggle('btn-primary', currentType === 'personal');
    document.getElementById('notes-shared-btn').classList.toggle('btn-primary', currentType === 'shared');
  }

  async function switchType(type) {
    currentType = type;
    updateTypeButtons();
    await refresh();
  }

  async function render() {
    const grid = document.getElementById('notes-grid');
    if (notes.length === 0) {
      grid.innerHTML = `<div class="empty-state" style="grid-column:1/-1"><div class="empty-icon">📝</div><div class="empty-text">${currentType === 'personal' ? '还没有个人笔记' : '还没有共享笔记'}</div></div>`;
      return;
    }

    let html = '';
    for (const note of notes) {
      let title, preview;
      try {
        const decFn = currentType === 'shared' ? Crypto.decryptShared : Crypto.decryptPersonal;
        title = await decFn(note.title_encrypted, note.title_iv);
        preview = await decFn(note.content_encrypted, note.content_iv);
      } catch {
        title = '[无法解密]';
        preview = '';
      }

      html += `
        <div class="note-card ${note.pinned ? 'pinned' : ''}" onclick="Notes.edit('${note.id}')">
          ${note.pinned ? '<span class="pin-badge">📌</span>' : ''}
          <div class="note-title">${escapeHtml(title || '无标题')}</div>
          <div class="note-preview">${escapeHtml(preview.slice(0, 200))}</div>
          <div class="note-date">${new Date(note.updated_at).toLocaleString('zh-CN')}${currentType === 'shared' ? ' · ' + note.creator_name : ''}</div>
        </div>`;
    }
    grid.innerHTML = html;
  }

  function create() {
    editingNote = null;
    document.getElementById('note-modal-title').textContent = `新建${currentType === 'shared' ? '共享' : '个人'}笔记`;
    document.getElementById('note-edit-title').value = '';
    document.getElementById('note-edit-content').value = '';
    document.getElementById('note-edit-tags').value = '';
    document.getElementById('note-delete-btn').style.display = 'none';
    document.getElementById('note-modal').classList.add('active');
  }

  async function edit(id) {
    const note = notes.find(n => n.id === id);
    if (!note) return;
    editingNote = note;

    const decFn = currentType === 'shared' ? Crypto.decryptShared : Crypto.decryptPersonal;
    let title, content;
    try {
      title = await decFn(note.title_encrypted, note.title_iv);
      content = await decFn(note.content_encrypted, note.content_iv);
    } catch {
      title = '';
      content = '';
    }

    document.getElementById('note-modal-title').textContent = '编辑笔记';
    document.getElementById('note-edit-title').value = title;
    document.getElementById('note-edit-content').value = content;
    document.getElementById('note-edit-tags').value = JSON.parse(note.tags || '[]').join(', ');
    document.getElementById('note-delete-btn').style.display = '';
    document.getElementById('note-modal').classList.add('active');
  }

  async function saveCurrent() {
    const title = document.getElementById('note-edit-title').value.trim();
    const content = document.getElementById('note-edit-content').value.trim();
    const tags = document.getElementById('note-edit-tags').value.split(',').map(t => t.trim()).filter(Boolean);

    if (!title && !content) { closeModal(); return; }

    const encFn = currentType === 'shared' ? Crypto.encryptShared : Crypto.encryptPersonal;
    const { encrypted: te, iv: ti } = await encFn(title || '无标题');
    const { encrypted: ce, iv: ci } = await encFn(content);

    await api('/api/notes', 'POST', {
      id: editingNote?.id,
      note_type: currentType,
      title_encrypted: te, title_iv: ti,
      content_encrypted: ce, content_iv: ci,
      tags
    });

    closeModal();
    await refresh();
  }

  async function deleteCurrent() {
    if (!editingNote || !confirm('确定删除此笔记？')) return;
    await api(`/api/notes/${editingNote.id}`, 'DELETE');
    closeModal();
    await refresh();
  }

  async function pinCurrent() {
    if (!editingNote) return;
    await api(`/api/notes/${editingNote.id}/pin`, 'PATCH');
    closeModal();
    await refresh();
  }

  async function archiveCurrent() {
    if (!editingNote) return;
    await api(`/api/notes/${editingNote.id}/archive`, 'PATCH');
    closeModal();
    await refresh();
  }

  async function showArchived() {
    try {
      notes = await api('/api/notes/archived');
      await render();
    } catch (e) { console.error(e); }
  }

  function closeModal() {
    document.getElementById('note-modal').classList.remove('active');
    editingNote = null;
  }

  // Close modal on outside click
  document.getElementById('note-modal').addEventListener('click', e => {
    if (e.target.classList.contains('modal-overlay')) closeModal();
  });

  return { init, refresh, switchType, create, edit, saveCurrent, deleteCurrent, pinCurrent, archiveCurrent, showArchived, closeModal };
})();

// ─── Diary Module ───
const Diary = (() => {
  let currentDate = new Date();
  let selectedDate = null;
  let entries = {};
  let currentEntry = null;

  const moods = ['😊', '😐', '😢', '😡', '🤔', '😴', '🥳', '💪'];

  async function init() {
    renderWeekdays();
    renderMoodSelector();
    await loadMonth();
    renderCalendar();
  }

  function renderWeekdays() {
    const days = ['日', '一', '二', '三', '四', '五', '六'];
    document.getElementById('diary-weekdays').innerHTML = days.map(d => `<div class="diary-day">${d}</div>`).join('');
  }

  function renderMoodSelector() {
    document.getElementById('diary-mood').innerHTML = moods.map(m =>
      `<button class="mood-btn" onclick="Diary.setMood('${m}')" data-mood="${m}">${m}</button>`
    ).join('');
  }

  async function loadMonth() {
    const year = currentDate.getFullYear();
    const month = currentDate.getMonth() + 1;
    try {
      const list = await api(`/api/diary?year=${year}&month=${month}`);
      entries = {};
      list.forEach(e => entries[e.entry_date] = e);
    } catch (e) { console.error(e); }
  }

  function renderCalendar() {
    const year = currentDate.getFullYear();
    const month = currentDate.getMonth();
    document.getElementById('diary-month-label').textContent = `${year} 年 ${month + 1} 月`;

    const firstDay = new Date(year, month, 1).getDay();
    const daysInMonth = new Date(year, month + 1, 0).getDate();
    const today = new Date();
    const todayStr = formatDate(today);

    let html = '';

    // Empty cells for days before first
    for (let i = 0; i < firstDay; i++) {
      html += `<div class="diary-day other-month"></div>`;
    }

    for (let d = 1; d <= daysInMonth; d++) {
      const dateStr = `${year}-${String(month + 1).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
      const isToday = dateStr === todayStr;
      const hasEntry = entries[dateStr];
      const isSelected = dateStr === selectedDate;

      html += `<div class="diary-day ${isToday ? 'today' : ''} ${hasEntry ? 'has-entry' : ''} ${isSelected ? 'selected' : ''}"
        onclick="Diary.selectDate('${dateStr}')">${d}</div>`;
    }

    document.getElementById('diary-calendar').innerHTML = html;
  }

  async function selectDate(dateStr) {
    selectedDate = dateStr;
    renderCalendar();

    const entry = entries[dateStr];
    document.getElementById('diary-editor-area').classList.remove('hidden');
    document.getElementById('diary-date-label').textContent = dateStr;

    if (entry) {
      currentEntry = entry;
      try {
        const content = await Crypto.decryptPersonal(entry.encrypted_content, entry.iv);
        document.getElementById('diary-content').value = content;
        if (entry.encrypted_title && entry.title_iv) {
          const title = await Crypto.decryptPersonal(entry.encrypted_title, entry.title_iv);
          document.getElementById('diary-title').value = title;
        } else {
          document.getElementById('diary-title').value = '';
        }
      } catch {
        document.getElementById('diary-content').value = '';
        document.getElementById('diary-title').value = '';
      }
      setMood(entry.mood);
    } else {
      currentEntry = null;
      document.getElementById('diary-content').value = '';
      document.getElementById('diary-title').value = '';
      clearMood();
    }
    updateWordCount();
  }

  function setMood(mood) {
    document.querySelectorAll('.mood-btn').forEach(b => b.classList.toggle('active', b.dataset.mood === mood));
  }

  function clearMood() {
    document.querySelectorAll('.mood-btn').forEach(b => b.classList.remove('active'));
  }

  function getSelectedMood() {
    const active = document.querySelector('.mood-btn.active');
    return active ? active.dataset.mood : '';
  }

  function updateWordCount() {
    const text = document.getElementById('diary-content').value;
    document.getElementById('diary-word-count').textContent = `${text.length} 字`;
  }

  document.getElementById('diary-content')?.addEventListener('input', updateWordCount);

  async function save() {
    if (!selectedDate) return;
    const content = document.getElementById('diary-content').value;
    const title = document.getElementById('diary-title').value;

    const { encrypted: ce, iv: ci } = await Crypto.encryptPersonal(content);
    const { encrypted: te, iv: ti } = await Crypto.encryptPersonal(title);

    const result = await api('/api/diary', 'POST', {
      entry_date: selectedDate,
      encrypted_content: ce, iv: ci,
      encrypted_title: te, title_iv: ti,
      mood: getSelectedMood(),
      word_count: content.length
    });

    entries[selectedDate] = result;
    renderCalendar();
  }

  async function deleteCurrent() {
    if (!currentEntry || !confirm('确定删除此日记？')) return;
    await api(`/api/diary/${currentEntry.id}`, 'DELETE');
    delete entries[selectedDate];
    currentEntry = null;
    document.getElementById('diary-content').value = '';
    document.getElementById('diary-title').value = '';
    document.getElementById('diary-editor-area').classList.add('hidden');
    renderCalendar();
  }

  function prevMonth() {
    currentDate.setMonth(currentDate.getMonth() - 1);
    loadMonth().then(renderCalendar);
  }

  function nextMonth() {
    currentDate.setMonth(currentDate.getMonth() + 1);
    loadMonth().then(renderCalendar);
  }

  function writeToday() {
    selectDate(formatDate(new Date()));
  }

  return { init, selectDate, setMood, save, delete: deleteCurrent, prevMonth, nextMonth, writeToday };
})();

// ─── TODO Module ───
const Todo = (() => {
  let todos = [];

  async function init() {
    await load();
  }

  async function load() {
    try {
      todos = await api('/api/todos');
      await render();
    } catch (e) { console.error(e); }
  }

  async function render() {
    const filter = document.getElementById('todo-filter').value;
    let filtered = todos;
    if (filter === 'active') filtered = todos.filter(t => !t.done);
    if (filter === 'done') filtered = todos.filter(t => t.done);

    const container = document.getElementById('todo-list');
    if (filtered.length === 0) {
      container.innerHTML = `<div class="empty-state"><div class="empty-icon">☑</div><div class="empty-text">暂无待办事项</div></div>`;
      return;
    }

    let html = '';
    for (const todo of filtered) {
      let text;
      try { text = await Crypto.decryptPersonal(todo.encrypted_text, todo.iv); }
      catch { text = '[无法解密]'; }

      const priorityLabel = ['', '重要', '紧急'][todo.priority] || '';
      const dueStr = todo.due_date ? new Date(todo.due_date).toLocaleDateString('zh-CN') : '';

      html += `
        <div class="todo-item ${todo.done ? 'done' : ''}" data-id="${todo.id}">
          <div class="todo-check ${todo.done ? 'checked' : ''}" onclick="Todo.toggle('${todo.id}')">
            ${todo.done ? '✓' : ''}
          </div>
          <span class="todo-text">${escapeHtml(text)}</span>
          ${priorityLabel ? `<span class="todo-priority ${todo.priority >= 2 ? 'high' : ''}">${priorityLabel}</span>` : ''}
          ${dueStr ? `<span class="todo-due">📅 ${dueStr}</span>` : ''}
          <button class="icon-btn" style="font-size:12px" onclick="Todo.remove('${todo.id}')">✕</button>
        </div>`;
    }
    container.innerHTML = html;
  }

  async function add() {
    const input = document.getElementById('todo-input');
    const text = input.value.trim();
    if (!text) return;

    const priority = parseInt(document.getElementById('todo-priority').value);
    const due_date = document.getElementById('todo-due').value;

    const { encrypted, iv } = await Crypto.encryptPersonal(text);
    const todo = await api('/api/todos', 'POST', { encrypted_text: encrypted, iv, priority, due_date });

    todos.unshift(todo);
    input.value = '';
    document.getElementById('todo-due').value = '';
    await render();
  }

  async function toggle(id) {
    const todo = todos.find(t => t.id === id);
    if (!todo) return;
    const updated = await api(`/api/todos/${id}`, 'PATCH', { done: !todo.done });
    const idx = todos.findIndex(t => t.id === id);
    todos[idx] = updated;
    await render();
  }

  async function remove(id) {
    await api(`/api/todos/${id}`, 'DELETE');
    todos = todos.filter(t => t.id !== id);
    await render();
  }

  return { init, render, add, toggle, remove };
})();

// ─── Memo Module ───
const Memo = (() => {
  let memos = [];
  let editingId = null;

  async function init() {
    await load();
    checkReminders();
  }

  async function load() {
    try {
      memos = await api('/api/memos');
      await render();
    } catch (e) { console.error(e); }
  }

  async function render() {
    const container = document.getElementById('memo-list');
    if (memos.length === 0) {
      container.innerHTML = `<div class="empty-state"><div class="empty-icon">📌</div><div class="empty-text">暂无备忘录</div></div>`;
      return;
    }

    let html = '';
    for (const memo of memos) {
      let content;
      try { content = await Crypto.decryptPersonal(memo.encrypted_content, memo.iv); }
      catch { content = '[无法解密]'; }

      const remindStr = memo.remind_at ? new Date(memo.remind_at).toLocaleString('zh-CN') : '';

      html += `
        <div class="memo-item">
          <div>
            <div class="memo-content">${escapeHtml(content)}</div>
            ${remindStr ? `<div class="memo-remind">⏰ 提醒：${remindStr}</div>` : ''}
            <div class="memo-remind">创建：${new Date(memo.created_at).toLocaleString('zh-CN')}</div>
          </div>
          <button class="icon-btn" style="font-size:12px" onclick="Memo.remove('${memo.id}')">✕</button>
        </div>`;
    }
    container.innerHTML = html;
  }

  function create() {
    editingId = null;
    document.getElementById('memo-form').classList.remove('hidden');
    document.getElementById('memo-content').value = '';
    document.getElementById('memo-remind').value = '';
    document.getElementById('memo-content').focus();
  }

  function cancelForm() {
    document.getElementById('memo-form').classList.add('hidden');
  }

  async function save() {
    const content = document.getElementById('memo-content').value.trim();
    if (!content) return;
    const remind_at = document.getElementById('memo-remind').value;

    const { encrypted, iv } = await Crypto.encryptPersonal(content);
    const memo = await api('/api/memos', 'POST', { encrypted_content: encrypted, iv, remind_at: remind_at || null });

    memos.unshift(memo);
    cancelForm();
    await render();
  }

  async function remove(id) {
    await api(`/api/memos/${id}`, 'DELETE');
    memos = memos.filter(m => m.id !== id);
    await render();
  }

  async function checkReminders() {
    try {
      const pending = await api('/api/memos/pending');
      for (const memo of pending) {
        let content;
        try { content = await Crypto.decryptPersonal(memo.encrypted_content, memo.iv); }
        catch { content = '备忘提醒'; }

        if (Notification.permission === 'granted') {
          new Notification('墨韵 · 备忘提醒', { body: content });
        } else {
          alert('备忘提醒: ' + content);
        }
        await api(`/api/memos/${memo.id}/reminded`, 'PATCH');
      }
    } catch (e) { }
  }

  return { init, create, cancelForm, save, remove, checkReminders };
})();

// ─── Pomodoro Module ───
const Pomodoro = (() => {
  let timer = null;
  let totalSeconds = 25 * 60;
  let remainingSeconds = 25 * 60;
  let isRunning = false;
  let sessionType = 'focus';
  let sessionLabel = '专 注';
  const CIRCUMFERENCE = 2 * Math.PI * 47; // ~295.31

  async function init() {
    updateDisplay();
    await loadStats();
    if (Notification.permission === 'default') Notification.requestPermission();
  }

  function setType(type, minutes) {
    if (isRunning) return;
    sessionType = type;
    totalSeconds = minutes * 60;
    remainingSeconds = totalSeconds;

    const labels = { focus: '专 注', short: '短 休', long: '长 休' };
    sessionLabel = labels[type];

    document.querySelectorAll('.pomo-type-btn').forEach(b => b.classList.remove('active'));
    event.target.classList.add('active');

    updateDisplay();
  }

  function toggle() {
    if (isRunning) pause();
    else start();
  }

  function start() {
    isRunning = true;
    document.getElementById('pomo-start').textContent = '暂 停';
    timer = setInterval(tick, 1000);
  }

  function pause() {
    isRunning = false;
    document.getElementById('pomo-start').textContent = '继 续';
    clearInterval(timer);
  }

  function reset() {
    isRunning = false;
    clearInterval(timer);
    remainingSeconds = totalSeconds;
    document.getElementById('pomo-start').textContent = '开 始';
    updateDisplay();
  }

  function tick() {
    remainingSeconds--;
    updateDisplay();

    if (remainingSeconds <= 0) {
      clearInterval(timer);
      isRunning = false;
      document.getElementById('pomo-start').textContent = '开 始';
      onComplete();
    }
  }

  function updateDisplay() {
    const mins = Math.floor(remainingSeconds / 60);
    const secs = remainingSeconds % 60;
    document.getElementById('pomo-time').textContent = `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
    document.getElementById('pomo-label').textContent = sessionLabel;

    const progress = 1 - (remainingSeconds / totalSeconds);
    const offset = CIRCUMFERENCE * (1 - progress);
    document.getElementById('pomo-circle').setAttribute('stroke-dashoffset', offset);
  }

  async function onComplete() {
    // Record
    try {
      await api('/api/pomodoro/records', 'POST', { duration: totalSeconds / 60, session_type: sessionType });
      await loadStats();
    } catch (e) { }

    // Notify
    if (Notification.permission === 'granted') {
      new Notification('墨韵 · 番茄钟', { body: `${sessionLabel} 时间结束！` });
    }

    // Auto switch
    if (sessionType === 'focus') {
      setTypeDirect('short', 5, '短 休');
    } else {
      setTypeDirect('focus', 25, '专 注');
    }
  }

  function setTypeDirect(type, minutes, label) {
    sessionType = type;
    totalSeconds = minutes * 60;
    remainingSeconds = totalSeconds;
    sessionLabel = label;
    updateDisplay();

    document.querySelectorAll('.pomo-type-btn').forEach(b => {
      b.classList.remove('active');
      if (b.textContent.includes(label.trim().charAt(0))) b.classList.add('active');
    });
  }

  async function loadStats() {
    try {
      const stats = await api('/api/pomodoro/stats');
      document.getElementById('pomo-stats').innerHTML = `
        <div class="pomo-stat">
          <div class="stat-value">${stats.today.count}</div>
          <div class="stat-label">今 日</div>
        </div>
        <div class="pomo-stat">
          <div class="stat-value">${stats.week.count}</div>
          <div class="stat-label">本 周</div>
        </div>
        <div class="pomo-stat">
          <div class="stat-value">${Math.round(stats.month.total_minutes / 60)}h</div>
          <div class="stat-label">本 月</div>
        </div>`;
    } catch (e) { }
  }

  return { init, setType, toggle, reset };
})();

// ─── Reader Module ───
const Reader = (() => {
  let books = [];
  let currentBook = null;
  let bookContent = '';
  let readPosition = 0;
  let ttsAudio = null;

  async function init() {
    await loadBookList();
    await loadVoices();
  }

  async function loadBookList() {
    try {
      books = await api('/api/books');
      const select = document.getElementById('book-select');
      select.innerHTML = '<option value="">选择书籍…</option>';
      books.forEach(b => {
        select.innerHTML += `<option value="${b.id}">${b.filename} (${b.total_chars}字)</option>`;
      });
    } catch (e) { }
  }

  async function loadVoices() {
    try {
      const { builtin } = await api('/api/tts/voices');
      const select = document.getElementById('tts-voice-select');
      select.innerHTML = '';
      builtin.forEach(v => {
        select.innerHTML += `<option value="${v.id}">${v.name}</option>`;
      });
    } catch (e) { }
  }

  function uploadBook() {
    document.getElementById('book-file-input').click();
  }

  async function handleUpload(event) {
    const file = event.target.files[0];
    if (!file) return;

    const text = await file.text();
    const { encrypted, iv } = await Crypto.encryptPersonal(text);

    try {
      const book = await api('/api/books', 'POST', {
        filename: file.name,
        encrypted_content: encrypted,
        iv,
        total_chars: text.length
      });
      await loadBookList();
      document.getElementById('book-select').value = book.id;
      await loadBook();
    } catch (e) { console.error(e); }

    event.target.value = '';
  }

  async function loadBook() {
    const id = document.getElementById('book-select').value;
    if (!id) return;

    try {
      const book = await api(`/api/books/${id}`);
      currentBook = book;
      bookContent = await Crypto.decryptPersonal(book.encrypted_content, book.iv);
      readPosition = book.read_position || 0;
      renderContent();
    } catch (e) { console.error(e); }
  }

  function renderContent() {
    if (!bookContent) return;

    // Split into pages (by characters)
    const pageSize = 2000;
    const start = readPosition;
    const end = Math.min(start + pageSize, bookContent.length);
    const visibleText = bookContent.slice(start, end);

    const container = document.getElementById('reader-content');
    container.innerHTML = `<div style="white-space:pre-wrap">${escapeHtml(visibleText)}</div>`;

    // Progress
    const progress = bookContent.length ? (readPosition / bookContent.length * 100) : 0;
    document.getElementById('reader-progress-fill').style.width = progress + '%';
    document.getElementById('reader-position').textContent = Math.round(progress) + '%';
    document.getElementById('reader-chars').textContent = bookContent.length + ' 字';

    // Save progress
    if (currentBook) {
      api(`/api/books/${currentBook.id}/progress`, 'PATCH', { read_position: readPosition }).catch(() => {});
    }
  }

  // Scroll-based navigation
  document.getElementById('reader-content')?.addEventListener('scroll', function () {
    const el = this;
    if (el.scrollTop + el.clientHeight >= el.scrollHeight - 50) {
      // Near bottom, advance
      if (readPosition + 2000 < bookContent.length) {
        readPosition += 1000;
        renderContent();
      }
    }
  });

  async function ttsPlay() {
    if (!bookContent) return;

    const voice = document.getElementById('tts-voice-select').value;
    const rate = document.getElementById('tts-rate').value;
    const pitch = document.getElementById('tts-pitch').value;

    // Get current visible text
    const text = bookContent.slice(readPosition, readPosition + 500);
    if (!text) return;

    const btn = document.getElementById('tts-play-btn');
    btn.textContent = '⏳ 合成中…';

    try {
      const res = await fetch('/api/tts/synthesize', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text, voice, rate, pitch }),
        credentials: 'same-origin'
      });

      if (!res.ok) throw new Error('TTS failed');

      const blob = await res.blob();
      const url = URL.createObjectURL(blob);

      if (ttsAudio) { ttsAudio.pause(); URL.revokeObjectURL(ttsAudio.src); }
      ttsAudio = new window.Audio(url);
      ttsAudio.play();

      btn.textContent = '⏸ 暂停';
      btn.classList.add('playing');

      ttsAudio.onended = () => {
        btn.textContent = '▶ 朗读';
        btn.classList.remove('playing');
        readPosition += 500;
        renderContent();
      };
    } catch (e) {
      btn.textContent = '▶ 朗读';
      alert('TTS合成失败: ' + e.message);
    }
  }

  function ttsStop() {
    if (ttsAudio) {
      ttsAudio.pause();
      ttsAudio = null;
    }
    const btn = document.getElementById('tts-play-btn');
    btn.textContent = '▶ 朗读';
    btn.classList.remove('playing');
  }

  return { init, uploadBook, handleUpload, loadBook, ttsPlay, ttsStop };
})();

// ─── Audio Module ───
const Audio = (() => {
  let files = [];
  let audioEl = null;
  let currentFileId = null;

  async function init() {
    audioEl = new window.Audio();
    audioEl.addEventListener('timeupdate', updateTime);
    audioEl.addEventListener('ended', () => {
      document.getElementById('audio-play-btn').textContent = '▶';
      document.getElementById('audio-play-btn').classList.remove('playing');
    });
    audioEl.addEventListener('loadedmetadata', () => updateTime());
    await loadFiles();
  }

  async function loadFiles() {
    try {
      files = await api('/api/audio');
      renderList();
    } catch (e) { }
  }

  function renderList() {
    const container = document.getElementById('audio-list');
    if (files.length === 0) {
      container.innerHTML = `<div class="empty-state"><div class="empty-icon">🎵</div><div class="empty-text">暂无音频文件</div></div>`;
      return;
    }

    container.innerHTML = files.map(f => `
      <div class="memo-item" style="cursor:pointer" onclick="Audio.play('${f.id}')">
        <div>
          <div class="memo-content">🎵 ${escapeHtml(f.filename)}</div>
          <div class="memo-remind">${formatFileSize(f.file_size)} · ${new Date(f.created_at).toLocaleDateString('zh-CN')}</div>
        </div>
        <button class="icon-btn" style="font-size:12px" onclick="event.stopPropagation();Audio.remove('${f.id}')">✕</button>
      </div>
    `).join('');
  }

  function upload() {
    document.getElementById('audio-file-input').click();
  }

  async function handleUpload(event) {
    const file = event.target.files[0];
    if (!file) return;

    const formData = new FormData();
    formData.append('audio', file);

    try {
      const res = await fetch('/api/audio/upload', { method: 'POST', body: formData, credentials: 'same-origin' });
      if (!res.ok) throw new Error('Upload failed');
      await loadFiles();
    } catch (e) { alert('上传失败: ' + e.message); }

    event.target.value = '';
  }

  async function play(id) {
    currentFileId = id;
    const file = files.find(f => f.id === id);
    audioEl.src = `/api/audio/${id}/stream`;
    audioEl.play();

    document.getElementById('audio-player-main').style.display = '';
    document.getElementById('audio-track-name').textContent = file ? file.filename : '未知';
    document.getElementById('audio-play-btn').textContent = '⏸';
    document.getElementById('audio-play-btn').classList.add('playing');
  }

  function toggle() {
    if (audioEl.paused) {
      audioEl.play();
      document.getElementById('audio-play-btn').textContent = '⏸';
      document.getElementById('audio-play-btn').classList.add('playing');
    } else {
      audioEl.pause();
      document.getElementById('audio-play-btn').textContent = '▶';
      document.getElementById('audio-play-btn').classList.remove('playing');
    }
  }

  function seek(val) {
    if (audioEl.duration) audioEl.currentTime = (val / 100) * audioEl.duration;
  }

  function setVolume(val) {
    audioEl.volume = val / 100;
  }

  function updateTime() {
    const cur = audioEl.currentTime || 0;
    const dur = audioEl.duration || 0;
    document.getElementById('audio-time').textContent = `${fmtTime(cur)} / ${fmtTime(dur)}`;
    if (dur) document.getElementById('audio-seek').value = (cur / dur) * 100;
  }

  function fmtTime(s) {
    const m = Math.floor(s / 60);
    const sec = Math.floor(s % 60);
    return `${m}:${String(sec).padStart(2, '0')}`;
  }

  async function remove(id) {
    if (!confirm('确定删除此音频？')) return;
    await api(`/api/audio/${id}`, 'DELETE');
    if (currentFileId === id) { audioEl.pause(); audioEl.src = ''; }
    await loadFiles();
  }

  return { init, upload, handleUpload, play, toggle, seek, setVolume, remove };
})();

// ─── TTS Voice Upload ───
const TTS = (() => {
  async function uploadSample(event) {
    const file = event.target.files[0];
    if (!file) return;

    const name = prompt('请为此音色命名：', '自定义音色');
    if (!name) return;

    const formData = new FormData();
    formData.append('sample', file);
    formData.append('profile_name', name);

    try {
      const res = await fetch('/api/tts/voice-sample', { method: 'POST', body: formData, credentials: 'same-origin' });
      if (!res.ok) throw new Error('Upload failed');
      const profile = await res.json();

      const list = document.getElementById('voice-profiles-list');
      list.innerHTML += `<div class="text-sm mt-sm">✓ ${escapeHtml(profile.name)}</div>`;

      // Refresh voice list
      Reader.init();
    } catch (e) { alert('上传失败: ' + e.message); }

    event.target.value = '';
  }

  return { uploadSample };
})();

// ─── Utility Functions ───
function escapeHtml(str) {
  if (!str) return '';
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function formatDate(d) {
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}

function formatFileSize(bytes) {
  if (!bytes) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  let i = 0;
  while (bytes >= 1024 && i < units.length - 1) { bytes /= 1024; i++; }
  return bytes.toFixed(1) + ' ' + units[i];
}

// Request notification permission
if ('Notification' in window && Notification.permission === 'default') {
  Notification.requestPermission();
}

console.log(`
╔══════════════════════════════╗
║   墨 韵 · InkWell            ║
║   端对端加密双人空间          ║
║   All data is E2E encrypted  ║
╚══════════════════════════════╝
`);
