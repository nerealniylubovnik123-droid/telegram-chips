/* Telegram Chips Game — SSE instant updates with active admin tracking */
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));
const Database = require('better-sqlite3');

const PORT = process.env.PORT || 3000;
const BOT_TOKEN = process.env.BOT_TOKEN;
const SQLITE_PATH = process.env.SQLITE_PATH || './data.sqlite';
const DEV_ALLOW_UNSAFE = (process.env.DEV_ALLOW_UNSAFE || 'false').toLowerCase() === 'true';

if (!BOT_TOKEN) {
  console.error('ERROR: BOT_TOKEN is required');
  process.exit(1);
}

/* ---------- DB ---------- */
const db = new Database(SQLITE_PATH);
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS game (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  admin_user_id TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  ended_at TEXT
);
CREATE TABLE IF NOT EXISTS player (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  game_id INTEGER NOT NULL,
  user_id TEXT NOT NULL,
  first_name TEXT,
  username TEXT,
  joined_at TEXT NOT NULL DEFAULT (datetime('now')),
  is_admin INTEGER NOT NULL DEFAULT 0,
  UNIQUE(game_id, user_id)
);
CREATE TABLE IF NOT EXISTS chip_tx (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  game_id INTEGER NOT NULL,
  user_id TEXT NOT NULL,
  type TEXT NOT NULL,        -- 'request' | 'return'
  amount INTEGER NOT NULL,
  status TEXT NOT NULL,      -- 'pending' | 'approved' | 'rejected' | 'revoked'
  requested_at TEXT NOT NULL DEFAULT (datetime('now')),
  decided_at TEXT,
  decided_by TEXT
);
`);

const app = express();
app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

/* ---------- Telegram initData ---------- */
function parseInitData(str) {
  if (!str) return {};
  const data = {};
  for (const p of String(str).split('&')) {
    const eq = p.indexOf('=');
    if (eq < 0) continue;
    const k = p.slice(0, eq);
    const v = decodeURIComponent(p.slice(eq + 1).replace(/\+/g, '%20'));
    data[k] = v;
  }
  return data;
}

function verifyInitData(initDataRaw) {
  if (DEV_ALLOW_UNSAFE) return { ok: true, user: null };
  if (!initDataRaw) return { ok: false, error: 'Missing initData' };
  const data = parseInitData(initDataRaw);
  const hash = data.hash;
  if (!hash) return { ok: false, error: 'Missing hash' };
  delete data.hash;
  const dataCheckString = Object.entries(data).map(([k, v]) => `${k}=${v}`).join('\n');
  const secretKey = crypto.createHash('sha256').update(BOT_TOKEN).digest();
  const hmac = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');
  if (hmac !== hash) return { ok: false, error: 'Invalid initData signature' };
  let user = null;
  try { user = JSON.parse(data.user || '{}'); } catch {}
  return { ok: true, user };
}

/* ---------- Middleware (/api) ---------- */
app.use('/api', (req, res, next) => {
  const initDataRaw = req.body?.__initData;
  const unsafeRaw = req.body?.__initDataUnsafe;
  const unsafe = JSON.parse(unsafeRaw || '{}');
  const check = verifyInitData(initDataRaw);
  const user = check.user || unsafe.user;
  if (!user?.id) return res.status(401).json({ ok: false, error: 'Missing user.id' });
  req.tgUser = user;
  req.tgUnsafe = unsafe;
  next();
});

/* ---------- Helpers ---------- */
function getActiveGame() {
  return db.prepare(`SELECT * FROM game WHERE status='active' ORDER BY id DESC LIMIT 1`).get();
}

async function notifyTelegram(userId, text) {
  try {
    await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: userId, text })
    });
  } catch (e) {
    console.error('notifyTelegram error:', e.message);
  }
}

/* =======================================================
   ===============  SSE (Server-Sent Events)  =============
   ======================================================= */
const sseClients = new Set();   // { res, userId }
const activeAdmins = new Set(); // userIds, которые сейчас реально слушают SSE как админ

function sseSend(res, event, data) {
  if (event) res.write(`event: ${event}\n`);
  res.write(`data: ${JSON.stringify(data)}\n\n`);
}

function broadcastTo(predicate, event, data) {
  for (const client of Array.from(sseClients)) {
    try {
      if (predicate(client)) sseSend(client.res, event, data);
    } catch {
      try { client.res.end(); } catch {}
      sseClients.delete(client);
      activeAdmins.delete(client.userId);
    }
  }
}

function isCurrentAdmin(userId) {
  const g = getActiveGame();
  if (!g) return false;
  return String(g.admin_user_id) === String(userId);
}

function pushToAdmins(event, payload) {
  // шлём только тем, кто помечен активным админом (подключён SSE как админ)
  broadcastTo(c => activeAdmins.has(c.userId), event, payload);
}

/* SSE endpoint: принимает initData и initDataUnsafe через query */
app.get('/api/stream', (req, res) => {
  const initDataRaw = req.query.initData;
  const unsafeRaw = req.query.initDataUnsafe || '{}';

  let user = null;
  const check = verifyInitData(initDataRaw);
  if (check.ok && check.user) {
    user = check.user;
  } else {
    try { user = JSON.parse(unsafeRaw || '{}').user || null; } catch { user = null; }
    if (!DEV_ALLOW_UNSAFE && !check.ok) {
      return res.status(401).end(); // при строгом режиме без валидной подписи — отказ
    }
  }
  if (!user?.id) return res.status(401).end();

  // SSE headers
  res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders?.();

  const client = { res, userId: String(user.id) };
  sseClients.add(client);

  // если этот пользователь — текущий админ, отмечаем его активным админом
  if (isCurrentAdmin(client.userId)) activeAdmins.add(client.userId);

  // приветствие и мгновенный статус
  sseSend(res, 'hello', { ok: true, isAdmin: activeAdmins.has(client.userId) });

  // пинги, чтобы соединение не засыпало
  const ping = setInterval(() => {
    try { res.write(': ping\n\n'); } catch {}
  }, 25000);

  req.on('close', () => {
    clearInterval(ping);
    sseClients.delete(client);
    activeAdmins.delete(client.userId);
  });
});

/* ---------- API ---------- */

// Start/join game
app.post('/api/game/start', (req, res) => {
  const user = req.tgUser;
  let game = getActiveGame();

  if (!game) {
    const info = db.transaction(() => {
      const r = db.prepare(`INSERT INTO game (admin_user_id) VALUES (?)`).run(String(user.id));
      const gid = r.lastInsertRowid;
      db.prepare(`INSERT INTO player (game_id,user_id,first_name,username,is_admin)
                  VALUES (?,?,?,?,1)`)
        .run(gid, String(user.id), user.first_name || '', user.username || null);
      return db.prepare(`SELECT * FROM game WHERE id=?`).get(gid);
    })();
    game = info;
  } else {
    db.prepare(`INSERT OR IGNORE INTO player (game_id,user_id,first_name,username,is_admin)
                VALUES (?,?,?,?,0)`)
      .run(game.id, String(user.id), user.first_name || '', user.username || null);
  }

  res.json({ ok: true, game });
});

// Player request/return (Telegram notify + SSE push to admins)
app.post('/api/player/request', async (req, res) => {
  const user = req.tgUser;
  const { amount, type } = req.body || {};
  const a = parseInt(amount, 10);
  if (!['request', 'return'].includes(type)) return res.json({ ok: false, error: 'Invalid type' });
  if (!Number.isInteger(a) || a <= 0) return res.json({ ok: false, error: 'Invalid amount' });

  const game = getActiveGame();
  if (!game) return res.json({ ok: false, error: 'No active game' });

  const txId = db.prepare(`INSERT INTO chip_tx (game_id,user_id,type,amount,status)
                           VALUES (?,?,?,?, 'pending')`)
                 .run(game.id, String(user.id), type, a).lastInsertRowid;

  // Telegram notify админу (если не сам админ создал)
  if (game.admin_user_id && String(game.admin_user_id) !== String(user.id)) {
    const who = `${user.first_name || 'Игрок'}${user.username ? ' @' + user.username : ''}`;
    const msg = type === 'request'
      ? `💰 ${who} просит ${a} фишек`
      : `♻️ ${who} возвращает ${a} фишек`;
    await notifyTelegram(game.admin_user_id, msg);
  }

  // Мгновенно пушим всем активным админам
  pushToAdmins('new_request', {
    id: txId,
    type,
    amount: a,
    user: { id: String(user.id), first_name: user.first_name || '', username: user.username || null }
  });

  res.json({ ok: true, message: 'Request created', id: txId });
});

// Player history
app.post('/api/player/history', (req, res) => {
  const user = req.tgUser;
  const game = getActiveGame();
  if (!game) return res.json({ ok: true, history: [] });

  const rows = db.prepare(`
    SELECT id, type, amount, status, requested_at, decided_at
    FROM chip_tx
    WHERE game_id = ? AND user_id = ?
    ORDER BY id DESC
  `).all(game.id, String(user.id));

  res.json({ ok: true, history: rows });
});

// Admin: pending requests
app.post('/api/admin/pending', (req, res) => {
  const user = req.tgUser;
  const game = getActiveGame();
  if (!game) return res.json({ ok: false, error: 'No active game' });
  if (String(game.admin_user_id) !== String(user.id))
    return res.json({ ok: false, error: 'Not admin' });

  const rows = db.prepare(`
    SELECT t.id,t.user_id,t.type,t.amount,t.status,p.first_name,p.username
    FROM chip_tx t
    JOIN player p ON p.user_id=t.user_id AND p.game_id=t.game_id
    WHERE t.game_id=? AND t.status='pending'
    ORDER BY t.requested_at ASC
  `).all(game.id);

  res.json({ ok: true, requests: rows });
});

// Admin: approve/reject
app.post('/api/admin/decide', (req, res) => {
  const user = req.tgUser;
  const { id, status } = req.body || {};
  if (!['approved', 'rejected'].includes(status)) return res.json({ ok: false, error: 'Bad status' });

  const game = getActiveGame();
  if (!game) return res.json({ ok: false, error: 'No active game' });
  if (String(game.admin_user_id) !== String(user.id))
    return res.json({ ok: false, error: 'Not admin' });

  const tx = db.prepare(`SELECT * FROM chip_tx WHERE id=? AND game_id=?`).get(id, game.id);
  if (!tx) return res.json({ ok: false, error: 'No such tx' });
  if (tx.status !== 'pending') return res.json({ ok: false, error: 'Already decided' });

  db.prepare(`UPDATE chip_tx SET status=?, decided_at=datetime('now'), decided_by=? WHERE id=?`)
    .run(status, String(user.id), id);

  // сообщаем админам, чтобы обновили очередь мгновенно
  pushToAdmins('queue_update', { id, status });

  res.json({ ok: true });
});

// Admin: players summary (diff = returned - issued; + это «в плюсе»)
app.post('/api/admin/players', (req, res) => {
  const user = req.tgUser;
  const game = getActiveGame();
  if (!game) return res.json({ ok: false, error: 'No active game' });
  if (String(game.admin_user_id) !== String(user.id))
    return res.json({ ok: false, error: 'Not admin' });

  const rows = db.prepare(`
    SELECT p.user_id, p.first_name, p.username,
      COALESCE(SUM(CASE WHEN t.type='request' AND t.status='approved' THEN t.amount ELSE 0 END),0) AS issued,
      COALESCE(SUM(CASE WHEN t.type='return'  AND t.status='approved' THEN t.amount ELSE 0 END),0) AS returned
    FROM player p
    LEFT JOIN chip_tx t ON t.user_id = p.user_id AND t.game_id = p.game_id
    WHERE p.game_id = ?
    GROUP BY p.user_id, p.first_name, p.username
    ORDER BY (returned - issued) DESC, p.first_name ASC
  `).all(game.id);

  res.json({ ok: true, players: rows.map(r => ({ ...r, diff: r.returned - r.issued })) });
});

// Admin: change admin
app.post('/api/admin/change', (req, res) => {
  const user = req.tgUser;
  const { new_admin_user_id } = req.body || {};
  const game = getActiveGame();
  if (!game) return res.json({ ok: false, error: 'No active game' });
  if (String(game.admin_user_id) !== String(user.id))
    return res.json({ ok: false, error: 'Not admin' });

  const target = db.prepare(`SELECT * FROM player WHERE game_id=? AND user_id=?`).get(game.id, String(new_admin_user_id));
  if (!target) return res.json({ ok: false, error: 'Target user is not a player' });

  db.transaction(() => {
    db.prepare(`UPDATE game SET admin_user_id=? WHERE id=?`).run(String(new_admin_user_id), game.id);
    db.prepare(`UPDATE player SET is_admin=CASE WHEN user_id=? THEN 1 ELSE 0 END WHERE game_id=?`)
      .run(String(new_admin_user_id), game.id);
  })();

  // обновляем активных админов: старого удалим, новый подключится/переподключится
  for (const u of Array.from(activeAdmins)) {
    if (!isCurrentAdmin(u)) activeAdmins.delete(u);
  }

  // оповещаем всех клиентов о смене админа (клиенты сами переключат роль)
  broadcastTo(() => true, 'admin_changed', { admin_user_id: String(new_admin_user_id) });

  res.json({ ok: true });
});

// Admin: end game
app.post('/api/admin/end', (req, res) => {
  const user = req.tgUser;
  const game = getActiveGame();
  if (!game) return res.json({ ok: false, error: 'No active game' });
  if (String(game.admin_user_id) !== String(user.id))
    return res.json({ ok: false, error: 'Only admin can end the game' });

  db.prepare(`UPDATE game SET status='ended', ended_at=datetime('now') WHERE id=?`).run(game.id);

  // всем сообщаем, что игра завершена
  broadcastTo(() => true, 'game_ended', { id: game.id });

  res.json({ ok: true });
});

/* ---------- Static ---------- */
app.get('*', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
