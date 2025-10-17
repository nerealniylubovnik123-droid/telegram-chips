
/* Minimal Express + SQLite backend for Telegram Mini App (chips game) */
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));
const Database = require('better-sqlite3');

const PORT = process.env.PORT || 3000;
const BOT_TOKEN = process.env.BOT_TOKEN;
const PUBLIC_URL = process.env.PUBLIC_URL || `http://localhost:${PORT}`;
const SQLITE_PATH = process.env.SQLITE_PATH || './data.sqlite';
const DEV_ALLOW_UNSAFE = (process.env.DEV_ALLOW_UNSAFE || 'false').toLowerCase() === 'true';

if (!BOT_TOKEN) {
  console.error('ERROR: BOT_TOKEN is required in .env');
  process.exit(1);
}

// --- DB setup ---
const db = new Database(SQLITE_PATH);
db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS game (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  chat_id TEXT NOT NULL,
  admin_user_id TEXT,
  status TEXT NOT NULL DEFAULT 'active', -- active | ended
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  ended_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_game_chat_status ON game(chat_id, status);

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
  type TEXT NOT NULL,     -- request | return
  amount INTEGER NOT NULL,
  status TEXT NOT NULL,   -- pending | approved | rejected | revoked
  requested_at TEXT NOT NULL DEFAULT (datetime('now')),
  decided_at TEXT,
  decided_by TEXT,
  note TEXT
);
`);

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// --- Telegram initData verification ---
function checkTelegramInitData(initData) {
  if (DEV_ALLOW_UNSAFE) return { ok: true, data: {} };
  if (!initData) return { ok: false, error: 'Missing initData' };

  // Parse querystring-like initData
  const params = {};
  initData.split('&').forEach(kv => {
    const [k, v] = kv.split('=');
    params[k] = decodeURIComponent((v || '').replace(/\+/g, '%20'));
  });

  const hash = params['hash'];
  if (!hash) return { ok: false, error: 'Missing hash' };

  // Build data-check-string
  const checkParams = [];
  for (const [k, v] of Object.entries(params)) {
    if (k === 'hash') continue;
    checkParams.push(`${k}=${v}`);
  }
  checkParams.sort(); // lexicographical
  const dataCheckString = checkParams.join('\n');

  // Create secret key
  const secretKey = crypto.createHash('sha256').update(BOT_TOKEN).digest();

  // HMAC-SHA256
  const hmac = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');

  const ok = hmac === hash;
  return { ok, data: params, error: ok ? null : 'Invalid initData signature' };
}

function getUserFromInitDataUnsafe(initDataUnsafe) {
  try {
    const parsed = JSON.parse(initDataUnsafe);
    return parsed;
  } catch {
    return {};
  }
}

// Helper to get active game by chat id
function getActiveGame(chat_id) {
  return db.prepare(`SELECT * FROM game WHERE chat_id = ? AND status = 'active' ORDER BY id DESC LIMIT 1`).get(chat_id);
}

// Telegram notify
async function tgNotifyUser(user_id, text) {
  try {
    await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ chat_id: user_id, text })
    });
  } catch (e) {
    console.error('notify error', e.message);
  }
}

// --- Middleware: verify initData header ---
app.use((req, res, next) => {
  const initData = req.header('X-Tg-Init-Data') || req.query.initData;
  const check = checkTelegramInitData(initData);
  if (!check.ok) {
    return res.status(401).json({ ok: false, error: check.error, hint: DEV_ALLOW_UNSAFE ? 'DEV_ALLOW_UNSAFE=true to bypass locally' : undefined });
  }
  req.tgInit = check.data;

  // Parse user, chat from initDataUnsafe (if present)
  const initDataUnsafe = req.header('X-Tg-Init-Data-Unsafe') || req.query.initDataUnsafe;
  req.tgUnsafe = initDataUnsafe ? getUserFromInitDataUnsafe(initDataUnsafe) : {};
  next();
});

// --- API routes ---

// Create or get active game for a chat. If none, create and set caller as admin.
app.post('/api/game/start', (req, res) => {
  const chat = req.tgUnsafe.chat;
  const user = req.tgUnsafe.user;
  if (!chat || !chat.id) {
    return res.status(400).json({ ok: false, error: 'Запусти мини‑апп из ГРУППОВОГО чата' });
  }
  if (!user || !user.id) {
    return res.status(400).json({ ok: false, error: 'Нет user.id в initData' });
  }

  let game = getActiveGame(String(chat.id));
  if (!game) {
    const info = db.transaction(() => {
      const insert = db.prepare(`INSERT INTO game (chat_id, admin_user_id, status) VALUES (?, ?, 'active')`);
      const result = insert.run(String(chat.id), String(user.id));
      const game_id = result.lastInsertRowid;

      // insert admin as player
      db.prepare(`INSERT OR IGNORE INTO player (game_id, user_id, first_name, username, is_admin)
                  VALUES (?, ?, ?, ?, 1)`).run(game_id, String(user.id), user.first_name || '', user.username || null);
      return db.prepare(`SELECT * FROM game WHERE id = ?`).get(game_id);
    })();
    game = info;
  } else {
    // ensure user in players
    db.prepare(`INSERT OR IGNORE INTO player (game_id, user_id, first_name, username, is_admin)
                VALUES (?, ?, ?, ?, CASE WHEN ? = admin_user_id THEN 1 ELSE 0 END )`)
      .run(game.id, String(user.id), user.first_name || '', user.username || null, String(user.id));
  }

  return res.json({ ok: true, game });
});

// Get my requests history for current active game
app.get('/api/player/history', (req, res) => {
  const chat = req.tgUnsafe.chat;
  const user = req.tgUnsafe.user;
  if (!chat?.id || !user?.id) return res.status(400).json({ ok: false, error: 'Нет chat/user в initData' });

  const game = getActiveGame(String(chat.id));
  if (!game) return res.json({ ok: true, history: [] });

  const rows = db.prepare(`SELECT id, type, amount, status, requested_at, decided_at FROM chip_tx
                           WHERE game_id = ? AND user_id = ?
                           ORDER BY id DESC`).all(game.id, String(user.id));
  res.json({ ok: true, history: rows });
});

// Create a request (type: request | return)
app.post('/api/player/request', (req, res) => {
  const chat = req.tgUnsafe.chat;
  const user = req.tgUnsafe.user;
  const { amount, type } = req.body || {};
  if (!chat?.id || !user?.id) return res.status(400).json({ ok: false, error: 'Нет chat/user' });

  const game = getActiveGame(String(chat.id));
  if (!game) return res.status(400).json({ ok: false, error: 'Нет активной игры' });

  const a = parseInt(amount, 10);
  if (!['request', 'return'].includes(type)) return res.status(400).json({ ok: false, error: 'Неверный type' });
  if (!Number.isInteger(a) || a <= 0) return res.status(400).json({ ok: false, error: 'amount должен быть целым > 0' });

  db.prepare(`INSERT OR IGNORE INTO player (game_id, user_id, first_name, username)
              VALUES (?, ?, ?, ?)`)
    .run(game.id, String(user.id), user.first_name || '', user.username || null);

  const txId = db.prepare(`INSERT INTO chip_tx (game_id, user_id, type, amount, status) VALUES (?, ?, ?, ?, 'pending')`)
    .run(game.id, String(user.id), type, a).lastInsertRowid;

  // Notify admin
  if (game.admin_user_id) {
    const who = `${user.first_name || 'Игрок'}${user.username ? ' @' + user.username : ''}`;
    const text = type === 'request'
      ? `${who} просит ${a} фишек`
      : `${who} возвращает ${a} фишек (после подтверждения игра завершится)`;
    tgNotifyUser(game.admin_user_id, text).catch(()=>{});
  }

  res.json({ ok: true, id: txId });
});

// Revoke my pending request
app.post('/api/player/request/:id/revoke', (req, res) => {
  const chat = req.tgUnsafe.chat;
  const user = req.tgUnsafe.user;
  const id = parseInt(req.params.id, 10);
  if (!chat?.id || !user?.id) return res.status(400).json({ ok: false, error: 'Нет chat/user' });

  const game = getActiveGame(String(chat.id));
  if (!game) return res.status(400).json({ ok: false, error: 'Нет активной игры' });

  const row = db.prepare(`SELECT * FROM chip_tx WHERE id = ? AND game_id = ? AND user_id = ?`).get(id, game.id, String(user.id));
  if (!row) return res.status(404).json({ ok: false, error: 'Запрос не найден' });
  if (row.status !== 'pending') return res.status(400).json({ ok: false, error: 'Можно отозвать только pending' });

  db.prepare(`UPDATE chip_tx SET status = 'revoked', decided_at = datetime('now') WHERE id = ?`).run(id);
  res.json({ ok: true });
});

// --- Admin helpers ---
function requireAdmin(req, res, next) {
  const chat = req.tgUnsafe.chat;
  const user = req.tgUnsafe.user;
  if (!chat?.id || !user?.id) return res.status(400).json({ ok: false, error: 'Нет chat/user' });

  const game = getActiveGame(String(chat.id));
  if (!game) return res.status(400).json({ ok: false, error: 'Нет активной игры' });
  if (String(game.admin_user_id) !== String(user.id)) {
    return res.status(403).json({ ok: false, error: 'Только админ' });
  }
  req.game = game;
  next();
}

// Admin: queue
app.get('/api/admin/queue', requireAdmin, (req, res) => {
  const rows = db.prepare(`SELECT tx.id, tx.user_id, p.first_name, p.username, tx.type, tx.amount, tx.status, tx.requested_at
                           FROM chip_tx tx
                           LEFT JOIN player p ON p.user_id = tx.user_id AND p.game_id = tx.game_id
                           WHERE tx.game_id = ? AND tx.status = 'pending'
                           ORDER BY tx.id ASC`).all(req.game.id);
  res.json({ ok: true, queue: rows, pending_count: rows.length });
});

// Admin: decide request
app.post('/api/admin/request/:id/decide', requireAdmin, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const approve = !!req.body?.approve;

  const row = db.prepare(`SELECT * FROM chip_tx WHERE id = ? AND game_id = ?`).get(id, req.game.id);
  if (!row) return res.status(404).json({ ok: false, error: 'Запрос не найден' });
  if (row.status !== 'pending') return res.status(400).json({ ok: false, error: 'Запрос уже решён' });

  db.prepare(`UPDATE chip_tx SET status = ?, decided_at = datetime('now'), decided_by = ? WHERE id = ?`)
    .run(approve ? 'approved' : 'rejected', String(req.tgUnsafe.user.id), id);

  // notify player
  const who = db.prepare(`SELECT first_name, username FROM player WHERE game_id = ? AND user_id = ?`)
    .get(req.game.id, row.user_id) || {};
  const text = approve
    ? (row.type === 'request' ? `Вам выдано ${row.amount} фишек` : `Возврат ${row.amount} фишек подтверждён`)
    : `Ваш запрос на ${row.amount} фишек отклонён`;
  tgNotifyUser(row.user_id, text).catch(()=>{});

  // If approved return -> end game
  if (approve && row.type === 'return') {
    db.prepare(`UPDATE game SET status = 'ended', ended_at = datetime('now') WHERE id = ?`).run(req.game.id);
    // Try to broadcast finish to all players (optional)
    try {
      const players = db.prepare(`SELECT DISTINCT user_id FROM player WHERE game_id = ?`).all(req.game.id);
      await Promise.all(players.map(pl => tgNotifyUser(pl.user_id, 'Игра завершена')));
    } catch {}
  }

  res.json({ ok: true });
});

// Admin: summary
app.get('/api/admin/summary', requireAdmin, (req, res) => {
  const rows = db.prepare(`
  SELECT p.user_id, p.first_name, p.username,
         COALESCE((SELECT SUM(amount) FROM chip_tx WHERE game_id = p.game_id AND user_id = p.user_id AND status='approved' AND type='request'),0) AS issued,
         COALESCE((SELECT SUM(amount) FROM chip_tx WHERE game_id = p.game_id AND user_id = p.user_id AND status='approved' AND type='return'),0) AS returned
  FROM player p
  WHERE p.game_id = ?
  ORDER BY (issued - returned) DESC, p.first_name ASC
  `).all(req.game.id);

  const withDiff = rows.map(r => ({...r, diff: (r.issued - r.returned)}));
  res.json({ ok: true, summary: withDiff });
});

// Admin: history
app.get('/api/admin/history', requireAdmin, (req, res) => {
  const rows = db.prepare(`
    SELECT tx.id, tx.user_id, p.first_name, p.username, tx.type, tx.amount, tx.status, tx.requested_at, tx.decided_at
    FROM chip_tx tx
    LEFT JOIN player p ON p.user_id = tx.user_id AND p.game_id = tx.game_id
    WHERE tx.game_id = ?
    ORDER BY tx.id DESC
  `).all(req.game.id);
  res.json({ ok: true, history: rows });
});

// Admin: change admin
app.post('/api/admin/change-admin', requireAdmin, (req, res) => {
  const { new_admin_user_id } = req.body || {};
  if (!new_admin_user_id) return res.status(400).json({ ok: false, error: 'new_admin_user_id обязателен' });

  const exists = db.prepare(`SELECT 1 FROM player WHERE game_id = ? AND user_id = ?`).get(req.game.id, String(new_admin_user_id));
  if (!exists) return res.status(400).json({ ok: false, error: 'Игрок не найден в игре' });

  db.transaction(() => {
    db.prepare(`UPDATE player SET is_admin = 0 WHERE game_id = ?`).run(req.game.id);
    db.prepare(`UPDATE player SET is_admin = 1 WHERE game_id = ? AND user_id = ?`).run(req.game.id, String(new_admin_user_id));
    db.prepare(`UPDATE game SET admin_user_id = ? WHERE id = ?`).run(String(new_admin_user_id), req.game.id);
  })();

  res.json({ ok: true });
});

// Admin: end game manually
app.post('/api/admin/end-game', requireAdmin, (req, res) => {
  db.prepare(`UPDATE game SET status = 'ended', ended_at = datetime('now') WHERE id = ?`).run(req.game.id);
  res.json({ ok: true });
});

// Fallback to SPA
app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server running on ${PORT}`);
});
