/* Telegram Chips Game — full version with in-app admin panel */
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
  type TEXT NOT NULL,
  amount INTEGER NOT NULL,
  status TEXT NOT NULL,
  requested_at TEXT NOT NULL DEFAULT (datetime('now')),
  decided_at TEXT,
  decided_by TEXT
);
`);

const app = express();
app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

/* Parse + verify Telegram initData */
function parseInitData(str) {
  if (!str) return {};
  const data = {};
  const pairs = String(str).split('&');
  for (const p of pairs) {
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

  const dataCheckString = Object.entries(data)
    .map(([k, v]) => `${k}=${v}`)
    .join('\n');

  const secretKey = crypto.createHash('sha256').update(BOT_TOKEN).digest();
  const hmac = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');
  if (hmac !== hash) return { ok: false, error: 'Invalid initData signature' };

  let user = null;
  try { user = JSON.parse(data.user || '{}'); } catch {}
  return { ok: true, user };
}

/* Middleware */
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

/* Helpers */
function getActiveGame() {
  return db.prepare(`SELECT * FROM game WHERE status='active' ORDER BY id DESC LIMIT 1`).get();
}

/* === GAME LOGIC === */

/* 1️⃣ Start or join game */
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

/* 2️⃣ Player makes a chip request or return */
app.post('/api/player/request', (req, res) => {
  const user = req.tgUser;
  const { amount, type } = req.body || {};
  const a = parseInt(amount, 10);
  if (!['request', 'return'].includes(type)) return res.json({ ok: false, error: 'Invalid type' });
  if (!Number.isInteger(a) || a <= 0) return res.json({ ok: false, error: 'Invalid amount' });

  const game = getActiveGame();
  if (!game) return res.json({ ok: false, error: 'No active game' });

  db.prepare(`INSERT INTO chip_tx (game_id,user_id,type,amount,status)
              VALUES (?,?,?,?, 'pending')`)
    .run(game.id, String(user.id), type, a);

  res.json({ ok: true, message: 'Request created' });
});

/* 3️⃣ Admin sees pending requests */
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

/* 4️⃣ Admin approves or rejects */
app.post('/api/admin/decide', (req, res) => {
  const user = req.tgUser;
  const { id, status } = req.body || {};
  const game = getActiveGame();
  if (!game) return res.json({ ok: false, error: 'No active game' });
  if (String(game.admin_user_id) !== String(user.id))
    return res.json({ ok: false, error: 'Not admin' });
  if (!['approved', 'rejected'].includes(status))
    return res.json({ ok: false, error: 'Bad status' });

  const tx = db.prepare(`SELECT * FROM chip_tx WHERE id=? AND game_id=?`).get(id, game.id);
  if (!tx) return res.json({ ok: false, error: 'No such tx' });
  if (tx.status !== 'pending') return res.json({ ok: false, error: 'Already decided' });

  db.prepare(`UPDATE chip_tx SET status=?,decided_at=datetime('now'),decided_by=? WHERE id=?`)
    .run(status, String(user.id), id);

  res.json({ ok: true });
});

/* 5️⃣ Admin summary */
app.post('/api/admin/summary', (req, res) => {
  const user = req.tgUser;
  const game = getActiveGame();
  if (!game) return res.json({ ok: false, error: 'No active game' });
  if (String(game.admin_user_id) !== String(user.id))
    return res.json({ ok: false, error: 'Only admin can view summary' });

  const rows = db.prepare(`
    SELECT p.first_name,p.username,
      COALESCE(SUM(CASE WHEN t.type='request' AND t.status='approved' THEN t.amount ELSE 0 END),0) AS issued,
      COALESCE(SUM(CASE WHEN t.type='return'  AND t.status='approved' THEN t.amount ELSE 0 END),0) AS returned
    FROM player p
    LEFT JOIN chip_tx t ON t.user_id=p.user_id AND t.game_id=p.game_id
    WHERE p.game_id=?
    GROUP BY p.user_id
  `).all(game.id);

  res.json({ ok: true, summary: rows.map(r => ({ ...r, diff: r.issued - r.returned })) });
});

/* 6️⃣ End game */
app.post('/api/admin/end', (req, res) => {
  const user = req.tgUser;
  const game = getActiveGame();
  if (!game) return res.json({ ok: false, error: 'No active game' });
  if (String(game.admin_user_id) !== String(user.id))
    return res.json({ ok: false, error: 'Only admin can end the game' });

  db.prepare(`UPDATE game SET status='ended', ended_at=datetime('now') WHERE id=?`).run(game.id);
  res.json({ ok: true });
});

/* static */
app.get('*', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
