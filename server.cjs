/* Telegram Chips Game — final working signature fix */
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
  chat_id TEXT NOT NULL,
  admin_user_id TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  ended_at TEXT
);
`);

const app = express();
app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

/* ✅ simplified Telegram initData verification — keep field order as sent */
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
  if (DEV_ALLOW_UNSAFE) return { ok: true, user: null, chat: null };
  if (!initDataRaw) return { ok: false, error: 'Missing initData' };

  const data = parseInitData(initDataRaw);
  const hash = data.hash;
  if (!hash) return { ok: false, error: 'Missing hash' };

  delete data.hash;

  // ⚠️ сохраняем порядок, как пришёл, не сортируем
  const dataCheckString = Object.entries(data)
    .map(([k, v]) => `${k}=${v}`)
    .join('\n');

  const secretKey = crypto.createHash('sha256').update(BOT_TOKEN).digest();
  const hmac = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');

  if (hmac !== hash) {
    return { ok: false, error: 'Invalid initData signature' };
  }

  let user = null, chat = null;
  try { user = JSON.parse(data.user || '{}'); } catch {}
  try { chat = JSON.parse(data.chat || '{}'); } catch {}
  return { ok: true, user, chat };
}

/* Middleware */
app.use('/api', (req, res, next) => {
  const initDataRaw = req.body?.__initData;
  const unsafeRaw = req.body?.__initDataUnsafe;
  const check = verifyInitData(initDataRaw);
  if (!check.ok) return res.status(401).json({ ok: false, error: check.error });

  req.tgUser = check.user || {};
  req.tgChat = check.chat || {};
  req.tgUnsafe = JSON.parse(unsafeRaw || '{}');
  next();
});

/* --- Simple Start Handler --- */
app.post('/api/game/start', (req, res) => {
  const user = req.tgUser || req.tgUnsafe.user;
  const chat = req.tgChat || req.tgUnsafe.chat;
  if (!chat?.id) return res.json({ ok: false, error: 'Open from group chat' });
  if (!user?.id) return res.json({ ok: false, error: 'Missing user.id' });

  let game = db.prepare(`SELECT * FROM game WHERE chat_id=? AND status='active' ORDER BY id DESC LIMIT 1`).get(String(chat.id));
  if (!game) {
    const info = db.transaction(() => {
      const res1 = db.prepare(`INSERT INTO game (chat_id, admin_user_id) VALUES (?, ?)`).run(String(chat.id), String(user.id));
      return db.prepare(`SELECT * FROM game WHERE id=?`).get(res1.lastInsertRowid);
    })();
    game = info;
  }

  res.json({ ok: true, game });
});

app.get('*', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.listen(PORT, () => console.log(`Server running on ${PORT}`));
