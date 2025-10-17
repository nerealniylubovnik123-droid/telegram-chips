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
const SQLITE_PATH = process.env.SQLITE_PATH || './data.sqlite';
const DEV_ALLOW_UNSAFE = (process.env.DEV_ALLOW_UNSAFE || 'false').toLowerCase() === 'true';

if (!BOT_TOKEN) {
  console.error('ERROR: BOT_TOKEN is required in .env');
  process.exit(1);
}

// --- DB ---
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
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

/* ---------- Telegram initData verification (robust) ----------
 * Источники initData (в порядке приоритета):
 *  1) Заголовок:     X-Tg-Init-Data
 *  2) Тело POST:     __initData
 *  3) Query в URL:   ?initData=...
 * Сервер корректно обрабатывает случаи, когда initData попал как ещё раз
 * проценти-рованный параметр (т.е. содержит %26 вместо & и %3D вместо =).
 */
function extractInitDataRaw(req) {
  const fromHeader = req.header('X-Tg-Init-Data');
  if (fromHeader) return fromHeader;
  const fromBody = req.body?.__initData;
  if (fromBody) return fromBody;

  const url = req.originalUrl || '';
  const m = url.match(/[?&]initData=([^&]+)/);
  if (m) return m[1]; // вернём как есть (percent-encoded значение)
  return null;
}

function extractInitDataUnsafeRaw(req) {
  const fromHeader = req.header('X-Tg-Init-Data-Unsafe');
  if (fromHeader) return fromHeader;
  const fromBody = req.body?.__initDataUnsafe;
  if (fromBody) return fromBody;

  const url = req.originalUrl || '';
  const m = url.match(/[?&]initDataUnsafe=([^&]+)/);
  return m ? m[1] : null;
}

/** Нормализуем initData-строку для вычисления подписи.
 * Приходит одно из:
 *  - "query_id=...&user=...&auth_date=...&hash=..."          (сырой)
 *  - "query_id%3D...%26user%3D...%26auth_date%3D...%26hash%3D..." (ещё раз проценти-рованный)
 * Возвращаем строку вида "k=v&k=v..." с уже декодированными `&` и `=`, но
 * с нормальной интерпретацией '+' как пробелов.
 */
function normalizeInitDataString(raw) {
  if (!raw) return null;
  let s = String(raw);

  // Если в значении видны %26 или %3D — это знак, что весь query за-энкоден как одно значение.
  const looksEncodedAsWhole = /%26|%3D|%3d/.test(s);
  if (looksEncodedAsWhole) {
    try { s = decodeURIComponent(s.replace(/\+/g, '%20')); } catch {}
  }
  // теперь s должен выглядеть как "k=v&k=v..."
  return s;
}

function checkTelegramInitData(initDataRaw) {
  if (DEV_ALLOW_UNSAFE) return { ok: true, data: {} };
  if (!initDataRaw) return { ok: false, error: 'Missing initData' };

  const s = normalizeInitDataString(initDataRaw);
  if (!s) return { ok: false, error: 'Missing initData' };

  // Парсим вручную, сохраняя точные значения
  const pairs = s.split('&');
  const items = [];
  let hash = null;

  for (const p of pairs) {
    const i = p.indexOf('=');
    if (i < 0) continue;
    const k = p.slice(0, i);
    const vRaw = p.slice(i + 1);

    if (k === 'hash') {
      hash = vRaw; // hash — шестн. строка, уже нормальная
      continue;
    }

    // Значения Telegram считаем decoded по стандартным правилам query:
    // '+' → пробел, %xx → байт
    let v;
    try { v = decodeURIComponent(vRaw.replace(/\+/g, '%20')); }
    catch { v = vRaw; }
    items.push({ k, v });
  }

  if (!hash) return { ok: false, error: 'Missing hash' };

  // data_check_string: сортируем по ключу, склеиваем `key=value` с ДЕКОДИРОВАННЫМИ values
  items.sort((a, b) => a.k.localeCompare(b.k, 'en'));
  const dataCheckString = items.map(it => `${it.k}=${it.v}`).join('\n');

  // Подпись
  const secretKey = crypto.createHash('sha256').update(BOT_TOKEN).digest();
  const hmac = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');

  const ok = hmac === hash;
  // Сформируем объект данных для удобства
  const dataObj = {};
  for (const it of items) dataObj[it.k] = it.v;
  dataObj.hash = hash;

  return { ok, data: dataObj, error: ok ? null : 'Invalid initData signature' };
}

function parseUnsafeJSON(raw) {
  if (!raw) return {};
  let s = String(raw);
  // Если пришёл проценти-рованный JSON, декодируем (и '+' → пробел)
  try { s = decodeURIComponent(s.replace(/\+/g, '%20')); } catch {}
  try { return JSON.parse(s); } catch { return {}; }
}

// Подключаем проверку только на /api/*
app.use('/api', (req, res, next) => {
  const initDataRaw = extractInitDataRaw(req);
  const unsafeRaw = extractInitDataUnsafeRaw(req);

  const check = checkTelegramInitData(initDataRaw);
  if (!check.ok) return res.status(401).json({ ok:false, error: check.error });

  req.tgInit = check.data;               // разобранные пары
  req.tgUnsafe = parseUnsafeJSON(unsafeRaw); // объект из initDataUnsafe
  next();
});

// Helpers
function getActiveGame(chat_id) {
  return db.prepare(`SELECT * FROM game WHERE chat_id = ? AND status = 'active' ORDER BY id DESC LIMIT 1`).get(chat_id);
}
async function tgNotifyUser(user_id, text) {
  try {
    await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ chat_id: user_id, text })
    });
  } catch {}
}

// --- API ---
function startGameHandler(req, res) {
  const chat = req.tgUnsafe.chat;
  const user = req.tgUnsafe.user;
  if (!chat?.id) return res.status(400).json({ ok:false, error:'Запусти мини-апп из ГРУППОВОГО чата' });
  if (!user?.id) return res.status(400).json({ ok:false, error:'Нет user.id в initData' });

  let game = getActiveGame(String(chat.id));
  if (!game) {
    const info = db.transaction(() => {
      const result = db.prepare(`INSERT INTO game (chat_id, admin_user_id, status) VALUES (?, ?, 'active')`)
        .run(String(chat.id), String(user.id));
      const game_id = result.lastInsertRowid;
      db.prepare(`INSERT OR IGNORE INTO player (game_id, user_id, first_name, username, is_admin)
                  VALUES (?, ?, ?, ?, 1)`)
        .run(game_id, String(user.id), user.first_name || '', user.username || null);
      return db.prepare(`SELECT * FROM game WHERE id = ?`).get(game_id);
    })();
    game = info;
  } else {
    db.prepare(`INSERT OR IGNORE INTO player (game_id, user_id, first_name, username, is_admin)
                VALUES (?, ?, ?, ?, CASE WHEN ? = admin_user_id THEN 1 ELSE 0 END )`)
      .run(game.id, String(user.id), user.first_name || '', user.username || null, String(user.id));
  }
  res.json({ ok:true, game });
}
app.get('/api/game/start', startGameHandler);
app.post('/api/game/start', startGameHandler);

// История игрока
app.get('/api/player/history', (req, res) => {
  const chat = req.tgUnsafe.chat, user = req.tgUnsafe.user;
  if (!chat?.id || !user?.id) return res.status(400).json({ ok:false, error:'Нет chat/user' });
  const game = getActiveGame(String(chat.id));
  if (!game) return res.json({ ok:true, history: [] });
  const rows = db.prepare(`SELECT id, type, amount, status, requested_at, decided_at
                           FROM chip_tx WHERE game_id = ? AND user_id = ? ORDER BY id DESC`)
                 .all(game.id, String(user.id));
  res.json({ ok:true, history: rows });
});

// Создание заявки
app.post('/api/player/request', (req, res) => {
  const chat = req.tgUnsafe.chat, user = req.tgUnsafe.user;
  const { amount, type } = req.body || {};
  if (!chat?.id || !user?.id) return res.status(400).json({ ok:false, error:'Нет chat/user' });
  const game = getActiveGame(String(chat.id));
  if (!game) return res.status(400).json({ ok:false, error:'Нет активной игры' });

  const a = parseInt(amount, 10);
  if (!['request','return'].includes(type)) return res.status(400).json({ ok:false, error:'Неверный type' });
  if (!Number.isInteger(a) || a <= 0) return res.status(400).json({ ok:false, error:'amount должен быть целым > 0' });

  db.prepare(`INSERT OR IGNORE INTO player (game_id, user_id, first_name, username)
              VALUES (?, ?, ?, ?)`)
    .run(game.id, String(user.id), user.first_name || '', user.username || null);

  const txId = db.prepare(`INSERT INTO chip_tx (game_id, user_id, type, amount, status)
                           VALUES (?, ?, ?, ?, 'pending')`)
                 .run(game.id, String(user.id), type, a).lastInsertRowid;

  if (game.admin_user_id) {
    const who = `${user.first_name || 'Игрок'}${user.username ? ' @'+user.username : ''}`;
    const text = type === 'request'
      ? `${who} просит ${a} фишек`
      : `${who} возвращает ${a} фишек (после подтверждения игра завершится)`;
    tgNotifyUser(game.admin_user_id, text).catch(()=>{});
  }
  res.json({ ok:true, id: txId });
});

// Отзыв заявки
app.post('/api/player/request/:id/revoke', (req, res) => {
  const chat = req.tgUnsafe.chat, user = req.tgUnsafe.user;
  const id = parseInt(req.params.id, 10);
  if (!chat?.id || !user?.id) return res.status(400).json({ ok:false, error:'Нет chat/user' });
  const game = getActiveGame(String(chat.id));
  if (!game) return res.status(400).json({ ok:false, error:'Нет активной игры' });

  const row = db.prepare(`SELECT * FROM chip_tx WHERE id = ? AND game_id = ? AND user_id = ?`)
                .get(id, game.id, String(user.id));
  if (!row) return res.status(404).json({ ok:false, error:'Запрос не найден' });
  if (row.status !== 'pending') return res.status(400).json({ ok:false, error:'Можно отозвать только pending' });

  db.prepare(`UPDATE chip_tx SET status='revoked', decided_at=datetime('now') WHERE id = ?`).run(id);
  res.json({ ok:true });
});

// Админ-миддлвар
function requireAdmin(req, res, next) {
  const chat = req.tgUnsafe.chat, user = req.tgUnsafe.user;
  if (!chat?.id || !user?.id) return res.status(400).json({ ok:false, error:'Нет chat/user' });
  const game = getActiveGame(String(chat.id));
  if (!game) return res.status(400).json({ ok:false, error:'Нет активной игры' });
  if (String(game.admin_user_id) !== String(user.id)) return res.status(403).json({ ok:false, error:'Только админ' });
  req.game = game; next();
}

app.get('/api/admin/queue', requireAdmin, (req, res) => {
  const rows = db.prepare(`SELECT tx.id, tx.user_id, p.first_name, p.username, tx.type, tx.amount, tx.status, tx.requested_at
                           FROM chip_tx tx
                           LEFT JOIN player p ON p.user_id = tx.user_id AND p.game_id = tx.game_id
                           WHERE tx.game_id = ? AND tx.status='pending' ORDER BY tx.id ASC`)
                 .all(req.game.id);
  res.json({ ok:true, queue: rows, pending_count: rows.length });
});

app.post('/api/admin/request/:id/decide', requireAdmin, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const approve = !!req.body?.approve;
  const row = db.prepare(`SELECT * FROM chip_tx WHERE id = ? AND game_id = ?`).get(id, req.game.id);
  if (!row) return res.status(404).json({ ok:false, error:'Запрос не найден' });
  if (row.status !== 'pending') return res.status(400).json({ ok:false, error:'Запрос уже решён' });

  db.prepare(`UPDATE chip_tx SET status=?, decided_at=datetime('now'), decided_by=? WHERE id = ?`)
    .run(approve ? 'approved' : 'rejected', String(req.tgUnsafe.user.id), id);

  const text = approve
    ? (row.type === 'request' ? `Вам выдано ${row.amount} фишек` : `Возврат ${row.amount} фишек подтверждён`)
    : `Ваш запрос на ${row.amount} фишек отклонён`;
  tgNotifyUser(row.user_id, text).catch(()=>{});

  if (approve && row.type === 'return') {
    db.prepare(`UPDATE game SET status='ended', ended_at=datetime('now') WHERE id = ?`).run(req.game.id);
    try {
      const players = db.prepare(`SELECT DISTINCT user_id FROM player WHERE game_id = ?`).all(req.game.id);
      await Promise.all(players.map(pl => tgNotifyUser(pl.user_id, 'Игра завершена')));
    } catch {}
  }
  res.json({ ok:true });
});

app.get('/api/admin/summary', requireAdmin, (req, res) => {
  const rows = db.prepare(`
    SELECT p.user_id, p.first_name, p.username,
           COALESCE((SELECT SUM(amount) FROM chip_tx WHERE game_id=p.game_id AND user_id=p.user_id AND status='approved' AND type='request'),0) AS issued,
           COALESCE((SELECT SUM(amount) FROM chip_tx WHERE game_id=p.game_id AND user_id=p.user_id AND status='approved' AND type='return'),0) AS returned
    FROM player p
    WHERE p.game_id = ?
    ORDER BY (issued - returned) DESC, p.first_name ASC
  `).all(req.game.id);
  res.json({ ok:true, summary: rows.map(r => ({...r, diff: r.issued - r.returned})) });
});

app.get('/api/admin/history', requireAdmin, (req, res) => {
  const rows = db.prepare(`
    SELECT tx.id, tx.user_id, p.first_name, p.username, tx.type, tx.amount, tx.status, tx.requested_at, tx.decided_at
    FROM chip_tx tx
    LEFT JOIN player p ON p.user_id = tx.user_id AND p.game_id = tx.game_id
    WHERE tx.game_id = ?
    ORDER BY tx.id DESC
  `).all(req.game.id);
  res.json({ ok:true, history: rows });
});

// SPA
app.get('*', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => console.log(`Server running on ${PORT}`));
