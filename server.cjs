/* Telegram Chips Game — fixed final version */
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
  console.error('ERROR: BOT_TOKEN is required');
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

/* ----- simplified Telegram initData check ----- */
function parseInitData(str) {
  if (!str) return {};
  const data = {};
  const pairs = String(str).split('&');
  for (const p of pairs) {
    const [k, v] = p.split('=');
    if (!k) continue;
    data[k] = decodeURIComponent((v || '').replace(/\+/g, '%20'));
  }
  return data;
}

function checkInitData(initDataRaw) {
  if (DEV_ALLOW_UNSAFE) return { ok:true, user:null, chat:null };
  if (!initDataRaw) return { ok:false, error:'Missing initData' };

  const data = parseInitData(initDataRaw);
  const hash = data.hash;
  if (!hash) return { ok:false, error:'Missing hash' };
  delete data.hash;

  const checkString = Object.keys(data)
    .sort()
    .map(k => `${k}=${data[k]}`)
    .join('\n');

  const secret = crypto.createHash('sha256').update(BOT_TOKEN).digest();
  const hmac = crypto.createHmac('sha256', secret).update(checkString).digest('hex');
  if (hmac !== hash) return { ok:false, error:'Invalid initData signature' };

  try {
    const user = JSON.parse(data.user || '{}');
    const chat = JSON.parse(data.chat || '{}');
    return { ok:true, user, chat };
  } catch {
    return { ok:true, user:null, chat:null };
  }
}

app.use('/api', (req, res, next) => {
  const initDataRaw = req.body?.__initData || req.header('X-Tg-Init-Data');
  const unsafeRaw = req.body?.__initDataUnsafe || '{}';
  const check = checkInitData(initDataRaw);
  if (!check.ok) return res.status(401).json({ ok:false, error:check.error });
  req.tgUnsafe = JSON.parse(unsafeRaw || '{}');
  req.tgUser = check.user;
  req.tgChat = check.chat;
  next();
});

function getActiveGame(chat_id) {
  return db.prepare(`SELECT * FROM game WHERE chat_id=? AND status='active' ORDER BY id DESC LIMIT 1`).get(chat_id);
}
async function tgNotify(id,text){ try{
  await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`,
    {method:'POST',headers:{'Content-Type':'application/json'},
     body:JSON.stringify({chat_id:id,text})});
}catch{} }

function startGameHandler(req,res){
  const chat=req.tgChat||req.tgUnsafe.chat, user=req.tgUser||req.tgUnsafe.user;
  if(!chat?.id)return res.json({ok:false,error:'Запусти из группового чата'});
  if(!user?.id)return res.json({ok:false,error:'Нет user.id'});
  let game=getActiveGame(String(chat.id));
  if(!game){
    const row=db.transaction(()=>{
      const r=db.prepare(`INSERT INTO game(chat_id,admin_user_id,status)VALUES(?,?, 'active')`)
        .run(String(chat.id),String(user.id));
      const gid=r.lastInsertRowid;
      db.prepare(`INSERT INTO player(game_id,user_id,first_name,username,is_admin)VALUES(?,?,?,?,1)`)
        .run(gid,String(user.id),user.first_name||'',user.username||null);
      return db.prepare(`SELECT * FROM game WHERE id=?`).get(gid);
    })();
    game=row;
  }else{
    db.prepare(`INSERT OR IGNORE INTO player(game_id,user_id,first_name,username,is_admin)
                VALUES(?,?,?,?,CASE WHEN ?=admin_user_id THEN 1 ELSE 0 END)`)
      .run(game.id,String(user.id),user.first_name||'',user.username||null,String(user.id));
  }
  res.json({ok:true,game});
}
app.post('/api/game/start', startGameHandler);
app.get('/api/game/start', startGameHandler);

/* остальные эндпоинты не нужны пока для проверки */
app.get('*', (_req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
app.listen(PORT,()=>console.log('Server on '+PORT));
