# Telegram Chips — мини‑апп

Этот проект — готовый каркас мини‑приложения для Telegram:
- игра на фишки в групповом чате,
- один админ, остальные игроки,
- запрос/возврат фишек c подтверждением админом,
- возврат (после подтверждения) завершает игру,
- история заявок у игрока, у админа: очередь/сводка/история/настройки.

## 0) Что нужно
- Node.js LTS
- Бот в Telegram (получите токен у @BotFather)
- Railway и GitHub аккаунты

## 1) Локальный запуск
```bash
cp .env.example .env
# откройте .env и вставьте BOT_TOKEN=...
npm install
npm start
```
Откройте http://localhost:3000 и запустите мини‑апп из группового чата (нужен initData с chat.id).

> Для локального теста без Telegram поставьте `DEV_ALLOW_UNSAFE=true` и добавьте заголовки вручную (в prod выключите).

## 2) Переменные окружения
- `BOT_TOKEN` — токен вашего бота
- `PUBLIC_URL` — публичный URL (на Railway будет вида https://...up.railway.app)
- `SQLITE_PATH` — путь к SQLite файлу (по умолчанию ./data.sqlite)
- `DEV_ALLOW_UNSAFE` — **false** в проде; **true** только локально

## 3) Эндпойнты (основные)
- `POST /api/game/start` — создать/получить активную игру для чата
- `GET /api/player/history` — моя история заявок
- `POST /api/player/request` — создать заявку (body: {amount, type:'request'|'return'})
- `POST /api/player/request/:id/revoke` — отозвать свою pending
- `GET /api/admin/queue` — очередь заявок (только админ)
- `POST /api/admin/request/:id/decide` — принять/отклонить (body:{approve:true|false})
- `GET /api/admin/summary` — сводка
- `GET /api/admin/history` — история
- `POST /api/admin/change-admin` — сменить админа (body:{new_admin_user_id})
- `POST /api/admin/end-game` — завершить игру

## 4) Замечания
- Для уведомлений пользователи должны **начать диалог с ботом** (нажать Start).
- Mini App корректно получает `chat.id`, когда её открывают из **группового чата**.
