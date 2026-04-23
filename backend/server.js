'use strict';

const express  = require('express');
const path     = require('path');
const bcrypt   = require('bcryptjs');
const cors     = require('cors');
const { Pool } = require('pg');

// ВСТАВЬТЕ СЮДА External Database URL от Render.com
const DATABASE_URL = process.env.DATABASE_URL
  || 'postgresql://kinofinder_user:mVwnszaZ2V0W3WUNPALqRzeIt6Aet878@dpg-d7c72r4p3tds739nrmq0-a.oregon-postgres.render.com/kinofinder';

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL.includes('localhost') ? false : { rejectUnauthorized: false },
});

async function q(text, params) {
  const client = await pool.connect();
  try { return await client.query(text, params); }
  finally { client.release(); }
}

async function initDB() {
  await q(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY, name TEXT NOT NULL,
      phone TEXT NOT NULL UNIQUE, password TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS orders (
      id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
      items JSONB NOT NULL, total NUMERIC NOT NULL,
      delivery TEXT NOT NULL, name TEXT NOT NULL, phone TEXT NOT NULL,
      address TEXT NOT NULL DEFAULT '', comment TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
  const adminCheck = await q("SELECT id FROM users WHERE role = 'admin'");
  if (!adminCheck.rows.length) {
    const hash = await bcrypt.hash('admin123', 10);
    await q('INSERT INTO users (name, phone, password, role) VALUES ($1,$2,$3,$4)',
      ['Администратор', 'admin', hash, 'admin']);
    console.log('[DB] Admin создан: логин=admin пароль=admin123');
  }
  console.log('[DB] Готово');
}

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

async function requireUser(req, res, next) {
  const userId = req.headers['x-user-id'];
  if (!userId) return res.status(401).json({ error: 'Не авторизован' });
  try {
    const r = await q('SELECT * FROM users WHERE id = $1', [userId]);
    if (!r.rows.length) return res.status(401).json({ error: 'Пользователь не найден' });
    req.user = r.rows[0]; next();
  } catch (e) { next(e); }
}

async function requireAdmin(req, res, next) {
  await requireUser(req, res, () => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Нет доступа' });
    next();
  });
}

app.post('/api/auth/register', async (req, res, next) => {
  try {
    const { name, phone, password } = req.body || {};
    if (!name || !phone || !password) return res.status(400).json({ error: 'Заполните все поля' });
    if (String(password).length < 6) return res.status(400).json({ error: 'Пароль минимум 6 символов' });
    const exists = await q('SELECT id FROM users WHERE phone = $1', [phone.trim()]);
    if (exists.rows.length) return res.status(409).json({ error: 'Этот номер уже зарегистрирован' });
    const hash = await bcrypt.hash(String(password), 10);
    const r = await q('INSERT INTO users (name,phone,password) VALUES ($1,$2,$3) RETURNING id,name,phone,role',
      [name.trim(), phone.trim(), hash]);
    res.status(201).json({ user: r.rows[0] });
  } catch (e) { next(e); }
});

app.post('/api/auth/login', async (req, res, next) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'Введите логин и пароль' });
    const r = await q('SELECT * FROM users WHERE phone = $1', [String(username).trim()]);
    if (!r.rows.length) return res.status(401).json({ error: 'Неверный логин или пароль' });
    const user = r.rows[0];
    const ok = await bcrypt.compare(String(password), user.password);
    if (!ok) return res.status(401).json({ error: 'Неверный логин или пароль' });
    res.json({ user: { id: user.id, name: user.name, phone: user.phone, role: user.role } });
  } catch (e) { next(e); }
});

app.post('/api/orders', requireUser, async (req, res, next) => {
  try {
    const { items, total, delivery, name, phone, address, comment } = req.body || {};
    if (!items || !items.length) return res.status(400).json({ error: 'Корзина пуста' });
    if (!total || !delivery || !name || !phone) return res.status(400).json({ error: 'Не хватает данных' });
    const r = await q(
      `INSERT INTO orders (user_id,items,total,delivery,name,phone,address,comment)
       VALUES ($1,$2::jsonb,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [req.user.id, JSON.stringify(items), Number(total), delivery,
       name.trim(), phone.trim(), (address||'').trim(), (comment||'').trim()]
    );
    res.status(201).json({ order: r.rows[0] });
  } catch (e) { next(e); }
});

app.get('/api/orders/all', requireAdmin, async (req, res, next) => {
  try {
    const r = await q('SELECT * FROM orders ORDER BY created_at DESC');
    res.json({ orders: r.rows });
  } catch (e) { next(e); }
});

app.get('/api/orders/user/:userId', requireUser, async (req, res, next) => {
  try {
    const targetId = parseInt(req.params.userId, 10);
    if (req.user.role !== 'admin' && req.user.id !== targetId)
      return res.status(403).json({ error: 'Нет доступа' });
    const r = await q('SELECT * FROM orders WHERE user_id=$1 ORDER BY created_at DESC', [targetId]);
    res.json({ orders: r.rows });
  } catch (e) { next(e); }
});

app.patch('/api/orders/:id/status', requireAdmin, async (req, res, next) => {
  try {
    const { status } = req.body || {};
    const allowed = ['pending','preparing','ready','delivery','done'];
    if (!allowed.includes(status)) return res.status(400).json({ error: 'Недопустимый статус' });
    const r = await q('UPDATE orders SET status=$1 WHERE id=$2 RETURNING id',
      [status, parseInt(req.params.id, 10)]);
    if (!r.rows.length) return res.status(404).json({ error: 'Заказ не найден' });
    res.json({ success: true });
  } catch (e) { next(e); }
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.use((err, req, res, next) => {
  console.error('[ERROR]', err.message);
  res.status(500).json({ error: 'Внутренняя ошибка сервера' });
});

const PORT = process.env.PORT || 3000;
initDB().then(() => {
  app.listen(PORT, () => {
    console.log('\n  Генацвале — запущен на http://localhost:' + PORT);
    console.log('  Admin: admin / admin123\n');
  });
}).catch(err => {
  console.error('\n[FATAL] Ошибка БД:', err.message);
  console.error('Проверьте DATABASE_URL в server.js\n');
  process.exit(1);
});