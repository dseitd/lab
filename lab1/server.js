const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const db = new sqlite3.Database(path.join(__dirname, 'db.sqlite'));
const PORT = process.env.PORT || 3000;

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL
    )
  `);
});

app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'replace-this-secret',
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true },
  })
);

function styles() {
  return `
    <style>
      :root {
        --bg: #f0f2f5;
        --card: #ffffff;
        --text: #222;
        --muted: #6b7280;
        --border: #e5e7eb;
        --primary: #64748b;
        --primary-hover: #4b5563;
      }
      * { box-sizing: border-box; }
      body {
        margin: 0; padding: 0;
        background: var(--bg);
        color: var(--text);
        font-family: -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
        display: grid;
        min-height: 100vh;
        place-items: center;
      }
      .card {
        width: 100%;
        max-width: 380px;
        background: var(--card);
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 22px;
        box-shadow: 0 6px 20px rgba(0,0,0,0.06);
      }
      h1, h2 {
        margin: 0 0 12px;
        font-size: 20px;
        font-weight: 600;
        letter-spacing: 0.2px;
      }
      p { margin: 8px 0; color: var(--muted); }
      form { margin: 14px 0; }
      label { display: block; margin-bottom: 6px; color: var(--muted); font-size: 13px; }
      input[type="email"], input[type="password"], input[type="text"] {
        width: 100%;
        padding: 10px 12px;
        border: 1px solid var(--border);
        border-radius: 10px;
        background: #f9fafb;
        outline: none;
        font-size: 14px;
      }
      input:focus { border-color: #cbd5e1; background: #fff; }
      .btn {
        width: 100%;
        padding: 10px 12px;
        border: none;
        border-radius: 10px;
        background: var(--primary);
        color: #fff;
        font-weight: 600;
        cursor: pointer;
        transition: background .15s ease;
        margin-top: 6px;
      }
      .btn:hover { background: var(--primary-hover); }
      .link { color: var(--primary); text-decoration: none; }
      .link:hover { text-decoration: underline; }
      .row { display: flex; gap: 10px; }
      .row .btn { flex: 1; }
      .footer { margin-top: 6px; text-align: center; font-size: 13px; color: var(--muted); }
    </style>
  `;
}

function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  next();
}

app.get('/', (req, res) => {
  if (req.session.userId) return res.redirect('/dashboard');
  return res.redirect('/login');
});

app.get('/register', (req, res) => {
  res.send(`
    <html>
      <head><title>Регистрация</title>${styles()}</head>
      <body>
        <div class="card">
          <h2>Регистрация</h2>
          <form method="POST" action="/register">
            <label>Email</label>
            <input type="email" name="email" required />
            <label>Пароль</label>
            <input type="password" name="password" required minlength="6" />
            <button class="btn" type="submit">Зарегистрироваться</button>
          </form>
          <div class="footer">Уже есть аккаунт? <a class="link" href="/login">Войти</a></div>
        </div>
      </body>
    </html>
  `);
});

app.post('/register', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password || password.length < 6) {
    return res.status(400).send('Некорректные данные. Пароль минимум 6 символов.');
  }
  const password_hash = bcrypt.hashSync(password, 10);
  const created_at = new Date().toISOString();
  const insertSql = `INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)`;
  db.run(insertSql, [email.trim().toLowerCase(), password_hash, created_at], function (err) {
    if (err) {
      if (String(err.message || '').includes('UNIQUE')) {
        return res.status(409).send('Пользователь с таким email уже существует. <a href="/login">Войти</a>');
      }
      return res.status(500).send('Ошибка сервера.');
    }
    req.session.userId = this.lastID;
    res.redirect('/dashboard');
  });
});

app.get('/login', (req, res) => {
  res.send(`
    <html>
      <head><title>Вход</title>${styles()}</head>
      <body>
        <div class="card">
          <h2>Вход</h2>
          <form method="POST" action="/login">
            <label>Email</label>
            <input type="email" name="email" required />
            <label>Пароль</label>
            <input type="password" name="password" required />
            <button class="btn" type="submit">Войти</button>
          </form>
          <div class="footer">Нет аккаунта? <a class="link" href="/register">Регистрация</a></div>
        </div>
      </body>
    </html>
  `);
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).send('Введите email и пароль.');
  const sql = `SELECT id, email, password_hash FROM users WHERE email = ?`;
  db.get(sql, [email.trim().toLowerCase()], (err, user) => {
    if (err) return res.status(500).send('Ошибка сервера.');
    if (!user) return res.status(401).send('Неверные учетные данные.');
    const ok = bcrypt.compareSync(password, user.password_hash);
    if (!ok) return res.status(401).send('Неверные учетные данные.');
    req.session.userId = user.id;
    res.redirect('/dashboard');
  });
});

app.get('/dashboard', requireAuth, (req, res) => {
  res.send(`
    <html>
      <head><title>Личный кабинет</title>${styles()}</head>
      <body>
        <div class="card">
          <h2>Личный кабинет</h2>
          <p>Вы вошли в систему.</p>
          <form method="POST" action="/data">
            <label>Любые данные (пример)</label>
            <input type="text" name="any" placeholder="Введите текст" required />
            <div class="row">
              <button class="btn" type="submit">Отправить</button>
            </div>
          </form>
          <form method="POST" action="/logout">
            <button class="btn" type="submit">Выйти</button>
          </form>
        </div>
      </body>
    </html>
  `);
});

app.post('/data', requireAuth, (req, res) => {
  const { any } = req.body;
  res.send(`
    <html>
      <head><title>Данные приняты</title>${styles()}</head>
      <body>
        <div class="card">
          <h2>Данные приняты</h2>
          <p>Вы ввели: ${any ? String(any).replace(/[<>]/g, '') : ''}</p>
          <div class="footer"><a class="link" href="/dashboard">Назад</a></div>
        </div>
      </body>
    </html>
  `);
});

app.post('/logout', requireAuth, (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

app.listen(PORT, () => {
  console.log(`Server started at http://localhost:${PORT}/`);
});
