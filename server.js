const express    = require('express');
const Database   = require('better-sqlite3');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const cors       = require('cors');
const path       = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'phoenix-store-secret-2024';

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── DATABASE ───
const db = new Database('store.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS products (
    barcode TEXT PRIMARY KEY,
    name    TEXT NOT NULL,
    price   REAL NOT NULL,
    stock   INTEGER NOT NULL DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS logs (
    id       TEXT PRIMARY KEY,
    date     TEXT NOT NULL,
    items    TEXT NOT NULL,
    total    REAL NOT NULL,
    totalQty INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password TEXT NOT NULL
  );
`);

// Create admin user if not exists
const existingUser = db.prepare('SELECT * FROM users WHERE username = ?').get('admin');
if (!existingUser) {
  const hashed = bcrypt.hashSync('1879', 10);
  db.prepare('INSERT INTO users (username, password) VALUES (?, ?)').run('admin', hashed);
  console.log('Admin user created.');
}

// Seed sample products if empty
const count = db.prepare('SELECT COUNT(*) as c FROM products').get();
if (count.c === 0) {
  const ins = db.prepare('INSERT INTO products (barcode, name, price, stock) VALUES (?, ?, ?, ?)');
  ins.run('1234567890123', 'Sample Widget A', 29.99, 50);
  ins.run('9876543210123', 'Custom Tool – Model X', 89.99, 15);
  ins.run('4567891234567', 'Project Component 04', 4.50, 102);
  console.log('Sample products added.');
}

// ─── AUTH MIDDLEWARE ───
function requireAuth(req, res, next) {
  const token = (req.headers['authorization'] || '').split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token.' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token.' });
    req.user = user;
    next();
  });
}

// ─── LOGIN ───
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required.' });
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: 'Invalid username or password.' });
  const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ token, username: user.username });
});

// ─── PRODUCTS ───
app.get('/api/products', requireAuth, (req, res) => {
  res.json(db.prepare('SELECT * FROM products').all());
});

app.post('/api/products', requireAuth, (req, res) => {
  const { barcode, name, price, stock } = req.body;
  if (!barcode || !name) return res.status(400).json({ error: 'Barcode and name required.' });
  if (db.prepare('SELECT 1 FROM products WHERE barcode = ?').get(barcode))
    return res.status(409).json({ error: `Barcode ${barcode} already exists.` });
  db.prepare('INSERT INTO products (barcode, name, price, stock) VALUES (?, ?, ?, ?)')
    .run(barcode, name, parseFloat(price) || 0, parseInt(stock) || 0);
  res.json({ success: true });
});

app.put('/api/products/:barcode', requireAuth, (req, res) => {
  const { name, price, stock } = req.body;
  db.prepare('UPDATE products SET name=?, price=?, stock=? WHERE barcode=?')
    .run(name, parseFloat(price) || 0, parseInt(stock) || 0, req.params.barcode);
  res.json({ success: true });
});

app.delete('/api/products/:barcode', requireAuth, (req, res) => {
  db.prepare('DELETE FROM products WHERE barcode=?').run(req.params.barcode);
  res.json({ success: true });
});

// ─── LOGS ───
app.get('/api/logs', requireAuth, (req, res) => {
  const logs = db.prepare('SELECT * FROM logs ORDER BY rowid DESC').all();
  res.json(logs.map(l => ({ ...l, items: JSON.parse(l.items) })));
});

app.post('/api/logs', requireAuth, (req, res) => {
  const { id, date, items, total, totalQty } = req.body;
  // Deduct stock
  const upd = db.prepare('UPDATE products SET stock = MAX(0, stock - ?) WHERE barcode = ?');
  for (const item of items) upd.run(item.qty, item.barcode);
  db.prepare('INSERT INTO logs (id, date, items, total, totalQty) VALUES (?, ?, ?, ?, ?)')
    .run(id, date, JSON.stringify(items), total, totalQty);
  res.json({ success: true });
});

app.delete('/api/logs', requireAuth, (req, res) => {
  db.prepare('DELETE FROM logs').run();
  res.json({ success: true });
});

// ─── START ───
app.listen(PORT, () => console.log(`Phoenix Store running on port ${PORT}`));
