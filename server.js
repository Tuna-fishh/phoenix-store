// ─── IMPORTS ───
const express = require('express');
const { Pool } = require('pg');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const cors    = require('cors');
const path    = require('path');

// ─── SETUP ───
const app  = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'phoenix-store-secret-2024';

// ─── MIDDLEWARE ───
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── DATABASE SETUP ───
// Railway automatically provides DATABASE_URL for linked PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ─── CREATE TABLES ───
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS products (
      barcode TEXT PRIMARY KEY,
      name    TEXT NOT NULL,
      price   REAL NOT NULL,
      stock   INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS logs (
      id        TEXT PRIMARY KEY,
      date      TEXT NOT NULL,
      items     TEXT NOT NULL,
      total     REAL NOT NULL,
      totalqty  INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS users (
      username TEXT PRIMARY KEY,
      password TEXT NOT NULL
    );
  `);

  // Seed admin user if not exists
  const userRes = await pool.query('SELECT * FROM users WHERE username = $1', ['admin']);
  if (userRes.rows.length === 0) {
    const hashedPassword = bcrypt.hashSync('1879', 10);
    await pool.query('INSERT INTO users (username, password) VALUES ($1, $2)', ['admin', hashedPassword]);
    console.log('Admin user created.');
  }

  // Seed sample products if none exist
  const countRes = await pool.query('SELECT COUNT(*) as count FROM products');
  if (parseInt(countRes.rows[0].count) === 0) {
    await pool.query('INSERT INTO products (barcode, name, price, stock) VALUES ($1,$2,$3,$4)', ['1234567890123','Sample Widget A',29.99,50]);
    await pool.query('INSERT INTO products (barcode, name, price, stock) VALUES ($1,$2,$3,$4)', ['9876543210123','Custom Tool – Model X',89.99,15]);
    await pool.query('INSERT INTO products (barcode, name, price, stock) VALUES ($1,$2,$3,$4)', ['4567891234567','Project Component 04',4.50,102]);
    console.log('Sample products added.');
  }

  console.log('Database ready.');
}

// ─── AUTH MIDDLEWARE ───
function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided. Please log in.' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token. Please log in again.' });
    req.user = user;
    next();
  });
}

// ─── ROUTES ───

// ── LOGIN ──
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required.' });

  const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
  const user = result.rows[0];
  if (!user) return res.status(401).json({ error: 'Invalid username or password.' });

  const passwordMatch = bcrypt.compareSync(password, user.password);
  if (!passwordMatch) return res.status(401).json({ error: 'Invalid username or password.' });

  const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ token, username: user.username });
});

// ── GET ALL PRODUCTS ──
app.get('/api/products', requireAuth, async (req, res) => {
  const result = await pool.query('SELECT * FROM products');
  res.json(result.rows);
});

// ── ADD PRODUCT ──
app.post('/api/products', requireAuth, async (req, res) => {
  const { barcode, name, price, stock } = req.body;
  if (!barcode || !name) return res.status(400).json({ error: 'Barcode and name are required.' });

  const existing = await pool.query('SELECT * FROM products WHERE barcode = $1', [barcode]);
  if (existing.rows.length > 0) return res.status(409).json({ error: `Barcode ${barcode} already exists.` });

  await pool.query('INSERT INTO products (barcode, name, price, stock) VALUES ($1,$2,$3,$4)',
    [barcode, name, parseFloat(price) || 0, parseInt(stock) || 0]);
  res.json({ success: true });
});

// ── UPDATE PRODUCT ──
app.put('/api/products/:barcode', requireAuth, async (req, res) => {
  const { name, price, stock } = req.body;
  const { barcode } = req.params;
  await pool.query('UPDATE products SET name=$1, price=$2, stock=$3 WHERE barcode=$4',
    [name, parseFloat(price) || 0, parseInt(stock) || 0, barcode]);
  res.json({ success: true });
});

// ── DELETE PRODUCT ──
app.delete('/api/products/:barcode', requireAuth, async (req, res) => {
  await pool.query('DELETE FROM products WHERE barcode = $1', [req.params.barcode]);
  res.json({ success: true });
});

// ── GET ALL LOGS ──
app.get('/api/logs', requireAuth, async (req, res) => {
  const result = await pool.query('SELECT * FROM logs ORDER BY date DESC');
  const parsed = result.rows.map(l => ({ ...l, items: JSON.parse(l.items) }));
  res.json(parsed);
});

// ── SAVE PURCHASE LOG ──
app.post('/api/logs', requireAuth, async (req, res) => {
  const { id, date, items, total, totalQty } = req.body;

  for (const item of items) {
    await pool.query('UPDATE products SET stock = GREATEST(0, stock - $1) WHERE barcode = $2',
      [item.qty, item.barcode]);
  }

  await pool.query('INSERT INTO logs (id, date, items, total, totalqty) VALUES ($1,$2,$3,$4,$5)',
    [id, date, JSON.stringify(items), total, totalQty]);
  res.json({ success: true });
});

// ── DELETE ALL LOGS ──
app.delete('/api/logs', requireAuth, async (req, res) => {
  await pool.query('DELETE FROM logs');
  res.json({ success: true });
});

// ─── START SERVER ───
initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`Phoenix Store server running on port ${PORT}`);
  });
}).catch(err => {
  console.error('Failed to initialize database:', err);
  process.exit(1);
});
