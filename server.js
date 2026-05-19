// ─── IMPORTS ───
// We bring in all the packages we installed
const express    = require('express');        // web server framework
const Database   = require('better-sqlite3'); // database
const bcrypt     = require('bcryptjs');        // password hashing
const jwt        = require('jsonwebtoken');    // login tokens
const cors       = require('cors');            // allow cross-origin requests
const path       = require('path');            // helps with file paths (built into Node)
const fs         = require('fs');              // helps read/write files (built into Node)

// ─── SETUP ───
const app  = express();           // create the express app
const PORT = process.env.PORT || 3000; // use Railway's port or 3000 locally

// This is the secret key used to sign login tokens.
// In production Railway will set this as an environment variable (more secure).
// For now we have a fallback string.
const JWT_SECRET = process.env.JWT_SECRET || 'phoenix-store-secret-2024';

// ─── MIDDLEWARE ───
// Middleware is code that runs on every request before it reaches your routes.

app.use(cors());                          // allow requests from any origin
app.use(express.json());                  // allow the server to read JSON request bodies
app.use(express.static(path.join(__dirname, 'public'))); // serve files from the public folder

// ─── DATABASE SETUP ───
// This creates (or opens if it already exists) a file called store.db
// All your data lives in this file permanently
const db = new Database('store.db');

// Create tables if they don't exist yet
// This runs every time the server starts, but IF NOT EXISTS means
// it won't overwrite data that's already there
db.exec(`
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
    totalQty  INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password TEXT NOT NULL
  );
`);

// ─── SEED DEFAULT USER ───
// Check if admin user exists. If not, create it.
// We hash the password "1879" before storing it — never store plain text passwords.
const existingUser = db.prepare('SELECT * FROM users WHERE username = ?').get('admin');
if (!existingUser) {
  const hashedPassword = bcrypt.hashSync('1879', 10);
  // The 10 is the "salt rounds" — how many times the hashing runs.
  // More rounds = more secure but slower. 10 is the standard.
  db.prepare('INSERT INTO users (username, password) VALUES (?, ?)').run('admin', hashedPassword);
  console.log('Admin user created.');
}

// ─── SEED SAMPLE PRODUCTS ───
// If there are no products yet, add some samples so the app isn't empty
const productCount = db.prepare('SELECT COUNT(*) as count FROM products').get();
if (productCount.count === 0) {
  const insert = db.prepare('INSERT INTO products (barcode, name, price, stock) VALUES (?, ?, ?, ?)');
  insert.run('1234567890123', 'Sample Widget A', 29.99, 50);
  insert.run('9876543210123', 'Custom Tool – Model X', 89.99, 15);
  insert.run('4567891234567', 'Project Component 04', 4.50, 102);
  console.log('Sample products added.');
}

// ─── AUTH MIDDLEWARE ───
// This function checks if a request has a valid login token.
// We'll use it to protect all routes that require login.
function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  // The token is sent in the Authorization header as "Bearer <token>"
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'No token provided. Please log in.' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token. Please log in again.' });
    }
    req.user = user; // attach the user info to the request
    next();          // move on to the actual route handler
  });
}

// ─── ROUTES ───
// Routes are the URLs your server responds to.
// Each one listens for a specific method (GET, POST, PUT, DELETE) and path.

// ── LOGIN ──
// POST /api/login
// The frontend sends { username, password }, we check it and return a token
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required.' });
  }

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

  if (!user) {
    return res.status(401).json({ error: 'Invalid username or password.' });
  }

  // bcrypt.compareSync checks if the plain password matches the stored hash
  const passwordMatch = bcrypt.compareSync(password, user.password);

  if (!passwordMatch) {
    return res.status(401).json({ error: 'Invalid username or password.' });
  }

  // Password is correct — create a token that expires in 24 hours
  const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '24h' });

  res.json({ token, username: user.username });
});

// ── GET ALL PRODUCTS ──
// GET /api/products
// Returns all products from the database
app.get('/api/products', requireAuth, (req, res) => {
  const products = db.prepare('SELECT * FROM products').all();
  res.json(products);
});

// ── ADD PRODUCT ──
// POST /api/products
// Adds a new product
app.post('/api/products', requireAuth, (req, res) => {
  const { barcode, name, price, stock } = req.body;

  if (!barcode || !name) {
    return res.status(400).json({ error: 'Barcode and name are required.' });
  }

  const existing = db.prepare('SELECT * FROM products WHERE barcode = ?').get(barcode);
  if (existing) {
    return res.status(409).json({ error: `Barcode ${barcode} already exists.` });
  }

  db.prepare('INSERT INTO products (barcode, name, price, stock) VALUES (?, ?, ?, ?)')
    .run(barcode, name, parseFloat(price) || 0, parseInt(stock) || 0);

  res.json({ success: true });
});

// ── UPDATE PRODUCT ──
// PUT /api/products/:barcode
// Updates an existing product by barcode
app.put('/api/products/:barcode', requireAuth, (req, res) => {
  const { name, price, stock } = req.body;
  const { barcode } = req.params;

  db.prepare('UPDATE products SET name = ?, price = ?, stock = ? WHERE barcode = ?')
    .run(name, parseFloat(price) || 0, parseInt(stock) || 0, barcode);

  res.json({ success: true });
});

// ── DELETE PRODUCT ──
// DELETE /api/products/:barcode
app.delete('/api/products/:barcode', requireAuth, (req, res) => {
  db.prepare('DELETE FROM products WHERE barcode = ?').run(req.params.barcode);
  res.json({ success: true });
});

// ── GET ALL LOGS ──
// GET /api/logs
app.get('/api/logs', requireAuth, (req, res) => {
  const logs = db.prepare('SELECT * FROM logs ORDER BY rowid DESC').all();
  // items was stored as JSON string, parse it back
  const parsed = logs.map(l => ({ ...l, items: JSON.parse(l.items) }));
  res.json(parsed);
});

// ── SAVE PURCHASE LOG ──
// POST /api/logs
app.post('/api/logs', requireAuth, (req, res) => {
  const { id, date, items, total, totalQty } = req.body;

  // Deduct stock for each item purchased
  const updateStock = db.prepare('UPDATE products SET stock = MAX(0, stock - ?) WHERE barcode = ?');
  for (const item of items) {
    updateStock.run(item.qty, item.barcode);
  }

  // Save the log (store items array as JSON string)
  db.prepare('INSERT INTO logs (id, date, items, total, totalQty) VALUES (?, ?, ?, ?, ?)')
    .run(id, date, JSON.stringify(items), total, totalQty);

  res.json({ success: true });
});

// ── DELETE ALL LOGS ──
// DELETE /api/logs
app.delete('/api/logs', requireAuth, (req, res) => {
  db.prepare('DELETE FROM logs').run();
  res.json({ success: true });
});

// ─── START SERVER ───
app.listen(PORT, () => {
  console.log(`Phoenix Store server running on port ${PORT}`);
});