/**
 * ─────────────────────────────────────────────
 *  Kota Kadak Chai  ·  Client Download Portal
 *  Backend: Node.js + Express + JWT
 * ─────────────────────────────────────────────
 *
 *  SETUP:
 *    npm init -y
 *    npm install express jsonwebtoken bcryptjs cors dotenv
 *    node server.js
 *
 *  The server runs on http://localhost:3000
 *  Open index.html via a local server (e.g. VS Code Live Server)
 *  or serve it from Express itself (already configured below).
 *
 *  TO ADD / CHANGE CLIENTS:
 *    Edit the CLIENTS object below, or use the /admin/add-client endpoint.
 *
 *  TO CHANGE THE APK DOWNLOAD:
 *    Put your .apk file in the same folder and set APK_FILENAME below.
 * ─────────────────────────────────────────────
 */

const express  = require('express');
const jwt      = require('jsonwebtoken');
const bcrypt   = require('bcryptjs');
const cors     = require('cors');
const path     = require('path');
const fs       = require('fs');

const app  = express();
const PORT = process.env.PORT || 3000;

// ─── CONFIGURATION ──────────────────────────
const JWT_SECRET  = process.env.JWT_SECRET  || 'change-this-to-a-long-random-secret-in-production';
const ADMIN_KEY   = process.env.ADMIN_KEY   || 'my-admin-key-2025';   // for /admin routes
const APK_FILENAME = 'kota-kadak-chai.apk';                            // put your APK here

// ─── CLIENT DATABASE ────────────────────────
// Login: naresh.sharma / kkc@admin
const CLIENTS = {
  'naresh.sharma': {
    passwordHash: bcrypt.hashSync('kkc@admin', 10),
    name: 'Naresh Sharma',
    plan: 'Premium',
    version: '1.0.0',
    active: true,
    downloads: 0,
    lastLogin: null,
    createdAt: new Date().toISOString(),
  },
};

// ─── MIDDLEWARE ──────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));   // serves index.html, style.css

// ─── AUTH MIDDLEWARE ─────────────────────────
function requireAuth(req, res, next) {
  const auth = req.headers['authorization'];
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }
  try {
    const decoded = jwt.verify(auth.slice(7), JWT_SECRET);
    req.user = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function requireAdmin(req, res, next) {
  const key = req.headers['x-admin-key'];
  if (key !== ADMIN_KEY) return res.status(403).json({ error: 'Forbidden' });
  next();
}

// ─── RATE LIMITER (simple in-memory) ─────────
const loginAttempts = {};
function rateLimitLogin(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress;
  const now = Date.now();
  if (!loginAttempts[ip]) loginAttempts[ip] = [];
  loginAttempts[ip] = loginAttempts[ip].filter(t => now - t < 15 * 60 * 1000); // 15 min window
  if (loginAttempts[ip].length >= 5) {
    return res.status(429).json({ error: 'Too many attempts. Try again in 15 minutes.' });
  }
  loginAttempts[ip].push(now);
  next();
}

// ════════════════════════════════════════════
//  ROUTES
// ════════════════════════════════════════════

// ── POST /api/login ──────────────────────────
// Body: { username, password }
// Returns: { token, user }
app.post('/api/login', rateLimitLogin, async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  const client = CLIENTS[username.toLowerCase().trim()];

  // Timing-safe: always compare even if user doesn't exist
  const hash = client?.passwordHash || bcrypt.hashSync('dummy', 10);
  const valid = await bcrypt.compare(password, hash);

  if (!client || !valid) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  if (!client.active) {
    return res.status(403).json({ error: 'Account disabled. Contact support.' });
  }

  // Update last login
  client.lastLogin = new Date().toISOString();
  // Clear rate limit on success
  delete loginAttempts[req.ip];

  const token = jwt.sign(
    { username, name: client.name, plan: client.plan },
    JWT_SECRET,
    { expiresIn: '24h' }
  );

  res.json({
    token,
    user: {
      username,
      name: client.name,
      plan: client.plan,
      version: client.version,
      lastLogin: client.lastLogin,
    },
  });
});

// ── GET /api/me ──────────────────────────────
// Returns current user info from token
app.get('/api/me', requireAuth, (req, res) => {
  const client = CLIENTS[req.user.username];
  if (!client) return res.status(404).json({ error: 'User not found' });
  res.json({
    username: req.user.username,
    name: client.name,
    plan: client.plan,
    version: client.version,
    downloads: client.downloads,
    lastLogin: client.lastLogin,
    createdAt: client.createdAt,
  });
});

// ── GET /api/download ────────────────────────
// Protected: redirects to Google Drive APK
const GDRIVE_FILE_ID = '1DZ-5kBVbbE75z5cevBv9wziAUb5nxH9z';
const GDRIVE_URL = `https://drive.google.com/uc?export=download&id=${GDRIVE_FILE_ID}&confirm=t`;

app.get('/api/download', requireAuth, (req, res) => {
  const client = CLIENTS[req.user.username];
  if (client) client.downloads++;

  console.log(`[Download] ${req.user.username} (${req.user.name}) downloaded v${client?.version}`);

  // Redirect to Google Drive direct download
  res.redirect(GDRIVE_URL);
});

// ── GET /api/changelog ───────────────────────
app.get('/api/changelog', requireAuth, (req, res) => {
  res.json([
    { version: '1.0.0', date: '2025-04-15', notes: ['Initial release', 'Menu, Cart, Orders, Dues, Payments screens', 'Firebase Firestore integration', 'Bill generation'] },
  ]);
});

// ── POST /api/logout ─────────────────────────
// (JWT is stateless; client just deletes token.
//  This endpoint exists for logging/audit trail.)
app.post('/api/logout', requireAuth, (req, res) => {
  console.log(`[Logout] ${req.user.username}`);
  res.json({ message: 'Logged out' });
});

// ════════════════════════════════════════════
//  ADMIN ROUTES  (protected by ADMIN_KEY header)
// ════════════════════════════════════════════

// ── POST /admin/add-client ───────────────────
// Header: x-admin-key: <ADMIN_KEY>
// Body: { username, password, name, plan }
app.post('/admin/add-client', requireAdmin, async (req, res) => {
  const { username, password, name, plan } = req.body;
  if (!username || !password || !name) {
    return res.status(400).json({ error: 'username, password, name required' });
  }
  if (CLIENTS[username]) return res.status(409).json({ error: 'Username taken' });
  CLIENTS[username] = {
    passwordHash: await bcrypt.hash(password, 10),
    name, plan: plan || 'Standard',
    version: '1.0.0', active: true,
    downloads: 0, lastLogin: null,
    createdAt: new Date().toISOString(),
  };
  res.json({ message: `Client "${username}" created` });
});

// ── POST /admin/disable-client ───────────────
app.post('/admin/disable-client', requireAdmin, (req, res) => {
  const { username } = req.body;
  if (!CLIENTS[username]) return res.status(404).json({ error: 'Not found' });
  CLIENTS[username].active = false;
  res.json({ message: `Client "${username}" disabled` });
});

// ── GET /admin/clients ───────────────────────
app.get('/admin/clients', requireAdmin, (req, res) => {
  const list = Object.entries(CLIENTS).map(([u, c]) => ({
    username: u, name: c.name, plan: c.plan,
    active: c.active, downloads: c.downloads,
    lastLogin: c.lastLogin, createdAt: c.createdAt,
  }));
  res.json(list);
});

// ─── CATCH-ALL → index.html ──────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ─── START ───────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n  ┌──────────────────────────────────────┐`);
  console.log(`  │   Kota Kadak Chai · Download Portal   │`);
  console.log(`  │   http://localhost:${PORT}               │`);
  console.log(`  └──────────────────────────────────────┘`);
  console.log(`\n  Login: naresh.sharma / kkc@admin\n`);
});