const express = require('express');
const helmet = require('helmet');
const crypto = require('crypto');
const path = require('path');
const Database = require('better-sqlite3');

const app = express();
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '200kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const fs = require('fs');
fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new Database(path.join(DATA_DIR, 'budget.sqlite'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL DEFAULT '',
  account_code TEXT UNIQUE NOT NULL,
  pin_salt TEXT NOT NULL,
  pin_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS user_data (
  user_id TEXT PRIMARY KEY,
  data_json TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
`);
// Backward-compatible migration for existing databases.
try { db.exec("ALTER TABLE users ADD COLUMN name TEXT NOT NULL DEFAULT ''"); } catch (e) { if (!String(e.message).includes('duplicate column')) throw e; }

const attempts = new Map();
function rateLimit(req, res, next) {
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  let entry = attempts.get(ip);
  if (!entry || now - entry.start > 15 * 60 * 1000) entry = { start: now, count: 0 };
  entry.count++;
  attempts.set(ip, entry);
  if (entry.count > 40) return res.status(429).json({ error: 'Too many attempts. Wait 15 minutes and try again.' });
  next();
}
function hashPin(pin, salt) {
  return crypto.scryptSync(pin, salt, 64).toString('hex');
}
function validPin(pin) { return typeof pin === 'string' && /^\d{6}$/.test(pin); }
function newAccountCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code;
  do { code = Array.from(crypto.randomBytes(8), b => chars[b % chars.length]).join(''); }
  while (db.prepare('SELECT 1 FROM users WHERE account_code=?').get(code));
  return code;
}
function tokenHash(token) { return crypto.createHash('sha256').update(token).digest('hex'); }
function auth(req, res, next) {
  const raw = req.headers.authorization || '';
  const token = raw.startsWith('Bearer ') ? raw.slice(7) : '';
  if (!token) return res.status(401).json({ error: 'Please unlock your account.' });
  const session = db.prepare('SELECT user_id, expires_at FROM sessions WHERE token_hash=?').get(tokenHash(token));
  if (!session || session.expires_at < Date.now()) {
    if (session) db.prepare('DELETE FROM sessions WHERE token_hash=?').run(tokenHash(token));
    return res.status(401).json({ error: 'Session expired. Please unlock again.' });
  }
  req.userId = session.user_id;
  next();
}
app.get('/api/health', (req,res) => res.json({ok:true}));
app.post('/api/register', rateLimit, (req,res) => {
  const pin = String(req.body.pin || '');
  const name = String(req.body.name || '').trim().slice(0,60);
  const income = Number(req.body.income);
  if (!name) return res.status(400).json({error:'Enter your name.'});
  if (!Number.isFinite(income) || income < 0 || income > 100000000) return res.status(400).json({error:'Enter a valid monthly income.'});
  if (!validPin(pin)) return res.status(400).json({error:'Choose a PIN with exactly 6 digits.'});
  const id = crypto.randomUUID();
  const accountCode = newAccountCode();
  const salt = crypto.randomBytes(16).toString('hex');
  const pinHash = hashPin(pin, salt);
  const now = new Date().toISOString();
  db.prepare('INSERT INTO users (id,name,account_code,pin_salt,pin_hash,created_at) VALUES (?,?,?,?,?,?)')
    .run(id, name, accountCode, salt, pinHash, now);
  const defaultData = {
    income,
    folders: [],
    transactions: []
  };
  db.prepare('INSERT INTO user_data (user_id,data_json,updated_at) VALUES (?,?,?)')
    .run(id, JSON.stringify(defaultData), now);
  const token = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO sessions (token_hash,user_id,expires_at) VALUES (?,?,?)')
    .run(tokenHash(token), id, Date.now() + 30*24*60*60*1000);
  res.json({token, accountCode, data:defaultData});
});
app.post('/api/login', rateLimit, (req,res) => {
  const accountCode = String(req.body.accountCode || '').trim().toUpperCase();
  const pin = String(req.body.pin || '');
  const user = db.prepare('SELECT * FROM users WHERE account_code=?').get(accountCode);
  if (!user || !validPin(pin) || hashPin(pin,user.pin_salt) !== user.pin_hash) {
    return res.status(401).json({error:'Account code or PIN is incorrect.'});
  }
  const token = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO sessions (token_hash,user_id,expires_at) VALUES (?,?,?)')
    .run(tokenHash(token), user.id, Date.now() + 30*24*60*60*1000);
  const row = db.prepare('SELECT data_json FROM user_data WHERE user_id=?').get(user.id);
  res.json({token, accountCode:user.account_code, data:JSON.parse(row.data_json)});
});
app.get('/api/data', auth, (req,res) => {
  const row = db.prepare('SELECT data_json,updated_at FROM user_data WHERE user_id=?').get(req.userId);
  if (!row) return res.status(404).json({error:'Budget data not found.'});
  res.json({data:JSON.parse(row.data_json), updatedAt:row.updated_at});
});
app.put('/api/data', auth, (req,res) => {
  const data = req.body && req.body.data;
  if (!data || !Array.isArray(data.folders) || !Array.isArray(data.transactions) ||
      typeof data.income !== 'number' || data.folders.length > 100 || data.transactions.length > 20000) {
    return res.status(400).json({error:'Invalid budget data.'});
  }
  const json = JSON.stringify(data);
  if (json.length > 150000) return res.status(413).json({error:'Backup is too large.'});
  const now = new Date().toISOString();
  db.prepare('INSERT INTO user_data (user_id,data_json,updated_at) VALUES (?,?,?) ON CONFLICT(user_id) DO UPDATE SET data_json=excluded.data_json,updated_at=excluded.updated_at')
    .run(req.userId, json, now);
  res.json({ok:true,updatedAt:now});
});
app.post('/api/logout', auth, (req,res) => {
  const raw = (req.headers.authorization || '').slice(7);
  db.prepare('DELETE FROM sessions WHERE token_hash=?').run(tokenHash(raw));
  res.json({ok:true});
});
app.get('*', (req,res) => res.sendFile(path.join(__dirname,'public','index.html')));
app.listen(PORT, '0.0.0.0', () => console.log(`Budget tracker listening on ${PORT}`));
