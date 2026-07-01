const path = require('path');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data.sqlite');
const db = new Database(DB_PATH);

db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS admin (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    passwordHash TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS employees (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    hourlyRate REAL NOT NULL,
    currency TEXT NOT NULL,
    notes TEXT,
    passwordHash TEXT,
    active INTEGER NOT NULL DEFAULT 1,
    createdAt TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS records (
    id TEXT PRIMARY KEY,
    employeeId TEXT NOT NULL,
    employeeName TEXT NOT NULL,
    clockIn TEXT NOT NULL,
    clockOut TEXT,
    durationHours REAL,
    date TEXT NOT NULL,
    period INTEGER NOT NULL,
    month TEXT NOT NULL,
    isManual INTEGER NOT NULL DEFAULT 0,
    notes TEXT
  );
`);

if (!db.prepare('SELECT id FROM admin WHERE id = 1').get()) {
  db.prepare('INSERT INTO admin (id, passwordHash) VALUES (1, ?)').run(bcrypt.hashSync('admin123', 10));
}

module.exports = db;
