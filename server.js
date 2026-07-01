const path = require('path');
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('./db');

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const PORT = process.env.PORT || 5173;

const app = express();
app.use(cors());
app.use(express.json());

const uuid = () => Date.now().toString(36) + crypto.randomBytes(6).toString('hex');
const getPeriod = (ds) => (parseInt(ds.split('-')[2], 10) <= 15 ? 1 : 2);
const getDateStr = (d = new Date()) =>
  `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
const getMonthStr = (d = new Date()) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;

// ── seed sample employees on first run ──
if (db.prepare('SELECT COUNT(*) c FROM employees').get().c === 0) {
  const seed = [
    { name: 'Nguyễn Văn An', hourlyRate: 18, currency: 'USD', notes: 'Bộ phận kho', password: 'nv123' },
    { name: 'Trần Thị Bình', hourlyRate: 22, currency: 'USD', notes: 'Kế toán', password: 'ttb456' },
    { name: 'Lê Quốc Hùng', hourlyRate: 8.5, currency: 'USD', notes: 'IT - Dev', password: null },
  ];
  const ins = db.prepare(
    `INSERT INTO employees (id,name,hourlyRate,currency,notes,passwordHash,active,createdAt) VALUES (?,?,?,?,?,?,1,?)`
  );
  seed.forEach((e) =>
    ins.run(uuid(), e.name, e.hourlyRate, e.currency, e.notes, e.password ? bcrypt.hashSync(e.password, 10) : null, new Date().toISOString())
  );
}

// ── auth helpers ──
function requireAuth(req, res, next) {
  const hdr = req.headers.authorization || '';
  const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'unauthorized' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'unauthorized' });
  }
}
function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'forbidden' });
  next();
}

function employeeOut(e) {
  return {
    id: e.id,
    name: e.name,
    hourlyRate: e.hourlyRate,
    currency: e.currency,
    notes: e.notes,
    active: !!e.active,
    hasPassword: !!e.passwordHash,
    createdAt: e.createdAt,
  };
}

function isPasswordTakenByEmployee(pw, excludeId) {
  const rows = db.prepare('SELECT id, name, passwordHash FROM employees WHERE passwordHash IS NOT NULL').all();
  return rows.some((r) => r.id !== excludeId && bcrypt.compareSync(pw, r.passwordHash));
}

// ══════════════════════════════════════════
// AUTH
// ══════════════════════════════════════════
app.post('/api/login', (req, res) => {
  const { password } = req.body || {};
  if (!password) return res.status(400).json({ error: 'empty' });

  const admin = db.prepare('SELECT passwordHash FROM admin WHERE id = 1').get();
  if (bcrypt.compareSync(password, admin.passwordHash)) {
    const token = jwt.sign({ role: 'admin', userId: 'admin', name: 'Admin' }, JWT_SECRET, { expiresIn: '30d' });
    return res.json({ role: 'admin', userId: 'admin', name: 'Admin', token });
  }

  const emps = db.prepare('SELECT * FROM employees WHERE active = 1 AND passwordHash IS NOT NULL').all();
  const matches = emps.filter((e) => bcrypt.compareSync(password, e.passwordHash));

  if (matches.length === 1) {
    const emp = matches[0];
    const token = jwt.sign({ role: 'employee', userId: emp.id, name: emp.name }, JWT_SECRET, { expiresIn: '30d' });
    return res.json({ role: 'employee', userId: emp.id, name: emp.name, notes: emp.notes, token });
  }
  if (matches.length > 1) return res.status(400).json({ error: 'multi' });
  return res.status(400).json({ error: 'wrong' });
});

app.get('/api/me', requireAuth, (req, res) => {
  if (req.user.role === 'admin') return res.json({ role: 'admin', userId: 'admin', name: 'Admin' });
  const emp = db.prepare('SELECT * FROM employees WHERE id = ?').get(req.user.userId);
  if (!emp || !emp.active) return res.status(401).json({ error: 'unauthorized' });
  res.json({ role: 'employee', userId: emp.id, name: emp.name, notes: emp.notes });
});

// ══════════════════════════════════════════
// EMPLOYEES (admin only)
// ══════════════════════════════════════════
app.get('/api/employees', requireAuth, requireAdmin, (req, res) => {
  const rows = db.prepare('SELECT * FROM employees ORDER BY createdAt ASC').all();
  res.json(rows.map(employeeOut));
});

app.post('/api/employees', requireAuth, requireAdmin, (req, res) => {
  const { name, hourlyRate, currency, notes, password } = req.body || {};
  if (!name || !hourlyRate || hourlyRate <= 0) return res.status(400).json({ error: 'invalid' });
  if (password) {
    const admin = db.prepare('SELECT passwordHash FROM admin WHERE id = 1').get();
    if (bcrypt.compareSync(password, admin.passwordHash)) return res.status(400).json({ error: 'clash-admin' });
    if (isPasswordTakenByEmployee(password, null)) return res.status(400).json({ error: 'clash-emp' });
  }
  const id = uuid();
  db.prepare(
    `INSERT INTO employees (id,name,hourlyRate,currency,notes,passwordHash,active,createdAt) VALUES (?,?,?,?,?,?,1,?)`
  ).run(id, name, hourlyRate, currency || 'USD', notes || '', password ? bcrypt.hashSync(password, 10) : null, new Date().toISOString());
  res.json(employeeOut(db.prepare('SELECT * FROM employees WHERE id = ?').get(id)));
});

app.put('/api/employees/:id', requireAuth, requireAdmin, (req, res) => {
  const emp = db.prepare('SELECT * FROM employees WHERE id = ?').get(req.params.id);
  if (!emp) return res.status(404).json({ error: 'not-found' });
  const { name, hourlyRate, currency, notes, password } = req.body || {};
  if (!name || !hourlyRate || hourlyRate <= 0) return res.status(400).json({ error: 'invalid' });
  if (password) {
    const admin = db.prepare('SELECT passwordHash FROM admin WHERE id = 1').get();
    if (bcrypt.compareSync(password, admin.passwordHash)) return res.status(400).json({ error: 'clash-admin' });
    if (isPasswordTakenByEmployee(password, emp.id)) return res.status(400).json({ error: 'clash-emp' });
  }
  db.prepare(
    `UPDATE employees SET name=?, hourlyRate=?, currency=?, notes=?, passwordHash=COALESCE(?, passwordHash) WHERE id=?`
  ).run(name, hourlyRate, currency || 'USD', notes || '', password ? bcrypt.hashSync(password, 10) : null, emp.id);
  if (name !== emp.name) {
    db.prepare('UPDATE records SET employeeName=? WHERE employeeId=?').run(name, emp.id);
  }
  res.json(employeeOut(db.prepare('SELECT * FROM employees WHERE id = ?').get(emp.id)));
});

app.put('/api/employees/:id/active', requireAuth, requireAdmin, (req, res) => {
  const emp = db.prepare('SELECT * FROM employees WHERE id = ?').get(req.params.id);
  if (!emp) return res.status(404).json({ error: 'not-found' });
  db.prepare('UPDATE employees SET active=? WHERE id=?').run(emp.active ? 0 : 1, emp.id);
  res.json(employeeOut(db.prepare('SELECT * FROM employees WHERE id = ?').get(emp.id)));
});

app.put('/api/employees/:id/password', requireAuth, requireAdmin, (req, res) => {
  const emp = db.prepare('SELECT * FROM employees WHERE id = ?').get(req.params.id);
  if (!emp) return res.status(404).json({ error: 'not-found' });
  const { password } = req.body || {};
  if (password) {
    const admin = db.prepare('SELECT passwordHash FROM admin WHERE id = 1').get();
    if (bcrypt.compareSync(password, admin.passwordHash)) return res.status(400).json({ error: 'clash-admin' });
    if (isPasswordTakenByEmployee(password, emp.id)) return res.status(400).json({ error: 'clash-emp' });
  }
  db.prepare('UPDATE employees SET passwordHash=? WHERE id=?').run(password ? bcrypt.hashSync(password, 10) : null, emp.id);
  res.json({ ok: true });
});

app.delete('/api/employees/:id', requireAuth, requireAdmin, (req, res) => {
  db.prepare('DELETE FROM employees WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

// ══════════════════════════════════════════
// RECORDS
// ══════════════════════════════════════════
app.get('/api/records', requireAuth, (req, res) => {
  const rows =
    req.user.role === 'admin'
      ? db.prepare('SELECT * FROM records ORDER BY clockIn DESC').all()
      : db.prepare('SELECT * FROM records WHERE employeeId=? ORDER BY clockIn DESC').all(req.user.userId);
  res.json(rows.map((r) => ({ ...r, isManual: !!r.isManual })));
});

app.post('/api/records', requireAuth, requireAdmin, (req, res) => {
  const { employeeId, clockIn, clockOut, notes, tip } = req.body || {};
  const emp = db.prepare('SELECT * FROM employees WHERE id=?').get(employeeId);
  if (!emp) return res.status(400).json({ error: 'invalid' });
  if (!clockIn) return res.status(400).json({ error: 'invalid' });
  const ci = new Date(clockIn);
  const co = clockOut ? new Date(clockOut) : null;
  if (co && co <= ci) return res.status(400).json({ error: 'out-before-in' });
  const ds = getDateStr(ci);
  const id = uuid();
  db.prepare(
    `INSERT INTO records (id,employeeId,employeeName,clockIn,clockOut,durationHours,date,period,month,isManual,notes,tip) VALUES (?,?,?,?,?,?,?,?,?,1,?,?)`
  ).run(id, emp.id, emp.name, ci.toISOString(), co ? co.toISOString() : null, co ? (co - ci) / 3600000 : null, ds, getPeriod(ds), getMonthStr(ci), notes || '', Number(tip) || 0);
  res.json(db.prepare('SELECT * FROM records WHERE id=?').get(id));
});

app.put('/api/records/:id', requireAuth, requireAdmin, (req, res) => {
  const rec = db.prepare('SELECT * FROM records WHERE id=?').get(req.params.id);
  if (!rec) return res.status(404).json({ error: 'not-found' });
  const { employeeId, clockIn, clockOut, notes, tip } = req.body || {};
  const emp = db.prepare('SELECT * FROM employees WHERE id=?').get(employeeId);
  if (!emp || !clockIn) return res.status(400).json({ error: 'invalid' });
  const ci = new Date(clockIn);
  const co = clockOut ? new Date(clockOut) : null;
  if (co && co <= ci) return res.status(400).json({ error: 'out-before-in' });
  const ds = getDateStr(ci);
  const keepTip = tip === undefined ? rec.tip : Number(tip) || 0;
  db.prepare(
    `UPDATE records SET employeeId=?, employeeName=?, clockIn=?, clockOut=?, durationHours=?, date=?, period=?, month=?, notes=?, tip=?, isManual=1 WHERE id=?`
  ).run(emp.id, emp.name, ci.toISOString(), co ? co.toISOString() : null, co ? (co - ci) / 3600000 : null, ds, getPeriod(ds), getMonthStr(ci), notes || '', keepTip, rec.id);
  res.json(db.prepare('SELECT * FROM records WHERE id=?').get(rec.id));
});

app.put('/api/records/:id/tip', requireAuth, requireAdmin, (req, res) => {
  const rec = db.prepare('SELECT * FROM records WHERE id=?').get(req.params.id);
  if (!rec) return res.status(404).json({ error: 'not-found' });
  const tip = Number(req.body && req.body.tip) || 0;
  if (tip < 0) return res.status(400).json({ error: 'invalid' });
  db.prepare('UPDATE records SET tip=? WHERE id=?').run(tip, rec.id);
  res.json(db.prepare('SELECT * FROM records WHERE id=?').get(rec.id));
});

app.delete('/api/records/:id', requireAuth, requireAdmin, (req, res) => {
  db.prepare('DELETE FROM records WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

app.post('/api/punch', requireAuth, (req, res) => {
  const employeeId = req.user.role === 'admin' ? req.body.employeeId : req.user.userId;
  if (!employeeId) return res.status(400).json({ error: 'invalid' });
  const emp = db.prepare('SELECT * FROM employees WHERE id=?').get(employeeId);
  if (!emp) return res.status(400).json({ error: 'invalid' });
  const open = db.prepare('SELECT * FROM records WHERE employeeId=? AND clockOut IS NULL').get(employeeId);
  const now = new Date();
  if (open) {
    const durationHours = (now - new Date(open.clockIn)) / 3600000;
    db.prepare('UPDATE records SET clockOut=?, durationHours=? WHERE id=?').run(now.toISOString(), durationHours, open.id);
    return res.json({ action: 'out', record: db.prepare('SELECT * FROM records WHERE id=?').get(open.id) });
  }
  const ds = getDateStr(now);
  const id = uuid();
  db.prepare(
    `INSERT INTO records (id,employeeId,employeeName,clockIn,clockOut,durationHours,date,period,month,isManual,notes) VALUES (?,?,?,?,NULL,NULL,?,?,?,0,'')`
  ).run(id, emp.id, emp.name, now.toISOString(), ds, getPeriod(ds), getMonthStr(now));
  res.json({ action: 'in', record: db.prepare('SELECT * FROM records WHERE id=?').get(id) });
});

// ══════════════════════════════════════════
// PASSWORDS (admin)
// ══════════════════════════════════════════
app.put('/api/admin-password', requireAuth, requireAdmin, (req, res) => {
  const { oldPassword, newPassword } = req.body || {};
  const admin = db.prepare('SELECT passwordHash FROM admin WHERE id = 1').get();
  if (!bcrypt.compareSync(oldPassword || '', admin.passwordHash)) return res.status(400).json({ error: 'wrong-old' });
  if (!newPassword || newPassword.length < 4) return res.status(400).json({ error: 'min-len' });
  if (isPasswordTakenByEmployee(newPassword, null)) return res.status(400).json({ error: 'clash-emp' });
  db.prepare('UPDATE admin SET passwordHash=? WHERE id=1').run(bcrypt.hashSync(newPassword, 10));
  res.json({ ok: true });
});

// ── static frontend ──
app.use(express.static(path.join(__dirname, 'public')));
app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => console.log(`ChamCong Pro server listening on :${PORT}`));
