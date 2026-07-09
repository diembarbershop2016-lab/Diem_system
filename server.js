const express = require('express');
const cookieSession = require('cookie-session');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const DEFAULT_PIN = '1234';
const DEFAULT_SERVICES = [
  { id: 's1', name: 'Corte Degradado', price: 6000, duration: 30, color: '#1A1916' },
  { id: 's2', name: 'Corte Express', price: 5000, duration: 20, color: '#2E86AB' },
  { id: 's3', name: 'Corte %', price: 5160, duration: 25, color: '#7F5AF0' },
  { id: 's4', name: 'Corte + Barba', price: 10000, duration: 45, color: '#C9A84C' },
  { id: 's5', name: 'Corte + Barba %', price: 8600, duration: 40, color: '#E07B39' },
  { id: 's6', name: 'Corte + Perfilado', price: 8000, duration: 35, color: '#A23B72' },
  { id: 's7', name: 'Corte + Barba %%', price: 7500, duration: 35, color: '#1A6E3A' },
  { id: 's8', name: 'Barba', price: 5000, duration: 20, color: '#C0392B' },
  { id: 's9', name: 'Barba Perfilada', price: 3000, duration: 15, color: '#6B6860' },
  { id: 's10', name: 'Perfilado', price: 2500, duration: 10, color: '#B5A060' },
];

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '5mb' }));
app.use(cookieSession({
  name: 'diem_session',
  keys: [process.env.SESSION_SECRET || 'dev-secret-change-me'],
  maxAge: 30 * 24 * 60 * 60 * 1000,
  httpOnly: true,
  sameSite: 'lax',
}));

const MAX_LOGIN_ATTEMPTS = 5;
const LOGIN_LOCKOUT_MS = 5 * 60 * 1000;
const loginAttempts = new Map();
function loginLockedOut(ip) {
  const entry = loginAttempts.get(ip);
  return !!(entry && entry.lockUntil && Date.now() < entry.lockUntil);
}
function recordLoginFailure(ip) {
  const entry = loginAttempts.get(ip) || { count: 0 };
  entry.count += 1;
  if (entry.count >= MAX_LOGIN_ATTEMPTS) {
    entry.lockUntil = Date.now() + LOGIN_LOCKOUT_MS;
    entry.count = 0;
  }
  loginAttempts.set(ip, entry);
}
function recordLoginSuccess(ip) {
  loginAttempts.delete(ip);
}

async function ensureBootstrap() {
  const { rows } = await pool.query("SELECT value FROM settings WHERE key = 'pin_hash'");
  if (!rows.length) {
    const hash = await bcrypt.hash(DEFAULT_PIN, 10);
    await pool.query(
      "INSERT INTO settings (key, value) VALUES ('pin_hash', $1), ('pin_is_default', '1') ON CONFLICT (key) DO NOTHING",
      [hash]
    );
  }
  const { rows: svcRows } = await pool.query('SELECT 1 FROM services LIMIT 1');
  if (!svcRows.length) {
    for (const s of DEFAULT_SERVICES) {
      await pool.query(
        'INSERT INTO services (id, name, price, duration, color) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (id) DO NOTHING',
        [s.id, s.name, s.price, s.duration, s.color]
      );
    }
  }
}

function requireAuth(req, res, next) {
  if (req.session && req.session.authed) return next();
  res.status(401).json({ error: 'unauthorized' });
}

app.get('/api/branding', async (req, res) => {
  const { rows } = await pool.query(
    "SELECT key, value FROM settings WHERE key IN ('barber_name','barber_sub','logo_data','pin_is_default')"
  );
  const settings = {};
  for (const row of rows) settings[row.key] = row.value;
  res.json(settings);
});

app.post('/api/login', async (req, res) => {
  if (loginLockedOut(req.ip)) {
    return res.status(429).json({ error: 'too_many_attempts' });
  }
  const pin = String(req.body.pin || '');
  const { rows } = await pool.query("SELECT value FROM settings WHERE key = 'pin_hash'");
  const hash = rows[0] && rows[0].value;
  const ok = hash && await bcrypt.compare(pin, hash);
  if (!ok) {
    recordLoginFailure(req.ip);
    return res.status(401).json({ error: 'invalid_pin' });
  }
  recordLoginSuccess(req.ip);
  req.session.authed = true;
  res.json({ ok: true });
});

app.post('/api/logout', (req, res) => {
  req.session = null;
  res.json({ ok: true });
});

app.post('/api/change-pin', requireAuth, async (req, res) => {
  const oldPin = String(req.body.oldPin || '');
  const newPin = String(req.body.newPin || '');
  if (!newPin) return res.status(400).json({ error: 'missing_new_pin' });
  const { rows } = await pool.query("SELECT value FROM settings WHERE key = 'pin_hash'");
  const hash = rows[0] && rows[0].value;
  const ok = hash && await bcrypt.compare(oldPin, hash);
  if (!ok) return res.status(401).json({ error: 'invalid_pin' });
  const newHash = await bcrypt.hash(newPin, 10);
  await pool.query(
    "INSERT INTO settings (key, value) VALUES ('pin_hash', $1) ON CONFLICT (key) DO UPDATE SET value = $1",
    [newHash]
  );
  await pool.query(
    "INSERT INTO settings (key, value) VALUES ('pin_is_default', '0') ON CONFLICT (key) DO UPDATE SET value = '0'"
  );
  res.json({ ok: true });
});

app.get('/api/state', requireAuth, async (req, res) => {
  const [servicesRes, entriesRes, settingsRes] = await Promise.all([
    pool.query('SELECT id, name, price, duration, color FROM services ORDER BY name'),
    pool.query(`SELECT id, service_id AS "svcId", to_char(date, 'YYYY-MM-DD') AS date,
                       to_char(time, 'HH24:MI') AS time, price, tip, note
                FROM log_entries ORDER BY date, time`),
    pool.query("SELECT key, value FROM settings WHERE key IN ('barber_name','barber_sub','logo_data')"),
  ]);
  const settings = {};
  for (const row of settingsRes.rows) settings[row.key] = row.value;
  res.json({ services: servicesRes.rows, logEntries: entriesRes.rows, settings });
});

app.put('/api/state', requireAuth, async (req, res) => {
  const { services, logEntries, settings } = req.body;
  if (!Array.isArray(services) || !Array.isArray(logEntries)) {
    return res.status(400).json({ error: 'invalid_body' });
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM services');
    for (const s of services) {
      await client.query(
        'INSERT INTO services (id, name, price, duration, color) VALUES ($1,$2,$3,$4,$5)',
        [s.id, s.name, s.price || 0, s.duration || 0, s.color || '#1A1916']
      );
    }
    await client.query('DELETE FROM log_entries');
    for (const e of logEntries) {
      await client.query(
        `INSERT INTO log_entries (id, service_id, service_name_snapshot, date, time, price, tip, note)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
        [e.id, e.svcId || null, e.serviceNameSnapshot || null, e.date, e.time, e.price || 0, e.tip || 0, e.note || '']
      );
    }
    if (settings && typeof settings === 'object') {
      for (const key of ['barber_name', 'barber_sub', 'logo_data']) {
        if (Object.prototype.hasOwnProperty.call(settings, key)) {
          await client.query(
            'INSERT INTO settings (key, value) VALUES ($1,$2) ON CONFLICT (key) DO UPDATE SET value = $2',
            [key, settings[key]]
          );
        }
      }
    }
    await client.query('COMMIT');
    res.json({ ok: true });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ error: 'save_failed' });
  } finally {
    client.release();
  }
});

app.use(express.static(__dirname));

const PORT = process.env.PORT || 3000;
ensureBootstrap()
  .catch((err) => console.error('bootstrap failed', err))
  .finally(() => {
    app.listen(PORT, () => console.log(`Diem_system listening on ${PORT}`));
  });
