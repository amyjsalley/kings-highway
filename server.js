// Mom's 70th Road Trip: a tiny live tracker.
// Family enters FAMILY_CODE to view. Amy enters AMY_CODE to check in, post notes and add photos/video.
const express = require('express');
const crypto = require('crypto');
const path = require('path');
const { Pool } = require('pg');
const webpush = require('web-push');

const PORT = process.env.PORT || 3000;
const FAMILY_CODE = (process.env.FAMILY_CODE || 'graceland').trim().toLowerCase();
const AMY_CODE = (process.env.AMY_CODE || 'changeme').trim().toLowerCase();
const SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
let TRIP = null;
try { TRIP = JSON.parse(process.env.TRIP_DATA || 'null'); } catch (e) { console.error('TRIP_DATA is not valid JSON'); }
const VAPID_PUBLIC = process.env.VAPID_PUBLIC || '';
const VAPID_PRIVATE = process.env.VAPID_PRIVATE || '';
if (VAPID_PUBLIC && VAPID_PRIVATE) webpush.setVapidDetails('mailto:trip@example.com', VAPID_PUBLIC, VAPID_PRIVATE);
const STORAGE_CAP = 900 * 1024 * 1024; // stay under the free database's 1 GB
const MAX_UPLOAD = 25 * 1024 * 1024;
const OK_TYPES = ['image/jpeg', 'image/png', 'image/webp', 'image/gif', 'video/mp4', 'video/quicktime', 'video/webm'];

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && !/localhost|127\.0\.0\.1/.test(process.env.DATABASE_URL) ? { rejectUnauthorized: false } : false,
});
pool.on('error', e => console.error('db idle error', e.message));
process.on('unhandledRejection', e => console.error('unhandled', e && e.message));

async function init() {
  await pool.query(`CREATE TABLE IF NOT EXISTS kv (key text PRIMARY KEY, value jsonb NOT NULL)`);
  await pool.query(`CREATE TABLE IF NOT EXISTS moments (
    id serial PRIMARY KEY, kind text NOT NULL, stop_id text, caption text,
    at timestamptz NOT NULL DEFAULT now(), mime text NOT NULL, data bytea NOT NULL)`);
  await pool.query(`ALTER TABLE moments ADD COLUMN IF NOT EXISTS by_name text`);
  await pool.query(`CREATE TABLE IF NOT EXISTS subs (endpoint text PRIMARY KEY, sub jsonb NOT NULL, prefs jsonb NOT NULL, created timestamptz NOT NULL DEFAULT now())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS viewers (id text PRIMARY KEY, name text NOT NULL, first_seen timestamptz NOT NULL DEFAULT now(), last_seen timestamptz NOT NULL DEFAULT now(), visits int NOT NULL DEFAULT 1)`);
  await pool.query(`ALTER TABLE subs ADD COLUMN IF NOT EXISTS viewer_id text`);
}
async function getKV(key, fallback) {
  const r = await pool.query('SELECT value FROM kv WHERE key=$1', [key]);
  return r.rows[0] ? r.rows[0].value : fallback;
}
async function setKV(key, value) {
  await pool.query('INSERT INTO kv(key,value) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value', [key, JSON.stringify(value)]);
}

// ---- tiny signed-cookie sessions ----
const sign = v => v + '.' + crypto.createHmac('sha256', SECRET).update(v).digest('base64url');
function readRole(req) {
  const m = /(?:^|;\s*)trip=([^;]+)/.exec(req.headers.cookie || '');
  if (!m) return null;
  const raw = decodeURIComponent(m[1]); const i = raw.lastIndexOf('.');
  const v = raw.slice(0, i);
  const good = sign(v);
  if (good.length !== raw.length || !crypto.timingSafeEqual(Buffer.from(good), Buffer.from(raw))) return null;
  if (v === 'amy' || v === 'family') return v;
  return /^family:[a-f0-9]{16}$/.test(v) ? v : null;
}
const need = role => (req, res, next) => {
  const r = readRole(req);
  if (!r || (role === 'amy' && r !== 'amy')) return res.status(401).json({ error: 'not allowed' });
  req.role = r === 'amy' ? 'amy' : 'family'; req.vid = r.startsWith('family:') ? r.slice(7) : null; next();
};

// slow down passcode guessing
const tries = new Map();
function throttled(ip) {
  const now = Date.now(), t = (tries.get(ip) || []).filter(x => now - x < 10 * 60 * 1000);
  tries.set(ip, t); return t.length >= 20;
}

// ---- push notifications ----
const PREFS = ['all', 'night', 'fun', 'bucees', 'home', 'photos', 'notes'];
async function notify(topic, title, body) {
  if (!VAPID_PUBLIC) return;
  try {
    const r = await pool.query('SELECT endpoint, sub, prefs FROM subs');
    const msg = JSON.stringify({ title, body });
    await Promise.all(r.rows.map(async row => {
      const p = row.prefs || [];
      const stopTopic = !['photos', 'notes'].includes(topic);
      if (!(p.includes(topic) || (stopTopic && p.includes('all')))) return;
      try { await webpush.sendNotification(row.sub, msg, { TTL: 3600 }); }
      catch (e) { if (e.statusCode === 404 || e.statusCode === 410) await pool.query('DELETE FROM subs WHERE endpoint=$1', [row.endpoint]); }
    }));
  } catch (e) { console.error('notify failed', e.message); }
}
let lastPhotoPing = 0;

const app = express();
const wrapAsync = fn => (req, res, next) => { try { const p = fn(req, res, next); if (p && p.catch) p.catch(next); } catch (e) { next(e); } };
for (const m of ['get', 'post', 'delete']) { const orig = app[m].bind(app); app[m] = (first, ...hs) => hs.length ? orig(first, ...hs.map(h => typeof h === 'function' && h.length < 4 ? wrapAsync(h) : h)) : orig(first); }
app.set('trust proxy', 1);
app.use((req, res, next) => { res.set('X-Content-Type-Options', 'nosniff'); res.set('Referrer-Policy', 'no-referrer'); next(); });
app.use(express.json({ limit: '20kb' }));
app.get('/sw.js', (req, res, next) => { res.set('Cache-Control', 'no-cache'); next(); });

app.post('/api/login', async (req, res) => {
  if (throttled(req.ip)) return res.status(429).json({ error: 'Too many tries. Wait a few minutes.' });
  const code = String((req.body && req.body.code) || '').trim().toLowerCase();
  let role = null;
  if (code && code === AMY_CODE) role = 'amy';
  else if (code && code === FAMILY_CODE) role = 'family';
  if (!role) { tries.get(req.ip).push(Date.now()); return res.status(401).json({ error: 'That passcode didn’t work.' }); }
  let val = role;
  if (role === 'family') {
    const name = String((req.body && req.body.name) || '').trim().slice(0, 40) || 'Family member';
    const found = name === 'Family member' ? { rows: [] } : await pool.query('SELECT id FROM viewers WHERE lower(name) = lower($1) LIMIT 1', [name]);
    let vid = found.rows[0] && found.rows[0].id;
    if (!vid) { vid = crypto.randomBytes(8).toString('hex'); await pool.query('INSERT INTO viewers(id, name) VALUES($1,$2)', [vid, name]); }
    val = 'family:' + vid;
  }
  res.set('Set-Cookie', `trip=${encodeURIComponent(sign(val))}; Path=/; Max-Age=${60 * 60 * 24 * 30}; HttpOnly; Secure; SameSite=Lax`);
  res.json({ role });
});
app.post('/api/logout', (req, res) => { res.set('Set-Cookie', 'trip=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax'); res.json({ ok: true }); });

app.get('/api/state', need('family'), async (req, res) => {
  const [checkins, note, loc, ms] = await Promise.all([
    getKV('checkins', {}), getKV('note', null), getKV('loc', null),
    pool.query('SELECT id, kind, stop_id, caption, at, by_name FROM moments ORDER BY at'),
  ]);
  res.set('Cache-Control', 'no-store');
  let me = null;
  if (req.vid) { const u = await pool.query("UPDATE viewers SET visits = visits + CASE WHEN last_seen < now() - interval '30 minutes' THEN 1 ELSE 0 END, last_seen = now() WHERE id=$1 RETURNING name", [req.vid]); me = u.rows[0] ? u.rows[0].name : null; }
  res.json({ role: req.role, me, trip: TRIP, loc, checkins, note, moments: ms.rows.map(r => ({ id: r.id, kind: r.kind, stopId: r.stop_id, caption: r.caption, at: r.at, by: r.by_name || 'Amy' })), pushKey: VAPID_PUBLIC });
});

const validStop = s => typeof s === 'string' && /^[a-z0-9-]{1,30}$/.test(s);
app.post('/api/checkin', need('amy'), async (req, res) => {
  const { stopId } = req.body || {};
  if (!validStop(stopId)) return res.status(400).json({ error: 'bad stop' });
  const c = await getKV('checkins', {}); const already = !!c[stopId]; c[stopId] = new Date().toISOString(); await setKV('checkins', c);
  res.json({ ok: true });
  const st = TRIP && Array.isArray(TRIP.stops) ? TRIP.stops.find(x => x.id === stopId) : null;
  if (st && !already) notify(st.cat || 'road', st.cat === 'home' ? 'Elvis has left the building!' : 'The King\u2019s Highway', (st.cat === 'home' ? '' : '\u2713 ') + st.name + (st.cat === 'home' ? '' : ' \u00b7 ' + String(st.place || '').split(' \u00b7 ')[0]));
});
app.post('/api/undo', need('amy'), async (req, res) => {
  const { stopId } = req.body || {};
  if (!validStop(stopId)) return res.status(400).json({ error: 'bad stop' });
  const c = await getKV('checkins', {}); delete c[stopId]; await setKV('checkins', c);
  res.json({ ok: true });
});
app.post('/api/location', need('amy'), async (req, res) => {
  const { lat, lon, acc } = req.body || {};
  const ok = n => typeof n === 'number' && isFinite(n);
  if (!ok(lat) || !ok(lon) || Math.abs(lat) > 90 || Math.abs(lon) > 180) return res.status(400).json({ error: 'bad location' });
  await setKV('loc', { lat: +lat.toFixed(5), lon: +lon.toFixed(5), acc: ok(acc) ? Math.round(acc) : null, at: new Date().toISOString() });
  res.json({ ok: true });
});
app.post('/api/location/off', need('amy'), async (req, res) => { await setKV('loc', null); res.json({ ok: true }); });
app.post('/api/note', need('amy'), async (req, res) => {
  const text = String((req.body && req.body.text) || '').trim().slice(0, 240);
  await setKV('note', text ? { text, at: new Date().toISOString() } : null);
  res.json({ ok: true });
  if (text) notify('notes', 'Note from Amy', text);
});

const upTries = new Map();
app.post('/api/moments', need('family'), (req, res, next) => {
  const now = Date.now(), t = (upTries.get(req.ip) || []).filter(x => now - x < 3600000);
  if (req.role !== 'amy' && t.length >= 40) return res.status(429).json({ error: 'That\u2019s a lot of uploads! Try again in a bit.' });
  t.push(now); upTries.set(req.ip, t); next();
}, express.raw({ type: () => true, limit: MAX_UPLOAD }), async (req, res) => {
  const mime = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
  if (!OK_TYPES.includes(mime)) return res.status(415).json({ error: 'That file type isn’t supported.' });
  if (!req.body || !req.body.length) return res.status(400).json({ error: 'empty file' });
  const stopId = validStop(req.query.stopId) ? req.query.stopId : null;
  const caption = String(req.query.caption || '').slice(0, 160);
  const kind = mime.startsWith('video/') ? 'video' : 'photo';
  const byName = req.role === 'amy' ? 'Amy' : (String(req.query.by || '').trim().slice(0, 40) || 'Family');
  const used = await pool.query('SELECT COALESCE(SUM(octet_length(data)),0)::bigint AS n FROM moments');
  if (Number(used.rows[0].n) + req.body.length > STORAGE_CAP) return res.status(507).json({ error: 'The photo album is full. Share extra videos in the iCloud album instead.' });
  const r = await pool.query('INSERT INTO moments(kind, stop_id, caption, mime, data, by_name) VALUES($1,$2,$3,$4,$5,$6) RETURNING id', [kind, stopId, caption, mime, req.body, byName]);
  res.json({ id: r.rows[0].id });
  if (Date.now() - lastPhotoPing > 10 * 60000) { lastPhotoPing = Date.now(); notify('photos', 'New ' + kind + ' from ' + byName, caption || 'Tap to see it on The King\u2019s Highway.'); }
});
app.delete('/api/moments/:id', need('amy'), async (req, res) => {
  await pool.query('DELETE FROM moments WHERE id=$1', [parseInt(req.params.id, 10) || 0]);
  res.json({ ok: true });
});

// media with Range support (Safari needs it for video)
app.get('/media/:id', need('family'), async (req, res) => {
  const r = await pool.query('SELECT mime, data FROM moments WHERE id=$1', [parseInt(req.params.id, 10) || 0]);
  if (!r.rows[0]) return res.status(404).end();
  const { mime, data } = r.rows[0];
  const type = mime === 'video/quicktime' ? 'video/mp4' : mime;
  res.set({ 'Content-Type': type, 'Accept-Ranges': 'bytes', 'Cache-Control': 'private, max-age=86400' });
  const range = /bytes=(\d*)-(\d*)/.exec(req.headers.range || '');
  if (range) {
    let start = range[1] === '' ? data.length - parseInt(range[2], 10) : parseInt(range[1], 10);
    let end = range[1] !== '' && range[2] !== '' ? parseInt(range[2], 10) : data.length - 1;
    if (isNaN(start) || start < 0) start = 0;
    end = Math.min(end, data.length - 1);
    if (start > end) { res.set('Content-Range', `bytes */${data.length}`); return res.status(416).end(); }
    res.status(206).set('Content-Range', `bytes ${start}-${end}/${data.length}`).set('Content-Length', end - start + 1);
    return res.end(data.subarray(start, end + 1));
  }
  res.set('Content-Length', data.length).end(data);
});

app.post('/api/push/subscribe', need('family'), async (req, res) => {
  const { sub, prefs } = req.body || {};
  if (!sub || typeof sub.endpoint !== 'string' || !/^https:\/\//.test(sub.endpoint) || !sub.keys) return res.status(400).json({ error: 'bad subscription' });
  const clean = Array.isArray(prefs) ? prefs.filter(p => PREFS.includes(p)) : [];
  await pool.query('INSERT INTO subs(endpoint, sub, prefs, viewer_id) VALUES($1,$2,$3,$4) ON CONFLICT(endpoint) DO UPDATE SET sub=EXCLUDED.sub, prefs=EXCLUDED.prefs, viewer_id=EXCLUDED.viewer_id', [sub.endpoint, JSON.stringify(sub), JSON.stringify(clean), req.vid || null]);
  res.json({ ok: true });
});
app.post('/api/push/mine', need('family'), async (req, res) => {
  const r = await pool.query('SELECT prefs FROM subs WHERE endpoint=$1', [String((req.body && req.body.endpoint) || '')]);
  res.json({ prefs: r.rows[0] ? r.rows[0].prefs : null });
});
app.post('/api/push/unsubscribe', need('family'), async (req, res) => {
  await pool.query('DELETE FROM subs WHERE endpoint=$1', [String((req.body && req.body.endpoint) || '')]);
  res.json({ ok: true });
});
app.post('/api/push/test', need('family'), async (req, res) => {
  const ep = String((req.body && req.body.endpoint) || '');
  const r = await pool.query('SELECT sub FROM subs WHERE endpoint=$1', [ep]);
  if (!r.rows[0] || !VAPID_PUBLIC) return res.status(404).json({ error: 'not subscribed' });
  try { await webpush.sendNotification(r.rows[0].sub, JSON.stringify({ title: 'Thank you, thank you very much', body: 'Notifications are on for The King\u2019s Highway.' })); res.json({ ok: true }); }
  catch (e) { res.status(502).json({ error: 'push failed' }); }
});
app.get('/api/followers', need('amy'), async (req, res) => {
  const v = await pool.query('SELECT v.name, v.first_seen, v.last_seen, v.visits, EXISTS(SELECT 1 FROM subs s WHERE s.viewer_id = v.id) AS alerts FROM viewers v ORDER BY v.last_seen DESC');
  const subs = await pool.query('SELECT COUNT(*)::int AS n FROM subs');
  res.set('Cache-Control', 'no-store');
  res.json({ viewers: v.rows, alerts: subs.rows[0].n });
});
app.get('/healthz', (req, res) => res.send('ok'));
const ICON = Buffer.from('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', 'base64');
app.get(['/icon-192.png', '/icon-512.png'], (req, res) => res.type('image/png').set('Cache-Control', 'public, max-age=86400').send(ICON));
const STATIC = { '/': 'index.html', '/index.html': 'index.html', '/sw.js': 'sw.js', '/manifest.webmanifest': 'manifest.webmanifest' };
app.get(Object.keys(STATIC), (req, res) => {
  if (req.path.endsWith('.webmanifest')) res.type('application/manifest+json');
  res.sendFile(path.join(__dirname, STATIC[req.path]));
});
app.use((err, req, res, next) => {
  if (err && err.type === 'entity.too.large') return res.status(413).json({ error: 'That file is too big.' });
  console.error(err && err.message); if (res.headersSent) return; res.status(500).json({ error: 'Something went wrong. Try again in a moment.' });
});

init().then(() => app.listen(PORT, () => console.log('Trip site on ' + PORT)))
  .catch(e => { console.error('DB init failed', e); process.exit(1); });
