// سرداب الألفي — horror & facts platform (production build)
// Express + libSQL (Turso in production, local file in dev). No build step.
const express = require('express');
const { createClient } = require('@libsql/client');
const multer = require('multer');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const PORT = process.env.PORT || 3000;
const BASE = __dirname;
const UPLOADS_TMP = path.join(BASE, 'data', 'tmp');
const DATA = path.join(BASE, 'data');
for (const d of [UPLOADS_TMP, DATA]) fs.mkdirSync(d, { recursive: true });

const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
const ALLOW_FIRST_ADMIN = ADMIN_EMAILS.length === 0; // prod always sets ADMIN_EMAILS
const DEMO_CODES = process.env.DEMO_CODES !== '0';
const ENFORCE_HTTPS = process.env.ENFORCE_HTTPS === '1';
const COOKIE_SECURE = process.env.COOKIE_SECURE !== '0';
// SMS verification is off unless a paid SMS provider is wired (SMS_ENABLED=1).
// Free route: phone number is collected and stored, verification is by email.
const SMS_ENABLED = process.env.SMS_ENABLED === '1';

// App secret for CSRF HMAC: env in production, generated+persisted locally.
function loadSecret() {
  if (process.env.APP_SECRET) return process.env.APP_SECRET;
  const f = path.join(DATA, 'app.secret');
  if (fs.existsSync(f)) return fs.readFileSync(f, 'utf8').trim();
  const s = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(f, s, { mode: 0o600 });
  return s;
}
const APP_SECRET = loadSecret();

// ---------------------------------------------------------------- database
const db = createClient({
  url: process.env.TURSO_URL || `file:${path.join(DATA, 'sardab.db')}`,
  authToken: process.env.TURSO_AUTH_TOKEN,
});

async function initDb() {
  await db.batch([
    `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      phone TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'member',
      email_verified INTEGER NOT NULL DEFAULT 0,
      phone_verified INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`,
    `CREATE TABLE IF NOT EXISTS codes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      channel TEXT NOT NULL,
      code_hash TEXT NOT NULL,
      attempts INTEGER NOT NULL DEFAULT 0,
      expires_at TEXT NOT NULL,
      used INTEGER NOT NULL DEFAULT 0
    )`,
    `CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`,
    `CREATE TABLE IF NOT EXISTS videos (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      description TEXT DEFAULT '',
      category TEXT NOT NULL DEFAULT 'horror',
      mime TEXT NOT NULL,
      size INTEGER NOT NULL,
      data BLOB NOT NULL,
      views INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`,
    `CREATE TABLE IF NOT EXISTS posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      body TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`,
  ]);
}
const q = {
  get: async (sql, args = []) => (await db.execute({ sql, args })).rows[0],
  all: async (sql, args = []) => (await db.execute({ sql, args })).rows,
  run: async (sql, args = []) => db.execute({ sql, args }),
  batch: async (stmts) => db.batch(stmts),
};

// ---------------------------------------------------------------- helpers
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
}[c]));
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(pw, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
function checkPassword(pw, stored) {
  const [salt, hash] = stored.split(':');
  if (!salt || !hash) return false;
  const test = crypto.scryptSync(pw, salt, 64);
  const a = Buffer.from(hash, 'hex'), b = test;
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
const newCode = () => String(crypto.randomInt(100000, 999999));
const codeHash = (uid, channel, code) => sha256(`${uid}:${channel}:${code}`);

// ---- verification providers ----
// Email: Brevo SMTP (free tier, 300/day) via env BREVO_SMTP_USER/BREVO_SMTP_KEY.
// SMS:  plug a paid provider (e.g. Twilio Verify) into sendSmsCode and set SMS_ENABLED=1.
let mailer = null;
if (process.env.BREVO_SMTP_USER && process.env.BREVO_SMTP_KEY) {
  const nodemailer = require('nodemailer');
  mailer = nodemailer.createTransport({
    host: 'smtp-relay.brevo.com', port: 587,
    auth: { user: process.env.BREVO_SMTP_USER, pass: process.env.BREVO_SMTP_KEY },
  });
}
async function sendEmailCode(user, code) {
  if (!mailer) { console.log(`[demo-email] -> ${user.email}: ${code}`); return; }
  await mailer.sendMail({
    from: process.env.MAIL_FROM || `سرداب الألفي <${process.env.BREVO_SMTP_USER}>`,
    to: user.email,
    subject: 'كود تأكيد حسابك — سرداب الألفي',
    text: `كود التأكيد بتاعك هو: ${code}\nصالح لمدة ١٠ دقائق. لو مش إنت اللي سجلت، تجاهل الرسالة دي.`,
    html: `<div dir="rtl" style="font-family:sans-serif"><h2>سرداب الألفي 👻</h2><p>كود التأكيد بتاعك:</p><p style="font-size:32px;font-weight:800;letter-spacing:6px;direction:ltr">${code}</p><p>صالح لمدة ١٠ دقائق. لو مش إنت اللي سجلت، تجاهل الرسالة دي.</p></div>`,
  });
}
async function sendSmsCode(user, code) {
  console.log(`[sms-disabled] -> ${user.phone}: ${code}`);
}

const normalizePhone = (p) => String(p || '').replace(/[^\d+]/g, '');

// ---------------------------------------------------------------- rate limit
const buckets = new Map();
function limited(key, max, windowSec) {
  const now = Date.now();
  let b = buckets.get(key);
  if (!b || b.reset < now) { b = { count: 0, reset: now + windowSec * 1000 }; buckets.set(key, b); }
  b.count++;
  return b.count > max;
}
setInterval(() => { const now = Date.now(); for (const [k, b] of buckets) if (b.reset < now) buckets.delete(k); }, 60000).unref();
const clientIp = (req) => (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || '?';
function rateLimit(name, max, windowSec) {
  return (req, res, next) => {
    if (limited(`${name}:${clientIp(req)}`, max, windowSec)) {
      return res.status(429).send(page(null, 'مهلاً', `<div class="card"><h1>محاولات كتير 🚧</h1><p>حاولت أكتر من اللازم في وقت قصير — استنى شوية وجرّب تاني.</p></div>`));
    }
    next();
  };
}

// ---------------------------------------------------------------- app
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.urlencoded({ extended: false, limit: '1mb' }));
app.use('/static', express.static(path.join(BASE, 'public'), { maxAge: '1h', immutable: true }));

// HTTPS only + security headers
app.use((req, res, next) => {
  if (ENFORCE_HTTPS && req.headers['x-forwarded-proto'] === 'http') {
    return res.redirect(301, `https://${req.headers.host}${req.originalUrl}`);
  }
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; img-src 'self' data:; media-src 'self'; " +
    "style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; " +
    "script-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'");
  next();
});

const upload = multer({
  storage: multer.diskStorage({
    destination: UPLOADS_TMP,
    filename: (req, file, cb) => cb(null, `${Date.now()}-${crypto.randomBytes(6).toString('hex')}.bin`)
  }),
  limits: { fileSize: 250 * 1024 * 1024 }, // 250 MB per video
  fileFilter: (req, file, cb) => {
    const ok = /^video\/(mp4|webm|quicktime|x-matroska)$/.test(file.mimetype);
    cb(ok ? null : new Error('video-only'), ok);
  }
});

// ---------------------------------------------------------------- cookies / csrf
function getCookie(req, name) {
  const m = (req.headers.cookie || '').split(';').map(s => s.trim()).find(s => s.startsWith(name + '='));
  return m ? decodeURIComponent(m.slice(name.length + 1)) : null;
}
function setCookie(res, name, val, opts = {}) {
  const parts = [`${name}=${encodeURIComponent(val)}`, 'Path=/', 'SameSite=Lax'];
  if (opts.httpOnly !== false) parts.push('HttpOnly');
  if (COOKIE_SECURE) parts.push('Secure');
  if (opts.maxAge) parts.push(`Max-Age=${opts.maxAge}`);
  res.setHeader('Set-Cookie', parts.join('; '));
}
function ensureVid(req, res) {
  let vid = getCookie(req, 'vid');
  if (!vid || !/^[a-f0-9]{32}$/.test(vid)) {
    vid = crypto.randomBytes(16).toString('hex');
    setCookie(res, 'vid', vid, { maxAge: 60 * 60 * 24 * 365 });
  }
  return vid;
}
const csrfToken = (req, res) => crypto.createHmac('sha256', APP_SECRET).update(ensureVid(req, res)).digest('hex');
function csrfProtect(req, res, next) {
  const expected = crypto.createHmac('sha256', APP_SECRET).update(getCookie(req, 'vid') || '').digest('hex');
  const got = String(req.body._csrf || '');
  if (got.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(got), Buffer.from(expected))) {
    return res.status(403).send(page(null, 'مرفوض', `<div class="card"><h1>الطلب مرفوض 🚫</h1><p>رمز الحماية ناقص أو مش صحيح — ارجع وجرّب من الصفحة نفسها.</p></div>`));
  }
  next();
}

// ---------------------------------------------------------------- auth
async function currentUser(req) {
  const token = getCookie(req, 'sid');
  if (!token || !/^[a-f0-9]{64}$/.test(token)) return null;
  return (await q.get('SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?', [sha256(token)])) || null;
}
async function setSession(res, userId) {
  const token = crypto.randomBytes(32).toString('hex');
  await q.run('INSERT INTO sessions (token_hash, user_id) VALUES (?, ?)', [sha256(token), userId]);
  setCookie(res, 'sid', token, { maxAge: 60 * 60 * 24 * 30 });
}
async function clearSession(req, res) {
  const token = getCookie(req, 'sid');
  if (token) await q.run('DELETE FROM sessions WHERE token_hash = ?', [sha256(token)]);
  setCookie(res, 'sid', '', { maxAge: 0 });
}
const h = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const requireUser = (req, res, next) => {
  const u = req.user;
  if (!u) return res.redirect('/login');
  if (!u.email_verified || !u.phone_verified) return res.redirect('/verify');
  next();
};
const requireAdmin = (req, res, next) => {
  requireUser(req, res, () => {
    if (req.user.role !== 'admin') return res.status(403).send(page(req.user, 'غير مسموح', `<div class="card"><h1>غير مسموح</h1><p>الصفحة دي للأدمن بس.</p></div>`));
    next();
  });
};
// load user on every request
app.use(h(async (req, res, next) => { req.user = await currentUser(req); next(); }));

// ---------------------------------------------------------------- layout
const APP_URL = (process.env.APP_URL || '').replace(/\/+$/, '');
const SITE_DESC = 'سرداب الألفي — منصة الرعب والحقائق: قصص رعب حقيقية، ألغاز غامضة، وسلسلة «معلومة صح». شاهد الحلقات وتابع آخر الأخبار.';
function page(user, title, body, description, path) {
  const desc = description || SITE_DESC;
  const req_path = path || '/';
  const logged = user && user.email_verified && user.phone_verified;
  const nav = logged ? `
    <a href="/">الرئيسية</a>
    <a href="/videos">الفيديوهات</a>
    <a href="/news">الأخبار</a>
    ${user.role === 'admin' ? '<a href="/admin" class="admin-link">لوحة التحكم</a>' : ''}
    <a href="/settings">حسابي</a>
    <a href="/logout" class="ghost">خروج (${esc(user.name.split(' ')[0])})</a>`
    : '';
  return `<!doctype html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="${esc(desc)}">
<meta name="robots" content="index, follow">
${APP_URL ? `<link rel="canonical" href="${APP_URL}${esc(req_path || '/')}">` : ''}
<meta property="og:type" content="website">
<meta property="og:site_name" content="سرداب الألفي">
<meta property="og:title" content="${esc(title)} | سرداب الألفي">
<meta property="og:description" content="${esc(desc)}">
${APP_URL ? `<meta property="og:url" content="${APP_URL}${esc(req_path || '/')}">` : ''}
<meta property="og:locale" content="ar_AR">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="${esc(title)} | سرداب الألفي">
<meta name="twitter:description" content="${esc(desc)}">
<title>${esc(title)} | سرداب الألفي</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;900&display=swap" rel="stylesheet">
<link rel="stylesheet" href="/static/style.css">
</head>
<body>
<header class="topbar">
  <a class="brand" href="/">
    <span class="brand-mark">👻</span>
    <span class="brand-name">سرداب <b>الألفي</b></span>
  </a>
  <nav>${nav}</nav>
</header>
<main class="wrap">${body}</main>
<footer class="foot">سرداب الألفي — منصة الرعب والحقائق · كل الحقوق محفوظة</footer>
</body></html>`;
}
const flash = (msg, kind = 'info') => msg ? `<div class="flash ${kind}">${esc(msg)}</div>` : '';
const csrfField = (req, res) => `<input type="hidden" name="_csrf" value="${csrfToken(req, res)}">`;

function videoCard(v) {
  return `<a class="vcard" href="/watch/${v.id}">
    <div class="vthumb"><span class="play">▶</span><span class="vcat ${v.category}">${v.category === 'facts' ? 'معلومة صح' : 'رعب'}</span></div>
    <div class="vmeta"><h3>${esc(v.title)}</h3><p>${esc(v.description).slice(0, 80)}</p>
    <span class="vstats">👁 ${v.views} · ${esc(String(v.created_at).slice(0, 10))}</span></div>
  </a>`;
}
const videoGrid = (vs) => vs.length
  ? `<div class="grid">${vs.map(videoCard).join('')}</div>`
  : `<div class="card empty">لسه مفيش فيديوهات — أول حلقة جاية في الطريق 👻</div>`;
const postList = (ps) => ps.length
  ? ps.map(p => `<a class="post" href="/post/${p.id}"><div><h3>${esc(p.title)}</h3><p>${esc(p.body).slice(0, 140)}…</p></div><span class="pdate">${esc(String(p.created_at).slice(0, 10))}</span></a>`).join('')
  : `<div class="card empty">مفيش أخبار لسه.</div>`;

// ---------------------------------------------------------------- pages
app.get('/', h(async (req, res) => {
  const u = req.user;
  if (!u) {
    return res.send(page(null, 'أهلاً بيك', `
<section class="hero">
  <div class="hero-inner">
    <div class="hero-badge">منصة الرعب والحقائق</div>
    <h1>سرداب <span>الألفي</span></h1>
    <p class="hero-sub">قصص رعب حقيقية، ألغاز غامضة، وسلسلة «معلومة صح» — كل المحتوى في مكان واحد.</p>
    <div class="hero-cta">
      <a class="btn big" href="/register">سجّل حسابك</a>
      <a class="btn big alt" href="/login">عندك حساب؟ ادخل</a>
    </div>
    <p class="hero-note">التسجيل بالإيميل ورقم الموبايل — عشان أمان حسابك.</p>
  </div>
</section>
<section class="features">
  <div class="feat"><div class="feat-ic">🎬</div><h3>فيديوهات حصرية</h3><p>حلقات الرعب والغموض وسلسلة معلومة صح بتنزل هنا الأول.</p></div>
  <div class="feat"><div class="feat-ic">📰</div><h3>أخبار وبوستات</h3><p>آخر الأخبار والتحديثات والكواليس في صفحة واحدة.</p></div>
  <div class="feat"><div class="feat-ic">🔐</div><h3>حساب آمن</h3><p>تأكيد بالإيميل والموبايل، وكلمة سر مشفّرة بالكامل.</p></div>
</section>`, undefined, '/'));
  }
  if (!u.email_verified || !u.phone_verified) return res.redirect('/verify');
  const videos = await q.all('SELECT id, title, description, category, views, created_at FROM videos ORDER BY id DESC LIMIT 6');
  const posts = await q.all('SELECT * FROM posts ORDER BY id DESC LIMIT 3');
  res.send(page(u, 'الرئيسية', `
<section class="hero small">
  <div class="hero-inner">
    <h1>أهلاً ${esc(u.name.split(' ')[0])} 👋</h1>
    <p class="hero-sub">أحدث الفيديوهات والأخبار من السرداب.</p>
  </div>
</section>
<h2 class="sec-title">🎬 أحدث الفيديوهات <a class="more" href="/videos">كل الفيديوهات ←</a></h2>
${videoGrid(videos)}
<h2 class="sec-title">📰 آخر الأخبار <a class="more" href="/news">كل الأخبار ←</a></h2>
${postList(posts)}`));
}));

// ---------------------------------------------------------------- register
app.get('/register', (req, res) => {
  res.send(page(null, 'حساب جديد', `
<div class="card form-card">
  <h1>سجّل في السرداب 👻</h1>
  <p class="muted">هنبعتلك كود تأكيد على إيميلك${SMS_ENABLED ? ' وكود تاني على موبايلك' : ''}.</p>
  ${flash(req.query.e, 'err')}
  <form method="post" action="/register">
    ${csrfField(req, res)}
    <label>الاسم<input name="name" required minlength="2" maxlength="60" placeholder="اسمك"></label>
    <label>الإيميل<input name="email" type="email" required maxlength="120" placeholder="name@example.com" dir="ltr"></label>
    <label>رقم الموبايل<input name="phone" required maxlength="20" placeholder="01xxxxxxxxx" dir="ltr" inputmode="tel"></label>
    <label>كلمة السر<input name="password" type="password" required minlength="8" maxlength="72" placeholder="٨ حروف على الأقل"></label>
    <button class="btn" type="submit">إنشاء الحساب</button>
  </form>
  <p class="muted center">عندك حساب؟ <a href="/login">ادخل من هنا</a></p>
</div>`));
});

app.post('/register', rateLimit('register', 5, 3600), csrfProtect, h(async (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 60);
  const email = String(req.body.email || '').trim().toLowerCase().slice(0, 120);
  const phone = normalizePhone(req.body.phone).slice(0, 20);
  const password = String(req.body.password || '');
  if (name.length < 2 || !/^\S+@\S+\.\S+$/.test(email) || password.length < 8 || password.length > 72 || !/^\+?\d{8,15}$/.test(phone)) {
    return res.redirect('/register?e=' + encodeURIComponent('راجع البيانات: إيميل صحيح، موبايل صحيح، وكلمة سر ٨ حروف على الأقل.'));
  }
  const exists = await q.get('SELECT id FROM users WHERE email = ? OR phone = ?', [email, phone]);
  if (exists) return res.redirect('/register?e=' + encodeURIComponent('الإيميل أو رقم الموبايل مسجل قبل كده — جرّب تدخل.'));
  const count = (await q.get('SELECT COUNT(*) c FROM users')).c;
  const role = (ADMIN_EMAILS.includes(email) || (ALLOW_FIRST_ADMIN && count === 0)) ? 'admin' : 'member';
  const phoneVerified = SMS_ENABLED ? 0 : 1; // free route: phone stored, verified when SMS provider wired
  const info = await q.run('INSERT INTO users (name, email, phone, password_hash, role, phone_verified) VALUES (?,?,?,?,?,?)',
    [name, email, phone, hashPassword(password), role, phoneVerified]);
  const uid = Number(info.lastInsertRowid);
  const ec = newCode();
  await q.run("INSERT INTO codes (user_id, channel, code_hash, expires_at) VALUES (?,?,?, datetime('now','+10 minutes'))", [uid, 'email', codeHash(uid, 'email', ec)]);
  const user = await q.get('SELECT * FROM users WHERE id = ?', [uid]);
  await sendEmailCode(user, ec);
  if (SMS_ENABLED) {
    const pc = newCode();
    await q.run("INSERT INTO codes (user_id, channel, code_hash, expires_at) VALUES (?,?,?, datetime('now','+10 minutes'))", [uid, 'phone', codeHash(uid, 'phone', pc)]);
    await sendSmsCode(user, pc);
  }
  await setSession(res, uid);
  res.redirect('/verify');
}));

// ---------------------------------------------------------------- verify
app.get('/verify', h(async (req, res) => {
  const u = req.user;
  if (!u) return res.redirect('/login');
  if (u.email_verified && u.phone_verified) return res.redirect('/');
  let demo = '';
  if (DEMO_CODES) {
    // codes are stored hashed; in demo mode we show the LAST issued codes from the log table
    const rows = await q.all("SELECT channel, code_plain FROM demo_codes WHERE user_id = ?", [u.id]).catch(() => []);
    demo = `<div class="demo-box">🔧 <b>وضع التجربة:</b> خدمة الإرسال لسه مش متوصلة، فالأكواد بتظهر هنا مؤقتًا.<br>
      كود الإيميل: <b dir="ltr">${esc(rows.find(r => r.channel === 'email')?.code_plain || '—')}</b>${SMS_ENABLED ? ` · كود الموبايل: <b dir="ltr">${esc(rows.find(r => r.channel === 'phone')?.code_plain || '—')}</b>` : ''}</div>`;
  }
  res.send(page(u, 'تأكيد الحساب', `
<div class="card form-card">
  <h1>تأكيد الحساب 🔐</h1>
  <p class="muted">دخل الكود اللي وصلك على الإيميل <b>${esc(u.email)}</b>${SMS_ENABLED ? ` وكمان كود الموبايل <b dir="ltr">${esc(u.phone)}</b>` : ''}.</p>
  ${demo}
  ${flash(req.query.e, 'err')}
  <form method="post" action="/verify">
    ${csrfField(req, res)}
    ${u.email_verified ? '' : '<label>كود الإيميل<input name="email_code" inputmode="numeric" pattern="[0-9]{6}" placeholder="٦ أرقام" dir="ltr"></label>'}
    ${u.phone_verified ? '' : '<label>كود الموبايل<input name="phone_code" inputmode="numeric" pattern="[0-9]{6}" placeholder="٦ أرقام" dir="ltr"></label>'}
    <button class="btn" type="submit">تأكيد</button>
  </form>
  <form method="post" action="/verify/resend" class="inline">${csrfField(req, res)}<button class="linkbtn" type="submit">ابعت أكواد جديدة</button></form>
</div>`));
}));

async function tryVerify(uid, channel, input) {
  const row = await q.get("SELECT * FROM codes WHERE user_id = ? AND channel = ? AND used = 0 AND expires_at > datetime('now') ORDER BY id DESC LIMIT 1", [uid, channel]);
  if (!row || row.attempts >= 5) return false;
  if (row.code_hash !== codeHash(uid, channel, String(input || '').trim())) {
    await q.run('UPDATE codes SET attempts = attempts + 1 WHERE id = ?', [row.id]);
    return false;
  }
  await q.run('UPDATE codes SET used = 1 WHERE id = ?', [row.id]);
  await q.run(`UPDATE users SET ${channel === 'email' ? 'email_verified' : 'phone_verified'} = 1 WHERE id = ?`, [uid]);
  return true;
}

app.post('/verify', rateLimit('verify', 10, 600), csrfProtect, h(async (req, res) => {
  const u = req.user;
  if (!u) return res.redirect('/login');
  let bad = 0;
  if (!u.email_verified) {
    if (await tryVerify(u.id, 'email', req.body.email_code)) u.email_verified = 1; else bad++;
  }
  if (!u.phone_verified) {
    if (await tryVerify(u.id, 'phone', req.body.phone_code)) u.phone_verified = 1; else bad++;
  }
  if (bad) return res.redirect('/verify?e=' + encodeURIComponent('في كود مش صح أو انتهت صلاحيته — جرّب تاني.'));
  await q.run('DELETE FROM demo_codes WHERE user_id = ?', [u.id]).catch(() => {});
  res.redirect('/');
}));

app.post('/verify/resend', rateLimit('resend', 3, 600), csrfProtect, h(async (req, res) => {
  const u = req.user;
  if (!u) return res.redirect('/login');
  if (!u.email_verified) {
    const c = newCode();
    await q.run("INSERT INTO codes (user_id, channel, code_hash, expires_at) VALUES (?,?,?, datetime('now','+10 minutes'))", [u.id, 'email', codeHash(u.id, 'email', c)]);
    await sendEmailCode(u, c);
  }
  if (!u.phone_verified) {
    const c = newCode();
    await q.run("INSERT INTO codes (user_id, channel, code_hash, expires_at) VALUES (?,?,?, datetime('now','+10 minutes'))", [u.id, 'phone', codeHash(u.id, 'phone', c)]);
    await sendSmsCode(u, c);
  }
  res.redirect('/verify');
}));

// ---------------------------------------------------------------- login/out
app.get('/login', (req, res) => {
  res.send(page(null, 'تسجيل الدخول', `
<div class="card form-card">
  <h1>ادخل السرداب 🚪</h1>
  ${flash(req.query.e, 'err')}
  <form method="post" action="/login">
    ${csrfField(req, res)}
    <label>الإيميل<input name="email" type="email" required maxlength="120" dir="ltr"></label>
    <label>كلمة السر<input name="password" type="password" required maxlength="72"></label>
    <button class="btn" type="submit">دخول</button>
  </form>
  <p class="muted center">لسه ماعملتش حساب؟ <a href="/register">سجّل دلوقتي</a></p>
</div>`));
});
app.post('/login', rateLimit('login', 10, 600), csrfProtect, h(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase().slice(0, 120);
  const u = await q.get('SELECT * FROM users WHERE email = ?', [email]);
  if (!u || !checkPassword(String(req.body.password || ''), u.password_hash)) {
    return res.redirect('/login?e=' + encodeURIComponent('الإيميل أو كلمة السر مش صح.'));
  }
  await setSession(res, u.id);
  res.redirect(u.email_verified && u.phone_verified ? '/' : '/verify');
}));
app.get('/logout', h(async (req, res) => { await clearSession(req, res); res.redirect('/'); }));

// ---------------------------------------------------------------- settings
app.get('/settings', requireUser, (req, res) => {
  res.send(page(req.user, 'حسابي', `
<div class="card form-card">
  <h1>حسابي ⚙️</h1>
  <p class="muted">${esc(req.user.email)} · <span dir="ltr">${esc(req.user.phone)}</span> · ${req.user.role === 'admin' ? 'أدمن 🛠' : 'عضو'}</p>
  ${flash(req.query.ok, 'ok')}${flash(req.query.e, 'err')}
  <form method="post" action="/settings/password">
    ${csrfField(req, res)}
    <label>كلمة السر الحالية<input name="current" type="password" required maxlength="72"></label>
    <label>كلمة السر الجديدة<input name="next" type="password" required minlength="8" maxlength="72"></label>
    <button class="btn" type="submit">غيّر كلمة السر</button>
  </form>
</div>`));
});
app.post('/settings/password', requireUser, rateLimit('pwchange', 5, 600), csrfProtect, h(async (req, res) => {
  const cur = String(req.body.current || ''), nxt = String(req.body.next || '');
  if (!checkPassword(cur, req.user.password_hash)) return res.redirect('/settings?e=' + encodeURIComponent('كلمة السر الحالية مش صح.'));
  if (nxt.length < 8 || nxt.length > 72) return res.redirect('/settings?e=' + encodeURIComponent('كلمة السر الجديدة لازم ٨ حروف على الأقل.'));
  await q.run('UPDATE users SET password_hash = ? WHERE id = ?', [hashPassword(nxt), req.user.id]);
  await q.run('DELETE FROM sessions WHERE user_id = ?', [req.user.id]); // kick every session
  res.redirect('/settings?ok=' + encodeURIComponent('كلمة السر اتغيرت ✅ — سجل دخول من جديد.'));
}));

// ---------------------------------------------------------------- videos
app.get('/videos', requireUser, h(async (req, res) => {
  const cat = req.query.c === 'facts' ? 'facts' : req.query.c === 'horror' ? 'horror' : null;
  const videos = cat
    ? await q.all('SELECT id, title, description, category, views, created_at FROM videos WHERE category = ? ORDER BY id DESC', [cat])
    : await q.all('SELECT id, title, description, category, views, created_at FROM videos ORDER BY id DESC');
  res.send(page(req.user, 'الفيديوهات', `
<h2 class="sec-title">🎬 الفيديوهات</h2>
<div class="tabs">
  <a class="${!cat ? 'on' : ''}" href="/videos">الكل</a>
  <a class="${cat === 'horror' ? 'on' : ''}" href="/videos?c=horror">رعب 👻</a>
  <a class="${cat === 'facts' ? 'on' : ''}" href="/videos?c=facts">معلومة صح ✅</a>
</div>
${videoGrid(videos)}`));
}));

app.get('/watch/:id', requireUser, h(async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id)) return res.status(404).send(page(req.user, 'مش موجود', '<div class="card"><h1>الفيديو مش موجود</h1></div>'));
  const v = await q.get('SELECT id, title, description, category, views, created_at FROM videos WHERE id = ?', [id]);
  if (!v) return res.status(404).send(page(req.user, 'مش موجود', '<div class="card"><h1>الفيديو مش موجود</h1></div>'));
  await q.run('UPDATE videos SET views = views + 1 WHERE id = ?', [v.id]);
  const related = await q.all('SELECT id, title, description, category, views, created_at FROM videos WHERE id != ? ORDER BY id DESC LIMIT 3', [v.id]);
  res.send(page(req.user, v.title, `
<div class="watch">
  <video class="player" src="/media/${v.id}" controls playsinline preload="metadata"></video>
  <div class="watch-meta">
    <span class="vcat ${v.category}">${v.category === 'facts' ? 'معلومة صح' : 'رعب'}</span>
    <h1>${esc(v.title)}</h1>
    <p class="muted">👁 ${v.views + 1} مشاهدة · ${esc(String(v.created_at).slice(0, 10))}</p>
    <p class="desc">${esc(v.description)}</p>
  </div>
</div>
<h2 class="sec-title">فيديوهات تانية</h2>
${videoGrid(related)}`));
}));

app.get('/media/:id', requireUser, h(async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id)) return res.status(404).end();
  const v = await q.get('SELECT id, mime, size FROM videos WHERE id = ?', [id]);
  if (!v) return res.status(404).end();
  const size = Number(v.size);
  const range = req.headers.range;
  let start = 0, len = size;
  res.setHeader('Content-Type', v.mime);
  res.setHeader('Accept-Ranges', 'bytes');
  res.setHeader('Cache-Control', 'private, max-age=300');
  if (range) {
    const m = /bytes=(\d*)-(\d*)/.exec(range);
    start = m && m[1] ? parseInt(m[1]) : 0;
    let end = m && m[2] ? parseInt(m[2]) : Math.min(start + 4 * 1024 * 1024, size - 1);
    end = Math.min(end, size - 1);
    if (start >= size || start > end) { res.status(416); return res.end(); }
    len = end - start + 1;
    res.status(206);
    res.setHeader('Content-Range', `bytes ${start}-${end}/${size}`);
  }
  res.setHeader('Content-Length', len);
  const row = await q.get('SELECT substr(data, ?, ?) chunk FROM videos WHERE id = ?', [start + 1, len, id]);
  if (!row || !row.chunk) return res.status(404).end();
  res.end(Buffer.from(row.chunk));
}));

// ---------------------------------------------------------------- news
app.get('/news', requireUser, h(async (req, res) => {
  const posts = await q.all('SELECT * FROM posts ORDER BY id DESC');
  res.send(page(req.user, 'الأخبار', `<h2 class="sec-title">📰 الأخبار والبوستات</h2>${postList(posts)}`));
}));
app.get('/post/:id', requireUser, h(async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const p = Number.isInteger(id) ? await q.get('SELECT * FROM posts WHERE id = ?', [id]) : null;
  if (!p) return res.status(404).send(page(req.user, 'مش موجود', '<div class="card"><h1>البوست مش موجود</h1></div>'));
  res.send(page(req.user, p.title, `
<article class="card article">
  <h1>${esc(p.title)}</h1>
  <p class="muted">${esc(String(p.created_at).slice(0, 10))}</p>
  <div class="body">${esc(p.body).replace(/\n/g, '<br>')}</div>
</article>`));
}));

// ---------------------------------------------------------------- admin
app.get('/admin', requireAdmin, h(async (req, res) => {
  const stats = {
    users: (await q.get('SELECT COUNT(*) c FROM users')).c,
    videos: (await q.get('SELECT COUNT(*) c FROM videos')).c,
    posts: (await q.get('SELECT COUNT(*) c FROM posts')).c,
    views: (await q.get('SELECT COALESCE(SUM(views),0) s FROM videos')).s,
  };
  const videos = await q.all('SELECT id, title, category, views, created_at FROM videos ORDER BY id DESC');
  const posts = await q.all('SELECT * FROM posts ORDER BY id DESC');
  const vRows = videos.map(v => `<div class="arow">
    <div><b>${esc(v.title)}</b><span class="muted"> · ${v.category === 'facts' ? 'معلومة صح' : 'رعب'} · 👁 ${v.views}</span></div>
    <div class="arow-actions">
      <a class="chip" href="/admin/video/${v.id}/edit">تعديل</a>
      <form method="post" action="/admin/video/${v.id}/delete" onsubmit="return confirm('متأكد إنك عاوز تمسح الفيديو ده؟')">${csrfField(req, res)}<button class="chip danger" type="submit">مسح</button></form>
    </div>
  </div>`).join('');
  const pRows = posts.map(p => `<div class="arow">
    <div><b>${esc(p.title)}</b><span class="muted"> · ${esc(String(p.created_at).slice(0, 10))}</span></div>
    <div class="arow-actions">
      <a class="chip" href="/admin/post/${p.id}/edit">تعديل</a>
      <form method="post" action="/admin/post/${p.id}/delete" onsubmit="return confirm('متأكد إنك عاوز تمسح البوست ده؟')">${csrfField(req, res)}<button class="chip danger" type="submit">مسح</button></form>
    </div>
  </div>`).join('');
  res.send(page(req.user, 'لوحة التحكم', `
<h2 class="sec-title">🛠 لوحة التحكم</h2>
<div class="stats">
  <div class="stat"><b>${stats.users}</b><span>عضو</span></div>
  <div class="stat"><b>${stats.videos}</b><span>فيديو</span></div>
  <div class="stat"><b>${stats.posts}</b><span>بوست</span></div>
  <div class="stat"><b>${stats.views}</b><span>مشاهدة</span></div>
</div>
<div class="admin-cols">
<div class="card form-card">
  <h1>⬆️ ارفع فيديو</h1>
  ${flash(req.query.v, 'ok')}
  <form method="post" action="/admin/upload" enctype="multipart/form-data">
    ${csrfField(req, res)}
    <label>العنوان<input name="title" required maxlength="140"></label>
    <label>القسم
      <select name="category"><option value="horror">رعب 👻</option><option value="facts">معلومة صح ✅</option></select>
    </label>
    <label>الوصف<textarea name="description" rows="3" maxlength="2000"></textarea></label>
    <label>ملف الفيديو<input type="file" name="video" accept="video/mp4,video/webm,video/quicktime,video/x-matroska" required></label>
    <button class="btn" type="submit">رفع</button>
  </form>
</div>
<div class="card form-card">
  <h1>📰 انزل بوست</h1>
  ${flash(req.query.p, 'ok')}
  <form method="post" action="/admin/post">
    ${csrfField(req, res)}
    <label>العنوان<input name="title" required maxlength="140"></label>
    <label>النص<textarea name="body" rows="6" required maxlength="10000"></textarea></label>
    <button class="btn" type="submit">نشر</button>
  </form>
</div>
</div>
<h2 class="sec-title">🎬 الفيديوهات الحالية</h2>
<div class="card list-card">${vRows || '<p class="muted">مفيش فيديوهات.</p>'}</div>
<h2 class="sec-title">📰 البوستات الحالية</h2>
<div class="card list-card">${pRows || '<p class="muted">مفيش بوستات.</p>'}</div>`));
}));

app.post('/admin/upload', requireAdmin, rateLimit('upload', 30, 3600), (req, res, next) => {
  upload.single('video')(req, res, async (err) => {
    try {
      if (err || !req.file) {
        if (req.file) fs.unlink(req.file.path, () => {});
        return res.redirect('/admin?v=' + encodeURIComponent('الرفع فشل — الملف لازم يكون فيديو وأقل من 250 ميجا.'));
      }
      // CSRF check after multer parsed the multipart body
      const expected = crypto.createHmac('sha256', APP_SECRET).update(getCookie(req, 'vid') || '').digest('hex');
      const got = String(req.body._csrf || '');
      if (got.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(got), Buffer.from(expected))) {
        return res.status(403).send(page(req.user, 'مرفوض', `<div class="card"><h1>الطلب مرفوض 🚫</h1><p>رمز الحماية ناقص أو مش صحيح — ارجع وجرّب من الصفحة نفسها.</p></div>`));
      }
      const title = String(req.body.title || '').trim().slice(0, 140) || 'بدون عنوان';
      const category = req.body.category === 'facts' ? 'facts' : 'horror';
      const description = String(req.body.description || '').trim().slice(0, 2000);
      const data = fs.readFileSync(req.file.path);
      await q.run('INSERT INTO videos (title, description, category, mime, size, data) VALUES (?,?,?,?,?,?)',
        [title, description, category, req.file.mimetype, data.length, data]);
      res.redirect('/admin?v=' + encodeURIComponent('الفيديو اترفع ✅'));
    } catch (e) {
      next(e);
    } finally {
      if (req.file) fs.unlink(req.file.path, () => {});
    }
  });
});

app.get('/admin/video/:id/edit', requireAdmin, h(async (req, res) => {
  const v = await q.get('SELECT id, title, description, category FROM videos WHERE id = ?', [parseInt(req.params.id, 10) || 0]);
  if (!v) return res.status(404).send(page(req.user, 'مش موجود', '<div class="card"><h1>الفيديو مش موجود</h1></div>'));
  res.send(page(req.user, 'تعديل فيديو', `
<div class="card form-card">
  <h1>تعديل الفيديو ✏️</h1>
  <form method="post" action="/admin/video/${v.id}/edit">
    ${csrfField(req, res)}
    <label>العنوان<input name="title" required maxlength="140" value="${esc(v.title)}"></label>
    <label>القسم
      <select name="category">
        <option value="horror" ${v.category === 'horror' ? 'selected' : ''}>رعب 👻</option>
        <option value="facts" ${v.category === 'facts' ? 'selected' : ''}>معلومة صح ✅</option>
      </select>
    </label>
    <label>الوصف<textarea name="description" rows="3" maxlength="2000">${esc(v.description)}</textarea></label>
    <button class="btn" type="submit">حفظ</button>
  </form>
</div>`));
}));
app.post('/admin/video/:id/edit', requireAdmin, csrfProtect, h(async (req, res) => {
  const id = parseInt(req.params.id, 10) || 0;
  const title = String(req.body.title || '').trim().slice(0, 140) || 'بدون عنوان';
  const category = req.body.category === 'facts' ? 'facts' : 'horror';
  const description = String(req.body.description || '').trim().slice(0, 2000);
  await q.run('UPDATE videos SET title = ?, description = ?, category = ? WHERE id = ?', [title, description, category, id]);
  res.redirect('/admin?v=' + encodeURIComponent('التعديل اتحفظ ✅'));
}));
app.post('/admin/video/:id/delete', requireAdmin, csrfProtect, h(async (req, res) => {
  await q.run('DELETE FROM videos WHERE id = ?', [parseInt(req.params.id, 10) || 0]);
  res.redirect('/admin?v=' + encodeURIComponent('الفيديو اتمسح 🗑'));
}));

app.post('/admin/post', requireAdmin, csrfProtect, h(async (req, res) => {
  const title = String(req.body.title || '').trim().slice(0, 140);
  const body = String(req.body.body || '').trim().slice(0, 10000);
  if (title && body) await q.run('INSERT INTO posts (title, body) VALUES (?,?)', [title, body]);
  res.redirect('/admin?p=' + encodeURIComponent('البوست اتنشر ✅'));
}));
app.get('/admin/post/:id/edit', requireAdmin, h(async (req, res) => {
  const p = await q.get('SELECT * FROM posts WHERE id = ?', [parseInt(req.params.id, 10) || 0]);
  if (!p) return res.status(404).send(page(req.user, 'مش موجود', '<div class="card"><h1>البوست مش موجود</h1></div>'));
  res.send(page(req.user, 'تعديل بوست', `
<div class="card form-card">
  <h1>تعديل البوست ✏️</h1>
  <form method="post" action="/admin/post/${p.id}/edit">
    ${csrfField(req, res)}
    <label>العنوان<input name="title" required maxlength="140" value="${esc(p.title)}"></label>
    <label>النص<textarea name="body" rows="6" required maxlength="10000">${esc(p.body)}</textarea></label>
    <button class="btn" type="submit">حفظ</button>
  </form>
</div>`));
}));
app.post('/admin/post/:id/edit', requireAdmin, csrfProtect, h(async (req, res) => {
  const id = parseInt(req.params.id, 10) || 0;
  const title = String(req.body.title || '').trim().slice(0, 140);
  const body = String(req.body.body || '').trim().slice(0, 10000);
  if (title && body) await q.run('UPDATE posts SET title = ?, body = ? WHERE id = ?', [title, body, id]);
  res.redirect('/admin?p=' + encodeURIComponent('التعديل اتحفظ ✅'));
}));
app.post('/admin/post/:id/delete', requireAdmin, csrfProtect, h(async (req, res) => {
  await q.run('DELETE FROM posts WHERE id = ?', [parseInt(req.params.id, 10) || 0]);
  res.redirect('/admin?p=' + encodeURIComponent('البوست اتمسح 🗑'));
}));

app.get('/healthz', (req, res) => res.json({ ok: true }));

// ---------------------------------------------------------------- SEO
app.get('/robots.txt', (req, res) => {
  res.type('text/plain').send(
    'User-agent: *\nAllow: /\nDisallow: /admin\nDisallow: /settings\n' +
    (APP_URL ? `Sitemap: ${APP_URL}/sitemap.xml\n` : ''));
});
app.get('/sitemap.xml', h(async (req, res) => {
  const base = APP_URL || `${req.protocol}://${req.get('host')}`;
  const urls = [
    { loc: '/', priority: '1.0' },
    { loc: '/register', priority: '0.6' },
    { loc: '/login', priority: '0.4' },
  ];
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls.map(u => `  <url><loc>${base}${u.loc}</loc><changefreq>weekly</changefreq><priority>${u.priority}</priority></url>`).join('\n')}
</urlset>`;
  res.type('application/xml').send(xml);
}));

// demo_codes table exists only for demo mode (stores plaintext codes to show on screen)
async function initDemoTable() {
  if (!DEMO_CODES) return;
  await db.execute(`CREATE TABLE IF NOT EXISTS demo_codes (
    user_id INTEGER NOT NULL, channel TEXT NOT NULL, code_plain TEXT NOT NULL,
    PRIMARY KEY (user_id, channel))`);
}
// hook demo recording into senders
const _sendEmailCode = sendEmailCode, _sendSmsCode = sendSmsCode;
sendEmailCode = async (user, code) => {
  _sendEmailCode(user, code);
  if (DEMO_CODES) await q.run('INSERT INTO demo_codes (user_id, channel, code_plain) VALUES (?,?,?) ON CONFLICT(user_id, channel) DO UPDATE SET code_plain = excluded.code_plain', [user.id, 'email', code]).catch(() => {});
};
sendSmsCode = async (user, code) => {
  _sendSmsCode(user, code);
  if (DEMO_CODES) await q.run('INSERT INTO demo_codes (user_id, channel, code_plain) VALUES (?,?,?) ON CONFLICT(user_id, channel) DO UPDATE SET code_plain = excluded.code_plain', [user.id, 'phone', code]).catch(() => {});
};

// error handler
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).send(page(req.user, 'غلطة', `<div class="card"><h1>حصلت غلطة ⚠️</h1><p>جرّب تاني بعد شوية.</p></div>`));
});

(async () => {
  await initDb();
  await initDemoTable();
  app.listen(PORT, () => console.log(`سرداب الألفي listening on :${PORT} (demo_codes=${DEMO_CODES ? 'on' : 'off'}, https=${ENFORCE_HTTPS ? 'enforced' : 'off'})`));
})().catch(e => { console.error('boot failed', e); process.exit(1); });
