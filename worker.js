// سرداب الألفي — Cloudflare Workers build (Hono + Turso). Ported from server.js (Express).
import { Hono } from 'hono';
import { getCookie, setCookie, deleteCookie } from 'hono/cookie';
import { createClient } from '@libsql/client/web';
import cssText from './public/style.css';

const app = new Hono();

// ---------------------------------------------------------------- helpers
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
}[c]));

const toHex = (buf) => Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
const fromHex = (hex) => new Uint8Array(hex.match(/.{2}/g).map(b => parseInt(b, 16)));
const randHex = (n) => toHex(crypto.getRandomValues(new Uint8Array(n)).buffer);

async function sha256(s) {
  return toHex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)));
}
async function hmacSha256(secret, msg) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return toHex(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(msg)));
}
function timingEq(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

async function hashPassword(pw) {
  const salt = randHex(16);
  const iters = 100000;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: fromHex(salt), iterations: iters }, key, 256);
  return `pbkdf2:${iters}:${salt}:${toHex(bits)}`;
}
async function checkPassword(pw, stored) {
  const parts = String(stored || '').split(':');
  if (parts[0] !== 'pbkdf2') return false;
  const [, itersStr, salt, hash] = parts;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: fromHex(salt), iterations: parseInt(itersStr, 10) }, key, 256);
  return timingEq(toHex(bits), hash);
}
const newCode = () => String(100000 + (crypto.getRandomValues(new Uint32Array(1))[0] % 900000));
const codeHash = (uid, channel, code) => sha256(`${uid}:${channel}:${code}`);
const normalizePhone = (p) => String(p || '').replace(/[^\d+]/g, '');

// ---------------------------------------------------------------- env + db
function envOf(c) {
  const e = c.env || {};
  return {
    TURSO_URL: e.TURSO_URL || '',
    TURSO_AUTH_TOKEN: e.TURSO_AUTH_TOKEN || '',
    ADMIN_EMAILS: (e.ADMIN_EMAILS || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean),
    DEMO_CODES: (e.DEMO_CODES || '0') !== '0',
    COOKIE_SECURE: (e.COOKIE_SECURE || '1') !== '0',
    APP_SECRET: e.APP_SECRET || 'dev-secret-change-me',
    BREVO_API_KEY: e.BREVO_API_KEY || '',
    MAIL_FROM: e.MAIL_FROM || 'sirdabelalfy@gmail.com',
    APP_URL: (e.APP_URL || '').replace(/\/+$/, ''),
  };
}
function dbOf(c) {
  const E = envOf(c);
  const db = createClient({ url: E.TURSO_URL, authToken: E.TURSO_AUTH_TOKEN });
  return {
    get: async (sql, args = []) => (await db.execute({ sql, args })).rows[0],
    all: async (sql, args = []) => (await db.execute({ sql, args })).rows,
    run: async (sql, args = []) => db.execute({ sql, args }),
    batch: (stmts) => db.batch(stmts),
  };
}
let schemaReady = false;
async function initDb(q) {
  if (schemaReady) return;
  await q.batch([
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
    `CREATE TABLE IF NOT EXISTS demo_codes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      channel TEXT NOT NULL,
      code_plain TEXT NOT NULL
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
      thumb BLOB,
      thumb_mime TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`,
    `CREATE TABLE IF NOT EXISTS posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      body TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`,
  ]);
  await q.run('ALTER TABLE videos ADD COLUMN thumb BLOB').catch(() => {});
  await q.run('ALTER TABLE videos ADD COLUMN thumb_mime TEXT').catch(() => {});
  schemaReady = true;
}

// ---------------------------------------------------------------- email (Brevo HTTP API)
async function sendEmailCode(c, user, code) {
  const E = envOf(c);
  if (E.DEMO_CODES) {
    const q = dbOf(c);
    await q.run('INSERT INTO demo_codes (user_id, channel, code_plain) VALUES (?,?,?)', [user.id, 'email', code]).catch(() => {});
    console.log(`[demo-email] -> ${user.email}: ${code}`);
    return;
  }
  if (!E.BREVO_API_KEY) { console.log(`[no-mailer] -> ${user.email}`); return; }
  const res = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: { 'api-key': E.BREVO_API_KEY, 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({
      sender: { email: E.MAIL_FROM, name: 'سرداب الألفي' },
      to: [{ email: user.email, name: user.name }],
      subject: 'كود تأكيد حسابك — سرداب الألفي',
      htmlContent: `<div dir="rtl" style="font-family:sans-serif"><h2>سرداب الألفي 👻</h2><p>كود التأكيد بتاعك:</p><p style="font-size:32px;font-weight:800;letter-spacing:6px;direction:ltr">${code}</p><p>صالح لمدة ١٠ دقائق. لو مش إنت اللي سجلت، تجاهل الرسالة دي.</p></div>`,
    }),
  });
  if (!res.ok) console.log('[brevo] send failed: ' + res.status);
}
async function sendSmsCode(c, user, code) {
  console.log(`[sms-disabled] -> ${user.phone}: ${code}`);
}

// ---------------------------------------------------------------- rate limit (per-isolate best effort)
const buckets = new Map();
function limited(key, max, windowSec) {
  const now = Date.now();
  let b = buckets.get(key);
  if (!b || b.reset < now) { b = { count: 0, reset: now + windowSec * 1000 }; buckets.set(key, b); }
  b.count++;
  if (buckets.size > 5000) { for (const [k, v] of buckets) if (v.reset < now) buckets.delete(k); }
  return b.count > max;
}
const rateLimit = (name, max, windowSec) => async (c, next) => {
  const ip = c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for') || '?';
  if (limited(`${name}:${ip}`, max, windowSec)) {
    return c.html(page(null, 'مهلاً', `<div class="card"><h1>محاولات كتير 🚧</h1><p>حاولت أكتر من اللازم في وقت قصير — استنى شوية وجرّب تاني.</p></div>`, undefined, undefined, envOf(c).APP_URL), 429);
  }
  await next();
};

// ---------------------------------------------------------------- security headers
app.use('*', async (c, next) => {
  await next();
  c.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  c.header('X-Content-Type-Options', 'nosniff');
  c.header('X-Frame-Options', 'DENY');
  c.header('Referrer-Policy', 'strict-origin-when-cross-origin');
  c.header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  c.header('Content-Security-Policy',
    "default-src 'self'; img-src 'self' data:; media-src 'self'; " +
    "style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; " +
    "script-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors='none'");
});

// ---------------------------------------------------------------- cookies / csrf
function cookieOpts(c, maxAge) {
  const o = { path: '/', httpOnly: true, sameSite: 'Lax' };
  if (envOf(c).COOKIE_SECURE) o.secure = true;
  if (maxAge !== undefined) o.maxAge = maxAge;
  return o;
}
async function ensureVid(c) {
  let vid = getCookie(c, 'vid');
  if (!vid || !/^[a-f0-9]{32}$/.test(vid)) {
    vid = randHex(16);
    setCookie(c, 'vid', vid, cookieOpts(c, 60 * 60 * 24 * 365));
  }
  return vid;
}
async function csrfToken(c) {
  let t = c.get('csrfTok');
  if (!t) { t = await hmacSha256(envOf(c).APP_SECRET, await ensureVid(c)); c.set('csrfTok', t); }
  return t;
}
const csrfField = async (c) => `<input type="hidden" name="_csrf" value="${await csrfToken(c)}">`;
async function csrfOk(c, got) {
  const expected = await hmacSha256(envOf(c).APP_SECRET, getCookie(c, 'vid') || '');
  return timingEq(String(got || ''), expected);
}
const csrfReject = (c) => c.html(page(null, 'مرفوض', `<div class="card"><h1>الطلب مرفوض 🚫</h1><p>رمز الحماية ناقص أو مش صحيح — ارجع وجرّب من الصفحة نفسها.</p></div>`, undefined, undefined, envOf(c).APP_URL), 403);

// ---------------------------------------------------------------- auth
async function currentUser(c) {
  const token = getCookie(c, 'sid');
  if (!token || !/^[a-f0-9]{64}$/.test(token)) return null;
  const q = dbOf(c);
  return (await q.get('SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?', [await sha256(token)])) || null;
}
async function setSession(c, userId) {
  const token = randHex(32);
  const q = dbOf(c);
  await q.run('INSERT INTO sessions (token_hash, user_id) VALUES (?, ?)', [await sha256(token), userId]);
  setCookie(c, 'sid', token, cookieOpts(c, 60 * 60 * 24 * 30));
}
async function clearSession(c) {
  const token = getCookie(c, 'sid');
  if (token) await dbOf(c).run('DELETE FROM sessions WHERE token_hash = ?', [await sha256(token)]);
  deleteCookie(c, 'sid', { path: '/' });
}
app.use('*', async (c, next) => {
  const q = dbOf(c);
  await initDb(q);
  c.set('user', await currentUser(c));
  await next();
});
const requireUser = async (c, next) => {
  const u = c.get('user');
  if (!u) return c.redirect('/login');
  if (!u.email_verified || !u.phone_verified) return c.redirect('/verify');
  await next();
};
const requireAdmin = async (c, next) => {
  const u = c.get('user');
  if (!u) return c.redirect('/login');
  if (!u.email_verified || !u.phone_verified) return c.redirect('/verify');
  if (u.role !== 'admin') return c.html(page(u, 'غير مسموح', `<div class="card"><h1>غير مسموح</h1><p>الصفحة دي للأدمن بس.</p></div>`, undefined, undefined, envOf(c).APP_URL), 403);
  await next();
};

// ---------------------------------------------------------------- layout
const SITE_DESC = 'سرداب الألفي — منصة الرعب والحقائق: قصص رعب حقيقية، ألغاز غامضة، وسلسلة «معلومة صح». شاهد الحلقات وتابع آخر الأخبار.';
function page(user, title, body, description, path, appUrl) {
  const desc = description || SITE_DESC;
  const reqPath = path || '/';
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
${appUrl ? `<link rel="canonical" href="${appUrl}${esc(reqPath)}">` : ''}
<meta property="og:type" content="website">
<meta property="og:site_name" content="سرداب الألفي">
<meta property="og:title" content="${esc(title)} | سرداب الألفي">
<meta property="og:description" content="${esc(desc)}">
${appUrl ? `<meta property="og:url" content="${appUrl}${esc(reqPath)}">` : ''}
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
const html = (c, user, title, body, description, path) => {
  const E = envOf(c);
  return c.html(page(user, title, body, description, path, E.APP_URL || new URL(c.req.url).origin));
};

const videoGrid = (vs) => vs.length
  ? `<div class="grid">${vs.map(v => `
  <a class="vcard" href="/watch/${v.id}">
    <div class="vthumb ${v.category}">${v.has_thumb ? `<img src="/thumb/${v.id}" alt="" loading="lazy">` : `<span>${v.category === 'facts' ? '✅' : '👻'}</span>`}</div>
    <div class="vmeta"><h3>${esc(v.title)}</h3><p>${esc(v.description).slice(0, 80)}</p>
    <div class="vstats"><span>👁 ${v.views}</span><span>${esc(String(v.created_at).slice(0, 10))}</span></div></div>
  </a>`).join('')}</div>`
  : '<p class="muted">مفيش فيديوهات هنا لسه.</p>';

const postList = (ps) => ps.length
  ? ps.map(p => `<a class="post" href="/post/${p.id}"><div><h3>${esc(p.title)}</h3><p>${esc(p.body).slice(0, 140)}…</p></div><span class="pdate">${esc(String(p.created_at).slice(0, 10))}</span></a>`).join('')
  : '<p class="muted">مفيش بوستات لسه.</p>';

// ---------------------------------------------------------------- static
app.get('/static/style.css', (c) => {
  c.header('Content-Type', 'text/css; charset=utf-8');
  c.header('Cache-Control', 'public, max-age=3600, immutable');
  return c.body(cssText);
});

// ---------------------------------------------------------------- home
app.get('/', async (c) => {
  const u = c.get('user');
  const q = dbOf(c);
  if (!u) {
    return html(c, null, 'أهلاً بيك', `
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
</section>`, undefined, '/');
  }
  if (!u.email_verified || !u.phone_verified) return c.redirect('/verify');
  const videos = await q.all('SELECT id, title, description, category, views, created_at, CASE WHEN thumb IS NULL THEN 0 ELSE 1 END has_thumb FROM videos ORDER BY id DESC LIMIT 6');
  const posts = await q.all('SELECT * FROM posts ORDER BY id DESC LIMIT 3');
  return html(c, u, 'الرئيسية', `
<section class="hero small">
  <div class="hero-inner">
    <h1>أهلاً ${esc(u.name.split(' ')[0])} 👋</h1>
    <p class="hero-sub">أحدث الفيديوهات والأخبار من السرداب.</p>
  </div>
</section>
<h2 class="sec-title">🎬 أحدث الفيديوهات <a class="more" href="/videos">كل الفيديوهات ←</a></h2>
${videoGrid(videos)}
<h2 class="sec-title">📰 آخر الأخبار <a class="more" href="/news">كل الأخبار ←</a></h2>
${postList(posts)}`);
});

// ---------------------------------------------------------------- register
app.get('/register', async (c) => {
  return html(c, null, 'حساب جديد', `
<div class="card form-card">
  <h1>سجّل في السرداب 👻</h1>
  <p class="muted">هنبعتلك كود تأكيد على إيميلك.</p>
  ${flash(c.req.query('e'), 'err')}
  <form method="post" action="/register">
    ${await csrfField(c)}
    <label>الاسم<input name="name" required minlength="2" maxlength="60" placeholder="اسمك"></label>
    <label>الإيميل<input name="email" type="email" required maxlength="120" placeholder="name@example.com" dir="ltr"></label>
    <label>رقم الموبايل<input name="phone" required maxlength="20" placeholder="01xxxxxxxxx" dir="ltr" inputmode="tel"></label>
    <label>كلمة السر<input name="password" type="password" required minlength="8" maxlength="72" placeholder="٨ حروف على الأقل"></label>
    <button class="btn" type="submit">إنشاء الحساب</button>
  </form>
  <p class="muted center">عندك حساب؟ <a href="/login">ادخل من هنا</a></p>
</div>`, undefined, '/register');
});

app.post('/register', rateLimit('register', 5, 3600), async (c) => {
  const body = await c.req.parseBody();
  if (!(await csrfOk(c, body._csrf))) return csrfReject(c);
  const E = envOf(c);
  const q = dbOf(c);
  const name = String(body.name || '').trim().slice(0, 60);
  const email = String(body.email || '').trim().toLowerCase().slice(0, 120);
  const phone = normalizePhone(body.phone).slice(0, 20);
  const password = String(body.password || '');
  if (name.length < 2 || !/^\S+@\S+\.\S+$/.test(email) || password.length < 8 || password.length > 72 || !/^\+?\d{8,15}$/.test(phone)) {
    return c.redirect('/register?e=' + encodeURIComponent('راجع البيانات: إيميل صحيح، موبايل صحيح، وكلمة سر ٨ حروف على الأقل.'));
  }
  const exists = await q.get('SELECT id FROM users WHERE email = ? OR phone = ?', [email, phone]);
  if (exists) return c.redirect('/register?e=' + encodeURIComponent('الإيميل أو رقم الموبايل مسجل قبل كده — جرّب تدخل.'));
  const role = E.ADMIN_EMAILS.includes(email) ? 'admin' : 'member';
  const pwHash = await hashPassword(password);
  const info = await q.run('INSERT INTO users (name, email, phone, password_hash, role, phone_verified) VALUES (?,?,?,?,?,1)',
    [name, email, phone, pwHash, role]);
  const uid = Number(info.lastInsertRowid);
  const ec = newCode();
  await q.run("INSERT INTO codes (user_id, channel, code_hash, expires_at) VALUES (?,?,?, datetime('now','+10 minutes'))", [uid, 'email', await codeHash(uid, 'email', ec)]);
  const user = await q.get('SELECT * FROM users WHERE id = ?', [uid]);
  await sendEmailCode(c, user, ec);
  await setSession(c, uid);
  return c.redirect('/verify');
});

// ---------------------------------------------------------------- verify
app.get('/verify', async (c) => {
  const u = c.get('user');
  if (!u) return c.redirect('/login');
  if (u.email_verified && u.phone_verified) return c.redirect('/');
  const E = envOf(c);
  const q = dbOf(c);
  let demo = '';
  if (E.DEMO_CODES) {
    const rows = await q.all('SELECT channel, code_plain FROM demo_codes WHERE user_id = ?', [u.id]).catch(() => []);
    demo = `<div class="demo-box">🔧 <b>وضع التجربة:</b> خدمة الإرسال لسه مش متوصلة، فالأكواد بتظهر هنا مؤقتًا.<br>
      كود الإيميل: <b dir="ltr">${esc(rows.find(r => r.channel === 'email')?.code_plain || '—')}</b></div>`;
  }
  return html(c, u, 'تأكيد الحساب', `
<div class="card form-card">
  <h1>تأكيد الحساب 🔐</h1>
  <p class="muted">دخل الكود اللي وصلك على الإيميل <b>${esc(u.email)}</b>.</p>
  ${demo}
  ${flash(c.req.query('e'), 'err')}
  <form method="post" action="/verify">
    ${await csrfField(c)}
    ${u.email_verified ? '' : '<label>كود الإيميل<input name="email_code" inputmode="numeric" pattern="[0-9]{6}" placeholder="٦ أرقام" dir="ltr"></label>'}
    <button class="btn" type="submit">تأكيد</button>
  </form>
  <form method="post" action="/verify/resend" class="inline">${await csrfField(c)}<button class="linkbtn" type="submit">ابعت أكواد جديدة</button></form>
</div>`);
});

async function tryVerify(q, uid, channel, input) {
  const row = await q.get("SELECT * FROM codes WHERE user_id = ? AND channel = ? AND used = 0 AND expires_at > datetime('now') ORDER BY id DESC LIMIT 1", [uid, channel]);
  if (!row || row.attempts >= 5) return false;
  if (row.code_hash !== await codeHash(uid, channel, String(input || '').trim())) {
    await q.run('UPDATE codes SET attempts = attempts + 1 WHERE id = ?', [row.id]);
    return false;
  }
  await q.run('UPDATE codes SET used = 1 WHERE id = ?', [row.id]);
  await q.run(`UPDATE users SET ${channel === 'email' ? 'email_verified' : 'phone_verified'} = 1 WHERE id = ?`, [uid]);
  return true;
}

app.post('/verify', rateLimit('verify', 10, 600), async (c) => {
  const u = c.get('user');
  if (!u) return c.redirect('/login');
  const body = await c.req.parseBody();
  if (!(await csrfOk(c, body._csrf))) return csrfReject(c);
  const q = dbOf(c);
  let ok = true;
  if (!u.email_verified) ok = await tryVerify(q, u.id, 'email', body.email_code);
  if (!ok) return c.redirect('/verify?e=' + encodeURIComponent('في كود مش صح أو انتهت صلاحيته — جرّب تاني.'));
  await q.run('DELETE FROM demo_codes WHERE user_id = ?', [u.id]).catch(() => {});
  return c.redirect('/');
});

app.post('/verify/resend', rateLimit('resend', 3, 600), async (c) => {
  const u = c.get('user');
  if (!u) return c.redirect('/login');
  const body = await c.req.parseBody();
  if (!(await csrfOk(c, body._csrf))) return csrfReject(c);
  const q = dbOf(c);
  if (!u.email_verified) {
    const code = newCode();
    await q.run("INSERT INTO codes (user_id, channel, code_hash, expires_at) VALUES (?,?,?, datetime('now','+10 minutes'))", [u.id, 'email', await codeHash(u.id, 'email', code)]);
    await sendEmailCode(c, u, code);
  }
  return c.redirect('/verify');
});

// ---------------------------------------------------------------- login/out
app.get('/login', async (c) => {
  return html(c, null, 'تسجيل الدخول', `
<div class="card form-card">
  <h1>ادخل السرداب 🚪</h1>
  ${flash(c.req.query('e'), 'err')}
  <form method="post" action="/login">
    ${await csrfField(c)}
    <label>الإيميل<input name="email" type="email" required maxlength="120" dir="ltr"></label>
    <label>كلمة السر<input name="password" type="password" required maxlength="72"></label>
    <button class="btn" type="submit">دخول</button>
  </form>
  <p class="muted center">لسه ماعملتش حساب؟ <a href="/register">سجّل دلوقتي</a></p>
</div>`, undefined, '/login');
});
app.post('/login', rateLimit('login', 10, 600), async (c) => {
  const body = await c.req.parseBody();
  if (!(await csrfOk(c, body._csrf))) return csrfReject(c);
  const email = String(body.email || '').trim().toLowerCase().slice(0, 120);
  const q = dbOf(c);
  const u = await q.get('SELECT * FROM users WHERE email = ?', [email]);
  if (!u || !(await checkPassword(String(body.password || ''), u.password_hash))) {
    return c.redirect('/login?e=' + encodeURIComponent('الإيميل أو كلمة السر مش صح.'));
  }
  await setSession(c, u.id);
  return c.redirect(u.email_verified && u.phone_verified ? '/' : '/verify');
});
app.get('/logout', async (c) => { await clearSession(c); return c.redirect('/'); });

// ---------------------------------------------------------------- settings
app.get('/settings', requireUser, async (c) => {
  const u = c.get('user');
  return html(c, u, 'حسابي', `
<div class="card form-card">
  <h1>حسابي ⚙️</h1>
  <p class="muted">${esc(u.email)} · <span dir="ltr">${esc(u.phone)}</span> · ${u.role === 'admin' ? 'أدمن 🛠' : 'عضو'}</p>
  ${flash(c.req.query('ok'), 'ok')}${flash(c.req.query('e'), 'err')}
  <form method="post" action="/settings/password">
    ${await csrfField(c)}
    <label>كلمة السر الحالية<input name="current" type="password" required maxlength="72"></label>
    <label>كلمة السر الجديدة<input name="next" type="password" required minlength="8" maxlength="72"></label>
    <button class="btn" type="submit">غيّر كلمة السر</button>
  </form>
</div>`);
});
app.post('/settings/password', requireUser, rateLimit('pwchange', 5, 600), async (c) => {
  const u = c.get('user');
  const body = await c.req.parseBody();
  if (!(await csrfOk(c, body._csrf))) return csrfReject(c);
  const cur = String(body.current || ''), nxt = String(body.next || '');
  if (!(await checkPassword(cur, u.password_hash))) return c.redirect('/settings?e=' + encodeURIComponent('كلمة السر الحالية مش صح.'));
  if (nxt.length < 8 || nxt.length > 72) return c.redirect('/settings?e=' + encodeURIComponent('كلمة السر الجديدة لازم ٨ حروف على الأقل.'));
  const q = dbOf(c);
  await q.run('UPDATE users SET password_hash = ? WHERE id = ?', [await hashPassword(nxt), u.id]);
  await q.run('DELETE FROM sessions WHERE user_id = ?', [u.id]);
  return c.redirect('/settings?ok=' + encodeURIComponent('كلمة السر اتغيرت ✅ — سجل دخول من جديد.'));
});

// ---------------------------------------------------------------- videos
app.get('/videos', requireUser, async (c) => {
  const q = dbOf(c);
  const catQ = c.req.query('c');
  const cat = catQ === 'facts' ? 'facts' : catQ === 'horror' ? 'horror' : null;
  const videos = cat
    ? await q.all('SELECT id, title, description, category, views, created_at, CASE WHEN thumb IS NULL THEN 0 ELSE 1 END has_thumb FROM videos WHERE category = ? ORDER BY id DESC', [cat])
    : await q.all('SELECT id, title, description, category, views, created_at, CASE WHEN thumb IS NULL THEN 0 ELSE 1 END has_thumb FROM videos ORDER BY id DESC');
  return html(c, c.get('user'), 'الفيديوهات', `
<h2 class="sec-title">🎬 الفيديوهات</h2>
<div class="tabs">
  <a class="${!cat ? 'on' : ''}" href="/videos">الكل</a>
  <a class="${cat === 'horror' ? 'on' : ''}" href="/videos?c=horror">رعب 👻</a>
  <a class="${cat === 'facts' ? 'on' : ''}" href="/videos?c=facts">معلومة صح ✅</a>
</div>
${videoGrid(videos)}`);
});

app.get('/watch/:id', requireUser, async (c) => {
  const q = dbOf(c);
  const u = c.get('user');
  const id = parseInt(c.req.param('id'), 10);
  if (!Number.isInteger(id)) return html(c, u, 'مش موجود', '<div class="card"><h1>الفيديو مش موجود</h1></div>');
  const v = await q.get('SELECT id, title, description, category, views, created_at, CASE WHEN thumb IS NULL THEN 0 ELSE 1 END has_thumb FROM videos WHERE id = ?', [id]);
  if (!v) return html(c, u, 'مش موجود', '<div class="card"><h1>الفيديو مش موجود</h1></div>');
  await q.run('UPDATE videos SET views = views + 1 WHERE id = ?', [v.id]);
  const related = await q.all('SELECT id, title, description, category, views, created_at, CASE WHEN thumb IS NULL THEN 0 ELSE 1 END has_thumb FROM videos WHERE id != ? ORDER BY id DESC LIMIT 3', [v.id]);
  return html(c, u, v.title, `
<div class="watch">
  <video class="player" src="/media/${v.id}"${v.has_thumb ? ` poster="/thumb/${v.id}"` : ''} controls playsinline preload="metadata"></video>
  <div class="watch-meta">
    <span class="vcat ${v.category}">${v.category === 'facts' ? 'معلومة صح' : 'رعب'}</span>
    <h1>${esc(v.title)}</h1>
    <p class="muted">👁 ${v.views + 1} مشاهدة · ${esc(String(v.created_at).slice(0, 10))}</p>
    <p class="desc">${esc(v.description)}</p>
  </div>
</div>
<h2 class="sec-title">فيديوهات تانية</h2>
${videoGrid(related)}`, v.description);
});

app.get('/media/:id', requireUser, async (c) => {
  const q = dbOf(c);
  const id = parseInt(c.req.param('id'), 10);
  if (!Number.isInteger(id)) return c.body(null, 404);
  const v = await q.get('SELECT id, mime, size FROM videos WHERE id = ?', [id]);
  if (!v) return c.body(null, 404);
  const size = Number(v.size);
  const range = c.req.header('range');
  let start = 0, len = size, status = 200;
  const headers = {
    'Content-Type': v.mime,
    'Accept-Ranges': 'bytes',
    'Cache-Control': 'private, max-age=300',
  };
  if (range) {
    const m = /bytes=(\d*)-(\d*)/.exec(range);
    start = m && m[1] ? parseInt(m[1]) : 0;
    let end = m && m[2] ? parseInt(m[2]) : Math.min(start + 4 * 1024 * 1024, size - 1);
    end = Math.min(end, size - 1);
    if (start >= size || start > end) return c.body(null, 416);
    len = end - start + 1;
    status = 206;
    headers['Content-Range'] = `bytes ${start}-${end}/${size}`;
  }
  headers['Content-Length'] = String(len);
  const row = await q.get('SELECT substr(data, ?, ?) chunk FROM videos WHERE id = ?', [start + 1, len, id]);
  if (!row || !row.chunk) return c.body(null, 404);
  const chunk = row.chunk instanceof ArrayBuffer ? new Uint8Array(row.chunk)
    : typeof row.chunk === 'string' ? fromHex(row.chunk) : new Uint8Array(row.chunk);
  return new Response(chunk, { status, headers });
});

app.get('/thumb/:id', async (c) => {
  const q = dbOf(c);
  const id = parseInt(c.req.param('id'), 10);
  if (!Number.isInteger(id)) return c.body(null, 404);
  const row = await q.get('SELECT thumb, thumb_mime FROM videos WHERE id = ?', [id]);
  if (!row || !row.thumb) return c.body(null, 404);
  const img = row.thumb instanceof ArrayBuffer ? new Uint8Array(row.thumb)
    : typeof row.thumb === 'string' ? fromHex(row.thumb) : new Uint8Array(row.thumb);
  return new Response(img, { headers: { 'Content-Type': row.thumb_mime || 'image/jpeg', 'Cache-Control': 'public, max-age=3600' } });
});

// ---------------------------------------------------------------- news
app.get('/news', requireUser, async (c) => {
  const q = dbOf(c);
  const posts = await q.all('SELECT * FROM posts ORDER BY id DESC');
  return html(c, c.get('user'), 'الأخبار', `<h2 class="sec-title">📰 الأخبار والبوستات</h2>${postList(posts)}`);
});
app.get('/post/:id', requireUser, async (c) => {
  const q = dbOf(c);
  const id = parseInt(c.req.param('id'), 10);
  const p = Number.isInteger(id) ? await q.get('SELECT * FROM posts WHERE id = ?', [id]) : null;
  if (!p) return html(c, c.get('user'), 'مش موجود', '<div class="card"><h1>البوست مش موجود</h1></div>');
  return html(c, c.get('user'), p.title, `
<article class="card article">
  <h1>${esc(p.title)}</h1>
  <p class="muted">${esc(String(p.created_at).slice(0, 10))}</p>
  <div class="body">${esc(p.body).replace(/\n/g, '<br>')}</div>
</article>`, p.body.slice(0, 160));
});

// ---------------------------------------------------------------- admin
app.get('/admin', requireAdmin, async (c) => {
  const q = dbOf(c);
  const u = c.get('user');
  const stats = {
    users: (await q.get('SELECT COUNT(*) c FROM users')).c,
    videos: (await q.get('SELECT COUNT(*) c FROM videos')).c,
    posts: (await q.get('SELECT COUNT(*) c FROM posts')).c,
    views: (await q.get('SELECT COALESCE(SUM(views),0) s FROM videos')).s,
  };
  const videos = await q.all('SELECT id, title, category, views, created_at FROM videos ORDER BY id DESC');
  const posts = await q.all('SELECT * FROM posts ORDER BY id DESC');
  const tok = await csrfField(c);
  const vRows = videos.map(v => `<div class="arow">
    <div><b>${esc(v.title)}</b><span class="muted"> · ${v.category === 'facts' ? 'معلومة صح' : 'رعب'} · 👁 ${v.views}</span></div>
    <div class="arow-actions">
      <a class="chip" href="/admin/video/${v.id}/edit">تعديل</a>
      <form method="post" action="/admin/video/${v.id}/delete" onsubmit="return confirm('متأكد إنك عاوز تمسح الفيديو ده؟')">${tok}<button class="chip danger" type="submit">مسح</button></form>
    </div>
  </div>`).join('');
  const pRows = posts.map(p => `<div class="arow">
    <div><b>${esc(p.title)}</b><span class="muted"> · ${esc(String(p.created_at).slice(0, 10))}</span></div>
    <div class="arow-actions">
      <a class="chip" href="/admin/post/${p.id}/edit">تعديل</a>
      <form method="post" action="/admin/post/${p.id}/delete" onsubmit="return confirm('متأكد إنك عاوز تمسح البوست ده؟')">${tok}<button class="chip danger" type="submit">مسح</button></form>
    </div>
  </div>`).join('');
  return html(c, u, 'لوحة التحكم', `
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
  ${flash(c.req.query('v'), 'ok')}
  <form method="post" action="/admin/upload" enctype="multipart/form-data">
    ${tok}
    <label>العنوان<input name="title" required maxlength="140"></label>
    <label>القسم
      <select name="category"><option value="horror">رعب 👻</option><option value="facts">معلومة صح ✅</option></select>
    </label>
    <label>الوصف<textarea name="description" rows="3" maxlength="2000"></textarea></label>
    <label>ملف الفيديو<input type="file" name="video" accept="video/mp4,video/webm,video/quicktime,video/x-matroska" required></label>
    <label>صورة الغلاف (اختياري)<input type="file" name="thumb" accept="image/jpeg,image/png,image/webp"></label>
    <button class="btn" type="submit">رفع</button>
  </form>
</div>
<div class="card form-card">
  <h1>📰 انزل بوست</h1>
  ${flash(c.req.query('p'), 'ok')}
  <form method="post" action="/admin/post">
    ${tok}
    <label>العنوان<input name="title" required maxlength="140"></label>
    <label>النص<textarea name="body" rows="6" required maxlength="10000"></textarea></label>
    <button class="btn" type="submit">نشر</button>
  </form>
</div>
</div>
<h2 class="sec-title">🎬 الفيديوهات الحالية</h2>
<div class="card list-card">${vRows || '<p class="muted">مفيش فيديوهات.</p>'}</div>
<h2 class="sec-title">📰 البوستات الحالية</h2>
<div class="card list-card">${pRows || '<p class="muted">مفيش بوستات.</p>'}</div>`);
});

app.post('/admin/upload', requireAdmin, rateLimit('upload', 30, 3600), async (c) => {
  const body = await c.req.parseBody();
  if (!(await csrfOk(c, body._csrf))) return csrfReject(c);
  const file = body.video;
  if (!file || typeof file === 'string' || !/^video\/(mp4|webm|quicktime|x-matroska)$/.test(file.type || '')) {
    return c.redirect('/admin?v=' + encodeURIComponent('الرفع فشل — الملف لازم يكون فيديو.'));
  }
  if (file.size > 50 * 1024 * 1024) {
    return c.redirect('/admin?v=' + encodeURIComponent('الفيديو أكبر من ٥٠ ميجا — صغّره وارفعه تاني.'));
  }
  const title = String(body.title || '').trim().slice(0, 140) || 'بدون عنوان';
  const category = body.category === 'facts' ? 'facts' : 'horror';
  const description = String(body.description || '').trim().slice(0, 2000);
  const data = new Uint8Array(await file.arrayBuffer());
  const tfile = body.thumb;
  let thumb = null, thumbMime = null;
  if (tfile && typeof tfile !== 'string' && tfile.size > 0) {
    if (!/^image\/(jpeg|png|webp)$/.test(tfile.type || '')) {
      return c.redirect('/admin?v=' + encodeURIComponent('صورة الغلاف لازم تكون JPG أو PNG أو WebP.'));
    }
    if (tfile.size > 2 * 1024 * 1024) {
      return c.redirect('/admin?v=' + encodeURIComponent('صورة الغلاف أكبر من ٢ ميجا — صغّرها وارفعها تاني.'));
    }
    thumb = new Uint8Array(await tfile.arrayBuffer());
    thumbMime = tfile.type;
  }
  const q = dbOf(c);
  await q.run('INSERT INTO videos (title, description, category, mime, size, data, thumb, thumb_mime) VALUES (?,?,?,?,?,?,?,?)',
    [title, description, category, file.type, data.length, data, thumb, thumbMime]);
  return c.redirect('/admin?v=' + encodeURIComponent('الفيديو اترفع ✅'));
});

app.get('/admin/video/:id/edit', requireAdmin, async (c) => {
  const q = dbOf(c);
  const v = await q.get('SELECT id, title, description, category, CASE WHEN thumb IS NULL THEN 0 ELSE 1 END has_thumb FROM videos WHERE id = ?', [parseInt(c.req.param('id'), 10) || 0]);
  if (!v) return html(c, c.get('user'), 'مش موجود', '<div class="card"><h1>الفيديو مش موجود</h1></div>');
  return html(c, c.get('user'), 'تعديل فيديو', `
<div class="card form-card">
  <h1>تعديل الفيديو ✏️</h1>
  <form method="post" action="/admin/video/${v.id}/edit" enctype="multipart/form-data">
    ${await csrfField(c)}
    <label>العنوان<input name="title" required maxlength="140" value="${esc(v.title)}"></label>
    <label>القسم
      <select name="category">
        <option value="horror" ${v.category === 'horror' ? 'selected' : ''}>رعب 👻</option>
        <option value="facts" ${v.category === 'facts' ? 'selected' : ''}>معلومة صح ✅</option>
      </select>
    </label>
    <label>الوصف<textarea name="description" rows="3" maxlength="2000">${esc(v.description)}</textarea></label>
    ${v.has_thumb ? `<label>الغلاف الحالي<br><img src="/thumb/${v.id}" alt="" style="max-width:220px;border-radius:12px"></label>` : ''}
    <label>غيّر صورة الغلاف (اختياري)<input type="file" name="thumb" accept="image/jpeg,image/png,image/webp"></label>
    <button class="btn" type="submit">حفظ</button>
  </form>
</div>`);
});
app.post('/admin/video/:id/edit', requireAdmin, async (c) => {
  const body = await c.req.parseBody();
  if (!(await csrfOk(c, body._csrf))) return csrfReject(c);
  const q = dbOf(c);
  const id = parseInt(c.req.param('id'), 10) || 0;
  const title = String(body.title || '').trim().slice(0, 140) || 'بدون عنوان';
  const category = body.category === 'facts' ? 'facts' : 'horror';
  const description = String(body.description || '').trim().slice(0, 2000);
  await q.run('UPDATE videos SET title = ?, description = ?, category = ? WHERE id = ?', [title, description, category, id]);
  const tfile = body.thumb;
  if (tfile && typeof tfile !== 'string' && tfile.size > 0) {
    if (!/^image\/(jpeg|png|webp)$/.test(tfile.type || '') || tfile.size > 2 * 1024 * 1024) {
      return c.redirect('/admin?v=' + encodeURIComponent('البيانات اتحفظت، بس الغلاف مترفعش — لازم JPG أو PNG أو WebP أقل من ٢ ميجا.'));
    }
    const img = new Uint8Array(await tfile.arrayBuffer());
    await q.run('UPDATE videos SET thumb = ?, thumb_mime = ? WHERE id = ?', [img, tfile.type, id]);
  }
  return c.redirect('/admin?v=' + encodeURIComponent('التعديل اتحفظ ✅'));
});
app.post('/admin/video/:id/delete', requireAdmin, async (c) => {
  const body = await c.req.parseBody();
  if (!(await csrfOk(c, body._csrf))) return csrfReject(c);
  await dbOf(c).run('DELETE FROM videos WHERE id = ?', [parseInt(c.req.param('id'), 10) || 0]);
  return c.redirect('/admin?v=' + encodeURIComponent('الفيديو اتمسح 🗑'));
});

app.post('/admin/post', requireAdmin, async (c) => {
  const body = await c.req.parseBody();
  if (!(await csrfOk(c, body._csrf))) return csrfReject(c);
  const title = String(body.title || '').trim().slice(0, 140);
  const text = String(body.body || '').trim().slice(0, 10000);
  if (title && text) await dbOf(c).run('INSERT INTO posts (title, body) VALUES (?,?)', [title, text]);
  return c.redirect('/admin?p=' + encodeURIComponent('البوست اتنشر ✅'));
});
app.get('/admin/post/:id/edit', requireAdmin, async (c) => {
  const q = dbOf(c);
  const p = await q.get('SELECT * FROM posts WHERE id = ?', [parseInt(c.req.param('id'), 10) || 0]);
  if (!p) return html(c, c.get('user'), 'مش موجود', '<div class="card"><h1>البوست مش موجود</h1></div>');
  return html(c, c.get('user'), 'تعديل بوست', `
<div class="card form-card">
  <h1>تعديل البوست ✏️</h1>
  <form method="post" action="/admin/post/${p.id}/edit">
    ${await csrfField(c)}
    <label>العنوان<input name="title" required maxlength="140" value="${esc(p.title)}"></label>
    <label>النص<textarea name="body" rows="6" required maxlength="10000">${esc(p.body)}</textarea></label>
    <button class="btn" type="submit">حفظ</button>
  </form>
</div>`);
});
app.post('/admin/post/:id/edit', requireAdmin, async (c) => {
  const body = await c.req.parseBody();
  if (!(await csrfOk(c, body._csrf))) return csrfReject(c);
  const id = parseInt(c.req.param('id'), 10) || 0;
  const title = String(body.title || '').trim().slice(0, 140);
  const text = String(body.body || '').trim().slice(0, 10000);
  if (title && text) await dbOf(c).run('UPDATE posts SET title = ?, body = ? WHERE id = ?', [title, text, id]);
  return c.redirect('/admin?p=' + encodeURIComponent('التعديل اتحفظ ✅'));
});
app.post('/admin/post/:id/delete', requireAdmin, async (c) => {
  const body = await c.req.parseBody();
  if (!(await csrfOk(c, body._csrf))) return csrfReject(c);
  await dbOf(c).run('DELETE FROM posts WHERE id = ?', [parseInt(c.req.param('id'), 10) || 0]);
  return c.redirect('/admin?p=' + encodeURIComponent('البوست اتمسح 🗑'));
});

// ---------------------------------------------------------------- SEO + health
app.get('/healthz', (c) => c.json({ ok: true }));
app.get('/robots.txt', (c) => {
  const E = envOf(c);
  const base = E.APP_URL || new URL(c.req.url).origin;
  return c.text('User-agent: *\nAllow: /\nDisallow: /admin\nDisallow: /settings\n' + `Sitemap: ${base}/sitemap.xml\n`);
});
app.get('/sitemap.xml', (c) => {
  const E = envOf(c);
  const base = E.APP_URL || new URL(c.req.url).origin;
  const urls = [
    { loc: '/', priority: '1.0' },
    { loc: '/register', priority: '0.6' },
    { loc: '/login', priority: '0.4' },
  ];
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls.map(u => `  <url><loc>${base}${u.loc}</loc><changefreq>weekly</changefreq><priority>${u.priority}</priority></url>`).join('\n')}
</urlset>`;
  c.header('Content-Type', 'application/xml; charset=utf-8');
  return c.body(xml);
});

export default app;
