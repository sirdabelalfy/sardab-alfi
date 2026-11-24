// One-time content migration: seeds the production Turso DB with the launch
// content (welcome video + 3 معلومة صح episodes + launch post).
// Usage: TURSO_URL=... TURSO_AUTH_TOKEN=... node seed_prod.js
const { createClient } = require('@libsql/client');
const fs = require('fs');

const db = createClient({ url: process.env.TURSO_URL, authToken: process.env.TURSO_AUTH_TOKEN });

const VIDEOS = [
  { title: 'ترحيب بمنصة سرداب الألفي', category: 'horror', file: '/tmp/seed.mp4',
    description: 'الفيديو الترحيبي الرسمي للمنصة — استنونا في أول حلقات الرعب ومعلومة صح.' },
  { title: 'كليوباترا أقرب للآيفون منها للهرم الأكبر', category: 'facts', file: '/downloads/facts_ep1_cleopatra-734fd4d8.mp4',
    description: 'كليوباترا عاشت أقرب زمنيًا لاختراع الآيفون منها لبناء الهرم الأكبر — الحلقة الأولى من معلومة صح.' },
  { title: 'دماغك بتاكل خمس طاقة جسمك وهي ٢٪ بس من وزنك', category: 'facts', file: '/downloads/facts_ep2_brain_vox-465eb0a8.mp4',
    description: 'الدماغ بتستهلك حوالي ٢٠٪ من طاقة الجسم رغم إن وزنها ٢٪ بس — الحلقة التانية من معلومة صح.' },
  { title: 'مخلوق عنده ٣ قلوب و٩ عقول ودمه أزرق', category: 'facts', file: '/downloads/facts_ep3_octopus-44ad40d5.mp4',
    description: 'الأخطبوط: ٣ قلوب، ٩ عقول، ودم أزرق بسبب النحاس — الحلقة التالتة من معلومة صح.' },
];
const POST = {
  title: 'المنصة فتحت رسمي 🎉',
  body: 'أهلاً بيكم في سرداب الألفي. سجّل حسابك بالإيميل والموبايل وابدأ تفرج على حلقات الرعب وسلسلة معلومة صح. الحلقات الجديدة بتنزل هنا أول بأول.',
};

(async () => {
  await db.batch([
    `CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE, phone TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'member', email_verified INTEGER NOT NULL DEFAULT 0, phone_verified INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT (datetime('now')))`,
    `CREATE TABLE IF NOT EXISTS codes (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, channel TEXT NOT NULL, code_hash TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, expires_at TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0)`,
    `CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')))`,
    `CREATE TABLE IF NOT EXISTS videos (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, description TEXT DEFAULT '', category TEXT NOT NULL DEFAULT 'horror', mime TEXT NOT NULL, size INTEGER NOT NULL, data BLOB NOT NULL, views INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT (datetime('now')))`,
    `CREATE TABLE IF NOT EXISTS posts (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, body TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')))`,
  ]);
  const existing = (await db.execute('SELECT COUNT(*) c FROM videos')).rows[0].c;
  if (existing > 0) { console.log(`videos already present (${existing}), skipping video seed`); }
  else {
    for (const v of VIDEOS) {
      const data = fs.readFileSync(v.file);
      await db.execute({ sql: 'INSERT INTO videos (title, description, category, mime, size, data) VALUES (?,?,?,?,?,?)',
        args: [v.title, v.description, v.category, 'video/mp4', data.length, data] });
      console.log(`seeded video: ${v.title} (${data.length} bytes)`);
    }
  }
  const existingPosts = (await db.execute('SELECT COUNT(*) c FROM posts')).rows[0].c;
  if (existingPosts > 0) { console.log(`posts already present (${existingPosts}), skipping post seed`); }
  else {
    await db.execute({ sql: 'INSERT INTO posts (title, body) VALUES (?,?)', args: [POST.title, POST.body] });
    console.log(`seeded post: ${POST.title}`);
  }
  console.log('migration complete');
})().catch(e => { console.error(e); process.exit(1); });
