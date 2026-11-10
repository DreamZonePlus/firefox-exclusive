#!/usr/bin/env node
'use strict';

/*
 * بوابة "واحد في الوقت" أمام حاوية jlesage/firefox (أو أي خدمة HTTP + WebSocket).
 *
 * - الدخول بدون كلمة سر: أول زائر يحصل على كوكي جلسة عشوائي ويصبح "المالك" الحصري.
 * - ما دام القفل قائماً، يرى أي زائر آخر صفحة "مشغول" تُعِيد المحاولة تلقائياً.
 * - يُرفع القفل في إحدى الحالتين:
 *     1) انقطاع المالك (إغلاق الصفحة) لمدة LOCK_GRACE_SECONDS، أو
 *     2) بلوغ الحد الأقصى LOCK_MAX_MINUTES من لحظة الدخول حتى لو بقي متصلاً.
 * - المالك المُخرَج بعد بلوغ الحد الأقصى لا يستطيع استعادة القفل فوراً
 *   (فترة تهدئة) ليتاح المجال لغيره.
 */

import http from 'node:http';
import net from 'node:net';
import crypto from 'node:crypto';

// ---------- الإعدادات (متغيرات البيئة) ----------
const BACKEND_HOST = process.env.BACKEND_HOST || 'firefox';
const BACKEND_PORT = intEnv('BACKEND_PORT', 5800);
const LISTEN_PORT = intEnv('LISTEN_PORT', 8080);

// الحد الأقصى للجلسة الواحدة بالدقائق (تُقبل قيم عشرية، مثال: 0.5 = 30 دقيقة).
const LOCK_MAX_MINUTES = numEnv('LOCK_MAX_MINUTES', 60);

// كم ثانية يبقى القفل قائماً بعد مغادرة المالك (فرصة ليعود قبل تحرير الدور).
const LOCK_GRACE_SECONDS = numEnv('LOCK_GRACE_SECONDS', 120);

// كل كم ثانية تُعِيد صفحة "مشغول" المحاولة تلقائياً.
const BUSY_RETRY_SECONDS = numEnv('BUSY_RETRY_SECONDS', 10);

// مفتاح إداري (اختياري): يسمح بتحرير القفل يدوياً عبر
// /__gateway/status?release=<ADMIN_KEY> دون إعادة نشر.
const ADMIN_KEY = process.env.ADMIN_KEY || '';

const COOKIE_NAME = 'fx_gate_sid';
const COOKIE_MAX_AGE = 30 * 24 * 3600; // 30 يوماً بالثواني

// نقطة نهاية عامة لمعرفة حالة البوابة (مفيدة للتحقق من أن المرور عبرها).
const STATUS_PATH = '/__gateway/status';

// ---------- أدوات مساعدة ----------
function intEnv(name, dflt) {
  const n = parseInt(process.env[name], 10);
  return Number.isFinite(n) && n > 0 ? n : dflt;
}

function numEnv(name, dflt) {
  const n = parseFloat(process.env[name]);
  return Number.isFinite(n) && n > 0 ? n : dflt;
}

function log(...args) {
  console.log(new Date().toISOString(), ...args);
}

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    try {
      out[k] = decodeURIComponent(v);
    } catch (_) {
      out[k] = v;
    }
  }
  return out;
}

// رؤوس hop-by-hop لا يجوز تمريرها عند وكالة طلبات HTTP العادية.
const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'proxy-connection',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

// ---------- حالة القفل ----------
let lock = null; // { sid, hardDeadline, hardTimer, graceTimer, sockets:Set }
const evictions = new Map(); // sid -> وقت انتهاء فترة التهدئة

function releaseLock(reason) {
  if (!lock) return;
  const cur = lock;
  lock = null;
  if (cur.hardTimer) clearTimeout(cur.hardTimer);
  if (cur.graceTimer) clearTimeout(cur.graceTimer);
  for (const s of cur.sockets) {
    try { s.destroy(); } catch (_) { /* ignore */ }
  }
  log(`القفل مرفوع (${reason})`);
}

function acquireLock(sid) {
  releaseLock('إعادة حجز');
  const maxMs = LOCK_MAX_MINUTES * 60_000;
  lock = {
    sid,
    hardDeadline: Date.now() + maxMs,
    hardTimer: setTimeout(() => {
      // بلوغ الحد الأقصى: طرد المالك + منعه من الاستعادة الفورية.
      evictions.set(sid, Date.now() + LOCK_GRACE_SECONDS * 1000);
      releaseLock('انتهاء الحد الأقصى للجلسة');
    }, maxMs),
    graceTimer: null,
    sockets: new Set(),
  };
  log(`القفل محجوز للجلسة ${sid.slice(0, 8)}… (الحد الأقصى: ${LOCK_MAX_MINUTES} دقيقة)`);
}

function cancelGrace() {
  if (lock && lock.graceTimer) {
    clearTimeout(lock.graceTimer);
    lock.graceTimer = null;
    log('المالك عاد — إلغاء عداد التحرير');
  }
}

function scheduleGrace() {
  if (!lock || lock.graceTimer) return;
  lock.graceTimer = setTimeout(
    () => releaseLock('مغادرة المالك وانقضاء المهلة'),
    LOCK_GRACE_SECONDS * 1000
  );
  log(`المالك انقطع — سيُحرَّر الدور بعد ${LOCK_GRACE_SECONDS} ثانية ما لم يعد`);
}

function isEvicted(sid) {
  if (!sid) return false;
  const until = evictions.get(sid);
  if (!until) return false;
  if (Date.now() >= until) {
    evictions.delete(sid);
    return false;
  }
  return true;
}

function getSession(req) {
  return parseCookies(req.headers.cookie)[COOKIE_NAME] || null;
}

function isOwner(req) {
  const sid = getSession(req);
  return !!sid && !!lock && sid === lock.sid;
}

// ---------- صفحة "مشغول" ----------
function busyPage(res, note) {
  const minutesLeft = lock
    ? Math.max(1, Math.ceil((lock.hardDeadline - Date.now()) / 60000))
    : 0;
  const html = `<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="${BUSY_RETRY_SECONDS}">
<title>المتصفح مشغول حالياً</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
    background: #0f172a; color: #e2e8f0;
    font-family: system-ui, "Segoe UI", Tahoma, sans-serif;
  }
  .card {
    max-width: 30rem; margin: 1rem; padding: 2.5rem 2rem; text-align: center;
    background: #1e293b; border-radius: 1rem;
    box-shadow: 0 10px 30px rgba(0,0,0,.35);
  }
  .spinner {
    width: 3rem; height: 3rem; margin: 0 auto 1.25rem;
    border: 4px solid #334155; border-top-color: #38bdf8; border-radius: 50%;
    animation: spin 1s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
  h1 { font-size: 1.25rem; margin: 0 0 .75rem; }
  p { margin: .4rem 0; color: #94a3b8; line-height: 1.7; }
  .muted { font-size: .85rem; }
</style>
</head>
<body>
  <div class="card">
    <div class="spinner"></div>
    <h1>المتصفح قيد الاستخدام من قبل مستخدم آخر</h1>
    <p>${note || `سيتم الدخول تلقائياً بمجرد توفر الدور.<br>هذه الصفحة تعيد المحاولة كل ${BUSY_RETRY_SECONDS} ثانية.`}</p>
    <p class="muted">أقصى مدة متبقية للجلسة الحالية: ${minutesLeft} دقيقة تقريباً (قد يتاح الدخول قبلها إذا أنهى المستخدم جلسته).</p>
  </div>
</body>
</html>`;
  res.writeHead(503, {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store',
    'Retry-After': String(BUSY_RETRY_SECONDS),
    'X-FX-Gateway': '1',
  });
  res.end(html);
}

// ---------- نقطة نهاية الحالة ----------
function statusPage(req, res) {
  // تحرير إداري اختياري: /__gateway/status?release=<ADMIN_KEY>
  if (ADMIN_KEY) {
    let key = null;
    try {
      key = new URL(req.url, 'http://localhost').searchParams.get('release');
    } catch (_) { /* ignore */ }
    if (key === ADMIN_KEY) releaseLock('تحرير إداري عبر ADMIN_KEY');
  }
  const payload = {
    gateway: 'firefox-exclusive',
    status: lock ? 'busy' : 'free',
    locked: !!lock,
    minutesLeft: lock ? Math.max(0, +((lock.hardDeadline - Date.now()) / 60000).toFixed(1)) : null,
    graceSeconds: LOCK_GRACE_SECONDS,
    maxMinutes: LOCK_MAX_MINUTES,
    activeSockets: lock ? lock.sockets.size : 0,
    backend: `${BACKEND_HOST}:${BACKEND_PORT}`,
  };
  res.writeHead(200, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-FX-Gateway': '1',
  });
  res.end(JSON.stringify(payload, null, 2));
}

// ---------- وكالة HTTP ----------
function proxyHttp(req, res, extraHeaders) {
  const headers = { ...req.headers };
  headers.host = `${BACKEND_HOST}:${BACKEND_PORT}`;
  for (const h of HOP_BY_HOP) delete headers[h];

  const upReq = http.request(
    { host: BACKEND_HOST, port: BACKEND_PORT, method: req.method, path: req.url, headers },
    (upRes) => {
      const out = { ...upRes.headers };
      for (const h of HOP_BY_HOP) delete out[h];
      out['X-FX-Gateway'] = '1';
      if (extraHeaders) Object.assign(out, extraHeaders);
      res.writeHead(upRes.statusCode, upRes.statusMessage, out);
      upRes.pipe(res);
      // إصلاح حرج: إذا انتهى طلب HTTP ولم يفتح المالك أي WebSocket،
      // نبدأ عداد التحرير — حتى لا يحجز زائر HTTP عادي (بوت/فحص) الدور كاملاً.
      res.on('close', () => {
        if (lock && lock.sockets.size === 0) scheduleGrace();
      });
    }
  );
  upReq.on('error', (err) => {
    log('خطأ في الوصول للخدمة الخلفية:', err.message);
    if (!res.headersSent) {
      res.writeHead(502, {
        'Content-Type': 'text/plain; charset=utf-8',
        'X-FX-Gateway': '1',
      });
      res.end('تعذر الوصول إلى الخدمة الخلفية');
    } else {
      res.destroy();
    }
  });
  req.pipe(upReq);
}

// ---------- وكالة WebSocket ----------
function handleUpgrade(req, socket, head) {
  socket.setNoDelay(true);
  let sid = getSession(req);
  let setCookieHeader = null;

  if (isOwner(req)) {
    cancelGrace();
  } else if (lock) {
    // الدور محجوز من غيره: رفض.
    socket.write('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
    socket.destroy();
    return;
  } else {
    // لا حجز حالياً: اتصال WebSocket بلا كوكي (مثلاً صفحة قديمة من ذاكرة المتصفح)
    // يلتقط الدور مباشرة — وهذا يجعل "Reconnecting..." تشفى ذاتياً دون تحديث الصفحة.
    if (isEvicted(sid)) {
      socket.write('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return;
    }
    const newSid = sid || crypto.randomBytes(16).toString('hex');
    acquireLock(newSid);
    setCookieHeader = `${COOKIE_NAME}=${newSid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${COOKIE_MAX_AGE}`;
  }

  // إعادة بناء الطلب الخام كما هو (مع تعديل Host) وتمريره للخدمة الخلفية.
  const headers = { ...req.headers, host: `${BACKEND_HOST}:${BACKEND_PORT}` };
  let raw = `${req.method} ${req.url} HTTP/1.1\r\n`;
  for (const [k, v] of Object.entries(headers)) {
    raw += `${k}: ${Array.isArray(v) ? v.join(', ') : v}\r\n`;
  }
  raw += '\r\n';

  const upSock = net.connect(BACKEND_PORT, BACKEND_HOST);
  upSock.setNoDelay(true);
  const owningLock = lock; // القفل الذي سمح بهذا الاتصال

  upSock.on('connect', () => {
    upSock.write(raw);
    if (head && head.length) upSock.write(head);
    socket.pipe(upSock);
    if (setCookieHeader) {
      // اعتراض مصافحة رد الخلفية لحقن كوكي المالك ضمن ترويسات 101.
      let hs = Buffer.alloc(0);
      const onHs = (d) => {
        hs = Buffer.concat([hs, d]);
        const idx = hs.indexOf('\r\n\r\n');
        if (idx === -1) return;
        upSock.off('data', onHs);
        const cookieBuf = Buffer.from(`\r\nSet-Cookie: ${setCookieHeader}`, 'latin1');
        socket.write(Buffer.concat([hs.slice(0, idx), cookieBuf, hs.slice(idx)]));
        upSock.pipe(socket);
      };
      upSock.on('data', onHs);
    } else {
      upSock.pipe(socket);
    }
    if (lock === owningLock) owningLock.sockets.add(socket);
  });

  const onGone = () => {
    owningLock.sockets.delete(socket);
    if (lock === owningLock && owningLock.sockets.size === 0) scheduleGrace();
  };
  socket.on('close', onGone);
  upSock.on('close', onGone);
  socket.on('error', () => upSock.destroy());
  upSock.on('error', () => socket.destroy());
}

// ---------- الخادم ----------
const server = http.createServer((req, res) => {
  // نقطة الحالة: عامة ولا تمر عبر نظام الحجز.
  if ((req.url || '').split('?')[0] === STATUS_PATH) {
    return statusPage(req, res);
  }

  if (isOwner(req)) {
    cancelGrace();
    return proxyHttp(req, res);
  }

  const sid = getSession(req);

  if (isEvicted(sid)) {
    return busyPage(res, 'انتهت مدة جلستك (الحد الأقصى).<br>انتظر قليلاً ثم أعد المحاولة.');
  }

  if (!lock) {
    // أول داخل: يصبح المالك بدون أي كلمة سر.
    const newSid = sid || crypto.randomBytes(16).toString('hex');
    acquireLock(newSid);
    const extra = {
      'Set-Cookie': `${COOKIE_NAME}=${newSid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${COOKIE_MAX_AGE}`,
    };
    return proxyHttp(req, res, extra);
  }

  busyPage(res);
});

server.on('upgrade', handleUpgrade);

server.listen(LISTEN_PORT, () => {
  log(`البوابة تعمل على المنفذ ${LISTEN_PORT} → ${BACKEND_HOST}:${BACKEND_PORT}`);
  log(`الحد الأقصى للجلسة: ${LOCK_MAX_MINUTES} دقيقة | مهلة ما بعد المغادرة: ${LOCK_GRACE_SECONDS} ثانية`);
});

// إنهاء نظيف عند إيقاف الحاوية.
function shutdown() {
  log('إيقاف البوابة…');
  if (lock) {
    if (lock.hardTimer) clearTimeout(lock.hardTimer);
    if (lock.graceTimer) clearTimeout(lock.graceTimer);
    for (const s of lock.sockets) {
      try { s.destroy(); } catch (_) { /* ignore */ }
    }
  }
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 3000).unref();
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
