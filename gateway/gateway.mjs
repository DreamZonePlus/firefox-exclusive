#!/usr/bin/env node
'use strict';

/*
 * بوابة وصول محدود أمام حاوية jlesage/firefox (أو أي خدمة HTTP + WebSocket).
 *
 * المزايا:
 * - الدخول بدون كلمة سر افتراضياً: أول زائر يحصل على كوكي جلسة ويحجز "دوراً".
 * - MAX_USERS: عدد المستخدمين المتزامنين المسموح لهم (افتراضياً 1 = واحد في الوقت).
 * - AUTH_USERNAME + AUTH_PASSWORD: عند تعبئتهما معاً يُفعَّل تسجيل الدخول
 *   (افتراضياً فارغان = معطّل، لكن المتغيرين موجودان وجاهزان للتفعيل وقت الحاجة).
 * - يُحرَّر الدور عند انقطاع صاحبه (بلا WebSocket حي) لمدة LOCK_GRACE_SECONDS،
 *   أو عند بلوغ الحد الأقصى LOCK_MAX_MINUTES لكل مستخدم.
 * - ADMIN_KEY: تحرير طوارئ لكل الأدوار عبر /__gateway/status?release=<المفتاح>.
 */

import http from 'node:http';
import net from 'node:net';
import crypto from 'node:crypto';

// ---------- الإعدادات (متغيرات البيئة) ----------
const BACKEND_HOST = process.env.BACKEND_HOST || 'firefox';
const BACKEND_PORT = intEnv('BACKEND_PORT', 5800);
const LISTEN_PORT = intEnv('LISTEN_PORT', 8080);

// الحد الأقصى لجلسة المستخدم الواحد بالدقائق (تُقبل قيم عشرية، مثال: 0.5 = 30 دقيقة).
const LOCK_MAX_MINUTES = numEnv('LOCK_MAX_MINUTES', 60);

// كم ثانية يبقى الدور محجوزاً بعد مغادرة صاحبه (فرصة ليعود قبل تحرير الدور).
const LOCK_GRACE_SECONDS = numEnv('LOCK_GRACE_SECONDS', 120);

// كل كم ثانية تُعِيد صفحة "مشغول" المحاولة تلقائياً.
const BUSY_RETRY_SECONDS = numEnv('BUSY_RETRY_SECONDS', 10);

// تسجيل الدخول — معطّل افتراضياً (المتغيران فارغان في docker-compose).
// يُفعَّل تلقائياً عند تعبئة القيمتين معاً.
const AUTH_USERNAME = process.env.AUTH_USERNAME || '';
const AUTH_PASSWORD = process.env.AUTH_PASSWORD || '';
const AUTH_ENABLED = !!(AUTH_USERNAME && AUTH_PASSWORD);

// عدد المستخدمين المتزامنين المسموح لهم (1 = وضع "واحد في الوقت" الحصري).
const MAX_USERS = intEnv('MAX_USERS', 1);

// مفتاح إداري (اختياري): تحرير كل الأدوار يدوياً عبر
// /__gateway/status?release=<ADMIN_KEY> دون إعادة نشر.
const ADMIN_KEY = process.env.ADMIN_KEY || '';

const COOKIE_NAME = 'fx_gate_sid';
const AUTH_COOKIE_NAME = 'fx_gate_auth';
const COOKIE_MAX_AGE = 30 * 24 * 3600; // 30 يوماً بالثواني

const STATUS_PATH = '/__gateway/status';
const LOGIN_PATH = '/__gateway/login';
const LOGOUT_PATH = '/__gateway/logout';

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

function ownerCookie(sid) {
  return `${COOKIE_NAME}=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${COOKIE_MAX_AGE}`;
}

function getSession(req) {
  return parseCookies(req.headers.cookie)[COOKIE_NAME] || null;
}

function readBody(req, limit = 8192) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) {
        reject(new Error('body too large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function timingSafeEq(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

// ---------- الأدوار (مستخدمون نشطون) ----------
// كل دور: مستخدم واحد لديه كوكي مالك + موعد انتهاء + اتصالات WebSocket حية.
const slots = new Map(); // sid -> slot
const evictions = new Map(); // sid -> وقت نهاية فترة التهدئة
const authSessions = new Set(); // توكنات تسجيل الدخول الصالحة

function releaseSlot(slot, reason) {
  if (!slots.has(slot.sid)) return;
  slots.delete(slot.sid);
  if (slot.hardTimer) clearTimeout(slot.hardTimer);
  if (slot.graceTimer) clearTimeout(slot.graceTimer);
  for (const s of slot.sockets) {
    try { s.destroy(); } catch (_) { /* ignore */ }
  }
  log(`تحرير دور ${slot.sid.slice(0, 8)}… (${reason}) — النشط الآن: ${slots.size}/${MAX_USERS}`);
}

function acquireSlot(sid) {
  if (slots.size >= MAX_USERS) return false;
  const maxMs = LOCK_MAX_MINUTES * 60_000;
  const slot = {
    sid,
    hardDeadline: Date.now() + maxMs,
    hardTimer: setTimeout(() => {
      // بلوغ الحد الأقصى: طرد صاحب الدور + منعه من الاستعادة الفورية.
      evictions.set(sid, Date.now() + LOCK_GRACE_SECONDS * 1000);
      releaseSlot(slot, 'انتهاء الحد الأقصى للجلسة');
    }, maxMs),
    graceTimer: null,
    sockets: new Set(),
  };
  slots.set(sid, slot);
  log(`دور محجوز للجلسة ${sid.slice(0, 8)}… (${slots.size}/${MAX_USERS} | الحد الأقصى للجلسة: ${LOCK_MAX_MINUTES} دقيقة)`);
  return true;
}

function cancelGrace(slot) {
  if (slot.graceTimer) {
    clearTimeout(slot.graceTimer);
    slot.graceTimer = null;
    log('المالك عاد — إلغاء عداد التحرير');
  }
}

function scheduleGrace(slot) {
  if (!slots.has(slot.sid) || slot.graceTimer) return;
  slot.graceTimer = setTimeout(
    () => releaseSlot(slot, 'مغادرة المالك وانقضاء المهلة'),
    LOCK_GRACE_SECONDS * 1000
  );
  log(`المالك ${slot.sid.slice(0, 8)}… انقطع — سيُحرَّر الدور بعد ${LOCK_GRACE_SECONDS} ثانية ما لم يعد`);
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

// ---------- المصادقة ----------
function hasValidAuth(req) {
  if (!AUTH_ENABLED) return true;
  const token = parseCookies(req.headers.cookie)[AUTH_COOKIE_NAME];
  return !!token && authSessions.has(token);
}

function authCookie(token) {
  return `${AUTH_COOKIE_NAME}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${COOKIE_MAX_AGE}`;
}

// ---------- الصفحات ----------
function busyPage(res) {
  const html = `<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="${BUSY_RETRY_SECONDS}">
<title>المتصفح قيد الاستخدام من قبل مستخدم آخر</title>
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
  h1 { font-size: 1.25rem; margin: 0; }
</style>
</head>
<body>
  <div class="card">
    <div class="spinner"></div>
    <h1>المتصفح قيد الاستخدام من قبل مستخدم آخر</h1>
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

function loginPage(res, error) {
  const html = `<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>تسجيل الدخول</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
    background: #0f172a; color: #e2e8f0;
    font-family: system-ui, "Segoe UI", Tahoma, sans-serif;
  }
  .card {
    max-width: 26rem; width: 100%; margin: 1rem; padding: 2.5rem 2rem;
    background: #1e293b; border-radius: 1rem;
    box-shadow: 0 10px 30px rgba(0,0,0,.35);
  }
  h1 { font-size: 1.25rem; margin: 0 0 1.25rem; text-align: center; }
  form { display: flex; flex-direction: column; gap: 1rem; }
  label { display: flex; flex-direction: column; gap: .35rem; font-size: .9rem; color: #94a3b8; }
  input {
    padding: .65rem .8rem; border-radius: .5rem; border: 1px solid #334155;
    background: #0f172a; color: #e2e8f0; font-size: 1rem;
  }
  input:focus { outline: 2px solid #38bdf8; border-color: transparent; }
  button {
    margin-top: .5rem; padding: .7rem; border: 0; border-radius: .5rem;
    background: #0ea5e9; color: #04121f; font-size: 1rem; font-weight: 600; cursor: pointer;
  }
  button:hover { background: #38bdf8; }
  .err { margin: 0 0 1rem; text-align: center; color: #f87171; }
</style>
</head>
<body>
  <div class="card">
    <h1>تسجيل الدخول</h1>
    ${error ? `<p class="err">${error}</p>` : ''}
    <form method="POST" action="${LOGIN_PATH}">
      <label>اسم المستخدم
        <input name="username" autocomplete="username" required autofocus>
      </label>
      <label>كلمة السر
        <input type="password" name="password" autocomplete="current-password" required>
      </label>
      <button type="submit">دخول</button>
    </form>
  </div>
</body>
</html>`;
  res.writeHead(401, {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store',
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
    if (key === ADMIN_KEY) {
      for (const slot of [...slots.values()]) {
        releaseSlot(slot, 'تحرير إداري عبر ADMIN_KEY');
      }
    }
  }
  let minutesLeft = null;
  if (slots.size > 0) {
    const earliest = Math.min(...[...slots.values()].map((s) => s.hardDeadline));
    minutesLeft = Math.max(0, +((earliest - Date.now()) / 60000).toFixed(1));
  }
  const payload = {
    gateway: 'firefox-exclusive',
    status: slots.size >= MAX_USERS ? 'busy' : 'free',
    locked: slots.size > 0,
    users: slots.size,
    maxUsers: MAX_USERS,
    authEnabled: AUTH_ENABLED,
    minutesLeft,
    graceSeconds: LOCK_GRACE_SECONDS,
    maxMinutes: LOCK_MAX_MINUTES,
    activeSockets: [...slots.values()].reduce((n, s) => n + s.sockets.size, 0),
    backend: `${BACKEND_HOST}:${BACKEND_PORT}`,
  };
  res.writeHead(200, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-FX-Gateway': '1',
  });
  res.end(JSON.stringify(payload, null, 2));
}

// ---------- تسجيل الدخول / الخروج ----------
async function handleLogin(req, res) {
  if (!AUTH_ENABLED) {
    res.writeHead(302, { Location: '/', 'Cache-Control': 'no-store' });
    res.end();
    return;
  }
  let user = '';
  let pass = '';
  try {
    const body = await readBody(req);
    const params = new URLSearchParams(body.toString('utf8'));
    user = params.get('username') || '';
    pass = params.get('password') || '';
  } catch (_) {
    loginPage(res, 'تعذر قراءة الطلب. حاول مجدداً.');
    return;
  }

  if (timingSafeEq(user, AUTH_USERNAME) && timingSafeEq(pass, AUTH_PASSWORD)) {
    const token = crypto.randomBytes(24).toString('hex');
    authSessions.add(token);
    log('تسجيل دخول ناجح');
    res.writeHead(302, {
      'Set-Cookie': authCookie(token),
      Location: '/',
      'Cache-Control': 'no-store',
      'X-FX-Gateway': '1',
    });
    res.end();
    return;
  }
  log('محاولة تسجيل دخول فاشلة');
  loginPage(res, 'بيانات الدخول غير صحيحة.');
}

function handleLogout(req, res) {
  // تسجيل الخروج يحرر دور صاحبه إن وجد.
  const sid = getSession(req);
  const slot = sid ? slots.get(sid) : undefined;
  if (slot) releaseSlot(slot, 'تسجيل خروج');
  res.writeHead(302, {
    'Set-Cookie': `${AUTH_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`,
    Location: '/',
    'Cache-Control': 'no-store',
    'X-FX-Gateway': '1',
  });
  res.end();
}

// ---------- وكالة HTTP ----------
function proxyHttp(req, res, extraHeaders, effSid) {
  const sid = effSid !== undefined ? effSid : getSession(req);
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
        const slot = sid ? slots.get(sid) : undefined;
        if (slot && slot.sockets.size === 0) scheduleGrace(slot);
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
  log('DEBUG handleUpgrade entry; auth valid =', hasValidAuth(req));
  socket.setNoDelay(true);

  // مع تفعيل المصادقة: يُشترط توكن تسجيل دخول صالح حتى لاتصال WebSocket.
  if (!hasValidAuth(req)) {
    socket.write('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
    socket.destroy();
    return;
  }

  const sid = getSession(req);
  let effSid = sid;
  let setCookieHeader = null;
  const existing = sid ? slots.get(sid) : undefined;

  if (existing) {
    cancelGrace(existing);
  } else {
    if (isEvicted(sid)) {
      socket.write('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return;
    }
    if (slots.size >= MAX_USERS) {
      socket.write('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return;
    }
    // لا أدوار متاحة؟ لا — يوجد مكان: اتصال WebSocket بلا كوكي مالك
    // (مثلاً صفحة قديمة من ذاكرة المتصفح) يلتقط الدور مباشرة — وهذا يجعل
    // "Reconnecting..." تشفى ذاتياً دون تحديث الصفحة.
    effSid = sid || crypto.randomBytes(16).toString('hex');
    if (!acquireSlot(effSid)) {
      socket.write('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return;
    }
    setCookieHeader = ownerCookie(effSid);
  }

  const owningSlot = slots.get(effSid);

  // إعادة بناء الطلب الخام كما هو (مع تعديل Host) وتمريره للخدمة الخلفية.
  const headers = { ...req.headers, host: `${BACKEND_HOST}:${BACKEND_PORT}` };
  let raw = `${req.method} ${req.url} HTTP/1.1\r\n`;
  for (const [k, v] of Object.entries(headers)) {
    raw += `${k}: ${Array.isArray(v) ? v.join(', ') : v}\r\n`;
  }
  raw += '\r\n';

  const upSock = net.connect(BACKEND_PORT, BACKEND_HOST);
  upSock.setNoDelay(true);

  upSock.on('connect', () => {
    log('DEBUG upSock connected');
    upSock.write(raw);
    if (head && head.length) upSock.write(head);
    socket.pipe(upSock);
    if (setCookieHeader && owningSlot) {
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
    if (owningSlot) owningSlot.sockets.add(socket);
  });

  const onGone = () => {
    log(`DEBUG onGone: owningSlot=${!!owningSlot}`, owningSlot ? `sid=${owningSlot.sid.slice(0, 8)} inMap=${slots.get(owningSlot.sid) === owningSlot} size=${owningSlot.sockets.size} graceTimer=${!!owningSlot.graceTimer}` : '');
    if (!owningSlot) return;
    owningSlot.sockets.delete(socket);
    if (slots.get(owningSlot.sid) === owningSlot && owningSlot.sockets.size === 0) {
      scheduleGrace(owningSlot);
    }
  };
  socket.on('close', () => { log('DEBUG socket close'); onGone(); });
  upSock.on('close', () => { log('DEBUG upSock close'); onGone(); });
  socket.on('error', (e) => { log('DEBUG socket error:', e.message); upSock.destroy(); });
  upSock.on('error', (e) => { log('DEBUG upSock error:', e.message); socket.destroy(); });
}

// ---------- الخادم ----------
const server = http.createServer((req, res) => {
  const path = (req.url || '').split('?')[0];

  // نقاط البوابة العامة: الحالة، تسجيل الدخول، تسجيل الخروج.
  if (path === STATUS_PATH) {
    return statusPage(req, res);
  }
  if (path === LOGOUT_PATH) {
    return handleLogout(req, res);
  }
  if (path === LOGIN_PATH) {
    if (req.method === 'POST') {
      handleLogin(req, res).catch((e) => {
        log('خطأ في معالجة تسجيل الدخول:', e.message);
        if (!res.headersSent) {
          res.writeHead(500, { 'X-FX-Gateway': '1' });
          res.end();
        }
      });
      return;
    }
    res.writeHead(302, { Location: '/', 'Cache-Control': 'no-store' });
    res.end();
    return;
  }

  // بوابة المصادقة: إن كانت مفعّلة، يُشترط تسجيل دخول صالح قبل أي شيء آخر.
  if (!hasValidAuth(req)) {
    return loginPage(res);
  }

  const sid = getSession(req);
  const slot = sid ? slots.get(sid) : undefined;

  if (slot) {
    cancelGrace(slot);
    return proxyHttp(req, res);
  }

  if (isEvicted(sid)) {
    return busyPage(res);
  }

  if (slots.size < MAX_USERS) {
    // يوجد مكان: هذا الزائر يصبح مالكاً (بدون كلمة سر ما لم تكن المصادقة مفعّلة).
    const newSid = sid || crypto.randomBytes(16).toString('hex');
    if (acquireSlot(newSid)) {
      // نمرر newSid صراحةً لأن كوكي المالك يصل في الاستجابة لا في الطلب.
      return proxyHttp(req, res, { 'Set-Cookie': ownerCookie(newSid) }, newSid);
    }
  }

  busyPage(res);
});

server.on('upgrade', handleUpgrade);

server.listen(LISTEN_PORT, () => {
  log(`البوابة تعمل على المنفذ ${LISTEN_PORT} → ${BACKEND_HOST}:${BACKEND_PORT}`);
  log(`المستخدمون المتزامنون المسموحون: ${MAX_USERS} | الحد الأقصى للجلسة: ${LOCK_MAX_MINUTES} دقيقة | مهلة ما بعد المغادرة: ${LOCK_GRACE_SECONDS} ثانية | المصادقة: ${AUTH_ENABLED ? 'مفعّلة' : 'معطّلة'}`);
});

// إنهاء نظيف عند إيقاف الحاوية.
function shutdown() {
  log('إيقاف البوابة…');
  for (const slot of [...slots.values()]) {
    if (slot.hardTimer) clearTimeout(slot.hardTimer);
    if (slot.graceTimer) clearTimeout(slot.graceTimer);
    for (const s of slot.sockets) {
      try { s.destroy(); } catch (_) { /* ignore */ }
    }
  }
  slots.clear();
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 3000).unref();
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
