const mineflayer = require('mineflayer');
const express = require('express');
const { SocksClient } = require('socks');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 10000;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// DASHBOARD AUTH: set DASHBOARD_PASSWORD in your hosting environment.
// If omitted, create a strong temporary password and print it once at startup.
const DASHBOARD_PASSWORD = process.env.DASHBOARD_PASSWORD || crypto.randomBytes(18).toString('base64url');
const DASHBOARD_SESSION_SECRET = crypto.randomBytes(32);
const DASHBOARD_SESSION_TTL_MS = 12 * 60 * 60 * 1000;

if (!process.env.DASHBOARD_PASSWORD) {
  console.warn('[SECURITY] DASHBOARD_PASSWORD chưa được cấu hình. Mật khẩu tạm thời của Dashboard:', DASHBOARD_PASSWORD);
  console.warn('[SECURITY] Hãy đặt biến môi trường DASHBOARD_PASSWORD để giữ mật khẩu ổn định sau mỗi lần khởi động.');
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>\"']/g, (char) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[char]);
}

function createDashboardToken() {
  const payload = String(Date.now());
  const signature = crypto.createHmac('sha256', DASHBOARD_SESSION_SECRET).update(payload).digest('hex');
  return `${payload}.${signature}`;
}

function isValidDashboardToken(token) {
  if (!token || typeof token !== 'string') return false;
  const parts = token.split('.');
  if (parts.length !== 2 || !/^\d+$/.test(parts[0])) return false;
  const issuedAt = Number(parts[0]);
  if (!Number.isFinite(issuedAt) || Date.now() - issuedAt > DASHBOARD_SESSION_TTL_MS || issuedAt > Date.now() + 60000) return false;
  const expected = crypto.createHmac('sha256', DASHBOARD_SESSION_SECRET).update(parts[0]).digest();
  let supplied;
  try { supplied = Buffer.from(parts[1], 'hex'); } catch { return false; }
  return supplied.length === expected.length && crypto.timingSafeEqual(supplied, expected);
}

function getCookie(req, name) {
  const header = req.headers.cookie || '';
  const entry = header.split(';').map(part => part.trim()).find(part => part.startsWith(`${name}=`));
  if (!entry) return '';
  try { return decodeURIComponent(entry.slice(name.length + 1)); } catch { return ''; }
}

const managedTimeouts = new Set();
function managedTimeout(callback, delay) {
  let timer;
  timer = setTimeout(() => {
    managedTimeouts.delete(timer);
    callback();
  }, delay);
  managedTimeouts.add(timer);
  return timer;
}

function loginPage(errorMessage = '') {
  return `<!DOCTYPE html><html lang="vi"><head><meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Đăng nhập Dashboard</title>
  <style>
    *{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:20px;
    font-family:Arial,sans-serif;color:#f8fafc;background:radial-gradient(circle at top,#172554,#020617)}
    .panel{width:min(420px,100%);padding:28px;border:1px solid #38bdf866;border-radius:18px;
    background:#0a0e1ae8;box-shadow:0 0 24px #38bdf833}h1{margin-top:0;color:#38bdf8}
    label{display:block;margin:16px 0 6px}input{width:100%;padding:12px;border-radius:8px;border:1px solid #475569;
    background:#020617;color:white}button{width:100%;margin-top:18px;padding:12px;border:0;border-radius:8px;
    background:#0284c7;color:white;font-weight:bold;cursor:pointer}.error{color:#fda4af}
  </style></head><body><form class="panel" method="POST" action="/login">
  <h1>𝑌𝑢𝑛𝑜 𝐵𝑎𝑏𝑦𝑏𝑢</h1><p>Đăng nhập để quản lý Bot Minecraft.</p>
  ${errorMessage ? `<p class="error">${escapeHtml(errorMessage)}</p>` : ''}
  <label for="password">Mật khẩu Dashboard</label>
  <input id="password" type="password" name="password" required autocomplete="current-password" autofocus>
  <button type="submit">ĐĂNG NHẬP</button></form></body></html>`;
}

// Keep the health-check endpoint public; protect the Dashboard and every control/API route.
app.use((req, res, next) => {
  if (req.path === '/api/ping' || req.path === '/login') return next();
  if (isValidDashboardToken(getCookie(req, 'kiru_dashboard_session'))) return next();
  return res.redirect('/login');
});

app.get('/login', (req, res) => {
  if (isValidDashboardToken(getCookie(req, 'kiru_dashboard_session'))) return res.redirect('/');
  res.status(200).send(loginPage());
});

app.post('/login', (req, res) => {
  const supplied = String(req.body.password || '');
  const expected = Buffer.from(DASHBOARD_PASSWORD);
  const actual = Buffer.from(supplied);
  const valid = actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
  if (!valid) return res.status(401).send(loginPage('Mật khẩu không đúng.'));
  const secure = req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `kiru_dashboard_session=${encodeURIComponent(createDashboardToken())}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${DASHBOARD_SESSION_TTL_MS / 1000}${secure}`);
  return res.redirect('/');
});

app.get('/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'kiru_dashboard_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
  res.redirect('/login');
});

// ÉP MÚI GIỜ VIỆT NAM TOÀN HỆ THỐNG
process.env.TZ = 'Asia/Ho_Chi_Minh';

let BOT_USERNAME = process.env.BOT_USERNAME || '𝑌𝑢𝑛𝑜 𝐵𝑎𝑏𝑦𝑏𝑢';
let BOT_PASSWORD = process.env.BOT_PASSWORD || 'YourPasswordHere';
let BOT_HOST = process.env.BOT_HOST || 'vangioinetwork.xyz';
let BOT_PORT = parseInt(process.env.BOT_PORT) || 25565;
let BOT_PROXY = process.env.BOT_PROXY || ''; // Định dạng: host:port hoặc user:pass@host:port (SOCKS5)

// --- BẬT/TẮT CÁC TÍNH NĂNG TOGGLE ---
const toggles = {
  afkmode: false,
  thien: false,
  quylay: false,
  dinhthan: false,
  quanghao: false,
  ngoi: false,     // Nút ngồi (Sneak)
  attackLeft: false,
  attackRight: false,
  skill1: false,
  skill2: false,
  skill3: false
};

// Cấu hình tốc độ click chuột (tối thiểu 0.1s = 100ms)
let attackLeftIntervalMs = 500;
let attackRightIntervalMs = 500;

// CẤU HÌNH Ô CÔNG CỤ (HOTBAR 1 -> 9 tương ứng Index 0 -> 8)
let hotbarEnabled = [false, false, false, false, false, false, false, false, false];
let hotbarHoldDurationSec = 5;
let currentHotbarCycleIndex = 0;

let bot = null;
let reconnectTimeout = null;
let isReconnecting = false;
let isManualStopped = false;
let isFirstSpawn = true;

let currentReconnectDelay = 10000;
let consecutiveFailures = 0; 

// TIMERS & INTERVALS
let actionTimeout = null;
let antiAfkTimeout = null;
let ramGcInterval = null;
let posCheckInterval = null;
let watchdogInterval = null;
let pingInterval = null;
let loginTimer1 = null;
let loginTimer2 = null;
let respawnTimer = null;
let commandResponseTimer = null;

let quylayInterval = null;
let ngoiInterval = null;
let attackLeftInterval = null;
let attackRightInterval = null;
let skillLoopInterval = null;
let hotbarLoopInterval = null;

let isAwaitingResponse = false;
let isAutoActionRunning = false;
let lastActionTime = Date.now();
let currentCoords = 'Đang xác định...';
let currentPing = 0;

const startTime = Date.now();
const serverChatLogs = [];
const errorLogs = [];    
const pingLogs = [];     
const botMentionLogs = [];

let lastTimeAge = 0;
let lastTimeAgeUpdate = Date.now();

function getVNTime() {
  return new Date().toLocaleTimeString('vi-VN', { timeZone: 'Asia/Ho_Chi_Minh', hour12: false });
}

function addChatLog(msg) {
  serverChatLogs.unshift(`[${getVNTime()}] ${msg}`);
  if (serverChatLogs.length > 30) serverChatLogs.pop();
}

function addErrorLog(type, details) {
  errorLogs.unshift({ time: getVNTime(), type: type, details: details });
  if (errorLogs.length > 30) errorLogs.pop();
}

function addPingLog(pingVal) {
  pingLogs.unshift({ time: getVNTime(), ping: pingVal });
  if (pingLogs.length > 15) pingLogs.pop();
}

function addBotMentionLog(msg) {
  botMentionLogs.unshift({ time: getVNTime(), text: msg });
  if (botMentionLogs.length > 20) botMentionLogs.pop();
}

function triggerChatWindow(durationMs = 8000) {
  isAwaitingResponse = true;
  if (commandResponseTimer) clearTimeout(commandResponseTimer);
  commandResponseTimer = managedTimeout(() => { isAwaitingResponse = false; }, durationMs);
}

function getHeldItemName() {
  if (!bot || !bot.heldItem) return 'Tay không';
  const item = bot.heldItem;
  return item.customName || item.displayName || item.name || 'Vật phẩm không tên';
}

function safeChat(msg) {
  if (bot && bot.entity && bot._client && bot._client.state === 'play' && !isManualStopped) {
    try {
      bot.chat(msg);
      addChatLog(`[TỰ ĐỘNG]: ${msg}`);
    } catch (e) {
      addErrorLog('Lỗi Chat', e.message);
    }
  }
}

app.get('/api/ping', (req, res) => res.send('PONG_OK'));

app.get('/api/status', (req, res) => {
  const online = !!(bot && bot._client && bot._client.state === 'play' && !isManualStopped);
  res.json({
    online, manualStopped: isManualStopped, username: BOT_USERNAME,
    host: BOT_HOST, port: BOT_PORT, proxy: BOT_PROXY ? 'Đang dùng Proxy' : 'Kết nối trực tiếp',
    ping: currentPing, coords: currentCoords, heldItem: getHeldItemName(),
    uptimeMinutes: Math.floor((Date.now() - startTime) / 60000),
    ramMb: (process.memoryUsage().heapUsed / 1024 / 1024).toFixed(1),
    toggles, chat: serverChatLogs.slice(0, 30), errors: errorLogs.slice(0, 30),
    mentions: botMentionLogs.slice(0, 20), pingLogs: pingLogs.slice(0, 15)
  });
});

// ENDPOINT CẬP NHẬT CẤU HÌNH (USERNAME, PASSWORD, HOST, PROXY)
app.post('/api/update-config', (req, res) => {
  try {
    const { username, password, host, proxy } = req.body;
    
    if (username !== undefined && username.trim() !== '') BOT_USERNAME = username.trim();
    if (password !== undefined && password.trim() !== '') BOT_PASSWORD = password.trim();
    if (proxy !== undefined) BOT_PROXY = proxy.trim();
    
    if (host !== undefined && host.trim() !== '') {
      let cleanHost = host.trim();
      if (cleanHost.includes(':')) {
        const parts = cleanHost.split(':');
        BOT_HOST = parts[0];
        BOT_PORT = parseInt(parts[1]) || 25565;
      } else {
        BOT_HOST = cleanHost;
        BOT_PORT = 25565;
      }
    }

    addErrorLog('CẤU HÌNH', `Đã lưu cấu hình Bot [${escapeHtml(BOT_USERNAME)}]. Đang tái kết nối...`);
    consecutiveFailures = 0;
    isManualStopped = false;
    createBot();
  } catch (err) {
    addErrorLog('Lỗi Lưu Cấu Hình', err.message);
  }
  res.redirect('/');
});

app.post('/api/command', (req, res) => {
  if (isManualStopped) return res.send('Bot đang ở trạng thái TẮT thủ công!');
  const cmd = req.body.command;
  if (!bot || !bot._client) return res.send('Bot đang ngoại tuyến!');
  if (cmd) {
    const safeCommand = String(cmd).slice(0, 256);
    try {
      bot.chat(safeCommand);
      addChatLog(`[WEB-ADMIN]: ${safeCommand}`);
      triggerChatWindow(8000);
    } catch (err) {
      addErrorLog('Lỗi gửi lệnh', err.message || String(err));
    }
  }
  res.redirect('/');
});

app.get('/api/toggle/:feature', (req, res) => {
  const feat = req.params.feature;
  if (toggles.hasOwnProperty(feat)) {
    toggles[feat] = !toggles[feat];
    addChatLog(`[CÀI ĐẶT] ${feat.toUpperCase()} ➔ ${toggles[feat] ? 'BẬT' : 'TẮT'}`);

    if (bot && bot.entity && bot._client && bot._client.state === 'play' && !isManualStopped) {
      if (feat === 'afkmode') safeChat(toggles[feat] ? '/afkmode vao' : '/afkmode ra');
      if (feat === 'thien') safeChat('/thien');
      if (feat === 'quylay') safeChat('/quylay');
      if (feat === 'dinhthan') safeChat('/dinhthan');
      if (feat === 'quanghao') safeChat('/quanghao');
      if (feat === 'skill1') safeChat('/kinang_1');
      if (feat === 'skill2') safeChat('/kinang_2');
      if (feat === 'skill3') safeChat('/kinang_3');

      restartLoops();
    }
  }
  res.redirect('/');
});

app.post('/api/update-hotbar', (req, res) => {
  const duration = parseInt(req.body.duration);
  if (!isNaN(duration) && duration >= 1) hotbarHoldDurationSec = duration;

  for (let i = 0; i < 9; i++) {
    hotbarEnabled[i] = req.body[`slot_${i}`] === 'on';
  }

  addChatLog(`[HOTBAR] Cập nhật danh sách ô cầm vật phẩm (${escapeHtml(hotbarHoldDurationSec)}s)`);
  restartLoops();
  res.redirect('/');
});

app.post('/api/update-click-speed', (req, res) => {
  const leftSpeed = parseFloat(req.body.leftSpeed);
  const rightSpeed = parseFloat(req.body.rightSpeed);

  if (!isNaN(leftSpeed) && leftSpeed >= 0.1) attackLeftIntervalMs = Math.round(leftSpeed * 1000);
  if (!isNaN(rightSpeed) && rightSpeed >= 0.1) attackRightIntervalMs = Math.round(rightSpeed * 1000);

  restartLoops();
  res.redirect('/');
});

app.get('/api/inventory', (req, res) => {
  if (bot && bot._client && !isManualStopped) {
    bot.chat('[inv]');
    addChatLog('[WEB-ADMIN]: [inv]');
    triggerChatWindow(4000);
  }
  res.redirect('/');
});

app.get('/api/tusat', (req, res) => {
  if (bot && bot._client && !isManualStopped) {
    safeChat('/tusat');
    triggerChatWindow(4000);
  }
  res.redirect('/');
});

app.get('/api/toggle-bot', (req, res) => {
  if (req.query.state === 'start') isManualStopped = false;
  else if (req.query.state === 'stop') isManualStopped = true;
  else isManualStopped = !isManualStopped;
  if (isManualStopped) {
    addErrorLog('THỦ CÔNG', 'Đã TẮT Bot từ Dashboard. Ngắt kết nối.');
    cleanupBot();
  } else {
    addErrorLog('THỦ CÔNG', 'Đã BẬT lại Bot từ Dashboard. Đang kết nối lại...');
    consecutiveFailures = 0;
    createBot();
  }
  res.redirect('/');
});

app.get('/api/reconnect', (req, res) => { isManualStopped = false; consecutiveFailures = 0; addErrorLog('DASHBOARD', 'Đang yêu cầu kết nối lại bot...'); createBot(); res.redirect('/'); });
app.get('/api/clear-error-log', (req, res) => { errorLogs.length = 0; res.redirect('/'); });
app.get('/api/clear-mention-log', (req, res) => { botMentionLogs.length = 0; res.redirect('/'); });
app.get('/api/hard-restart', (req, res) => { process.exit(1); });

app.get('/', (req, res) => {
  const online = !!(bot && bot._client && bot._client.state === 'play' && !isManualStopped);
  const uptimeMinutes = Math.floor((Date.now() - startTime) / 60000);
  const memoryUsage = (process.memoryUsage().heapUsed / 1024 / 1024).toFixed(1);
  const toggleButton = (key, label) => `<button class="feature ${toggles[key] ? 'active' : ''}" data-toggle="${key}"><span>${label}</span><b>${toggles[key] ? 'ĐANG BẬT' : 'ĐANG TẮT'}</b></button>`;
  res.send(`<!DOCTYPE html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Yuno Babybu | Minecraft Bot Dashboard</title>
  <link rel="preconnect" href="https://fonts.googleapis.com"><link href="https://fonts.googleapis.com/css2?family=Be+Vietnam+Pro:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
  :root{--bg:#090719;--panel:#15102b;--panel2:#1d1440;--line:#7042c8;--purple:#9b5cff;--pink:#ec79ff;--text:#f7efff;--muted:#b8a9d4;--green:#24e58b;--red:#ff526f;--gold:#ffb84d}
  *{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 75% -10%,#54218b66,transparent 42%),linear-gradient(135deg,#080617,#100a27 55%,#090719);color:var(--text);font-family:'Be Vietnam Pro',Arial,sans-serif;min-height:100vh}
  .layout{display:grid;grid-template-columns:245px 1fr;min-height:100vh}.sidebar{background:#100b25ed;border-right:1px solid #8b54d855;padding:24px 16px;display:flex;flex-direction:column;gap:12px;position:sticky;top:0;height:100vh}
  .brand{text-align:center;padding:12px 4px 26px}.brand .mascot{font-size:54px;filter:drop-shadow(0 0 15px #bb72ff)}.brand h1{font-size:25px;line-height:1.1;margin:6px 0;color:#d6a4ff;text-shadow:0 0 18px #9b5cff}.brand p{font-size:11px;color:var(--muted);margin:5px}
  .nav{width:100%;display:flex;align-items:center;gap:13px;padding:14px 15px;border:1px solid transparent;border-radius:14px;background:transparent;color:#d9c9f5;text-align:left;font:600 14px inherit;cursor:pointer}.nav:hover,.nav.selected{background:linear-gradient(100deg,#7b35e8,#a24af0);border-color:#d9a4ff;box-shadow:0 6px 22px #8b3be855;color:white}.nav span:first-child{font-size:20px;width:25px;text-align:center}.side-foot{margin-top:auto;text-align:center;color:#bfa9e6;font-size:12px;padding:16px;border-top:1px solid #7042c855}
  main{min-width:0;padding:22px 26px 40px}.topbar{display:flex;justify-content:space-between;align-items:center;gap:14px;margin-bottom:18px;flex-wrap:wrap}.pill{border:1px solid #7042c8;border-radius:30px;padding:9px 14px;background:#17102d;color:#d9c7fa;font-size:12px}.online-dot{color:var(--green);font-weight:800}.hero{border:1px solid #8146ce;border-radius:22px;padding:30px;background:radial-gradient(circle at 85% 40%,#963eea66,transparent 40%),linear-gradient(110deg,#241044,#17102e);box-shadow:0 10px 36px #6e36aa33;margin-bottom:18px;overflow:hidden}.hero h2{font-size:clamp(23px,3vw,36px);margin:0 0 8px}.hero p{color:#d5c0f4;margin:0}.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin:16px 0}.stat,.panel{background:linear-gradient(145deg,#1b1436,#100d24);border:1px solid #6840a7;border-radius:17px;padding:18px;box-shadow:0 8px 28px #0005}.stat{display:flex;gap:13px;align-items:center;min-width:0}.stat .ico{font-size:28px;color:#bd7bff}.stat small{display:block;color:var(--muted);font-size:11px}.stat strong{display:block;font-size:17px;margin-top:4px;overflow-wrap:anywhere}.columns{display:grid;grid-template-columns:1.2fr 1fr;gap:15px}.panel{margin-bottom:15px}.panel h3{margin:0 0 15px;font-size:16px}.muted{color:var(--muted);font-size:12px}.actions{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.action,button.submit{border:1px solid #a76aff;border-radius:12px;padding:13px;color:white;font-weight:700;background:linear-gradient(120deg,#7135d8,#a33de0);cursor:pointer}.action.green{background:linear-gradient(120deg,#07985c,#20c879);border-color:#41e99b}.action.red{background:linear-gradient(120deg,#bb244b,#ef405e);border-color:#ff7b90}.action.gold{background:linear-gradient(120deg,#bd6a0b,#f4a321);border-color:#ffc66b}.action:hover,button.submit:hover{filter:brightness(1.15);transform:translateY(-1px)}
  .feature-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:10px}.feature{border:1px solid #60418d;border-radius:12px;padding:13px;background:#100c22;color:white;text-align:left;cursor:pointer}.feature b{display:block;font-size:10px;color:#ff879d;margin-top:6px}.feature.active{background:#34205d;border-color:#c18aff}.feature.active b{color:var(--green)}
  label{display:block;font-size:12px;color:#d7c8ee;margin:12px 0 6px}input{width:100%;padding:12px;border-radius:10px;border:1px solid #64448e;background:#0b081a;color:white;outline:none}input:focus{border-color:#c18aff}.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}.slot-grid{display:grid;grid-template-columns:repeat(9,1fr);gap:7px}.slot{background:#100c22;border:1px solid #62448d;border-radius:10px;padding:9px 2px;text-align:center;font-size:11px}.slot input{width:auto;accent-color:#b46cff}.logs{height:250px;overflow:auto;background:#090615;border:1px solid #4c3374;border-radius:12px;padding:12px;font:12px/1.7 monospace;color:#d7c6f4;white-space:pre-wrap;overflow-wrap:anywhere}.hidden{display:none!important}.section-title{font-size:24px;margin:8px 0 18px}.statusline{font-size:12px;color:var(--muted);margin-top:12px}.toast{position:fixed;right:20px;bottom:20px;background:#2b1950;border:1px solid #bd80ff;padding:12px 18px;border-radius:12px;display:none;z-index:5}
  @media(max-width:1000px){.layout{grid-template-columns:190px 1fr}.grid{grid-template-columns:repeat(2,1fr)}.columns{grid-template-columns:1fr}}
  @media(max-width:650px){.layout{display:block}.sidebar{position:static;height:auto;padding:12px;display:grid;grid-template-columns:repeat(5,1fr);gap:5px}.brand{grid-column:1/-1;padding:5px}.brand .mascot,.brand p,.side-foot{display:none}.brand h1{font-size:19px}.nav{justify-content:center;padding:10px 4px;font-size:10px;gap:4px;flex-direction:column}.nav span:first-child{font-size:17px}main{padding:14px}.hero{padding:22px}.grid{gap:8px}.stat{padding:12px;gap:8px}.stat .ico{font-size:20px}.stat strong{font-size:13px}.form-grid{grid-template-columns:1fr}.slot-grid{grid-template-columns:repeat(5,1fr)}}
  </style></head><body><div class="layout"><aside class="sidebar"><div class="brand"><div class="mascot">🌸</div><h1>Yuno Babybu</h1><p>MINECRAFT BOT DASHBOARD</p></div>
  <button class="nav selected" data-page="home"><span>⌂</span>Trang Chủ</button><button class="nav" data-page="control"><span>🎮</span>Điều Khiển</button><button class="nav" data-page="utility"><span>🧰</span>Tiện Ích</button><button class="nav" data-page="settings"><span>⚙</span>Cài Đặt</button><button class="nav" data-page="logs"><span>▤</span>Nhật Ký</button><div class="side-foot">Powered by Yuno Babybu ♡<br>Bot Minecraft Thế Hệ Mới</div></aside>
  <main><div class="topbar"><div class="pill"><span class="online-dot" id="top-status">● ${online?'Bot: Đang Online':'Bot: Đang Offline'}</span></div><div><span class="pill">🕒 Giờ Việt Nam</span> <a class="pill" href="/logout" style="text-decoration:none">Đăng Xuất ↗</a></div></div>
  <section class="page" id="page-home"><div class="hero"><h2>Chào mừng trở lại! 👋</h2><p>Yuno Babybu – Minecraft Bot Dashboard</p><p class="statusline">“Bot luôn bên bạn, chinh phục mọi thế giới!” ♡</p></div>
  <div class="grid"><div class="stat"><div class="ico">🟩</div><div><small>Trạng Thái Bot</small><strong id="s-status">${online?'Đang Online':'Đang Offline'}</strong><small id="s-uptime">Hoạt động: ${uptimeMinutes} phút</small></div></div><div class="stat"><div class="ico">📶</div><div><small>Máy Chủ</small><strong id="s-server">${escapeHtml(BOT_HOST)}:${BOT_PORT}</strong><small>Ping: <b id="s-ping">${escapeHtml(currentPing)}ms</b></small></div></div><div class="stat"><div class="ico">👤</div><div><small>Nhân Vật</small><strong id="s-user">${escapeHtml(BOT_USERNAME)}</strong><small id="s-coords">${escapeHtml(currentCoords)}</small></div></div><div class="stat"><div class="ico">⚡</div><div><small>RAM</small><strong id="s-ram">${memoryUsage} MB</strong><small id="s-held">${escapeHtml(currentWeapon)}</small></div></div></div>
  <div class="columns"><div><div class="panel"><h3>📢 Thông Báo Hệ Thống</h3><p class="muted" id="home-message">${online?'Bot đang hoạt động bình thường!':'Bot đang chờ kết nối tới máy chủ.'}</p></div><div class="panel"><h3>📈 Lịch Sử Ping</h3><div class="logs" id="ping-log">Đang thu thập dữ liệu...</div></div></div><div class="panel"><h3>🚀 Điều Khiển Nhanh</h3><div class="actions"><button class="action green" id="start-bot">▶ Bật Bot</button><button class="action red" id="stop-bot">■ Tắt Bot</button><button class="action" id="restart-bot">⟳ Kết Nối Lại</button><button class="action gold" id="clear-errors">✦ Xóa Nhật Ký Lỗi</button></div></div></div></section>
  <section class="page hidden" id="page-control"><h2 class="section-title">🎮 Điều Khiển Bot</h2><div class="panel"><h3>Lệnh Chat / Command</h3><form id="command-form"><div class="form-grid"><input name="command" placeholder="Nhập lệnh hoặc tin nhắn..." required><button class="submit">Gửi Lệnh</button></div></form></div><div class="panel"><h3>🤖 Tự Động & Hoạt Động</h3><div class="feature-grid">${toggleButton('afkmode','AFK Mode')}${toggleButton('thien','Thiền')}${toggleButton('quylay','Quỳ Lạy')}${toggleButton('dinhthan','Định Thân')}${toggleButton('quanghao','Quang Hào')}${toggleButton('ngoi','Ngồi / Rón Rén')}${toggleButton('attackLeft','Đánh Trái')}${toggleButton('attackRight','Đánh Phải')}${toggleButton('skill1','Kỹ Năng 1')}${toggleButton('skill2','Kỹ Năng 2')}${toggleButton('skill3','Kỹ Năng 3')}</div></div><div class="panel"><h3>⚔️ Tốc Độ Đánh</h3><form action="/api/update-click-speed" method="POST" class="form-grid"><div><label>Tốc độ trái (giây)</label><input type="number" min="0.1" step="0.1" name="leftSpeed" value="${(attackLeftIntervalMs/1000).toFixed(1)}"></div><div><label>Tốc độ phải (giây)</label><input type="number" min="0.1" step="0.1" name="rightSpeed" value="${(attackRightIntervalMs/1000).toFixed(1)}"></div><button class="submit" style="grid-column:1/-1">Lưu Tốc Độ</button></form></div></section>
  <section class="page hidden" id="page-utility"><h2 class="section-title">🧰 Tiện Ích Bot</h2><div class="panel"><h3>Thanh Công Cụ (Ô 1 – 9)</h3><form action="/api/update-hotbar" method="POST"><label>Thời gian giữ mỗi ô (giây)</label><input type="number" min="1" name="duration" value="${hotbarHoldDurationSec}"><label>Chọn ô cần luân chuyển</label><div class="slot-grid">${[1,2,3,4,5,6,7,8,9].map((n,i)=>`<label class="slot">Ô ${n}<br><input type="checkbox" name="slot_${i}" ${hotbarEnabled[i]?'checked':''}></label>`).join('')}</div><button class="submit" style="width:100%;margin-top:14px">Lưu Thiết Lập Ô Cầm</button></form></div><div class="panel"><h3>🎒 Hành Động Nhanh</h3><div class="actions"><a href="/api/inventory"><button class="action">🎒 Mở Túi Đồ [inv]</button></a><a href="/api/tusat"><button class="action red">☠ Tự Sát (/tusat)</button></a><a href="/api/clear-mention-log"><button class="action">Xóa Log Mention</button></a></div></div></section>
  <section class="page hidden" id="page-settings"><h2 class="section-title">⚙️ Cài Đặt Kết Nối</h2><form action="/api/update-config" method="POST" class="panel"><h3>Thông Tin Tài Khoản & Máy Chủ</h3><div class="form-grid"><div><label>Tên nhân vật</label><input name="username" value="${escapeHtml(BOT_USERNAME)}" required></div><div><label>Mật khẩu Minecraft</label><input type="password" name="password" value="${escapeHtml(BOT_PASSWORD)}"></div></div><label>IP Server (Host hoặc Host:Port)</label><input name="host" value="${escapeHtml(BOT_HOST)}${BOT_PORT!==25565?':'+BOT_PORT:''}" required><label>SOCKS5 Proxy (để trống nếu không dùng)</label><input name="proxy" value="${escapeHtml(BOT_PROXY)}" placeholder="ip:port hoặc user:pass@ip:port"><button class="submit" style="width:100%;margin-top:16px">Lưu Cấu Hình & Kết Nối Lại</button><p class="muted">Máy chủ mặc định: vangioinetwork.xyz:25565</p></form></section>
  <section class="page hidden" id="page-logs"><h2 class="section-title">▤ Nhật Ký Hoạt Động</h2><div class="panel"><h3>💬 Chat Server Realtime</h3><div class="logs" id="chat-log">${serverChatLogs.length?serverChatLogs.map(x=>escapeHtml(x)).join('\n'):'Chưa có nhật ký...'}</div></div><div class="panel"><h3>⚠ Nhật Ký Lỗi Phát Sinh</h3><div class="logs" id="error-log">${errorLogs.length?errorLogs.map(e=>`[${escapeHtml(e.time)}] [${escapeHtml(e.type)}] ${escapeHtml(e.details)}`).join('\n'):'Không có lỗi!'}</div></div><div class="panel"><h3>🏷 Nhật Ký Mention</h3><div class="logs" id="mention-log">${botMentionLogs.length?botMentionLogs.map(e=>`[${escapeHtml(e.time)}] ${escapeHtml(e.text)}`).join('\n'):'Chưa có mention...'}</div></div></section>
  <div class="toast" id="toast"></div></main></div>
  <script>
  const toast=(m)=>{const t=document.getElementById('toast');t.textContent=m;t.style.display='block';setTimeout(()=>t.style.display='none',2600)};
  document.querySelectorAll('.nav').forEach(b=>b.addEventListener('click',()=>{document.querySelectorAll('.nav').forEach(x=>x.classList.remove('selected'));b.classList.add('selected');document.querySelectorAll('.page').forEach(x=>x.classList.add('hidden'));document.getElementById('page-'+b.dataset.page).classList.remove('hidden')}));
  async function call(url,method='GET',body){try{const r=await fetch(url,{method,headers:body?{'Content-Type':'application/x-www-form-urlencoded'}:{},body});if(!r.ok)throw Error('HTTP '+r.status);toast('Đã gửi thao tác');await refresh()}catch(e){toast('Lỗi: '+e.message)}}
  document.querySelectorAll('[data-toggle]').forEach(b=>b.addEventListener('click',()=>call('/api/toggle/'+b.dataset.toggle)));
  document.getElementById('start-bot').onclick=()=>call('/api/toggle-bot?state=start');document.getElementById('stop-bot').onclick=()=>call('/api/toggle-bot?state=stop');document.getElementById('restart-bot').onclick=()=>{if(confirm('Kết nối lại bot?'))call('/api/reconnect')};document.getElementById('clear-errors').onclick=()=>call('/api/clear-error-log');
  document.getElementById('command-form').onsubmit=async e=>{e.preventDefault();const fd=new FormData(e.target);await call('/api/command','POST',new URLSearchParams(fd));e.target.reset()};
  async function refresh(){try{const r=await fetch('/api/status',{cache:'no-store'});if(!r.ok)return;const d=await r.json();document.getElementById('top-status').textContent=d.online?'● Bot: Đang Online':(d.manualStopped?'● Bot: Đã Tắt':'● Bot: Đang Kết Nối');document.getElementById('s-status').textContent=d.online?'Đang Online':(d.manualStopped?'Đã Tắt':'Đang Kết Nối');document.getElementById('s-uptime').textContent='Hoạt động: '+d.uptimeMinutes+' phút';document.getElementById('s-server').textContent=d.host+':'+d.port;document.getElementById('s-ping').textContent=d.ping+'ms';document.getElementById('s-user').textContent=d.username;document.getElementById('s-coords').textContent=d.coords;document.getElementById('s-ram').textContent=d.ramMb+' MB';document.getElementById('s-held').textContent=d.heldItem;document.getElementById('chat-log').textContent=d.chat.join('\n')||'Chưa có nhật ký...';document.getElementById('error-log').textContent=d.errors.map(x=>'['+x.time+'] ['+x.type+'] '+x.details).join('\n')||'Không có lỗi!';document.getElementById('mention-log').textContent=d.mentions.map(x=>'['+x.time+'] '+x.text).join('\n')||'Chưa có mention...';document.getElementById('ping-log').textContent=d.pingLogs.map(x=>'['+x.time+'] '+x.ping+' ms').join('\n')||'Đang thu thập dữ liệu...';document.querySelectorAll('[data-toggle]').forEach(b=>{const on=!!d.toggles[b.dataset.toggle];b.classList.toggle('active',on);b.querySelector('b').textContent=on?'ĐANG BẬT':'ĐANG TẮT'})}catch(e){}}
  refresh();setInterval(refresh,3000);
  </script></body></html>`);
});

app.listen(port, () => console.log(`[HTTP SERVER] Running on port ${port}`));

function stopFeatureLoops() {
  if (quylayInterval) { clearInterval(quylayInterval); quylayInterval = null; }
  if (ngoiInterval) { clearInterval(ngoiInterval); ngoiInterval = null; }
  if (attackLeftInterval) { clearInterval(attackLeftInterval); attackLeftInterval = null; }
  if (attackRightInterval) { clearInterval(attackRightInterval); attackRightInterval = null; }
  if (skillLoopInterval) { clearInterval(skillLoopInterval); skillLoopInterval = null; }
  if (hotbarLoopInterval) { clearInterval(hotbarLoopInterval); hotbarLoopInterval = null; }
}

function restartLoops() {
  stopFeatureLoops();
  if (!bot || !bot.entity || !bot._client || bot._client.state !== 'play' || isManualStopped) return;

  if (toggles.quylay) {
    quylayInterval = setInterval(() => { if (toggles.quylay) safeChat('/quylay'); }, 47000);
  }
  if (toggles.ngoi) {
    ngoiInterval = setInterval(() => {
      if (bot && bot.entity && bot._client && bot._client.state === 'play' && !isManualStopped) {
        try {
          bot.setControlState('sneak', true);
          managedTimeout(() => { if (bot && bot.entity) bot.setControlState('sneak', false); }, 1200);
        } catch (e) {}
      }
    }, 5000);
  }
  if (toggles.attackLeft) {
    attackLeftInterval = setInterval(() => {
      if (bot && bot.entity && bot._client && bot._client.state === 'play' && !isManualStopped) {
        try {
          const target = bot.nearestEntity(entity =>
            entity && entity !== bot.entity &&
            (entity.type === 'mob' || entity.type === 'player') &&
            entity.position && bot.entity.position.distanceTo(entity.position) <= 4
          );
          if (target) bot.attack(target);
          else bot.swingArm('right');
        } catch (e) {}
      }
    }, attackLeftIntervalMs);
  }
  if (toggles.attackRight) {
    attackRightInterval = setInterval(() => {
      if (bot && bot.entity && bot._client && bot._client.state === 'play' && !isManualStopped) {
        try { bot.activateItem(); } catch (e) {}
      }
    }, attackRightIntervalMs);
  }
  if (toggles.skill1 || toggles.skill2 || toggles.skill3) {
    skillLoopInterval = setInterval(() => {
      if (bot && bot.entity && bot._client && !isManualStopped) {
        if (toggles.skill1) safeChat('/kinang_1');
        if (toggles.skill2) safeChat('/kinang_2');
        if (toggles.skill3) safeChat('/kinang_3');
      }
    }, 10000);
  }

  const activeSlots = hotbarEnabled.map((enabled, idx) => enabled ? idx : -1).filter(idx => idx !== -1);
  currentHotbarCycleIndex = 0;
  if (activeSlots.length >= 1) {
    try { bot.setQuickBarSlot(activeSlots[0]); } catch (e) {}
  }
  if (activeSlots.length > 1) {
    hotbarLoopInterval = setInterval(() => {
      if (bot && bot.entity && bot._client && bot._client.state === 'play' && !isManualStopped) {
        currentHotbarCycleIndex = (currentHotbarCycleIndex + 1) % activeSlots.length;
        try { bot.setQuickBarSlot(activeSlots[currentHotbarCycleIndex]); } catch (e) {}
      }
    }, hotbarHoldDurationSec * 1000);
  }
}

function cleanupBot() {
  isAutoActionRunning = false;
  currentCoords = 'Đang xác định...';
  currentPing = 0;

  stopFeatureLoops(); 

  if (actionTimeout) { clearTimeout(actionTimeout); actionTimeout = null; }
  if (antiAfkTimeout) { clearTimeout(antiAfkTimeout); antiAfkTimeout = null; }

  [ramGcInterval, posCheckInterval, watchdogInterval, pingInterval].forEach(i => i && clearInterval(i));
  ramGcInterval = posCheckInterval = watchdogInterval = pingInterval = null;
  [reconnectTimeout, loginTimer1, loginTimer2, respawnTimer, commandResponseTimer].forEach(t => t && clearTimeout(t));
  for (const timer of managedTimeouts) clearTimeout(timer);
  managedTimeouts.clear();
  reconnectTimeout = loginTimer1 = loginTimer2 = respawnTimer = commandResponseTimer = null;
  isAwaitingResponse = false;

  if (bot) {
    try {
      bot.removeAllListeners();
      if (bot._client) bot._client.removeAllListeners();
      bot.clearControlStates();
      bot.end(); 
    } catch (e) {}
    bot = null;
  }

  if (global.gc) {
    try { global.gc(); } catch (e) {}
  }
}

function scheduleNextAction() {
  if (actionTimeout) { clearTimeout(actionTimeout); actionTimeout = null; }
  if (isManualStopped || !bot || !bot.entity || !bot._client) {
    isAutoActionRunning = false;
    return;
  }
  isAutoActionRunning = true;
  lastActionTime = Date.now();
  const currentBot = bot;

  try {
    const actionType = Math.floor(Math.random() * 3);
    if (actionType === 0) currentBot.swingArm('right');
    else if (actionType === 1) {
      currentBot.setControlState('sneak', true);
      managedTimeout(() => { if (bot === currentBot && bot.entity) bot.setControlState('sneak', false); }, 200);
    } else {
      currentBot.activateItem();
    }
  } catch (err) {}

  actionTimeout = managedTimeout(scheduleNextAction, Math.floor(5000 + Math.random() * 5000));
}

function scheduleRandomRotation() {
  if (antiAfkTimeout) clearTimeout(antiAfkTimeout);
  if (isManualStopped) return;

  antiAfkTimeout = managedTimeout(() => {
    if (bot && bot.entity && bot.health > 0 && bot._client && bot._client.state === 'play') {
      try {
        bot.look(bot.entity.yaw + (Math.random() - 0.5) * 0.3, bot.entity.pitch + (Math.random() - 0.5) * 0.1, true);
      } catch (e) {}
    }
    scheduleRandomRotation();
  }, Math.floor(15000 + Math.random() * 20000));
}

function executeActiveFeaturesOnSpawn() {
  if (!bot || !bot.entity || !bot._client || isManualStopped) return;
  let delay = 1000;
  
  if (toggles.afkmode) { managedTimeout(() => safeChat('/afkmode vao'), delay); delay += 1200; }
  if (toggles.thien) { managedTimeout(() => safeChat('/thien'), delay); delay += 1200; }
  if (toggles.quylay) { managedTimeout(() => safeChat('/quylay'), delay); delay += 1200; }
  if (toggles.dinhthan) { managedTimeout(() => safeChat('/dinhthan'), delay); delay += 1200; }
  if (toggles.quanghao) { managedTimeout(() => safeChat('/quanghao'), delay); delay += 1200; }

  managedTimeout(() => { restartLoops(); }, delay + 500);
}

function createBot() {
  if (isManualStopped) return;
  if (reconnectTimeout) { clearTimeout(reconnectTimeout); reconnectTimeout = null; }
  isReconnecting = false;
  cleanupBot();
  isFirstSpawn = true;
  lastTimeAge = 0;
  lastTimeAgeUpdate = Date.now();

  const currentOptions = {
    host: BOT_HOST,
    port: BOT_PORT,
    username: BOT_USERNAME,
    hideErrors: false,
    checkTimeoutInterval: 60 * 1000, 
    keepAlive: true,
    physicsEnabled: true,
    viewDistance: 'tiny'
  };

  // NẾU CÓ CẤU HÌNH PROXY SOCKS5 -> SỬ DỤNG PROXY ĐỂ TRÁNH LỖI TRÙNG IP TRÊN RENDER
  if (BOT_PROXY && BOT_PROXY.trim() !== '') {
    currentOptions.connect = (client) => {
      let proxyHost = BOT_PROXY;
      let proxyPort = 1080;
      let proxyUser = undefined;
      let proxyPass = undefined;

      try {
        if (BOT_PROXY.includes('@')) {
          const parts = BOT_PROXY.split('@');
          const auth = parts[0].split(':');
          proxyUser = auth[0];
          proxyPass = auth[1];
          const serverParts = parts[1].split(':');
          proxyHost = serverParts[0];
          proxyPort = parseInt(serverParts[1]) || 1080;
        } else if (BOT_PROXY.includes(':')) {
          const parts = BOT_PROXY.split(':');
          proxyHost = parts[0];
          proxyPort = parseInt(parts[1]) || 1080;
        }

        SocksClient.createConnection({
          proxy: {
            host: proxyHost,
            port: proxyPort,
            type: 5,
            userId: proxyUser,
            password: proxyPass
          },
          command: 'connect',
          destination: {
            host: BOT_HOST,
            port: BOT_PORT
          }
        }, (err, info) => {
          if (err) {
            addErrorLog('Proxy Error', err.message);
            client.emit('error', err);
            return;
          }
          client.setSocket(info.socket);
          client.emit('connect');
        });
      } catch (proxyErr) {
        addErrorLog('Proxy Parse Error', proxyErr.message);
        client.emit('error', proxyErr);
      }
    };
  }

  console.log(`
[HỆ THỐNG] Kết nối đến ${escapeHtml(BOT_HOST)}:${escapeHtml(BOT_PORT)} (Proxy: ${BOT_PROXY || 'Không'}) với tên [${escapeHtml(BOT_USERNAME)}]...`);

  try {
    bot = mineflayer.createBot(currentOptions);
    bot.setMaxListeners(0);

    if (bot._client) {
      bot._client.setMaxListeners(0);
      bot._client.on('error', (err) => {
        addErrorLog('Socket Error', err.message || err.code || 'Lỗi TCP Socket');
      });
    }
  } catch (err) {
    addErrorLog('Init Failed', err.message);
    handleReconnect();
    return;
  }

  bot.on('spawn', () => {
    console.log('[LOG] Bot đã vào game!');
    addChatLog('Kết nối ổn định thành công!');
    triggerChatWindow(12000);
    consecutiveFailures = 0;
    currentReconnectDelay = 10000;

    if (isFirstSpawn) {
      isFirstSpawn = false;

      loginTimer1 = managedTimeout(() => {
        if (bot && bot._client && !isManualStopped) {
          bot.chat(`/l ${BOT_PASSWORD}`);
          triggerChatWindow(4000);
        }
      }, 3500);

      loginTimer2 = managedTimeout(() => {
        if (bot && bot.entity && bot._client && !isManualStopped) {
          executeActiveFeaturesOnSpawn();
          scheduleNextAction();
          scheduleRandomRotation();
        }
      }, 7000);

      // Mineflayer owns bot.entities. Do not delete live entities manually:
      // doing so breaks player/mob tracking and can destabilize combat/pathfinding.
      ramGcInterval = setInterval(() => {
        if (global.gc) { try { global.gc(); } catch (e) {} }
      }, 30000);

      pingInterval = setInterval(() => {
        if (bot && bot.player) {
          currentPing = bot.player.ping || 0;
          addPingLog(currentPing);
        }
      }, 10000);

      posCheckInterval = setInterval(() => {
        if (bot && bot.entity && bot.entity.position) {
          const pos = bot.entity.position;
          currentCoords = `X: ${pos.x.toFixed(1)}, Y: ${pos.y.toFixed(1)}, Z: ${pos.z.toFixed(1)}`;
        }
      }, 5000);

      watchdogInterval = setInterval(() => {
        if (!bot || isManualStopped) return;
        if (!isAutoActionRunning || Date.now() - lastActionTime > 20000) scheduleNextAction();

        if (bot.time) {
          if (bot.time.age === lastTimeAge) {
            if (Date.now() - lastTimeAgeUpdate > 45000) {
              addErrorLog('Watchdog', 'Kẹt Packet thế giới > 45s. Tiến hành Reconnect...');
              handleReconnect();
            }
          } else {
            lastTimeAge = bot.time.age;
            lastTimeAgeUpdate = Date.now();
          }
        }
      }, 15000);
    }
  });

  bot.on('death', () => {
    addChatLog('Bot tử vong! Chờ hồi sinh...');
    addErrorLog('Event Chết', 'Bot tử vong');

    respawnTimer = managedTimeout(() => {
      if (bot && bot._client && !isManualStopped) {
        try { bot.respawn(); } catch (e) {}
      }
      managedTimeout(() => {
        if (bot && bot.entity && bot._client && !isManualStopped) {
          executeActiveFeaturesOnSpawn();
          scheduleNextAction();
          scheduleRandomRotation();
        }
      }, 4500);
    }, 4000);
  });

  bot.on('message', (message) => {
    try {
      const text = message.toString().trim();
      if (!text) return;
      const lowerText = text.toLowerCase();

      if (lowerText.includes(BOT_USERNAME.toLowerCase())) {
        addBotMentionLog(text);
      }

      if (text.includes('█') || lowerText.includes('hồi chiêu') || lowerText.includes('cooldown')) return;

      addChatLog(text);
    } catch (e) {}
  });

  bot.on('end', (reason) => {
    stopFeatureLoops();
    addErrorLog('Mất Kết Nối (End)', `Server ngắt socket: ${reason}`);
    handleReconnect();
  });

  bot.on('error', (err) => {
    stopFeatureLoops();
    addErrorLog('Mineflayer Error', err.message || err.toString());
  });

  bot.on('kicked', (reason) => {
    stopFeatureLoops();
    const reasonStr = typeof reason === 'string' ? reason : JSON.stringify(reason);
    addErrorLog('Bị Server Kick', reasonStr);
    
    if (reasonStr.includes('IP') || reasonStr.includes('đã có người') || reasonStr.includes('LƯU DỮ LIỆU')) {
      currentReconnectDelay = 25000;
    }
    handleReconnect();
  });
}

function handleReconnect() {
  if (isManualStopped || isReconnecting) return;
  isReconnecting = true;
  cleanupBot();

  consecutiveFailures++;

  if (consecutiveFailures >= 12) {
    // Không tự tắt tiến trình web khi Minecraft mất kết nối.
    // Giữ Express hoạt động để Dashboard không bị 502 và tiếp tục thử kết nối.
    addErrorLog('CẢNH BÁO NẶNG', `Mất kết nối liên tục ${consecutiveFailures} lần. Tiếp tục thử lại sau ${Math.round(currentReconnectDelay / 1000)} giây...`);
  }

  const jitter = Math.floor(Math.random() * 3000);
  const waitTime = currentReconnectDelay + jitter;

  console.log(`Chờ ${Math.round(waitTime / 1000)}s để tái kết nối...`);
  
  reconnectTimeout = managedTimeout(() => {
    isReconnecting = false;
    currentReconnectDelay = Math.min(currentReconnectDelay * 1.25, 30000);
    createBot();
  }, waitTime);
}

createBot();

process.on('uncaughtException', (err) => {
  addErrorLog('Uncaught Exception', `${err.message} (${err.code || 'NO_CODE'})`);
  try { handleReconnect(); } catch(e) {}
});

process.on('unhandledRejection', (reason) => {
  addErrorLog('Unhandled Rejection', String(reason));
});


