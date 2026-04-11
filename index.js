const express = require('express');
const cors = require('cors');
const path = require('path');
const app = express();

// ── 보안 설정 ──
const blockedIPs = new Map();
const requestCounts = new Map();
const securityLogs = [];
const RATE_LIMIT = 60; // 1분에 최대 60요청

// SQL Injection / XSS 패턴
const sqlPatterns = /(\bSELECT\b|\bINSERT\b|\bDROP\b|\bUNION\b|--|;--|'--)/i;
const xssPatterns = /<script|javascript:|onerror=|onload=/i;

function getClientIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || req.connection.remoteAddress;
}

function getTime() {
  return new Date().toLocaleString('ko-KR', { timeZone: 'Asia/Seoul' });
}

function detectMalicious(req) {
  const body = JSON.stringify(req.body || {});
  const query = JSON.stringify(req.query || {});
  const ua = req.headers['user-agent'] || '';
  if (sqlPatterns.test(body) || sqlPatterns.test(query)) return 'SQL Injection';
  if (xssPatterns.test(body) || xssPatterns.test(query)) return 'XSS';
  if (!ua || ua.includes('sqlmap') || ua.includes('nikto') || ua.includes('masscan')) return 'Malicious Bot';
  return null;
}

app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'ALLOWALL');
  res.setHeader('Content-Security-Policy', "frame-ancestors *");
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

// ── 보안 미들웨어 ──
app.use((req, res, next) => {
  const ip = getClientIP(req);

  // 차단된 IP
  if (blockedIPs.has(ip)) {
    securityLogs.push({ time: getTime(), ip, type: '차단 IP 접근 시도' });
    return res.status(403).json({ error: 'Access denied' });
  }

  // Rate limiting
  const now = Date.now();
  const times = (requestCounts.get(ip) || []).filter(t => now - t < 60000);
  times.push(now);
  requestCounts.set(ip, times);
  if (times.length > RATE_LIMIT) {
    blockedIPs.set(ip, { reason: 'Rate Limit 초과', time: getTime() });
    securityLogs.push({ time: getTime(), ip, type: 'Rate Limit', detail: '1분 60회 초과' });
    return res.status(429).json({ error: 'Too many requests' });
  }

  // 악성 요청 감지
  const threat = detectMalicious(req);
  if (threat) {
    blockedIPs.set(ip, { reason: threat, time: getTime() });
    securityLogs.push({ time: getTime(), ip, type: threat, detail: '악성 요청 감지' });
    return res.status(403).json({ error: 'Forbidden' });
  }

  next();
});

app.use(express.static(path.join(__dirname, 'public')));

// ── 초대코드 ──
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'AITOOLS1';
const CODE_VERSION = process.env.CODE_VERSION || '1';

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/blog', (req, res) => res.sendFile(path.join(__dirname, 'public', 'blog.html')));
app.get('/cafe', (req, res) => res.sendFile(path.join(__dirname, 'public', 'cafe.html')));
app.get('/threads', (req, res) => res.sendFile(path.join(__dirname, 'public', 'threads.html')));

// 코드 검증
app.post('/api/verify-code', (req, res) => {
  const { code } = req.body;
  const upper = (code || '').trim().toUpperCase();
  if (upper === ADMIN_PASSWORD.toUpperCase()) {
    res.json({ success: true, version: CODE_VERSION });
  } else {
    const ip = getClientIP(req);
    securityLogs.push({ time: getTime(), ip, type: '코드 오류', detail: `잘못된 코드: ${code}` });
    res.json({ success: false });
  }
});

// ── OpenAI 프록시 ──
const generateCount = new Map(); // ip+date -> count
const DAILY_LIMIT = 50;
const burstCount = new Map();
const BURST_LIMIT = 5;
const BURST_WINDOW = 60000;
const cooldownIPs = new Map();

app.post('/api/generate', async (req, res) => {
  const ip = getClientIP(req);
  const today = new Date().toISOString().slice(0, 10);
  const now = Date.now();

  // 쿨다운 체크
  if (cooldownIPs.has(ip) && cooldownIPs.get(ip) > now) {
    const remain = Math.ceil((cooldownIPs.get(ip) - now) / 1000);
    return res.status(429).json({ error: `${remain}초 후 다시 시도해주세요` });
  }

  // 하루 제한
  const dayKey = ip + '_' + today;
  const dayCount = generateCount.get(dayKey) || 0;
  if (dayCount >= DAILY_LIMIT) {
    return res.status(429).json({ error: '오늘 생성 한도에 도달했어요. 내일 다시 이용해주세요.' });
  }

  // 버스트 제한 (1분에 5회)
  const burst = (burstCount.get(ip) || []).filter(t => now - t < BURST_WINDOW);
  burst.push(now);
  burstCount.set(ip, burst);
  if (burst.length > BURST_LIMIT) {
    cooldownIPs.set(ip, now + BURST_WINDOW);
    return res.status(429).json({ error: '너무 빠르게 생성하고 있어요. 1분 후 다시 시도해주세요.' });
  }

  generateCount.set(dayKey, dayCount + 1);

  try {
    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.OPENAI_API_KEY}`,
      },
      body: JSON.stringify(req.body),
    });
    const data = await response.json();
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: '서버 오류가 발생했어요.' });
  }
});

// ── 보안 로그 (어드민만) ──
const adminTokens = new Set();

app.post('/api/admin/auth', (req, res) => {
  const { password } = req.body;
  if (password === ADMIN_PASSWORD) {
    const token = Math.random().toString(36).slice(2) + Date.now();
    adminTokens.add(token);
    res.json({ success: true, token });
  } else {
    res.json({ success: false });
  }
});

function adminAuth(req, res, next) {
  const token = req.headers['x-admin-token'];
  if (!token || !adminTokens.has(token)) return res.status(403).json({ success: false });
  next();
}

app.get('/api/admin/logs', adminAuth, (req, res) => {
  res.json({
    blocked_count: blockedIPs.size,
    blocked_ips: [...blockedIPs.entries()].map(([ip, info]) => ({ ip, ...info })),
    security_logs: securityLogs.slice(-50),
  });
});

app.post('/api/admin/unblock', adminAuth, (req, res) => {
  const { ip } = req.body;
  blockedIPs.delete(ip);
  res.json({ success: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
