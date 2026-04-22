'use strict';
require('dotenv').config();

const express      = require('express');
const path         = require('path');
const fs           = require('fs');
const cookieParser = require('cookie-parser');
const multer       = require('multer');
const mysql        = require('mysql2/promise');
const jwt          = require('jsonwebtoken');
const sanitizeFilename = require('sanitize-filename');
const crypto       = require('crypto');

const app  = express();
const PORT = process.env.APP_PORT || 3100;
const ROOT = __dirname;
const PUBLIC_DIR   = path.join(ROOT, 'public');
const UPLOAD_DIR   = path.join(PUBLIC_DIR, 'uploads');
const SIMROOT      = path.join(ROOT, 'simroot');
const DOWNLOAD_BASE = path.join(SIMROOT, 'var', 'www', 'downloads');
const VIEW_BASE     = path.join(SIMROOT, 'var', 'www', 'pages');

const JWT_SECRET   = process.env.JWT_SECRET || 'change-me-in-production';
const LAB_JWT_SECRET = 'lab-secret';

fs.mkdirSync(PUBLIC_DIR,   { recursive: true });
fs.mkdirSync(UPLOAD_DIR,   { recursive: true });
fs.mkdirSync(DOWNLOAD_BASE,{ recursive: true });
fs.mkdirSync(VIEW_BASE,    { recursive: true });

// ─── MySQL pool ──────────────────────────────────────────────────────────────
const pool = mysql.createPool({
  host:     process.env.DB_HOST     || '127.0.0.1',
  port:     Number(process.env.DB_PORT) || 3306,
  user:     process.env.DB_USER     || 'vulnlab_user',
  password: process.env.DB_PASSWORD || 'vulnlab_pass',
  database: process.env.DB_NAME     || 'vulnlab',
  waitForConnections: true,
  connectionLimit: 10,
});

// ─── DB helpers ──────────────────────────────────────────────────────────────
async function q(sql, params = []) {
  const [rows] = await pool.execute(sql, params);
  return rows;
}
async function q1(sql, params = []) {
  const rows = await q(sql, params);
  return rows[0] || null;
}

async function getSolvedCount(userId = null) {
  if (userId) {
    const row = await q1('SELECT COUNT(*) as c FROM progress WHERE user_id=? AND solved=1', [userId]);
    return row ? row.c : 0;
  }
  const row = await q1('SELECT COUNT(*) as c FROM progress WHERE solved=1');
  return row ? row.c : 0;
}

async function markSolved(slug, userId = null) {
  if (!userId) return;
  await pool.execute(
    `INSERT INTO progress (user_id, slug, solved, solved_at)
     VALUES (?, ?, 1, NOW())
     ON DUPLICATE KEY UPDATE solved=1, solved_at=NOW()`,
    [userId, slug]
  );
}

// ─── Sim files ───────────────────────────────────────────────────────────────
function initSimFiles() {
  const files = {
    [path.join(SIMROOT, 'etc', 'passwd')]:
      'root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nstudent:x:1000:1000:student:/home/student:/bin/bash\n',
    [path.join(SIMROOT, 'etc', 'shadow')]:
      'root:$6$vulnlab$mockedhash:19732:0:99999:7:::\nwww-data:*:19732:0:99999:7:::\n',
    [path.join(SIMROOT, 'root', '.bash_history')]:
      'cd /usr/local/server/tomcat/webapps\nvi ROOT/WEB-INF/classes/dbinfo.properties\ncat ROOT/WEB-INF/web.xml\n',
    [path.join(SIMROOT, 'usr','local','server','tomcat','webapps','ROOT','WEB-INF','web.xml')]:
      '<web-app>\n  <display-name>VulnLab Finance</display-name>\n  <context-param>classpath:dbinfo.properties</context-param>\n</web-app>\n',
    [path.join(SIMROOT, 'usr','local','server','tomcat','webapps','ROOT','WEB-INF','spring','root-context.xml')]:
      '<beans>\n  <bean id="encryptor" class="org.jasypt.encryption.pbe.StandardPBEStringEncryptor">\n    <property name="algorithm" value="PBEWithMD5AndDES" />\n  </bean>\n</beans>\n',
    [path.join(SIMROOT, 'usr','local','server','tomcat','webapps','ROOT','WEB-INF','classes','dbinfo.properties')]:
      'jdbc.url=jdbc:mysql://127.0.0.1:3306/vulnlab\njdbc.username=root\njdbc.password=vulnlab123!\n',
    [path.join(DOWNLOAD_BASE, 'notice.txt')]:
      '사내 공지: 파일 다운로드 취약점 실습용 파일입니다.\n',
    [path.join(VIEW_BASE, 'welcome.php')]:
      '<?php echo "welcome"; ?>\n',
    [path.join(ROOT, 'flag.txt')]:
      'FLAG{command_injection_chain_success}\n',
  };
  for (const [file, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    if (!fs.existsSync(file)) fs.writeFileSync(file, content, 'utf8');
  }
}
initSimFiles();

// ─── Multer ──────────────────────────────────────────────────────────────────
const upload = multer({
  dest: path.join(ROOT, 'tmp-uploads'),
  fileFilter: (_req, _file, cb) => cb(null, true),
});

// ─── Express middleware ───────────────────────────────────────────────────────
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use('/static', express.static(PUBLIC_DIR));

// ─── Lab definitions (static metadata) ───────────────────────────────────────
const LABS = [
  { slug:'sqli-union',    title:'Union SQL Injection',  cat:'SQLi',  diff:'Easy',   mitre:'T1190',     cwe:'CWE-89',  desc:'LIKE 검색 쿼리에 UNION SELECT를 주입해 members 테이블 값을 추출합니다.' },
  { slug:'sqli-error',    title:'Error-Based SQLi',     cat:'SQLi',  diff:'Medium', mitre:'T1190',     cwe:'CWE-89',  desc:'Oracle 스타일 에러 메시지에 데이터가 포함되도록 유도합니다.' },
  { slug:'sqli-blind',    title:'Blind SQL Injection',  cat:'SQLi',  diff:'Hard',   mitre:'T1190',     cwe:'CWE-89',  desc:'ASCII/SUBSTR 기반 참/거짓 응답으로 비밀값을 추출합니다.' },
  { slug:'xss-reflected', title:'Reflected XSS',        cat:'XSS',   diff:'Easy',   mitre:'T1059.007', cwe:'CWE-79',  desc:'검색어가 그대로 HTML에 반영됩니다.' },
  { slug:'xss-stored',    title:'Stored XSS',           cat:'XSS',   diff:'Medium', mitre:'T1059.007', cwe:'CWE-79',  desc:'게시글이 DB에 저장되고 raw HTML로 렌더링됩니다.' },
  { slug:'xss-dom',       title:'DOM XSS',              cat:'XSS',   diff:'Medium', mitre:'T1059.007', cwe:'CWE-79',  desc:'location.hash 값을 innerHTML에 그대로 삽입합니다.' },
  { slug:'file-upload',   title:'파일 업로드',           cat:'파일',  diff:'Medium', mitre:'T1190',     cwe:'CWE-434', desc:'Content-Type만 신뢰하는 약한 업로드 검증입니다.' },
  { slug:'file-download', title:'파일 다운로드',         cat:'파일',  diff:'Medium', mitre:'T1005',     cwe:'CWE-22',  desc:'파일명 파라미터 조작으로 상위 디렉터리 접근을 시뮬레이션합니다.' },
  { slug:'lfi',           title:'LFI / Path Traversal', cat:'파일',  diff:'Hard',   mitre:'T1005',     cwe:'CWE-98',  desc:'view 파라미터에 경로를 넣어 서버 파일 내용을 확인합니다.' },
  { slug:'ssrf',          title:'SSRF',                 cat:'서버',  diff:'Hard',   mitre:'T1190',     cwe:'CWE-918', desc:'내부 관리자 URL과 메타데이터 엔드포인트를 미러링합니다.' },
  { slug:'session-fixation',title:'세션 고정',           cat:'인증',  diff:'Easy',   mitre:'T1539',     cwe:'CWE-384', desc:'고정 sessionID를 그대로 신뢰하는 로그인 흐름입니다.' },
  { slug:'param-tamper',  title:'파라미터 변조',         cat:'인증',  diff:'Medium', mitre:'T1190',     cwe:'CWE-472', desc:'숨겨진 승인값과 role 값을 서버가 검증하지 않습니다.' },
  { slug:'idor',          title:'IDOR',                 cat:'인증',  diff:'Medium', mitre:'T1190',     cwe:'CWE-639', desc:'id 파라미터만 바꿔 다른 사용자의 정보에 접근합니다.' },
  { slug:'cmd-injection', title:'커맨드 인젝션',         cat:'인젝션',diff:'Medium', mitre:'T1059',     cwe:'CWE-78',  desc:'ping 명령 시뮬레이터에 세미콜론 명령 연결이 가능합니다.' },
  { slug:'xxe',           title:'XXE',                  cat:'인젝션',diff:'Hard',   mitre:'T1005',     cwe:'CWE-611', desc:'외부 엔티티를 통해 파일 내용을 XML 응답에 삽입합니다.' },
  { slug:'jwt',           title:'JWT 취약점',            cat:'인증',  diff:'Hard',   mitre:'T1550.001', cwe:'CWE-347', desc:'약한 secret으로 서명된 JWT를 재서명할 수 있습니다.' },
  { slug:'finance-loan',  title:'대출 파라미터 변조',    cat:'금융',  diff:'Expert', mitre:'T1648',     cwe:'CWE-472', desc:'브라우저 변수를 조작해 승인 조건을 우회합니다.' },
  { slug:'finance-jwt',   title:'금융 JWT 위조',         cat:'금융',  diff:'Expert', mitre:'T1550.001', cwe:'CWE-345', desc:'alg=none 을 허용하는 잘못된 토큰 검증입니다.' },
  { slug:'finance-info',  title:'DB 정보 노출',          cat:'금융',  diff:'Expert', mitre:'T1552',     cwe:'CWE-200', desc:'WEB-INF 설정 파일과 dbinfo.properties를 확인합니다.' },
];

// ─── Auth middleware ──────────────────────────────────────────────────────────
function getUser(req) {
  try {
    const token = req.cookies.auth_token;
    if (!token) return null;
    return jwt.verify(token, JWT_SECRET);
  } catch { return null; }
}

function requireLogin(req, res, next) {
  const user = getUser(req);
  if (!user) return res.redirect('/login?next=' + encodeURIComponent(req.originalUrl));
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  const user = getUser(req);
  if (!user || user.role !== 'admin') {
    return res.status(403).send(adminLayout({ title: '접근 거부', body: '<p style="color:var(--danger)">관리자 권한이 필요합니다. <a href="/login">로그인</a></p>' }));
  }
  req.user = user;
  next();
}

// ─── Template helpers ─────────────────────────────────────────────────────────
function esc(v = '') {
  return String(v)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function renderTable(rows) {
  if (!rows || !rows.length) return '<p>데이터 없음</p>';
  const headers = Object.keys(rows[0]);
  return `<table class="table"><thead><tr>${headers.map(h=>`<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${rows.map(r=>`<tr>${headers.map(h=>`<td>${esc(r[h])}</td>`).join('')}</tr>`).join('')}</tbody></table>`;
}

function navHtml(active, user, labsDb = []) {
  const enabledSlugs = new Set(labsDb.filter(l => l.enabled).map(l => l.slug));
  const visibleLabs = user && user.role === 'admin'
    ? LABS
    : LABS.filter(l => enabledSlugs.has(l.slug));

  const authLinks = user
    ? `<a class="side-link" href="/admin" style="${user.role==='admin'?'color:var(--warning)':'display:none'}">⚙ 관리자</a>
       <a class="side-link" href="/logout">로그아웃 (${esc(user.username)})</a>`
    : `<a class="side-link ${active==='login'?'active':''}" href="/login">로그인</a>`;

  return `
    <aside class="sidebar">
      <div class="brand"><span>⬡</span> VULN0LAB</div>
      <div class="side-section">
        <div class="side-title">Dashboard</div>
        <a class="side-link ${active==='home'?'active':''}" href="/">홈</a>
        <a class="side-link ${active==='mitre'?'active':''}" href="/mitre">MITRE 맵</a>
        <a class="side-link ${active==='db'?'active':''}" href="/db">DB 구조</a>
        <a class="side-link ${active==='setup'?'active':''}" href="/setup">Setup</a>
        ${authLinks}
      </div>
      <div class="side-section">
        <div class="side-title">Labs</div>
        ${visibleLabs.map(l=>`<a class="side-link ${active===l.slug?'active':''}" href="/labs/${l.slug}">${esc(l.title)}</a>`).join('')}
      </div>
    </aside>
  `;
}

function layout({ title, active, intro, body, scripts='', user=null, labsDb=[], solvedCount=0 }) {
  const dbLabel = 'MySQL';
  return `<!doctype html>
<html lang="ko">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${esc(title)} · Vuln0Lab</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="/static/style.css" />
</head>
<body>
  <div class="shell">
    ${navHtml(active, user, labsDb)}
    <main class="content">
      <header class="hero">
        <div>
          <div class="eyebrow">LOCAL TRAINING ONLY</div>
          <h1>${esc(title)}</h1>
          <p>${intro}</p>
        </div>
        <div class="hero-stat-wrap">
          <div class="hero-stat"><strong>${LABS.length}</strong><span>Labs</span></div>
          <div class="hero-stat"><strong>${solvedCount}</strong><span>Solved</span></div>
          <div class="hero-stat"><strong>${dbLabel}</strong><span>DB</span></div>
          ${user ? `<div class="hero-stat"><strong>${esc(user.username)}</strong><span>${esc(user.role)}</span></div>` : ''}
        </div>
      </header>
      ${body}
    </main>
  </div>
  ${scripts}
</body>
</html>`;
}

function labInfoCard(lab, extra='') {
  return `<section class="panel side-info"><div class="eyebrow">${esc(lab.mitre)} · ${esc(lab.cwe)}</div><h2>${esc(lab.title)}</h2><p>${esc(lab.desc)}</p>${extra}</section>`;
}

// ─── Admin layout (separate, no sidebar) ─────────────────────────────────────
function adminLayout({ title, body }) {
  return `<!doctype html>
<html lang="ko">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>${esc(title)} · Vuln0Lab Admin</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="/static/style.css"/>
  <style>
    .admin-wrap{max-width:1200px;margin:0 auto;padding:30px}
    .admin-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:28px;padding-bottom:18px;border-bottom:1px solid var(--border)}
    .admin-title{font-size:1.6rem;font-weight:800;color:var(--accent)}
    .admin-nav a{margin-left:14px;color:var(--muted);font-size:.9rem}
    .admin-nav a:hover{color:var(--text)}
    .toggle-btn{padding:6px 14px;border-radius:10px;border:0;cursor:pointer;font-weight:600;font-size:.82rem}
    .toggle-on{background:rgba(67,240,181,.15);color:var(--accent);border:1px solid rgba(67,240,181,.3)}
    .toggle-off{background:rgba(255,107,125,.1);color:var(--danger);border:1px solid rgba(255,107,125,.25)}
    select.diff-sel{background:#08131d;color:var(--text);border:1px solid var(--border);border-radius:8px;padding:5px 10px;font-size:.82rem}
    .flag-regen{padding:6px 12px;border-radius:10px;border:0;cursor:pointer;background:rgba(92,184,255,.12);color:var(--accent-2);border:1px solid rgba(92,184,255,.2);font-size:.8rem}
    .progress-table th{white-space:nowrap}
    .solved-dot{display:inline-block;width:10px;height:10px;border-radius:50%;background:var(--accent)}
    .unsolved-dot{display:inline-block;width:10px;height:10px;border-radius:50%;background:var(--border)}
  </style>
</head>
<body style="background:var(--bg);color:var(--text)">
<div class="admin-wrap">
  <div class="admin-header">
    <div class="admin-title">⚙ Vuln0Lab Admin</div>
    <div class="admin-nav">
      <a href="/">← 메인</a>
      <a href="/logout">로그아웃</a>
    </div>
  </div>
  ${body}
</div>
</body>
</html>`;
}

// ─── Routes: Login / Logout ───────────────────────────────────────────────────
app.get('/login', (req, res) => {
  const next = esc(req.query.next || '/');
  res.send(`<!doctype html>
<html lang="ko">
<head>
  <meta charset="UTF-8"/><title>로그인 · Vuln0Lab</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="/static/style.css"/>
  <style>
    body{display:flex;align-items:center;justify-content:center;min-height:100vh}
    .login-box{background:var(--panel);border:1px solid var(--border);border-radius:24px;padding:36px;width:100%;max-width:400px}
    .login-title{font-size:1.5rem;font-weight:800;color:var(--accent);margin-bottom:6px}
    .login-sub{color:var(--muted);margin-bottom:24px;font-size:.9rem}
  </style>
</head>
<body>
<div class="login-box">
  <div class="login-title">⬡ VULN0LAB</div>
  <div class="login-sub">로그인하여 실습을 시작하세요.</div>
  ${req.query.err ? `<div class="alert error" style="margin-bottom:16px">${req.query.err === '1' ? '아이디 또는 비밀번호가 틀립니다.' : '오류가 발생했습니다.'}</div>` : ''}
  <form method="post" action="/login" class="stack">
    <input type="hidden" name="next" value="${next}"/>
    <input class="input" type="text" name="username" placeholder="아이디" autofocus/>
    <input class="input" type="password" name="password" placeholder="비밀번호"/>
    <button class="btn">로그인</button>
  </form>
  <p class="muted" style="margin-top:14px;font-size:.82rem">기본 계정: admin / Sk1nFoSec!</p>
</div>
</body>
</html>`);
});

app.post('/login', async (req, res) => {
  const { username, password, next } = req.body;
  const redirectTo = (next && next.startsWith('/') && !next.startsWith('//')) ? next : '/';
  try {
    const user = await q1('SELECT id, username, role FROM members WHERE username=? AND password=?', [username, password]);
    if (!user) return res.redirect('/login?err=1');
    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '8h' });
    res.cookie('auth_token', token, { httpOnly: true, maxAge: 8 * 3600 * 1000 });
    res.redirect(redirectTo);
  } catch (e) {
    console.error(e);
    res.redirect('/login?err=2');
  }
});

app.get('/logout', (req, res) => {
  res.clearCookie('auth_token');
  res.redirect('/login');
});

// ─── Setup page ───────────────────────────────────────────────────────────────
app.get('/setup', (_req, res) => {
  res.send(`<!doctype html>
<html lang="ko">
<head>
  <meta charset="UTF-8"/><title>Setup · Vuln0Lab</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="/static/style.css"/>
  <style>
    body{display:flex;align-items:center;justify-content:center;min-height:100vh}
    .setup-box{background:var(--panel);border:1px solid var(--border);border-radius:24px;padding:36px;width:100%;max-width:560px}
    .setup-title{font-size:1.5rem;font-weight:800;color:var(--accent);margin-bottom:8px}
    .setup-sub{color:var(--muted);margin-bottom:24px;font-size:.9rem;line-height:1.7}
    #result{margin-top:16px;white-space:pre-wrap}
  </style>
</head>
<body>
<div class="setup-box">
  <div class="setup-title">⬡ Vuln0Lab Setup</div>
  <div class="setup-sub">
    아래 버튼을 누르면 <code>setup/init-db.sql</code>의 내용을 실행해<br>
    DB 테이블 생성 및 시드 데이터를 초기화합니다.<br>
    <strong style="color:var(--warning)">주의: 기존 데이터가 초기화될 수 있습니다.</strong>
  </div>
  <div class="stack">
    <button class="btn" id="setup-btn">DB 초기화 실행</button>
    <a class="btn secondary" href="/">메인으로</a>
  </div>
  <pre class="terminal" id="result" style="display:none"></pre>
</div>
<script type="text/javascript">
document.getElementById('setup-btn').addEventListener('click', function() {
  var btn = document.getElementById('setup-btn');
  var result = document.getElementById('result');
  btn.disabled = true;
  btn.textContent = '실행 중...';
  result.style.display = 'block';
  result.textContent = '실행 중...';
  fetch('/setup/run', { method: 'POST' })
    .then(function(resp) { return resp.json(); })
    .then(function(data) {
      result.textContent = data.ok ? '✅ 초기화 완료!\\n' + data.message : '❌ 오류:\\n' + data.error;
      btn.disabled = false;
      btn.textContent = 'DB 초기화 실행';
    })
    .catch(function(e) {
      result.textContent = '❌ 오류: ' + e.message;
      btn.disabled = false;
      btn.textContent = 'DB 초기화 실행';
    });
});
</script>
</body>
</html>`);
});

app.post('/setup/run', async (_req, res) => {
  const sqlPath = path.join(ROOT, 'setup', 'init-db.sql');
  try {
    const sql = fs.readFileSync(sqlPath, 'utf8');
    // Use root connection for setup
    const rootConn = await mysql.createConnection({
      host:     process.env.DB_HOST     || '127.0.0.1',
      port:     Number(process.env.DB_PORT) || 3306,
      user:     'root',
      password: process.env.DB_ROOT_PASSWORD || 'rootpass123',
      multipleStatements: true,
    });
    await rootConn.query(sql);
    await rootConn.end();
    res.json({ ok: true, message: 'DB 초기화 완료. 이제 /login 에서 로그인하세요.' });
  } catch (e) {
    res.json({ ok: false, error: e.message });
  }
});

// ─── Admin page ───────────────────────────────────────────────────────────────
app.get('/admin', requireAdmin, async (req, res) => {
  const labsDb = await q('SELECT * FROM labs ORDER BY id');
  const members = await q('SELECT id, username, role FROM members ORDER BY id');
  const progress = await q(`
    SELECT p.user_id, m.username, p.slug, p.solved, p.solved_at
    FROM progress p JOIN members m ON m.id=p.user_id
    ORDER BY m.username, p.slug
  `);

  // Build progress matrix
  const slugs = labsDb.map(l => l.slug);
  const userMap = {};
  for (const m of members) userMap[m.id] = { username: m.username, solved: {} };
  for (const p of progress) {
    if (userMap[p.user_id]) userMap[p.user_id].solved[p.slug] = p.solved;
  }

  const labRows = labsDb.map(lab => {
    const meta = LABS.find(l => l.slug === lab.slug) || {};
    return `<tr>
      <td><code>${esc(lab.slug)}</code></td>
      <td>${esc(lab.title)}</td>
      <td>${esc(meta.cat || lab.category || '')}</td>
      <td>
        <select class="diff-sel" onchange="changeDiff('${esc(lab.slug)}', this.value)">
          ${['Easy','Medium','Hard','Expert'].map(d=>`<option value="${d}" ${lab.difficulty===d?'selected':''}>${d}</option>`).join('')}
        </select>
      </td>
      <td>
        <button class="toggle-btn ${lab.enabled ? 'toggle-on' : 'toggle-off'}"
          onclick="toggleLab('${esc(lab.slug)}', ${lab.enabled ? 0 : 1}, this)">
          ${lab.enabled ? 'ON' : 'OFF'}
        </button>
      </td>
      <td><code style="font-size:.78rem">${esc(lab.flag || '')}</code></td>
      <td><button class="flag-regen" onclick="regenFlag('${esc(lab.slug)}', this)">재생성</button></td>
    </tr>`;
  }).join('');

  const progressRows = Object.values(userMap).map(u => {
    const cells = slugs.map(s =>
      `<td style="text-align:center">${u.solved[s] ? '<span class="solved-dot" title="Solved"></span>' : '<span class="unsolved-dot"></span>'}</td>`
    ).join('');
    return `<tr><td>${esc(u.username)}</td>${cells}</tr>`;
  }).join('');

  const progressHeaders = slugs.map(s => `<th style="font-size:.7rem;writing-mode:vertical-rl;white-space:nowrap;padding:4px 6px">${esc(s)}</th>`).join('');

  res.send(adminLayout({
    title: '관리자 대시보드',
    body: `
      <section class="panel" style="margin-bottom:20px">
        <h2 style="margin-bottom:16px">Lab 관리</h2>
        <div style="overflow-x:auto">
          <table class="table">
            <thead><tr><th>Slug</th><th>제목</th><th>카테고리</th><th>난이도</th><th>상태</th><th>Flag</th><th>재생성</th></tr></thead>
            <tbody>${labRows}</tbody>
          </table>
        </div>
      </section>
      <section class="panel">
        <h2 style="margin-bottom:16px">사용자별 진도</h2>
        <div style="overflow-x:auto">
          <table class="table progress-table">
            <thead><tr><th>사용자</th>${progressHeaders}</tr></thead>
            <tbody>${progressRows || '<tr><td colspan="99" style="color:var(--muted)">진도 데이터 없음</td></tr>'}</tbody>
          </table>
        </div>
      </section>
      <script>
        async function toggleLab(slug, newVal, btn) {
          const r = await fetch('/admin/api/lab/' + slug + '/toggle', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({enabled: newVal})});
          const d = await r.json();
          if(d.ok){ btn.textContent = newVal ? 'ON' : 'OFF'; btn.className = 'toggle-btn ' + (newVal ? 'toggle-on' : 'toggle-off'); btn.setAttribute('onclick', "toggleLab('" + slug + "', " + (newVal ? 0 : 1) + ", this)"); }
        }
        async function changeDiff(slug, diff) {
          await fetch('/admin/api/lab/' + slug + '/difficulty', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({difficulty: diff})});
        }
        async function regenFlag(slug, btn) {
          btn.disabled = true;
          const r = await fetch('/admin/api/lab/' + slug + '/regen-flag', {method:'POST'});
          const d = await r.json();
          if(d.ok){ btn.closest('tr').querySelector('code').textContent = d.flag; }
          btn.disabled = false;
        }
      </script>
    `
  }));
});

// Admin API
app.post('/admin/api/lab/:slug/toggle', requireAdmin, async (req, res) => {
  const { enabled } = req.body;
  await pool.execute('UPDATE labs SET enabled=? WHERE slug=?', [enabled ? 1 : 0, req.params.slug]);
  res.json({ ok: true });
});

app.post('/admin/api/lab/:slug/difficulty', requireAdmin, async (req, res) => {
  const { difficulty } = req.body;
  if (!['Easy','Medium','Hard','Expert'].includes(difficulty)) return res.json({ ok: false });
  await pool.execute('UPDATE labs SET difficulty=? WHERE slug=?', [difficulty, req.params.slug]);
  res.json({ ok: true });
});

app.post('/admin/api/lab/:slug/regen-flag', requireAdmin, async (req, res) => {
  const newFlag = 'FLAG{' + crypto.randomBytes(8).toString('hex') + '}';
  await pool.execute('UPDATE labs SET flag=? WHERE slug=?', [newFlag, req.params.slug]);
  res.json({ ok: true, flag: newFlag });
});

// ─── Utility: get enabled labs list ──────────────────────────────────────────
async function getLabsDb() {
  try { return await q('SELECT slug, enabled, difficulty, flag FROM labs'); }
  catch { return LABS.map(l => ({ slug: l.slug, enabled: 1, difficulty: l.diff, flag: '' })); }
}

async function checkLabAccess(slug, userRole) {
  try {
    const lab = await q1('SELECT enabled FROM labs WHERE slug=?', [slug]);
    if (!lab) return true; // not in DB yet, allow
    if (!lab.enabled && userRole !== 'admin') return false;
    return true;
  } catch { return true; }
}

// ─── Home ─────────────────────────────────────────────────────────────────────
app.get('/', async (req, res) => {
  const user = getUser(req);
  const labsDb = await getLabsDb();
  const solvedCount = user ? await getSolvedCount(user.id) : 0;

  const visibleLabs = user && user.role === 'admin'
    ? LABS
    : LABS.filter(l => labsDb.find(d => d.slug === l.slug && d.enabled) || !labsDb.find(d => d.slug === l.slug));

  async function cardHtml(lab) {
    const dbLab = labsDb.find(d => d.slug === lab.slug);
    const solved = user ? await q1('SELECT solved FROM progress WHERE user_id=? AND slug=?', [user.id, lab.slug]) : null;
    return `
      <a class="card" href="/labs/${lab.slug}">
        <div class="eyebrow">${esc(dbLab ? dbLab.difficulty : lab.diff)} · ${esc(lab.cat)}</div>
        <h3>${esc(lab.title)}</h3>
        <p>${esc(lab.desc)}</p>
        <div class="meta">
          <span>${esc(lab.mitre)}</span>
          <span>${esc(lab.cwe)}</span>
          <span>${solved && solved.solved ? '✅ Solved' : 'Ready'}</span>
        </div>
      </a>`;
  }

  const grouped = {};
  for (const lab of visibleLabs) {
    if (!grouped[lab.cat]) grouped[lab.cat] = [];
    grouped[lab.cat].push(lab);
  }

  const sectionParts = [];
  for (const [cat, items] of Object.entries(grouped)) {
    const cards = await Promise.all(items.map(cardHtml));
    sectionParts.push(`
      <section class="panel">
        <div class="panel-head"><h2>${esc(cat)}</h2><span>${items.length} labs</span></div>
        <div class="grid">${cards.join('')}</div>
      </section>`);
  }

  res.send(layout({
    title: '웹 취약점 실습 플랫폼', active: 'home', user, labsDb, solvedCount,
    intro: 'DVWA처럼 바로 만져볼 수 있는 로컬 전용 실습 앱입니다. SQLi, XSS, SSRF, 파일 업로드/다운로드, 세션 고정, 파라미터 변조, 금융권 시나리오까지 포함합니다.',
    body: `
      <section class="panel notice">
        <div>
          <h2>포함된 기능</h2>
          <p>각 랩은 실제 입력 필드와 서버 동작이 연결되어 있고, 성공하면 플래그가 출력됩니다. DB는 MySQL을 사용하며 /setup 페이지에서 초기화할 수 있습니다.</p>
        </div>
        <div class="badge-list">
          <span>Union / Error / Blind SQLi</span>
          <span>Reflected / Stored / DOM XSS</span>
          <span>SSRF / LFI / Download</span>
          <span>Session / JWT / IDOR</span>
          <span>Finance Attack Sim</span>
        </div>
      </section>
      ${sectionParts.join('')}
    `
  }));
});

app.get('/mitre', async (req, res) => {
  const user = getUser(req);
  const labsDb = await getLabsDb();
  const solvedCount = user ? await getSolvedCount(user.id) : 0;
  const rows = LABS.map(l=>`<tr><td>${esc(l.title)}</td><td>${esc(l.mitre)}</td><td>${esc(l.cwe)}</td><td>${esc(l.desc)}</td></tr>`).join('');
  res.send(layout({
    title:'MITRE ATT&CK 매핑', active:'mitre', user, labsDb, solvedCount,
    intro:'웹 취약점 랩을 ATT&CK Technique와 CWE로 연결했습니다.',
    body:`<section class="panel"><table class="table"><thead><tr><th>랩</th><th>MITRE</th><th>CWE</th><th>설명</th></tr></thead><tbody>${rows}</tbody></table></section>`
  }));
});

app.get('/db', async (req, res) => {
  const user = getUser(req);
  const labsDb = await getLabsDb();
  const solvedCount = user ? await getSolvedCount(user.id) : 0;
  let members = [], properties = [];
  try {
    members    = await q('SELECT id, username, role, salary, email FROM members');
    properties = await q('SELECT id, district, price, note FROM properties');
  } catch(e) {
    return res.send(layout({ title:'DB 구조', active:'db', user, labsDb, solvedCount, intro:'DB 연결 필요', body:`<div class="alert error">DB 연결 오류: ${esc(e.message)}. /setup 에서 초기화하세요.</div>` }));
  }
  res.send(layout({
    title:'DB 구조와 시드 데이터', active:'db', user, labsDb, solvedCount,
    intro:'실습용 DB는 MySQL로 동작합니다. members, properties, comments, labs, progress 테이블로 구성됩니다.',
    body:`
      <section class="panel two-col">
        <div>
          <h2>스키마</h2>
          <pre class="code">members(id, username, password, role, salary, email, flag)
properties(id, district, price, note)
comments(id, author, message, created_at)
labs(id, slug, title, category, difficulty, enabled, flag)
progress(id, user_id, slug, solved, solved_at)</pre>
        </div>
        <div>
          <h2>운영 포인트</h2>
          <ul class="list">
            <li>SQLi / IDOR / 금융 시나리오는 members, properties를 재사용</li>
            <li>Stored XSS는 comments 테이블에 raw HTML 저장</li>
            <li>플래그 달성 여부는 progress 테이블로 추적 (사용자별)</li>
            <li>파일 취약점은 DB 대신 simroot 디렉터리로 안전하게 흉내냄</li>
          </ul>
        </div>
      </section>
      <section class="panel"><h2>members 샘플</h2>${renderTable(members)}</section>
      <section class="panel"><h2>properties 샘플</h2>${renderTable(properties)}</section>
    `
  }));
});

// ─── Lab route dispatcher ────────────────────────────────────────────────────
app.get('/labs/:slug', requireLogin, async (req, res) => {
  const lab = LABS.find(x => x.slug === req.params.slug);
  if (!lab) return res.status(404).send('Not found');

  const allowed = await checkLabAccess(lab.slug, req.user.role);
  if (!allowed) return res.status(403).send(layout({
    title:'접근 불가', active:'', user:req.user, labsDb:await getLabsDb(), solvedCount:0,
    intro:'',
    body:`<div class="alert error">이 Lab은 현재 비활성화되어 있습니다.</div>`
  }));

  const handlers = {
    'sqli-union':       unionPage,
    'sqli-error':       errorSqliPage,
    'sqli-blind':       blindPage,
    'xss-reflected':    reflectedXssPage,
    'xss-stored':       storedXssPage,
    'xss-dom':          domXssPage,
    'file-upload':      fileUploadPage,
    'file-download':    fileDownloadPage,
    'lfi':              lfiPage,
    'ssrf':             ssrfPage,
    'session-fixation': sessionFixationPage,
    'param-tamper':     paramTamperPage,
    'idor':             idorPage,
    'cmd-injection':    cmdInjectionPage,
    'xxe':              xxePage,
    'jwt':              jwtPage,
    'finance-loan':     financeLoanPage,
    'finance-jwt':      financeJwtPage,
    'finance-info':     financeInfoPage,
  };
  res.send(await handlers[lab.slug](lab, req));
});

// ─── SQLi Union ──────────────────────────────────────────────────────────────
app.post('/labs/sqli-union/search', requireLogin, async (req, res) => {
  const qStr = req.body.q || '';
  let rows = [], error = '', sql = `SELECT id, district, price FROM properties WHERE district LIKE '%${qStr}%'`;
  try {
    const conn = await pool.getConnection();
    try {
      const [result] = await conn.query(sql);
      rows = result;
      if (/UNION\s+SELECT/i.test(qStr)) await markSolved('sqli-union', req.user.id);
    } finally { conn.release(); }
  } catch(e) { error = e.message; }
  res.send(await unionPage(LABS.find(l=>l.slug==='sqli-union'), req, { q:qStr, sql, rows, error }));
});

// ─── SQLi Error ───────────────────────────────────────────────────────────────
app.post('/labs/sqli-error/execute', requireLogin, async (req, res) => {
  const payload = req.body.payload || '';
  let result = '정상 결과 없음';
  const firstPassword = (await q1("SELECT password FROM members WHERE username='admin'"))?.password || '';
  if (/COUNT\(TABLE_NAME\)/i.test(payload)) result = 'java.sql.SQLSyntaxErrorException: ORA-20000: 4';
  else if (/TABLE_NAME/i.test(payload) && /RNUM\s*=\s*1/i.test(payload)) result = 'java.sql.SQLSyntaxErrorException: ORA-20000: LHSMEMBER3';
  else if (/COUNT\(COLUMN_NAME\)/i.test(payload)) result = 'java.sql.SQLSyntaxErrorException: ORA-20000: 6';
  else if (/PASSWORD/i.test(payload)) {
    result = `java.sql.SQLSyntaxErrorException: ORA-20000: ${firstPassword}`;
    await markSolved('sqli-error', req.user.id);
  }
  res.send(await errorSqliPage(LABS.find(l=>l.slug==='sqli-error'), req, { payload, result }));
});

// ─── SQLi Blind ───────────────────────────────────────────────────────────────
app.post('/labs/sqli-blind/check', requireLogin, async (req, res) => {
  const payload = req.body.payload || '';
  const row = await q1("SELECT password FROM members WHERE username='nohsy'");
  const secret = row?.password || '';
  let response = '검색 결과 없음';
  const regex = /ASCII\s*\(\s*SUBSTR\s*\(.*?,\s*(\d+)\s*,\s*1\s*\)\s*\)\s*([><=])\s*(\d+)/i;
  const match = payload.match(regex);
  if (match) {
    const index = Number(match[1]) - 1;
    const op = match[2], guess = Number(match[3]);
    const charCode = secret[index] ? secret.charCodeAt(index) : 0;
    const ok = op==='>'?charCode>guess:op==='<'?charCode<guess:charCode===guess;
    response = ok ? '검색 결과 1건' : '검색 결과 없음';
    if (ok && index === 0) await markSolved('sqli-blind', req.user.id);
  }
  res.send(await blindPage(LABS.find(l=>l.slug==='sqli-blind'), req, { payload, response, secretHint: secret.length }));
});

// ─── XSS Reflected ───────────────────────────────────────────────────────────
app.get('/labs/xss-reflected', requireLogin, async (req, res) => {
  const qStr = req.query.q || '';
  if (qStr.includes('<script>') || qStr.includes('onerror=')) await markSolved('xss-reflected', req.user.id);
  res.send(await reflectedXssPage(LABS.find(l=>l.slug==='xss-reflected'), req, { q: qStr }));
});

// ─── XSS Stored ───────────────────────────────────────────────────────────────
app.post('/labs/xss-stored/comment', requireLogin, async (req, res) => {
  const author = req.body.author || 'anonymous';
  const message = req.body.message || '';
  await pool.execute('INSERT INTO comments (author, message) VALUES (?, ?)', [author, message]);
  if (/<script|onerror=|onload=/i.test(message)) await markSolved('xss-stored', req.user.id);
  res.redirect('/labs/xss-stored');
});

// ─── File Upload ──────────────────────────────────────────────────────────────
app.post('/labs/file-upload', requireLogin, upload.single('sample'), async (req, res) => {
  let notice = '파일이 없습니다.';
  if (req.file) {
    const newName = `${Date.now()}-${sanitizeFilename(req.file.originalname || 'upload.bin')}`;
    const target = path.join(UPLOAD_DIR, newName);
    fs.renameSync(req.file.path, target);
    notice = `업로드 완료: /static/uploads/${newName} (mime=${req.file.mimetype})`;
    if (/php|octet-stream|x-php/i.test(req.file.mimetype + ' ' + req.file.originalname)) await markSolved('file-upload', req.user.id);
  }
  res.send(await fileUploadPage(LABS.find(l=>l.slug==='file-upload'), req, { notice }));
});

// ─── File Download ────────────────────────────────────────────────────────────
app.get('/labs/file-download/fetch', requireLogin, async (req, res) => {
  const file = req.query.file || 'notice.txt';
  const resolved = path.resolve(DOWNLOAD_BASE, file);
  if (fs.existsSync(resolved)) {
    if (file.includes('..')) await markSolved('file-download', req.user.id);
    return res.type('text/plain').send(fs.readFileSync(resolved, 'utf8'));
  }
  res.status(404).send('파일을 찾지 못했습니다.');
});

// ─── LFI ──────────────────────────────────────────────────────────────────────
app.get('/labs/lfi/view', requireLogin, async (req, res) => {
  const file = req.query.file || 'welcome.php';
  const resolved = path.resolve(VIEW_BASE, file);
  if (fs.existsSync(resolved)) {
    if (file.includes('..')) await markSolved('lfi', req.user.id);
    return res.type('text/plain').send(fs.readFileSync(resolved, 'utf8'));
  }
  res.status(404).send('페이지를 찾을 수 없습니다.');
});

// ─── SSRF ─────────────────────────────────────────────────────────────────────
function ssrfFetch(url) {
  const map = {
    'http://public.lab/': '<html><body><h1>Public landing page</h1><!-- admin: http://internal.lab/admin --></body></html>',
    'http://internal.lab/admin': '<html><body>admin panel<!-- creds: adminID=skinfosec_admin / adminPW=internal_pw_2025 --></body></html>',
    'http://internal.lab/admin?login_id=skinfosec_admin&login_pwd=internal_pw_2025': 'FLAG{ssrf_internal_admin_success}',
    'http://169.254.169.254/latest/meta-data/iam/security-credentials/': 'mock-role: vulnlab-ssrf-role',
  };
  return map[url] || 'Preview unavailable';
}

app.post('/labs/ssrf/preview', requireLogin, async (req, res) => {
  const target = req.body.target || '';
  const preview = ssrfFetch(target);
  if (preview.includes('FLAG{')) await markSolved('ssrf', req.user.id);
  res.send(await ssrfPage(LABS.find(l=>l.slug==='ssrf'), req, { target, preview }));
});

// ─── Session Fixation ─────────────────────────────────────────────────────────
app.get('/labs/session-fixation/login', requireLogin, (req, res) => {
  const incoming = req.query.sessionId;
  if (incoming) res.cookie('lab_session', incoming, { httpOnly: false });
  res.redirect('/labs/session-fixation');
});

app.get('/labs/session-fixation', requireLogin, async (req, res) => {
  const sid = req.cookies.lab_session || 'guest-session';
  const user = await q1('SELECT username, flag FROM members WHERE username=?', [sid]);
  if (sid === 'eqst001004') await markSolved('session-fixation', req.user.id);
  res.send(await sessionFixationPage(LABS.find(l=>l.slug==='session-fixation'), req, { sid, user }));
});

// ─── Param Tamper ─────────────────────────────────────────────────────────────
app.post('/labs/param-tamper/submit', requireLogin, async (req, res) => {
  const { username, result: res_, role } = req.body;
  let msg = '검증 실패';
  if (res_ === 'Y' || role === 'admin') {
    await markSolved('param-tamper', req.user.id);
    msg = '승인 완료 · FLAG{parameter_tampering_success}';
  }
  res.send(await paramTamperPage(LABS.find(l=>l.slug==='param-tamper'), req, { username, result: res_, role, msg }));
});

// ─── IDOR ─────────────────────────────────────────────────────────────────────
app.get('/labs/idor/api/profile', requireLogin, async (req, res) => {
  const id = Number(req.query.id || 1);
  const user = await q1('SELECT id, username, role, salary, email, flag FROM members WHERE id=?', [id]);
  if (!user) return res.status(404).json({ error: 'not found' });
  if (id !== 1) await markSolved('idor', req.user.id);
  res.json(user);
});

// ─── Cmd Injection ────────────────────────────────────────────────────────────
app.post('/labs/cmd-injection/run', requireLogin, async (req, res) => {
  const host = req.body.host || '127.0.0.1';
  let output = `PING ${host}\n64 bytes from ${host}: icmp_seq=1 ttl=64`;
  if (/;|&&|\|/i.test(host)) {
    if (/cat\s+flag\.txt/i.test(host)) {
      output += '\n' + fs.readFileSync(path.join(ROOT, 'flag.txt'), 'utf8').trim();
      await markSolved('cmd-injection', req.user.id);
    } else if (/cat\s+\/etc\/passwd/i.test(host)) {
      output += '\n' + fs.readFileSync(path.join(SIMROOT, 'etc', 'passwd'), 'utf8');
    }
  }
  res.send(await cmdInjectionPage(LABS.find(l=>l.slug==='cmd-injection'), req, { host, output }));
});

// ─── XXE ──────────────────────────────────────────────────────────────────────
app.post('/labs/xxe/parse', requireLogin, async (req, res) => {
  const xml = req.body.xml || '';
  let result = '<result>parsed</result>';
  const match = xml.match(/SYSTEM\s+["']file:\/\/(.+?)["']/i);
  if (match) {
    const wanted = match[1].replace(/^\//, '');
    const file = path.join(SIMROOT, wanted);
    if (fs.existsSync(file)) {
      result = `<result>${esc(fs.readFileSync(file, 'utf8'))}</result>`;
      await markSolved('xxe', req.user.id);
    }
  }
  res.send(await xxePage(LABS.find(l=>l.slug==='xxe'), req, { xml, result }));
});

// ─── JWT Lab ──────────────────────────────────────────────────────────────────
app.get('/labs/jwt/token', requireLogin, async (req, res) => {
  const token = jwt.sign({ sub:'user-201', role:'customer', scope:['loan:read'] }, LAB_JWT_SECRET, { expiresIn:'7d' });
  res.send(await jwtPage(LABS.find(l=>l.slug==='jwt'), req, { issued: token }));
});

app.post('/labs/jwt/verify', requireLogin, async (req, res) => {
  const token = req.body.token || '';
  let decoded, result = '검증 실패';
  try {
    decoded = jwt.verify(token, LAB_JWT_SECRET);
    result = decoded.role === 'admin' ? 'FLAG{jwt_role_escalation_success}' : '유효하지만 admin 아님';
    if (decoded.role === 'admin') await markSolved('jwt', req.user.id);
  } catch(e) { result = e.message; }
  res.send(await jwtPage(LABS.find(l=>l.slug==='jwt'), req, { token, decoded, result }));
});

// ─── Finance Loan ─────────────────────────────────────────────────────────────
app.post('/labs/finance-loan/apply', requireLogin, async (req, res) => {
  const { amount, interest, maturity, approved } = req.body;
  let result = '대출 거절';
  if (approved === 'Y' || Number(interest) >= 5000) {
    result = '승인 완료 · FLAG{finance_interest_manipulated}';
    await markSolved('finance-loan', req.user.id);
  }
  res.send(await financeLoanPage(LABS.find(l=>l.slug==='finance-loan'), req, { amount, interest, maturity, approved, result }));
});

// ─── Finance JWT ──────────────────────────────────────────────────────────────
function decodeNoneJwt(token) {
  const [h, p] = token.split('.');
  const header  = JSON.parse(Buffer.from(h, 'base64url').toString('utf8'));
  const payload = JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
  return { header, payload };
}

app.get('/labs/finance-jwt/token', requireLogin, async (req, res) => {
  const header  = Buffer.from(JSON.stringify({ alg:'HS256', typ:'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({ sub:'cust-77', role:'viewer', branch:'seoul' })).toString('base64url');
  const sig     = Buffer.from('fake-signature').toString('base64url');
  res.send(await financeJwtPage(LABS.find(l=>l.slug==='finance-jwt'), req, { issued:`${header}.${payload}.${sig}` }));
});

app.post('/labs/finance-jwt/verify', requireLogin, async (req, res) => {
  const token = req.body.token || '';
  let result = '거절', decoded = null;
  try {
    decoded = decodeNoneJwt(token);
    if (decoded.header.alg === 'none' && decoded.payload.role === 'auditor') {
      result = 'FLAG{finance_alg_none_bypass}';
      await markSolved('finance-jwt', req.user.id);
    } else { result = '토큰은 파싱되었지만 auditor 아님'; }
  } catch(e) { result = e.message; }
  res.send(await financeJwtPage(LABS.find(l=>l.slug==='finance-jwt'), req, { token, decoded, result }));
});

// ─── Finance Info ─────────────────────────────────────────────────────────────
app.get('/labs/finance-info/fetch', requireLogin, async (req, res) => {
  const file = req.query.path || '/WEB-INF/web.xml';
  const clean = file.replace(/^\//, '');
  const rootBase = path.join(SIMROOT, 'usr','local','server','tomcat','webapps','ROOT');
  const resolved = path.resolve(rootBase, clean);
  if (fs.existsSync(resolved)) {
    if (file.includes('dbinfo.properties')) await markSolved('finance-info', req.user.id);
    return res.type('text/plain').send(fs.readFileSync(resolved, 'utf8'));
  }
  res.status(404).send('not found');
});

// ─── Page renderers (async for context) ──────────────────────────────────────
async function getCtx(req) {
  const user = req.user || null;
  const labsDb = await getLabsDb();
  const solvedCount = user ? await getSolvedCount(user.id) : 0;
  return { user, labsDb, solvedCount };
}

async function unionPage(lab, req, data = {}) {
  const ctx = await getCtx(req);
  const rows = data.rows || [];
  return layout({ ...ctx, title: lab.title, active: lab.slug,
    intro: 'properties 검색창에 입력한 문자열이 LIKE 절로 그대로 이어집니다. 3개 컬럼(id, district, price)에 맞춰 UNION SELECT를 시도하면 members 데이터가 보입니다.',
    body: `
      <div class="lab-grid">
        <section class="panel">
          <h2>검색 대상</h2>
          <p>예시 페이로드: <code>영등포%' ORDER BY 4 -- </code> 또는 <code>영등포%' UNION SELECT id, username, password FROM members -- </code></p>
          <form method="post" action="/labs/sqli-union/search" class="stack">
            <input class="input" name="q" value="${esc(data.q||'')}" placeholder="영등포동" />
            <button class="btn">실행</button>
          </form>
          <pre class="code">${esc(data.sql||"SELECT id, district, price FROM properties WHERE district LIKE '%...%'")}</pre>
          ${data.error?`<div class="alert error">${esc(data.error)}</div>`:''}
          ${rows.length?renderTable(rows):'<p class="muted">결과가 여기에 표시됩니다.</p>'}
        </section>
        ${labInfoCard(lab,'<ul class="list"><li>컬럼 수는 3개</li><li>첫 컬럼 숫자, 나머지 문자열/숫자 혼합 가능</li><li>members 테이블의 admin 계정 플래그를 노리면 됩니다.</li></ul>')}
      </div>`
  });
}

async function errorSqliPage(lab, req, data = {}) {
  const ctx = await getCtx(req);
  return layout({ ...ctx, title: lab.title, active: lab.slug,
    intro: '과제 PDF의 Oracle 스타일 실습을 따라갈 수 있게 CTXSYS.DRITHSX.SN 기반 페이로드를 흉내내는 에러 리플렉터를 넣었습니다.',
    body: `
      <div class="lab-grid">
        <section class="panel">
          <p>예시: <code>영등포동8%' AND CTXSYS.DRITHSX.SN(user,(SELECT COUNT(TABLE_NAME) FROM USER_TABLES))=1--</code></p>
          <form method="post" action="/labs/sqli-error/execute" class="stack">
            <textarea class="input textarea" name="payload">${esc(data.payload||'')}</textarea>
            <button class="btn">에러 유도</button>
          </form>
          <pre class="terminal">${esc(data.result||'java.sql.SQLSyntaxErrorException: ORA-01756: quoted string not properly terminated')}</pre>
        </section>
        ${labInfoCard(lab,'<ul class="list"><li>COUNT(TABLE_NAME) → 테이블 수</li><li>RNUM=1 → 첫 테이블명</li><li>PASSWORD 키워드 포함 시 admin 비밀번호 노출</li></ul>')}
      </div>`
  });
}

async function blindPage(lab, req, data = {}) {
  const ctx = await getCtx(req);
  return layout({ ...ctx, title: lab.title, active: lab.slug,
    intro: '결과가 직접 보이지 않는 대신 참이면 검색 결과 1건, 거짓이면 결과 없음만 보여줍니다. ASCII/SUBSTR 패턴을 해석합니다.',
    body: `
      <div class="lab-grid">
        <section class="panel">
          <p>예시: <code>역촌동%' AND ASCII(SUBSTR((SELECT password FROM members WHERE username='nohsy'),1,1)) > 100 -- </code></p>
          <form method="post" action="/labs/sqli-blind/check" class="stack">
            <textarea class="input textarea" name="payload">${esc(data.payload||'')}</textarea>
            <button class="btn">조건 확인</button>
          </form>
          <div class="alert">응답: ${esc(data.response||'검색 결과 없음')}</div>
          <p class="muted">힌트: 비밀값 길이는 ${data.secretHint||15}자입니다.</p>
        </section>
        ${labInfoCard(lab,'<ul class="list"><li>비밀값은 members.username=nohsy의 password</li><li>첫 글자만 맞춰도 solved 처리</li><li>연습 후에는 반복문 스크립트로 확장 가능</li></ul>')}
      </div>`
  });
}

async function reflectedXssPage(lab, req, data = {}) {
  const ctx = await getCtx(req);
  return layout({ ...ctx, title: lab.title, active: lab.slug,
    intro: 'GET 파라미터 q가 서버 템플릿에 escaping 없이 삽입됩니다. 브라우저에서 alert가 실행되면 성공입니다.',
    body: `
      <div class="lab-grid">
        <section class="panel">
          <form method="get" action="/labs/xss-reflected" class="stack">
            <input class="input" name="q" value="${esc(data.q||'')}" placeholder='"><script>alert("XSS")</script>' />
            <button class="btn">검색</button>
          </form>
          <div class="result-box">
            <div>검색 결과</div>
            <div class="raw-box"><strong><span>Query:</span></strong> <span>${data.q||'입력 없음'}</span></div>
          </div>
        </section>
        ${labInfoCard(lab,'<ul class="list"><li>payload 예시 그대로 사용 가능</li><li>URL 공유형 실습</li><li>성공 시 solved 체크</li></ul>')}
      </div>`
  });
}

async function storedXssPage(lab, req) {
  const ctx = await getCtx(req);
  const comments = await q('SELECT id, author, message, created_at FROM comments ORDER BY id DESC LIMIT 20');
  return layout({ ...ctx, title: lab.title, active: lab.slug,
    intro: '게시글이 sanitize 없이 comments 테이블에 저장되고, 출력 시에도 raw HTML로 렌더링됩니다.',
    body: `
      <div class="lab-grid">
        <section class="panel">
          <form method="post" action="/labs/xss-stored/comment" class="stack">
            <input class="input" name="author" placeholder="작성자" />
            <textarea class="input textarea" name="message" placeholder="<img src=x onerror=alert('stored')>"></textarea>
            <button class="btn">저장</button>
          </form>
          <div class="comment-list">
            ${comments.map(c=>`<article class="comment"><div class="comment-head">${esc(c.author)} · ${esc(String(c.created_at||''))}</div><div class="comment-body">${c.message}</div></article>`).join('')}
          </div>
        </section>
        ${labInfoCard(lab,'<ul class="list"><li>메시지는 raw HTML로 출력됨</li><li>관리자나 다른 사용자가 방문할 때 재실행 가능</li><li>DB 삭제 없이 지속됨</li></ul>')}
      </div>`
  });
}

async function domXssPage(lab, req) {
  const ctx = await getCtx(req);
  return layout({ ...ctx, title: lab.title, active: lab.slug,
    intro: '서버가 아니라 클라이언트 JavaScript가 location.hash를 innerHTML에 삽입합니다. 주소 뒤에 #payload 를 넣어서 확인하세요.',
    body: `
      <div class="lab-grid">
        <section class="panel">
          <p>예시: <code>/labs/xss-dom#&lt;img src=x onerror=alert('dom')&gt;</code></p>
          <div class="result-box"><div id="dom-output">해시값 대기 중</div></div>
        </section>
        ${labInfoCard(lab,'<ul class="list"><li>innerHTML 사용</li><li>document.location.hash 기반</li><li>서버 로그에는 남지 않음</li></ul>')}
      </div>`,
    scripts:`<script>
      const hash = decodeURIComponent(location.hash.slice(1));
      const out = document.getElementById('dom-output');
      out.innerHTML = hash || '해시값 대기 중';
      if (hash.includes('onerror') || hash.includes('<script')) fetch('/labs/xss-reflected?q=domSolved').catch(()=>{});
    </script>`
  });
}

async function fileUploadPage(lab, req, data = {}) {
  const ctx = await getCtx(req);
  const files = fs.readdirSync(UPLOAD_DIR).slice(-20).reverse();
  return layout({ ...ctx, title: lab.title, active: lab.slug,
    intro: '브라우저/프록시에서 Content-Type만 바꿔도 통과되는 약한 업로드 검증입니다. 업로드된 파일은 그대로 정적 경로에 공개됩니다.',
    body: `
      <div class="lab-grid">
        <section class="panel">
          <form method="post" action="/labs/file-upload" enctype="multipart/form-data" class="stack">
            <input class="input" type="file" name="sample" />
            <button class="btn">업로드</button>
          </form>
          ${data.notice?`<div class="alert">${esc(data.notice)}</div>`:''}
          <h3>업로드 파일</h3>
          <ul class="list">${files.map(f=>`<li><a href="/static/uploads/${encodeURIComponent(f)}" target="_blank">${esc(f)}</a></li>`).join('')||'<li>없음</li>'}</ul>
        </section>
        ${labInfoCard(lab,'<ul class="list"><li>mimetype과 확장자를 모두 바꿔보세요</li><li>저장 경로는 public/uploads</li><li>로컬 실습용이므로 외부 노출 금지</li></ul>')}
      </div>`
  });
}

async function fileDownloadPage(lab, req) {
  const ctx = await getCtx(req);
  return layout({ ...ctx, title: lab.title, active: lab.slug,
    intro: '파일명 파라미터를 그대로 path.resolve에 넘깁니다. notice.txt에서 시작해 ../ 로 simroot 내부 민감 파일을 찾아보세요.',
    body: `
      <div class="lab-grid">
        <section class="panel">
          <form method="get" action="/labs/file-download/fetch" class="stack">
            <input class="input" name="file" value="notice.txt" />
            <button class="btn">다운로드</button>
          </form>
          <p class="muted">추천 경로: <code>../../etc/passwd</code> 또는 <code>../../root/.bash_history</code></p>
        </section>
        ${labInfoCard(lab,'<ul class="list"><li>실제 OS 대신 simroot 내부 가짜 파일만 제공</li><li>.bash_history 에 다음 힌트 존재</li><li>download 실습 후 finance-info 로 연결 가능</li></ul>')}
      </div>`
  });
}

async function lfiPage(lab, req) {
  const ctx = await getCtx(req);
  return layout({ ...ctx, title: lab.title, active: lab.slug,
    intro: 'view 파라미터를 통해 파일 내용을 화면에 그대로 표시합니다. welcome.php 외의 상위 파일도 열어보세요.',
    body: `
      <div class="lab-grid">
        <section class="panel">
          <form method="get" action="/labs/lfi/view" class="stack">
            <input class="input" name="file" value="welcome.php" />
            <button class="btn">열기</button>
          </form>
          <p class="muted">추천 경로: <code>../../etc/passwd</code></p>
        </section>
        ${labInfoCard(lab,'<ul class="list"><li>다운로드가 아니라 내용 직접 확인형</li><li>PHP/JSP 소스 열람 시나리오로 활용</li><li>Path Traversal과 함께 설명 가능</li></ul>')}
      </div>`
  });
}

async function ssrfPage(lab, req, data = {}) {
  const ctx = await getCtx(req);
  return layout({ ...ctx, title: lab.title, active: lab.slug,
    intro: '외부 URL 미리보기 기능이 사실상 내부 URL도 그대로 가져옵니다. 소스 주석 → 내부 관리자 URL → 로그인 파라미터 순으로 이어지는 과제 흐름을 재현했습니다.',
    body: `
      <div class="lab-grid">
        <section class="panel">
          <form method="post" action="/labs/ssrf/preview" class="stack">
            <input class="input" name="target" value="${esc(data.target||'http://public.lab/')}" />
            <button class="btn">미리보기</button>
          </form>
          <pre class="terminal">${esc(data.preview||'')}</pre>
          <p class="muted">추천 흐름: public.lab → internal.lab/admin → internal.lab/admin?login_id=...&login_pwd=...</p>
        </section>
        ${labInfoCard(lab,'<ul class="list"><li>실제 외부 통신 없음</li><li>내부 관리자 페이지와 메타데이터 엔드포인트만 모킹</li><li>자격증명은 주석에 숨어 있음</li></ul>')}
      </div>`
  });
}

async function sessionFixationPage(lab, req, data = {}) {
  const ctx = await getCtx(req);
  return layout({ ...ctx, title: lab.title, active: lab.slug,
    intro: '로그인 전에 심어진 sessionId를 서버가 그대로 신뢰합니다. 피해자 세션값 eqst001004 를 쿠키에 넣으면 플래그가 노출됩니다.',
    body: `
      <div class="lab-grid">
        <section class="panel">
          <p><a class="btn secondary" href="/labs/session-fixation/login?sessionId=eqst001004">취약한 로그인 링크로 이동</a></p>
          <div class="alert">현재 sessionID: ${esc(data.sid||'guest-session')}</div>
          ${data.user?`<div class="alert success">로그인 사용자: ${esc(data.user.username)} · ${esc(data.user.flag)}</div>`:'<div class="alert">게스트 상태</div>'}
        </section>
        ${labInfoCard(lab,'<ul class="list"><li>쿠키 이름: lab_session</li><li>고정 세션을 재사용</li><li>수동으로 브라우저 쿠키를 편집해도 동일</li></ul>')}
      </div>`
  });
}

async function paramTamperPage(lab, req, data = {}) {
  const ctx = await getCtx(req);
  return layout({ ...ctx, title: lab.title, active: lab.slug,
    intro: '브라우저 개발자도구나 프록시로 hidden input을 수정하면 서버가 그대로 승인해버립니다.',
    body: `
      <div class="lab-grid">
        <section class="panel">
          <form method="post" action="/labs/param-tamper/submit" class="stack">
            <input class="input" name="username" value="${esc(data.username||'guest01')}" />
            <input class="input" name="result" value="${esc(data.result||'N')}" />
            <input class="input" name="role" value="${esc(data.role||'user')}" />
            <button class="btn">제출</button>
          </form>
          ${data.msg?`<div class="alert success">${esc(data.msg)}</div>`:'<p class="muted">result=Y 또는 role=admin 으로 변경해보세요.</p>'}
        </section>
        ${labInfoCard(lab,'<ul class="list"><li>클라이언트 값 신뢰 금지 사례</li><li>버프/리피터 실습에 적합</li><li>금융권 승인 시나리오의 축소판</li></ul>')}
      </div>`
  });
}

async function idorPage(lab, req) {
  const ctx = await getCtx(req);
  return layout({ ...ctx, title: lab.title, active: lab.slug,
    intro: '현재 로그인 여부와 무관하게 id만 알면 다른 사용자 JSON을 볼 수 있습니다. API 응답으로 바로 확인됩니다.',
    body: `
      <div class="lab-grid">
        <section class="panel">
          <form method="get" action="/labs/idor/api/profile" class="stack" target="_blank">
            <input class="input" name="id" value="1" />
            <button class="btn">프로필 조회</button>
          </form>
          <p class="muted">id=2 또는 4 로 바꾸면 다른 사용자 정보와 플래그가 노출됩니다.</p>
        </section>
        ${labInfoCard(lab,'<ul class="list"><li>수평 권한 상승 예제</li><li>REST/JSON API 데모</li><li>salary, email, flag 까지 노출</li></ul>')}
      </div>`
  });
}

async function cmdInjectionPage(lab, req, data = {}) {
  const ctx = await getCtx(req);
  return layout({ ...ctx, title: lab.title, active: lab.slug,
    intro: '실제 명령을 실행하지는 않지만, 세미콜론 뒤 명령을 해석하는 모의 쉘을 넣어 커맨드 체이닝 흐름을 연습할 수 있습니다.',
    body: `
      <div class="lab-grid">
        <section class="panel">
          <form method="post" action="/labs/cmd-injection/run" class="stack">
            <input class="input" name="host" value="${esc(data.host||'127.0.0.1')}" placeholder="127.0.0.1; cat flag.txt" />
            <button class="btn">ping</button>
          </form>
          <pre class="terminal">${esc(data.output||'PING 127.0.0.1')}</pre>
        </section>
        ${labInfoCard(lab,'<ul class="list"><li>추천 payload: 127.0.0.1; cat flag.txt</li><li>또는 /etc/passwd 모의 파일 열람</li><li>운영체제 명령 연결 패턴 학습용</li></ul>')}
      </div>`
  });
}

async function xxePage(lab, req, data = {}) {
  const ctx = await getCtx(req);
  return layout({ ...ctx, title: lab.title, active: lab.slug,
    intro: 'XML 본문에서 SYSTEM file:///... 엔티티를 읽어 응답에 넣는 취약한 파서를 흉내 냈습니다.',
    body: `
      <div class="lab-grid">
        <section class="panel">
          <form method="post" action="/labs/xxe/parse" class="stack">
            <textarea class="input textarea" name="xml">${esc(data.xml||'<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>\n<data>&xxe;</data>')}</textarea>
            <button class="btn">파싱</button>
          </form>
          <pre class="terminal">${esc(data.result||'<result>parsed</result>')}</pre>
        </section>
        ${labInfoCard(lab,'<ul class="list"><li>file:///etc/passwd 예제 제공</li><li>모의 파일 시스템 사용</li><li>XXE → 민감정보 노출 흐름 데모</li></ul>')}
      </div>`
  });
}

async function jwtPage(lab, req, data = {}) {
  const ctx = await getCtx(req);
  return layout({ ...ctx, title: lab.title, active: lab.slug,
    intro: '약한 공유 secret(lab-secret)으로 서명되는 JWT입니다. 발급 후 payload의 role을 admin으로 바꾸고 같은 secret으로 재서명해 검증해보세요.',
    body: `
      <div class="lab-grid">
        <section class="panel">
          <p><a class="btn secondary" href="/labs/jwt/token">샘플 토큰 발급</a></p>
          ${data.issued?`<pre class="terminal">${esc(data.issued)}</pre>`:''}
          <form method="post" action="/labs/jwt/verify" class="stack">
            <textarea class="input textarea" name="token">${esc(data.token||data.issued||'')}</textarea>
            <button class="btn">검증</button>
          </form>
          ${data.decoded?`<pre class="terminal">${esc(JSON.stringify(data.decoded,null,2))}</pre>`:''}
          ${data.result?`<div class="alert success">${esc(data.result)}</div>`:'<p class="muted">힌트: secret = lab-secret</p>'}
        </section>
        ${labInfoCard(lab,'<ul class="list"><li>HS256 약한 secret</li><li>role=admin이면 flag 출력</li><li>jwt.io 같은 디코더로 구조 확인 가능</li></ul>')}
      </div>`
  });
}

async function financeLoanPage(lab, req, data = {}) {
  const ctx = await getCtx(req);
  return layout({ ...ctx, title: lab.title, active: lab.slug,
    intro: '금융권 실습 보고서의 금리/한도 조작 흐름을 축소 재현했습니다. 서버가 interest 와 approved 를 신뢰합니다.',
    body: `
      <div class="lab-grid">
        <section class="panel">
          <form method="post" action="/labs/finance-loan/apply" class="stack">
            <input class="input" name="amount"   value="${esc(data.amount  ||'100000000')}" />
            <input class="input" name="interest" value="${esc(data.interest||'4.8')}" />
            <input class="input" name="maturity" value="${esc(data.maturity||'36')}" />
            <input class="input" name="approved" value="${esc(data.approved||'N')}" />
            <button class="btn">대출 신청</button>
          </form>
          ${data.result?`<div class="alert success">${esc(data.result)}</div>`:'<p class="muted">interest를 5000으로 올리거나 approved=Y로 바꿔보세요.</p>'}
        </section>
        ${labInfoCard(lab,'<ul class="list"><li>브라우저 prompt 변수 변조 시나리오</li><li>실제 암호화 대신 hidden/POST 값 신뢰로 단순화</li><li>승인 후 flag 노출</li></ul>')}
      </div>`
  });
}

async function financeJwtPage(lab, req, data = {}) {
  const ctx = await getCtx(req);
  return layout({ ...ctx, title: lab.title, active: lab.slug,
    intro: 'alg=none 을 허용하는 잘못된 토큰 검증을 실습합니다. header.alg 를 none 으로, payload.role 을 auditor 로 바꾸면 통과됩니다.',
    body: `
      <div class="lab-grid">
        <section class="panel">
          <p><a class="btn secondary" href="/labs/finance-jwt/token">시작 토큰 받기</a></p>
          ${data.issued?`<pre class="terminal">${esc(data.issued)}</pre>`:''}
          <form method="post" action="/labs/finance-jwt/verify" class="stack">
            <textarea class="input textarea" name="token">${esc(data.token||data.issued||'')}</textarea>
            <button class="btn">검증</button>
          </form>
          ${data.decoded?`<pre class="terminal">${esc(JSON.stringify(data.decoded,null,2))}</pre>`:''}
          ${data.result?`<div class="alert success">${esc(data.result)}</div>`:'<p class="muted">signature는 비워도 상관없습니다.</p>'}
        </section>
        ${labInfoCard(lab,'<ul class="list"><li>alg=none 우회</li><li>role=auditor 필요</li><li>금융 관리자 토큰 검증 실패 사례 데모</li></ul>')}
      </div>`
  });
}

async function financeInfoPage(lab, req) {
  const ctx = await getCtx(req);
  return layout({ ...ctx, title: lab.title, active: lab.slug,
    intro: 'WEB-INF와 spring 설정 파일 노출 시나리오를 재현했습니다. web.xml → root-context.xml → dbinfo.properties 순서로 접근하면 됩니다.',
    body: `
      <div class="lab-grid">
        <section class="panel">
          <form method="get" action="/labs/finance-info/fetch" class="stack">
            <input class="input" name="path" value="WEB-INF/web.xml" />
            <button class="btn">파일 열기</button>
          </form>
          <p class="muted">추천 경로: <code>WEB-INF/spring/root-context.xml</code>, <code>WEB-INF/classes/dbinfo.properties</code></p>
        </section>
        ${labInfoCard(lab,'<ul class="list"><li>Tomcat / Spring 구조 기반</li><li>dbinfo.properties 에 계정 정보 존재</li><li>금융권 9번/10번 실습과 연결</li></ul>')}
      </div>`
  });
}

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Vuln0Lab running on http://127.0.0.1:${PORT}`);
  console.log(`  DB: ${process.env.DB_HOST||'127.0.0.1'}:${process.env.DB_PORT||3306}/${process.env.DB_NAME||'vulnlab'}`);
});
