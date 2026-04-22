<<<<<<< HEAD
# Vuln0Lab

로컬 전용 웹 취약점 실습 플랫폼 (DVWA 스타일)

SQLi, XSS, SSRF, LFI, 파일 업로드/다운로드, 세션 고정, JWT, IDOR, 커맨드 인젝션, XXE, 금융 시나리오까지 19개 Lab 포함.

---

## 빠른 시작

### 1. MySQL 띄우기 (Docker)

```bash
docker-compose up -d
```

### 2. 환경변수 설정

```bash
cp .env.example .env
# .env 파일에서 필요한 값 수정 (기본값으로도 바로 동작)
```

### 3. 패키지 설치

```bash
npm install
```

### 4. 서버 실행

```bash
npm start
```

### 5. DB 초기화

브라우저에서 http://127.0.0.1:3100/setup 접속 후 **"DB 초기화 실행"** 버튼 클릭.

### 6. 로그인

http://127.0.0.1:3100/login 접속

| 계정 | 비밀번호 | 역할 |
|------|----------|------|
| admin | Sk1nFoSec! | 관리자 |
| eqst001004 | cookie_answer | 일반 사용자 |
| nohsy | blind_0racle_pw | 학생 |
| auditor | loanmaster | 감사 |

---

## 구조

```
vulnlab-project/
├── server.js          # 메인 서버 (Express + MySQL)
├── package.json
├── docker-compose.yml # MySQL 컨테이너
├── .env               # 환경변수 (git에 포함하지 말 것)
├── .env.example       # 환경변수 예시
├── setup/
│   └── init-db.sql    # DB 초기화 SQL
├── public/
│   ├── style.css
│   └── uploads/       # 파일 업로드 결과
└── simroot/           # 모의 파일 시스템 (취약점 실습용)
```

---

## 관리자 페이지 (/admin)

admin 계정으로 로그인 후 `/admin` 접속.

- Lab ON/OFF 토글
- 난이도 변경 (Easy / Medium / Hard / Expert)
- 플래그 재생성
- 사용자별 진도 확인

---

## 환경변수 (.env)

| 변수 | 기본값 | 설명 |
|------|--------|------|
| APP_PORT | 3100 | 서버 포트 |
| DB_HOST | 127.0.0.1 | MySQL 호스트 |
| DB_PORT | 3306 | MySQL 포트 |
| DB_USER | vulnlab_user | DB 접속 계정 |
| DB_PASSWORD | vulnlab_pass | DB 접속 비밀번호 |
| DB_NAME | vulnlab | DB 이름 |
| DB_ROOT_PASSWORD | rootpass123 | MySQL root 비밀번호 (docker-compose용) |
| JWT_SECRET | (변경 필요) | JWT 서명 키 |

---

## 주의사항

- **로컬 실습 전용**. 외부에 노출하지 마세요.
- 모든 취약점은 의도된 것입니다.
- DB 초기화 시 기존 데이터가 덮어씌워질 수 있습니다.
=======
This project is an intentionally vulnerable local training platform for web security education.
Do not deploy to a public server or production environment.
>>>>>>> c13ec3eb5c3b4220d1926e7a64cc8785af3e75e7
