-- ============================================================
-- Vuln0Lab - Database Initialization Script
-- Run this via the /setup page or: mysql -u root -p < setup/init-db.sql
-- ============================================================

CREATE DATABASE IF NOT EXISTS vulnlab CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE vulnlab;

-- ------------------------------------------------------------
-- Create application user with limited privileges
-- ------------------------------------------------------------
CREATE USER IF NOT EXISTS 'vulnlab_user'@'%' IDENTIFIED BY 'vulnlab_pass';
GRANT SELECT, INSERT, UPDATE, DELETE ON vulnlab.* TO 'vulnlab_user'@'%';
FLUSH PRIVILEGES;

-- ------------------------------------------------------------
-- Tables
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS properties (
  id       INT AUTO_INCREMENT PRIMARY KEY,
  district VARCHAR(100),
  price    INT,
  note     TEXT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS members (
  id       INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(100) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  role     VARCHAR(50)  NOT NULL DEFAULT 'user',
  salary   BIGINT       DEFAULT 0,
  email    VARCHAR(255),
  flag     VARCHAR(255)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS comments (
  id         INT AUTO_INCREMENT PRIMARY KEY,
  author     VARCHAR(100),
  message    TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS labs (
  id         INT AUTO_INCREMENT PRIMARY KEY,
  slug       VARCHAR(100) NOT NULL UNIQUE,
  title      VARCHAR(200) NOT NULL,
  category   VARCHAR(100),
  difficulty ENUM('Easy','Medium','Hard','Expert') DEFAULT 'Medium',
  enabled    TINYINT(1) DEFAULT 1,
  flag       VARCHAR(255)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS progress (
  id         INT AUTO_INCREMENT PRIMARY KEY,
  user_id    INT          NOT NULL,
  slug       VARCHAR(100) NOT NULL,
  solved     TINYINT(1)   DEFAULT 0,
  solved_at  DATETIME     DEFAULT NULL,
  UNIQUE KEY uq_user_slug (user_id, slug)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ------------------------------------------------------------
-- Seed: properties
-- ------------------------------------------------------------
INSERT IGNORE INTO properties (district, price, note) VALUES
  ('역촌동',       72000,  '은평구 오피스텔'),
  ('영등포동8가',   81000,  '오라클 실습용 매물'),
  ('영등포동',      98000,  '상가 포함'),
  ('신촌동',        55000,  '원룸'),
  ('논현동',       145000, '고급 빌라'),
  ('구로동',        63000,  '산업단지 인접');

-- ------------------------------------------------------------
-- Seed: members (admin first, role=admin)
-- ------------------------------------------------------------
INSERT IGNORE INTO members (username, password, role, salary, email, flag) VALUES
  ('admin',      'Sk1nFoSec!',        'admin',   90000000,  'admin@vulnlab.local',    'FLAG{union_admin_dump_success}'),
  ('eqst001004', 'cookie_answer',     'user',    42000000,  'victim1004@vulnlab.local','FLAG{session_fixation_complete}'),
  ('nohsy',      'blind_0racle_pw',   'student', 38000000,  '32221452@vulnlab.local', 'FLAG{blind_sqli_extracted}'),
  ('auditor',    'loanmaster',        'auditor', 110000000, 'audit@bank.local',       'FLAG{finance_panel_unlocked}');

-- ------------------------------------------------------------
-- Seed: comments
-- ------------------------------------------------------------
INSERT IGNORE INTO comments (author, message) VALUES
  ('manager', '오늘 점검 완료'),
  ('alice',   '테스트 게시글입니다.');

-- ------------------------------------------------------------
-- Seed: labs
-- ------------------------------------------------------------
INSERT IGNORE INTO labs (slug, title, category, difficulty, enabled, flag) VALUES
  ('sqli-union',    'Union SQL Injection',  'SQLi',  'Easy',   1, 'FLAG{union_admin_dump_success}'),
  ('sqli-error',    'Error-Based SQLi',     'SQLi',  'Medium', 1, 'FLAG{error_based_sqli_success}'),
  ('sqli-blind',    'Blind SQL Injection',  'SQLi',  'Hard',   1, 'FLAG{blind_sqli_extracted}'),
  ('xss-reflected', 'Reflected XSS',        'XSS',   'Easy',   1, 'FLAG{xss_reflected_success}'),
  ('xss-stored',    'Stored XSS',           'XSS',   'Medium', 1, 'FLAG{xss_stored_success}'),
  ('xss-dom',       'DOM XSS',              'XSS',   'Medium', 1, 'FLAG{dom_xss_success}'),
  ('file-upload',   '파일 업로드',           '파일',  'Medium', 1, 'FLAG{file_upload_success}'),
  ('file-download', '파일 다운로드',         '파일',  'Medium', 1, 'FLAG{file_download_success}'),
  ('lfi',           'LFI / Path Traversal', '파일',  'Hard',   1, 'FLAG{lfi_path_traversal_success}'),
  ('ssrf',          'SSRF',                 '서버',  'Hard',   1, 'FLAG{ssrf_internal_admin_success}'),
  ('session-fixation','세션 고정',           '인증',  'Easy',   1, 'FLAG{session_fixation_complete}'),
  ('param-tamper',  '파라미터 변조',         '인증',  'Medium', 1, 'FLAG{parameter_tampering_success}'),
  ('idor',          'IDOR',                 '인증',  'Medium', 1, 'FLAG{idor_access_success}'),
  ('cmd-injection', '커맨드 인젝션',         '인젝션','Medium', 1, 'FLAG{command_injection_chain_success}'),
  ('xxe',           'XXE',                  '인젝션','Hard',   1, 'FLAG{xxe_file_read_success}'),
  ('jwt',           'JWT 취약점',            '인증',  'Hard',   1, 'FLAG{jwt_role_escalation_success}'),
  ('finance-loan',  '대출 파라미터 변조',    '금융',  'Expert', 1, 'FLAG{finance_interest_manipulated}'),
  ('finance-jwt',   '금융 JWT 위조',         '금융',  'Expert', 1, 'FLAG{finance_alg_none_bypass}'),
  ('finance-info',  'DB 정보 노출',          '금융',  'Expert', 1, 'FLAG{finance_db_info_exposed}');
