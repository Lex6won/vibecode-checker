---
id: KISA-JS-INPUT-01
title_ko: JavaScript 원시 SQL 또는 template literal에 외부 입력값이 결합되어 SQL 삽입 위험
title_en: SQL injection via string concatenation or template literal in JavaScript
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Javascript 시큐어코딩 가이드(2023년 개정본)
    item: 제2절 1. SQL 삽입
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-17
cwe: [CWE-89]
severity: critical
decision_default: block
domains: [kisa-secure-coding]
languages: [javascript, typescript]
scenarios: [web-app, data-pipeline, backend-node]
related_baseline: [MOIS-49-INPUT-01, GOV-SQL-INJECTION-001]
verified_at: 2026-05-31
review_due: 2026-11-30
detection:
  patterns:
    - '\.query\s*\(\s*[`][^`]*\$\{'
    # 결합(+)은 *변수 식별자*로 이어질 때만 SQLi로 본다. 과거 패턴(`\+`만)은
    # 문자열 안의 "+09:00" 같은 리터럴이나 정적 SET 문도 결합으로 오인했다.
    # 따라서 `+` 뒤에 [A-Za-z_$](식별자 시작)을 요구해 숫자·따옴표 오매칭을 제거.
    - '\.query\s*\(\s*["''][^"'']*["'']\s*\+\s*[A-Za-z_$]'
    - "\\.(?:query|execute)\\s*\\(\\s*`[^`]*\\$\\{"
    - 'connection\.query\s*\([^,)]*\+\s*[A-Za-z_$]'
  category: kisa-secure-coding
  why_it_matters: >-
    Node.js의 mysql, pg, mssql 등 드라이버에서 ``db.query(`SELECT * FROM users
    WHERE id=${userId}`)`` 형태로 template literal에 변수를 끼우면 즉시 SQL
    삽입에 노출됩니다. ORM(Sequelize, TypeORM)을 쓰더라도 raw 쿼리에서 같은
    실수가 빈번합니다.
  public_sector_impact:
    - 민원·통계 DB 전체 조회·변조
    - 개인정보 유출
    - 행정 시스템 신뢰 손상
  safe_fix: |
    매개변수 placeholder를 사용하세요.
    db.query("SELECT * FROM users WHERE id = ?", [userId])           // mysql2
    db.query("SELECT * FROM users WHERE id = $1", [userId])          // pg
    ORM: User.findOne({ where: { id: userId } })
  references:
    - KISA JavaScript 가이드 제2절 1
    - MOIS-49-INPUT-01
    - CWE-89
  can_auto_fix: false
examples:
  language: javascript
  positive:
    - 'db.query("SELECT * FROM users WHERE n=" + name)'
    - 'db.query(`SELECT * FROM users WHERE id=${userId}`)'
    - "connection.query('SELECT ' + column)"
  negative:
    - 'pool.query(''SET time_zone = "+09:00"'')'
    - 'db.query("SELECT * FROM users WHERE id = ?", [id])'
    - 'db.query(`SELECT * FROM users`)'
---

## 무엇이 위험한가
JavaScript의 template literal은 가독성이 좋아서 *쿼리 문자열에 변수를 끼우는 패턴*이 너무 흔합니다. 그러나 SQL은 쿼리 구조와 데이터를 분리해야 안전하므로, 변수는 반드시 placeholder를 통해 바인딩해야 합니다.

## 안전한 패턴 (가이드 원문 인용)
```javascript
// mysql2
const [rows] = await db.execute("SELECT * FROM citizens WHERE name = ?", [name]);
// pg
const r = await client.query("SELECT * FROM citizens WHERE name = $1", [name]);
// Sequelize
const user = await User.findOne({ where: { name } });
```
