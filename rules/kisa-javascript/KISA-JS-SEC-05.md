---
id: KISA-JS-SEC-05
title_ko: Node.js 암호화되지 않은 중요정보 - 평문 저장/전송 (DB INSERT, socket.emit, http URL)
title_en: Cleartext storage/transmission of sensitive data in Node.js
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Javascript 시큐어코딩 가이드(2023년 개정본)
    item: 제2절 5. 암호화되지 않은 중요정보
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-36
cwe: [CWE-312, CWE-319, CWE-359]
severity: high
decision_default: block
domains: [kisa-secure-coding]
languages: [javascript, typescript]
scenarios: [auth, backend-node, web-app, data-store]
related_baseline: [MOIS-49-SEC-05]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    - "(?:INSERT\\s+INTO|UPDATE)\\s+\\w*user\\w*\\s+SET\\s+[^;'\"]*\\bpassword\\s*=\\s*\\?"
    - "(?i)(?:INSERT\\s+INTO|UPDATE)[^;'\"]{0,80}\\(\\s*[^)]*\\b(?:password|passwd|pwd|ssn|jumin|rrn|card_no|cardnumber|account_no)\\b[^)]*\\)\\s*VALUES"
    - "socket\\.emit\\s*\\(\\s*['\"](?:password|passwd|pwd|secret|token|ssn|jumin|card)['\"]\\s*,\\s*(?!.*(?:encrypt|cipher|hash|bcrypt|aes|sha))[a-zA-Z_$][\\w$]*\\s*\\)"
    - "(?:fetch|axios|got|request|http\\.request)\\s*\\(\\s*['\"]http://[^'\"]+['\"][\\s\\S]{0,200}?(?:password|secret|token|ssn|jumin|cardNumber|card_no)"
    - "(?:fetch|axios)\\s*\\(\\s*['\"]http://[^'\"]*['\"]\\s*,\\s*\\{[\\s\\S]{0,300}?body\\s*:\\s*JSON\\.stringify\\s*\\(\\s*\\{[\\s\\S]{0,200}?password\\s*:"
  category: kisa-secure-coding
  why_it_matters: >-
    개인정보·인증정보·금융정보를 *암호화 없이 DB에 저장*하거나 *http(평문) 채널로
    전송*하면, DB 덤프 한 번 또는 네트워크 스니핑 한 번으로 전 사용자 자격증명이
    유출됩니다. 가이드 §제2절 5는 *반드시 암호화 과정을 거치고 SSL/HTTPS 같은 보안
    채널을 사용*하라고 명시합니다. 공공 시스템의 개인정보보호법 위반·정보보안 기본
    지침 위배로 직결됩니다.
  public_sector_impact:
    - DB 유출 시 전 사용자 자격증명 즉시 노출
    - 평문 전송으로 인한 패킷 스니핑 자격증명 탈취
    - 개인정보보호법 위반 및 신고 대상
  safe_fix: |
    저장: 비밀번호는 bcrypt/argon2, 개인정보는 AES-256-GCM 후 저장.
    const hash = await bcrypt.hash(password, 12);
    db.query('INSERT INTO user(email, passwordHash) VALUES (?, ?)', [email, hash]);
    전송: HTTPS + 필요 시 AES 추가 암호화, socket.io는 wss:// 사용.
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    socket.emit('password', cipher.update(plain, 'utf8', 'base64') + cipher.final('base64'));
  references:
    - KISA JavaScript 가이드 제2절 5
    - MOIS-49-SEC-05
    - CWE-312
    - CWE-319
    - OWASP Password Plaintext Storage
  can_auto_fix: false
examples:
  language: javascript
  positive:
    - "dbconn.query('UPDATE user SET password=? WHERE user_id=?', [password, user_id]);"
    - "db.query('INSERT INTO user (email, password, name) VALUES (?, ?, ?)', [email, password, name]);"
    - "socket.emit('password', password);"
  negative:
    - "const hash = await bcrypt.hash(password, 12); dbconn.query('UPDATE user SET passwordHash=? WHERE user_id=?', [hash, user_id]);"
    - "const cipher = crypto.createCipheriv('aes-256-gcm', key, iv); socket.emit('password', cipher.update(password, 'utf8', 'base64'));"
    - "await fetch('https://api.example.gov.kr/login', { method: 'POST', body: JSON.stringify({ token }) });"
---

## 무엇이 위험한가
가이드 §제2절 5는 두 가지 패턴을 함께 다룹니다.
1. *중요정보 평문저장*: 사용자 비밀번호·주민번호·계좌번호를 해시/암호화 없이 DB에 그대로 저장 → DB 덤프 한 번에 전 자격증명 유출.
2. *중요정보 평문전송*: `socket.emit("password", password)` 또는 `http://` URL로 비밀번호를 보내면 같은 네트워크의 누구든 패킷 스니핑으로 가로챕니다.

## 안전한 패턴 (가이드 원문 인용)
```javascript
// 저장: 단방향 해시 + 솔트 (또는 bcrypt 권장)
const hashPw = crypto.createHash('sha256').update(password + salt, 'utf-8').digest('hex');
const sql = 'UPDATE user SET password=? WHERE user_id=?';
dbconn.query(sql, [hashPw, user_id], function(err) { /* ... */ });

// 전송: 대칭키 암호화 + (가능하면) wss/https
const cipherAes = crypto.createCipheriv('aes-256-cbc', key, iv);
const enc = cipherAes.update(plainText, 'utf8', 'base64') + cipherAes.final('base64');
socket.emit('password', enc);
```

## False positive 주의
- 평문 컬럼명 대신 `passwordHash`/`hash`/`encrypted_password`를 쓰는 SQL은 매칭되지 않습니다(`bcrypt|cipher|hash|aes` 키워드를 인근에서 제외 조건으로 검사).
- `https://` 도메인 호출은 평문 전송 패턴에서 제외합니다.
- socket.emit 채널명이 단순 메시지 (`'message'`, `'chat'`)인 경우는 매칭하지 않습니다.
- 외부 라이브러리가 컬럼명을 `password`로 강제하는 경우(예: passport 내부) `gvskb: ignore` 주석으로 예외 처리하세요.
