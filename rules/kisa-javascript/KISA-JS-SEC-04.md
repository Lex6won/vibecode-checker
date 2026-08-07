---
id: KISA-JS-SEC-04
title_ko: JavaScript에서 취약한 암호화 알고리즘 사용 (MD5/SHA1/DES/RC4)
title_en: Use of weak cryptographic algorithm in JavaScript (MD5/SHA1/DES/RC4)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Javascript 시큐어코딩 가이드(2023년 개정본)
    item: 제3절 4. 취약한 암호화 알고리즘 사용
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-37
cwe: [CWE-327]
severity: high
decision_default: warn
domains: [kisa-secure-coding]
languages: [javascript, typescript]
scenarios: [auth, web-app, backend-node]
related_baseline: [MOIS-49-SEC-04]
verified_at: 2026-05-31
review_due: 2026-11-30
detection:
  patterns:
    - "crypto\\.createHash\\s*\\(\\s*[\"'](md5|sha1|md4)[\"']"
    - "crypto\\.createHmac\\s*\\(\\s*[\"'](md5|sha1|md4)[\"']"
    - "crypto\\.createCipheriv?\\s*\\(\\s*[\"'](des|des-cbc|des3|rc4|arc4)[\"']"
    - 'CryptoJS\.(?:MD5|SHA1|DES|RC4|TripleDES)\s*\('
  category: kisa-secure-coding
  why_it_matters: >-
    Node.js crypto 모듈과 브라우저용 crypto-js의 MD5/SHA1/DES/RC4는 모두 충돌·
    키 길이·구조 문제로 더는 안전하지 않습니다. 비밀번호, 전자서명, 토큰
    무결성에 쓰면 공공기관 정보보안 기본지침의 암호 적합성 요건을 위배합니다.
  public_sector_impact:
    - 비밀번호 충돌 공격
    - 전자서명 위조 가능성
    - 정보보안 기본지침 위배
  safe_fix: |
    해시: crypto.createHash('sha256') 또는 SHA-3 계열.
    비밀번호: bcrypt, argon2 사용 (단일 해시 금지).
    대칭키: AES-256-GCM 또는 ChaCha20-Poly1305.
    crypto.createCipheriv('aes-256-gcm', key, iv) 형태.
  references:
    - KISA JavaScript 가이드 제3절 4
    - MOIS-49-SEC-04
    - CWE-327
    - 국정원 암호모듈 검증 정책
  can_auto_fix: false
examples:
  language: javascript
  positive:
    - "const digest = crypto.createHash(\"md5\").update(body).digest(\"hex\");"
    - "const mac = crypto.createHmac(\"sha1\", key).update(body).digest();"
    - "const hashed = CryptoJS.SHA1(password);"
  negative:
    - "const digest = crypto.createHash(\"sha256\").update(body).digest(\"hex\");"
    - "const mac = crypto.createHmac(\"sha256\", key).update(body).digest();"
---

## 무엇이 위험한가
Node.js `crypto.createHash('md5')`, 브라우저용 `CryptoJS.MD5(...)`, `crypto.createCipheriv('des-cbc', ...)` 모두 약한 알고리즘 사용 패턴입니다.

## 안전한 패턴 (가이드 원문 인용)
```javascript
import crypto from "crypto";

// 무결성 해시
const digest = crypto.createHash("sha256").update(data).digest("hex");

// 비밀번호 (bcrypt 권장)
import bcrypt from "bcrypt";
const hash = await bcrypt.hash(password, 12);

// AES-256-GCM
const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
```
