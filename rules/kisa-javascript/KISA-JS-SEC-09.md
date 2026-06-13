---
id: KISA-JS-SEC-09
title_ko: JavaScript 취약한 패스워드 처리 - 평문 비교 / 길이 검증 누락 / Math.random 토큰
title_en: Weak password handling in JavaScript (plain compare, short min, Math.random)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Javascript 시큐어코딩 가이드(2023년 개정본)
    item: 제3절 9. 취약한 패스워드 허용
cwe: [CWE-521, CWE-330, CWE-208]
severity: high
decision_default: warn
domains: [kisa-secure-coding]
languages: [javascript, typescript]
scenarios: [auth, backend-node]
related_baseline: [MOIS-49-SEC-09]
verified_at: 2026-05-31
review_due: 2026-11-30
detection:
  patterns:
    - "(?:user\\.password|stored_password|hashedPassword)\\s*===?\\s*(?:req|input)\\.[a-zA-Z_]+\\.password"
    - "(?:req|input)\\.[a-zA-Z_]+\\.password\\s*===?\\s*(?:user\\.password|stored_password)"
    - "password\\.length\\s*[<>]=?\\s*[1-7]\\b"
    - "(?i)(?:const|let|var)\\s+\\w*(?:Token|Password|Otp|Reset|Secret|Nonce)\\w*\\s*=[^;]*Math\\.random"
    - "(?i)(?:token|password|otp|resetkey|secret)\\s*=\\s*Math\\.random"
  category: kisa-secure-coding
  why_it_matters: >-
    `user.password === req.body.password` 같은 평문 비교는 (a) 비밀번호를 평문
    저장하고 있다는 신호이고 (b) `===` 자체가 timing-safe하지 않습니다.
    `Math.random()`으로 토큰·OTP·재설정 키를 만들면 예측 가능합니다.
    8자 미만 길이 정책도 KISA 가이드 권고에 미달합니다.
  public_sector_impact:
    - 비밀번호 평문 노출
    - 비밀번호 재설정 토큰 예측
    - 약한 OTP·세션 토큰
  safe_fix: |
    bcrypt + timing-safe 비교.
    import bcrypt from "bcrypt";
    const ok = await bcrypt.compare(req.body.password, user.passwordHash);

    // 보안 토큰은 crypto.randomBytes
    import { randomBytes } from "crypto";
    const token = randomBytes(32).toString("hex");
    // 길이 정책은 최소 12자 + 복잡도 또는 passphrase
  references:
    - KISA JS 가이드 제3절 9
    - MOIS-49-SEC-09
    - CWE-521, CWE-330
    - OWASP ASVS V6.2
  can_auto_fix: false
---

## 무엇이 위험한가
- 평문 비교 `===`: 비밀번호가 평문 저장된 강력한 신호 + timing attack 노출
- `Math.random()`: 시드 추정 가능 — 토큰/OTP/재설정 키 절대 금지
- 8자 미만 정책: 사실상 평문 수준

## 안전한 패턴
```javascript
import bcrypt from "bcrypt";
import { randomBytes } from "crypto";

const ok = await bcrypt.compare(req.body.password, user.passwordHash);
const resetToken = randomBytes(32).toString("hex");
```
