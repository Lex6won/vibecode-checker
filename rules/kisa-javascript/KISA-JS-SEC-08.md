---
id: KISA-JS-SEC-08
title_ko: Node.js 적절하지 않은 난수 값 사용 - Math.random / Date.now seed / 고정 seed
title_en: Insecure randomness in Node.js (Math.random / fixed seed / Date.now for security)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Javascript 시큐어코딩 가이드(2023년 개정본)
    item: 제2절 8. 적절하지 않은 난수 값 사용
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-39
cwe: [CWE-330, CWE-338, CWE-337]
severity: high
decision_default: warn
domains: [kisa-secure-coding]
languages: [javascript, typescript]
scenarios: [auth, backend-node, web-app]
related_baseline: [MOIS-49-SEC-08]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    - "(?i)(?:const|let|var)\\s+\\w*(?:otp|token|nonce|reset|secret|sessionId|sid|csrf|salt|iv|verif|coupon|inviteCode)\\w*\\s*=[^;\\n]*Math\\.random"
    - "(?i)(?:otp|token|nonce|resetKey|secret|sessionId|csrfToken|salt|iv|verifyCode|couponCode|inviteCode)\\s*[:=]\\s*[^;\\n,]*Math\\.random"
    - "getOtpNumber\\s*\\([^)]*\\)\\s*\\{[\\s\\S]{0,200}?Math\\.random"
    - "Math\\.floor\\s*\\(\\s*Math\\.random\\s*\\(\\s*\\)\\s*\\*\\s*\\d+\\s*\\)[\\s\\S]{0,80}?(?:otp|token|nonce|reset|verif)"
    - "Math\\.seedrandom\\s*\\(\\s*['\"][^'\"]+['\"]\\s*\\)"
  category: kisa-secure-coding
  why_it_matters: >-
    `Math.random()`은 V8의 xorshift128+ 기반으로 *암호학적으로 안전하지 않습니다*.
    OTP·세션ID·CSRF 토큰·비밀번호 재설정 키·쿠폰 코드를 Math.random으로 생성하면
    공격자가 인접 출력을 보고 다음 값을 역산할 수 있습니다. 가이드 §제2절 8은
    NodeJS는 `crypto.randomBytes`/`crypto.getRandomValues`, 브라우저는
    `window.crypto.getRandomValues`를 쓰라고 명시합니다. 고정 seed
    (`Math.seedrandom('fixed')`)는 모든 토큰이 결정론적으로 동일해집니다.
  public_sector_impact:
    - OTP·재설정 토큰 예측으로 인한 계정 탈취
    - 세션 ID 충돌·예측으로 인한 세션 하이재킹
    - 쿠폰·예약 번호 자동 생성으로 부정 사용
  safe_fix: |
    Node.js (서버): crypto.randomBytes 또는 crypto.getRandomValues.
    import { randomBytes, randomInt } from "crypto";
    const otp = String(randomInt(0, 1_000_000)).padStart(6, "0");
    const token = randomBytes(32).toString("hex");
    브라우저: window.crypto.getRandomValues(new Uint32Array(1)).
    UUID: crypto.randomUUID() (Node 19+, 또는 uuid v4).
  references:
    - KISA JavaScript 가이드 제2절 8
    - MOIS-49-SEC-08
    - CWE-330
    - OWASP Insecure Randomness
  can_auto_fix: false
examples:
  language: javascript
  positive:
    - "const otpCode = Math.floor(Math.random() * 1000000);"
    - "function getOtpNumber() { let r = ''; for (let i=0;i<6;i++) r += Math.floor(Math.random()*10); return r; }"
    - "const resetToken = Math.random().toString(36).slice(2);"
  negative:
    - "import { randomInt } from 'crypto'; const otpCode = String(randomInt(0, 1000000)).padStart(6, '0');"
    - "const token = crypto.randomBytes(32).toString('hex');"
    - "const r = Math.random(); // animation jitter only"
---

## 무엇이 위험한가
`Math.random()`은 V8 xorshift128+로 구현되어 *예측 가능*합니다. 동일 프로세스에서 몇 개 출력을 관찰하면 내부 상태를 복원해 다음 OTP·토큰을 계산할 수 있습니다. `Date.now()` seed나 `Math.seedrandom('fixed')`는 더 나쁘게, 모든 인스턴스가 동일 토큰을 생성합니다.

## 안전한 패턴 (가이드 원문 인용)
```javascript
const crypto = require("crypto");

function getOtpNumber() {
  // 보안기능에 적합한 난수 생성용 crypto 라이브러리 사용
  const array = new Uint32Array(1);
  // 브라우저에서는 crypto 대신에 window.crypto를 사용
  const randomStr = crypto.getRandomValues(array);
  let result;
  for (let i = 0; i < randomStr.length; i++) {
    result = array[i];
  }
  return String(result).substring(0, 6);
}
```

## False positive 주의
- 보안 목적이 아닌 `Math.random()` 사용(애니메이션 지터, 더미 데이터 셔플)은 변수명에 `otp|token|secret|nonce|reset` 등의 키워드가 없어 매칭되지 않습니다.
- `crypto.randomBytes`/`crypto.getRandomValues`/`randomInt`로 대체된 코드는 매칭되지 않습니다.
- UUID 라이브러리(`uuid.v4()`)는 내부적으로 안전한 난수를 사용하므로 매칭에서 제외됩니다.
