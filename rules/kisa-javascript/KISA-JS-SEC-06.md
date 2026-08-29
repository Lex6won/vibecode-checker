---
id: KISA-JS-SEC-06
title_ko: JavaScript 하드코드된 중요정보 - secret / API key 변수 리터럴
title_en: Hardcoded credentials in JavaScript source
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Javascript 시큐어코딩 가이드(2023년 개정본)
    item: 제3절 6. 하드코드된 중요정보
cwe: [CWE-798, CWE-259]
severity: critical
decision_default: block
domains: [kisa-secure-coding]
languages: [javascript, typescript]
scenarios: [web-app, backend-node, auth]
related_baseline: [MOIS-49-SEC-06, GOV-SECRET-APIKEY-001]
verified_at: 2026-05-31
review_due: 2026-11-30
detection:
  patterns:
    - "(?i)(?:const|let|var)\\s+(?:\\*\\*)?(?:password|passwd|pwd|api[_-]?key|secret|jwt[_-]?secret)(?:\\*\\*)?\\s*=\\s*['\"][^'\"\\s$\\{`]{6,}['\"]"
    - "(?i)(?:password|secret|jwt_secret|api_key)(?:\\*\\*)?\\s*:\\s*['\"][^'\"\\s$\\{`]{6,}['\"]"
    - "(?:postgres|mysql|mongodb)://[^:]+:[^@]+@"
    - "Bearer\\s+[A-Za-z0-9._-]{20,}"
  # 같은 코드를 다른 각도로 보는 룰과 한 묶음(GOV-SECRET-APIKEY-001, KISA-PY-SEC-06). 같은 줄에 함께 걸리면
  # 가장 확실한 엔진의 발견 하나만 남고 나머지는 also_matched 로 합쳐진다(개선요청 #34 C).
  dedup_group: hardcoded-credential
  category: secret-scanning
  why_it_matters: >-
    JavaScript는 브라우저 측·서버 측 양쪽에서 흔히 작성됩니다. 특히 *브라우저
    번들*에 secret이 박히면 모든 사용자에게 노출됩니다. NEXT_PUBLIC_*, REACT_APP_*
    같은 환경변수 접두사도 클라이언트로 그대로 나갑니다.
  public_sector_impact:
    - 서버 API 키 일괄 탈취
    - DB 직접 연결 노출
    - 인증서·서명키 노출
  safe_fix: |
    서버는 환경변수 또는 secret manager.
    const apiKey = process.env.UPSTREAM_API_KEY;
    브라우저 코드에는 *어떠한 비밀도 두지 말 것* - 백엔드 proxy 경유.
    Next.js: NEXT_PUBLIC_* 접두사 사용 금지 (모든 클라이언트에 노출됨).
  references:
    - KISA JS 가이드 제3절 6
    - MOIS-49-SEC-06
    - CWE-798
  can_auto_fix: false
examples:
  language: javascript
  positive:
    - "const jwtSecret = \"H3xK9mQ2pR7sT1uV5wY8\";"
    - "const password = \"hunter2plus9\";"
    - "const dsn = \"mongodb://admin:pw9x2mQ7@dbhost/app\";"
  negative:
    - "const jwtSecret = process.env.JWT_SECRET;"
    - "const password = \"\";"
---

## 무엇이 위험한가
프런트엔드 번들의 secret은 *모든 사용자가 devtools에서 볼 수 있다*고 봐야 합니다. Next.js / Vite의 `_PUBLIC_` 접두사 환경변수도 똑같이 노출됩니다.

## 안전한 패턴
```javascript
// 서버
const apiKey = process.env.UPSTREAM_API_KEY;

// 프런트엔드는 절대 secret을 가지지 않음 — 자체 백엔드 호출
const r = await fetch("/api/external-proxy", { method: "POST", body });
```
