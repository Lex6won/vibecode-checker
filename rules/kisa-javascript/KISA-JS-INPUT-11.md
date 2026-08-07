---
id: KISA-JS-INPUT-11
title_ko: Node.js CSRF 보호 누락 - SameSite=None / csurf 미사용 / app.disable('etag')
title_en: CSRF protection missing in Node.js (no csurf / SameSite=None)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Javascript 시큐어코딩 가이드(2023년 개정본)
    item: 제2절 11. 크로스사이트 요청 위조 (CSRF)
cwe: [CWE-352]
severity: high
decision_default: warn
domains: [kisa-secure-coding]
languages: [javascript, typescript]
scenarios: [backend-node, web-app]
related_baseline: [MOIS-49-INPUT-11]
verified_at: 2026-05-31
review_due: 2026-11-30
detection:
  patterns:
    - "sameSite\\s*:\\s*['\"]none['\"]"
    - "cookie-session\\s*\\(\\s*\\{[^}]*sameSite\\s*:\\s*false"
    - "csrfProtection\\s*=\\s*false"
    - "cors\\s*\\(\\s*\\{[^}]*origin\\s*:\\s*['\"]?\\*['\"]?\\s*,[^}]*credentials\\s*:\\s*true"
  category: kisa-secure-coding
  why_it_matters: >-
    쿠키 기반 세션을 쓰면서 `SameSite: 'none'`을 설정하거나, CORS에서 wildcard
    origin과 credentials=true를 동시에 켜면 cross-site 요청이 사용자 권한으로
    실행됩니다. 결재·민원 처리 API에서는 결재 변조로 직결됩니다.
  public_sector_impact:
    - 결재·민원 변조
    - 권한 우회 요청 실행
    - 세션 도용
  safe_fix: |
    상태 변경 API는 csurf 또는 double-submit 토큰 사용.
    SameSite는 'lax' 또는 'strict' 권장. CORS wildcard + credentials 조합 금지.
    app.use(cookieSession({ sameSite: "lax", secure: true, httpOnly: true }));
    app.use(csrf());                 // 또는 SameSite=strict + Origin 검증
    app.use(cors({ origin: ALLOWLIST, credentials: true }));  // 명시 origin
  references:
    - KISA JS 가이드 제2절 11
    - MOIS-49-INPUT-11
    - CWE-352
    - OWASP ASVS V7
  can_auto_fix: false
examples:
  language: javascript
  positive:
    - "res.cookie(\"sid\", token, { httpOnly: true, sameSite: 'none' });"
    - "app.use(cors({ origin: '*', credentials: true }));"
  negative:
    - "res.cookie(\"sid\", token, { httpOnly: true, sameSite: 'strict', secure: true });"
    - "app.use(cors({ origin: ALLOWED_ORIGINS, credentials: true }));"
---

## 무엇이 위험한가
SPA + 쿠키 세션 환경에서 SameSite를 끄거나 CORS wildcard로 우회하면 CSRF가 부활합니다. 공공 결재/민원 API는 항상 토큰 또는 Origin 검증을 거쳐야 합니다.

## 안전한 패턴
```javascript
import csurf from "csurf";
import cors from "cors";

app.use(cors({
  origin: ["https://approved.example.gov", ...],
  credentials: true,
}));
app.use(csurf({ cookie: { sameSite: "lax", secure: true } }));
```
