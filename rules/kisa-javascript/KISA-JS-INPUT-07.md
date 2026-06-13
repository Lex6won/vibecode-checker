---
id: KISA-JS-INPUT-07
title_ko: Node.js 신뢰되지 않은 URL로 자동 리다이렉트 (Open Redirect)
title_en: Open redirect via unvalidated user-supplied URL in Node.js
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Javascript 시큐어코딩 가이드(2023년 개정본)
    item: 제1절 7. 신뢰되지 않은 URL주소로 자동접속 연결
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-30
cwe: [CWE-601]
severity: high
decision_default: block
domains: [kisa-secure-coding]
languages: [javascript, typescript]
scenarios: [web-app, backend-node]
related_baseline: [MOIS-49-INPUT-07]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    - "res\\.redirect\\s*\\(\\s*(?:req|request)\\.(?:query|params|body)\\."
    - "res\\.redirect\\s*\\(\\s*[`\"'][^`\"']*\\$\\{(?:req|request)\\."
    - "(?:window\\.)?location\\.(?:href|replace|assign)\\s*=\\s*(?:req|request|location\\.search|window\\.location|new\\s+URLSearchParams)"
    - "location\\.(?:replace|assign)\\s*\\(\\s*(?:req|request|new\\s+URLSearchParams|location\\.search)"
  category: kisa-secure-coding
  why_it_matters: >-
    `res.redirect(req.query.url)` 처럼 사용자 입력 URL을 검증 없이 그대로
    리다이렉트하면 피싱·자격증명 탈취 사이트로 자동 연결됩니다. 공공 민원
    포털·SSO 콜백·이메일 링크 등 정상 도메인 신뢰를 이용해 시민을 속이는
    공격에 직접 이용됩니다.
  public_sector_impact:
    - 공공 도메인을 발판으로 한 피싱 공격
    - SSO 콜백 도용으로 인한 토큰 탈취
    - 공식 사이트 신뢰 손상
  safe_fix: |
    리다이렉트 대상은 서버측 화이트리스트로 관리하세요.
    const ALLOW = new Set(["/dashboard", "https://www.example.gov.kr"]);
    if (!ALLOW.has(url)) return res.status(400).send("invalid url");
    res.redirect(url);
    // 또는 상대경로만 허용: if (!url.startsWith("/") || url.startsWith("//")) reject;
  references:
    - KISA JavaScript 가이드 제1절 7
    - MOIS-49-INPUT-07
    - CWE-601
    - OWASP Unvalidated Redirects and Forwards Cheat Sheet
  can_auto_fix: false
examples:
  language: javascript
  positive:
    - "res.redirect(req.query.url);"
    - "res.redirect(`${req.query.next}`);"
    - "window.location.href = new URLSearchParams(location.search).get('next');"
  negative:
    - "const ALLOW = new Set(['/home']); if (ALLOW.has(url)) res.redirect(url);"
    - "res.redirect('/dashboard');"
    - "window.location.href = '/login';"
---

## 무엇이 위험한가
ExpressJS `res.redirect()`나 브라우저 `location.href = ...`에 사용자가 제어 가능한 URL을 그대로 넣으면, 공격자가 정상 도메인 링크처럼 보이는 URL로 시민을 피싱 사이트에 보냅니다. 가이드 §제1절 7은 *모든 리다이렉션은 서버 측 화이트리스트로 관리해야 한다*고 명시합니다.

## 안전한 패턴 (가이드 원문 인용)
```javascript
const express = require('express');
const whitelist = ["http://safe-site.com", "https://www.example.com"];
router.get("/patched", (req, res) => {
  const url = req.query.url;
  if (whitelist.indexOf(url) < 0) {
    return res.send("wrong url");
  }
  res.redirect(url);
});
```

## False positive 주의
- 정적 문자열(`res.redirect('/login')`)은 패턴이 `req.`/`request.`를 요구하므로 매칭되지 않습니다.
- `location.href = '/somewhere'` 처럼 좌변에 리터럴을 대입하는 케이스는 매칭에서 제외합니다.
- 라이브러리 내부에서 `location.href = location.origin + path` 형태를 쓰는 경우는 의도적인 매칭이며, 검증된 origin인지 확인이 필요합니다.
