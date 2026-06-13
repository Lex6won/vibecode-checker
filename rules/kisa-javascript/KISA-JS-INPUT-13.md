---
id: KISA-JS-INPUT-13
title_ko: 반사형 XSS - Express 응답에 사용자 입력 직접 결합 (res.send/write/end)
title_en: Reflected XSS via user input in Express response (res.send/write/end)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: JavaScript 시큐어코딩 가이드(2023년 개정본)
    item: 제1절 4. 크로스사이트 스크립트
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-04
severity: high
decision_default: warn
domains: [web-appsec]
languages: [javascript, typescript]
scenarios: [web-app]
related_baseline: [MOIS-49-INPUT-04]
verified_at: 2026-06-13
review_due: 2026-12-13
detection:
  patterns:
    # res.send/res.write/res.end 에 req.query/params/body 를 같은 라인에서 결합.
    # res.json 은 자동 escape 되므로 제외한다.
    - 'res\.(?:send|write|end)\s*\([^)]*req\.(?:query|params|body)'
  category: kisa-secure-coding
  why_it_matters: >-
    Express에서 `res.send("<div>"+req.query.name+"</div>")`처럼 요청 값을 응답
    HTML에 그대로 반영하면 입력이 스크립트로 실행되는 반사형 XSS가 발생합니다.
    `res.json`은 자동 escape되지만 `res.send`/`res.write`는 그렇지 않습니다.
  public_sector_impact:
    - 민원인 세션 탈취·쿠키 유출
    - 관리자 화면 스크립트 실행
    - 피싱·화면 변조
  safe_fix: |
    사용자 입력을 HTML로 반환하지 말고 이스케이프하거나 구조화 응답을 쓰세요.
        res.json({ name: String(req.query.name || "") });   // 자동 escape
    템플릿 엔진은 자동 escape를 켜고(예: EJS <%= %>), 출력 인코딩 라이브러리
    (he, DOMPurify)를 사용하세요.
  references:
    - KISA JavaScript 가이드 제1절 4
    - MOIS-49-INPUT-04
    - CWE-79 Cross-site Scripting
  can_auto_fix: false
examples:
  language: javascript
  positive:
    - "app.get('/h', (req,res)=>{ res.send('<div>'+req.query.name+'</div>'); });"
    - "res.write(req.params.id);"
  negative:
    - "res.json({ name: String(req.query.name || '') });"
    - "res.send('<div>static safe</div>');"
---

## 무엇이 위험한가
`res.send("<div>안녕하세요, " + req.query.name + "</div>")`처럼 요청 파라미터를 응답 HTML에 직접 붙이면, `req.query.name`에 `<script>...</script>`를 넣은 요청으로 피해자 브라우저에서 임의 스크립트가 실행됩니다(반사형 XSS).

## 안전한 패턴
```javascript
// 구조화 응답 — res.json은 자동 escape
res.json({ name: String(req.query.name || "") });

// HTML이 꼭 필요하면 출력 인코딩
const he = require("he");
res.send(`<div>${he.encode(req.query.name || "")}</div>`);
```
