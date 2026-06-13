---
id: GOV-HTML-DOM-XSS-001
title_ko: DOM 기반 XSS - 인라인 스크립트에서 location 값을 그대로 출력
title_en: DOM-based XSS - inline script writes location into the page
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: JavaScript 시큐어코딩 가이드(2023년 개정본)
    item: 제1절 4. 크로스사이트 스크립트
  - publisher: OWASP
    document: DOM based XSS Prevention Cheat Sheet
severity: high
decision_default: block
domains: [web-appsec]
languages: [html]
scenarios: [web-app]
related_baseline: [CWE-79]
verified_at: 2026-06-13
review_due: 2026-12-13
detection:
  patterns:
    # HTML 인라인 <script> 안에서 location/URL/window.name 같은 공격자 제어
    # 입력을 document.write / innerHTML 로 그대로 출력하는 패턴.
    - 'document\.write(?:ln)?\s*\([^)]*location\.'
    - '\.innerHTML\s*=[^;]*location\.'
    - 'document\.write(?:ln)?\s*\([^)]*(?:document\.URL|window\.name)'
  category: xss
  why_it_matters: >-
    HTML 인라인 스크립트가 `document.write(location.hash)`처럼 URL 조각을 그대로
    페이지에 쓰면, 공격자가 만든 링크로 피해자 브라우저에서 스크립트가 실행되는
    DOM 기반 XSS가 발생합니다. 서버를 거치지 않아 서버측 필터로 막히지 않습니다.
  public_sector_impact:
    - 민원 포털 세션·쿠키 탈취
    - 악성 링크 클릭 시 화면 변조
    - 관리자 페이지 스크립트 실행
  safe_fix: |
    location.hash/search/URL 등은 신뢰할 수 없는 입력입니다. document.write·
    innerHTML 대신 textContent를 쓰고, 필요한 경우 DOMPurify로 정제하세요.
        const v = new URLSearchParams(location.search).get("q") || "";
        el.textContent = v;            // 스크립트 실행 안 됨
  references:
    - KISA JavaScript 가이드 제1절 4
    - OWASP DOM based XSS Prevention Cheat Sheet
    - CWE-79 Cross-site Scripting
  can_auto_fix: false
examples:
  language: html
  positive:
    - "<script>document.write(location.hash.substring(1));</script>"
  negative:
    - "<script>document.write('정적 안내 문구');</script>"
---

## 무엇이 위험한가
`document.write(location.hash.substring(1))`은 URL의 `#` 뒤 값을 그대로 페이지에 씁니다. 공격자가 `https://site/#<img src=x onerror=alert(1)>` 같은 링크를 피해자에게 보내면 그 스크립트가 실행됩니다. 서버를 거치지 않는 DOM 기반 XSS라 서버측 입력 필터로는 막히지 않습니다.

## 안전한 패턴
```html
<script>
  const q = new URLSearchParams(location.search).get("q") || "";
  document.getElementById("out").textContent = q;  // textContent는 스크립트 미실행
</script>
```
