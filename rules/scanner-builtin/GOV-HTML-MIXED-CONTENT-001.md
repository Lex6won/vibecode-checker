---
id: GOV-HTML-MIXED-CONTENT-001
title_ko: HTTP 혼합 콘텐츠 - HTTPS 페이지에서 http:// 리소스 로드
title_en: Mixed content - http:// resource loaded on an HTTPS page
status: approved
source_layer: baseline
sources:
  - publisher: OWASP
    document: Transport Layer Security Cheat Sheet
  - publisher: 행정안전부
    document: 전자정부 웹사이트 구축·운영 가이드
severity: medium
decision_default: warn
domains: [web-appsec]
languages: [html]
scenarios: [web-app]
related_baseline: [CWE-319]
verified_at: 2026-06-13
review_due: 2026-12-13
detection:
  patterns:
    # HTTPS 페이지에 http:// 로 외부 스크립트/리소스를 로드 — 변조·도청 위험.
    - '<script[^>]+src\s*=\s*["'']http://'
    - '<(?:link|img|iframe)[^>]+(?:src|href)\s*=\s*["'']http://'
  category: misconfig
  why_it_matters: >-
    HTTPS 페이지가 `<script src="http://...">`처럼 http:// 리소스를 불러오면,
    중간자 공격으로 그 리소스가 변조·주입될 수 있고 통신이 도청됩니다. 특히
    스크립트 혼합 콘텐츠는 페이지 전체 무결성을 무너뜨립니다.
  public_sector_impact:
    - 외부 스크립트 변조로 화면·동작 조작
    - 행정 서비스 통신 도청
    - 브라우저 혼합 콘텐츠 차단으로 기능 장애
  safe_fix: |
    모든 외부 리소스를 https:// 로 로드하세요. 가능하면 프로토콜 상대 경로보다
    명시적 https를 쓰고, 무결성 검증(SRI)을 추가하세요.
        <script src="https://cdn.example.com/lib.js"
                integrity="sha384-..." crossorigin="anonymous"></script>
  references:
    - OWASP Transport Layer Security Cheat Sheet
    - CWE-319 Cleartext Transmission of Sensitive Information
  can_auto_fix: false
examples:
  language: html
  positive:
    - "<script src=\"http://cdn.example.com/lib.js\"></script>"
  negative:
    - "<script src=\"https://cdn.example.com/lib.js\"></script>"
    - "<script src=\"main.js\"></script>"
---

## 무엇이 위험한가
HTTPS로 제공되는 페이지가 `http://` 리소스를 불러오면, 그 구간은 암호화되지 않아 중간자가 내용을 보거나 바꿀 수 있습니다. 특히 외부 스크립트가 http로 로드되면 공격자가 임의 코드를 주입해 페이지 전체를 장악할 수 있습니다.

## 안전한 패턴
```html
<!-- 항상 https + 무결성 검증(SRI) -->
<script src="https://cdn.example.com/lib.js"
        integrity="sha384-..." crossorigin="anonymous"></script>
```
