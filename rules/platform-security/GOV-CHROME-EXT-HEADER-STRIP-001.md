---
id: GOV-CHROME-EXT-HEADER-STRIP-001
title_ko: 브라우저 확장이 응답 보안 헤더를 제거하거나 원격 코드를 로드합니다
title_en: Browser extension strips response security headers or loads remote code
status: approved
source_layer: baseline
sources:
  - publisher: Google
    document: Chrome Extensions — Manifest V3 (remotely hosted code policy)
  - publisher: Google
    document: Chrome Extensions — declarativeNetRequest (modifyHeaders)
cwe: [CWE-693, CWE-829]
severity: critical
decision_default: block
domains: [platform-security]
languages: [javascript, typescript]
scenarios: [web-app]
related_baseline: [GOV-CHROME-EXT-PERMISSION-001]
verified_at: 2026-10-25
review_due: 2027-04-25
detection:
  # ecosystem-surface 수집기. 확정: declarativeNetRequest 규칙 또는 webRequest 코드가 응답의 Content-Security-Policy /
  # X-Frame-Options / Strict-Transport-Security 를 제거·비움 · 확장 CSP 에 unsafe-eval/원격 script-src · 원격 스크립트 로드(import(https) ·
  # 원격 <script src> · fetch→eval).
  patterns: []
  confidence: confirmed
  category: platform-security
  why_it_matters: >-
    Manifest V3 정책은 확장 코드를 패키지 안에만 두도록(원격 코드 금지) 하고, 방문 사이트의 보안 헤더를 벗기는 규칙은 사용자 보호를
    무력화하므로 스토어 심사에서 거부됩니다. 이 룰은 그 두 가지를 표시합니다.
  public_sector_impact:
    - 사용자가 방문하는 모든 사이트의 보호장치가 확장 하나로 꺼질 수 있음
  safe_fix: |
    1. 보안 헤더(CSP·X-Frame-Options·HSTS)를 제거·수정하는 `modifyHeaders` 규칙과 `webRequest` 코드를 삭제하세요.
    2. 모든 스크립트를 확장 패키지에 포함하고, `eval`/`new Function`/원격 `import()` 를 쓰지 마세요. 확장 CSP 는 기본값을 유지하세요.
  references:
    - Chrome Extensions — Manifest V3 remotely hosted code policy
    - CWE-693 Protection Mechanism Failure
  can_auto_fix: false
examples:
  positive:
    - '[{"id": 1, "action": {"type": "modifyHeaders", "responseHeaders": [{"header": "content-security-policy", "operation": "remove"}]}, "condition": {"urlFilter": "*"}}]'
  negative:
    - '[{"id": 1, "action": {"type": "block"}, "condition": {"urlFilter": "ads.example"}}]'
---

요청을 차단·리다이렉트하는 규칙은 대상이 아니다. 응답 **보안 헤더를 벗기는** 규칙과 **원격 코드 로드**만 본다.
