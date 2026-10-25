---
id: GOV-CHROME-EXT-MESSAGE-001
title_ko: 브라우저 확장 메시지 핸들러가 발신자 검증 없이 민감 API 를 호출합니다
title_en: Browser extension message handler calls sensitive APIs without validating the sender
status: approved
source_layer: baseline
sources:
  - publisher: Google
    document: Chrome Extensions — Message passing (security considerations)
    url: https://developer.chrome.com/docs/extensions/develop/concepts/messaging
cwe: [CWE-346, CWE-749]
severity: high
decision_default: block
domains: [platform-security]
languages: [javascript, typescript]
scenarios: [web-app]
related_baseline: [GOV-CHROME-EXT-PERMISSION-001]
verified_at: 2026-10-25
review_due: 2027-04-25
detection:
  # ecosystem-surface 수집기. runtime.onMessage / onMessageExternal 리스너 근처에서 chrome.cookies·scripting·tabs.executeScript·
  # history·storage·downloads 또는 fetch 를 호출하면서 sender.id/origin/url 검증이 없음. External 이면 confirmed, 내부면 likely.
  patterns: []
  confidence: likely
  category: platform-security
  why_it_matters: >-
    메시지 전달 가이드는 `onMessageExternal` 과 콘텐츠 스크립트 메시지를 받을 때 `sender` 의 id·origin·url 을 확인하고 메시지
    필드를 검증한 뒤 민감 API 를 쓰도록 안내합니다. 이 룰은 그 검증이 빠진 핸들러를 표시합니다.
  public_sector_impact:
    - 웹페이지가 확장을 통해 쿠키·탭·스크립트 API 에 닿을 수 있는 경계
  safe_fix: |
    1. 리스너 첫 줄에서 `sender.id === chrome.runtime.id`(내부) 또는 허용 출처 목록과 `sender.origin`/`sender.url` 을 대조하세요.
    2. `message.type` 으로 분기하고 각 분기의 인자를 검증한 뒤에만 `chrome.cookies`·`scripting`·`tabs` API 를 호출하세요.
  references:
    - Chrome Extensions — Message passing
    - CWE-346 Origin Validation Error
  can_auto_fix: false
examples:
  positive:
    - "chrome.runtime.onMessageExternal.addListener((msg, sender, reply) => { chrome.cookies.getAll({}, reply); });"
  negative:
    - "chrome.runtime.onMessageExternal.addListener((msg, sender, reply) => { if (!ALLOWED_ORIGINS.includes(sender.origin)) return; if (msg.type === 'ping') reply('ok'); });"
---

발신자 검증과 타입 분기가 있는 핸들러는 잡지 않는다.
