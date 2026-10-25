---
id: GOV-CHROME-EXT-PERMISSION-001
title_ko: 브라우저 확장 manifest 의 권한·연결·업데이트 설정이 넓습니다
title_en: Browser extension manifest with broad permissions, open externally_connectable, MV2, or non-store update_url
status: approved
source_layer: baseline
sources:
  - publisher: Google
    document: Chrome Extensions — Declare permissions
    url: https://developer.chrome.com/docs/extensions/develop/concepts/declare-permissions
  - publisher: Google
    document: Chrome Extensions — Manifest V3 migration
cwe: [CWE-250, CWE-284]
severity: medium
decision_default: warn
domains: [platform-security]
languages: []
scenarios: [web-app]
related_baseline: [GOV-CHROME-EXT-HEADER-STRIP-001, GOV-CHROME-EXT-MESSAGE-001]
verified_at: 2026-10-25
review_due: 2027-04-25
detection:
  # ecosystem-surface 수집기(manifest.json 에 manifest_version 이 있을 때만). 경고: MV2 · 광역 호스트 + 민감 권한 2개 이상 ·
  # 스토어 밖 update_url. 확정: externally_connectable 이 모든 사이트/확장에 열림.
  patterns: []
  confidence: likely
  category: platform-security
  why_it_matters: >-
    확장 권한 가이드는 host_permissions 와 permissions 를 기능에 필요한 최소로 선언하고, externally_connectable 은 특정 출처로
    한정하며, Manifest V3 와 공식 스토어 업데이트 채널을 쓰도록 안내합니다. 이 룰은 그 범위를 넘는 선언을 표시합니다.
  public_sector_impact:
    - 필요 이상 넓은 권한은 확장 결함의 영향 범위를 키움
  safe_fix: |
    1. `host_permissions` 는 실제로 쓰는 사이트 패턴만, `permissions` 는 필요한 API 만 선언하세요(`<all_urls>` 지양).
    2. `externally_connectable.matches` 는 특정 출처만 나열하세요.
    3. `manifest_version: 3` 으로 옮기고 `update_url` 은 공식 스토어 주소만 쓰세요.
  references:
    - Chrome Extensions — Declare permissions
    - CWE-250 Execution with Unnecessary Privileges
  can_auto_fix: false
examples:
  positive:
    - '{"manifest_version": 3, "host_permissions": ["<all_urls>"], "permissions": ["cookies", "scripting", "tabs"]}'
  negative:
    - '{"manifest_version": 3, "host_permissions": ["https://intranet.example/*"], "permissions": ["storage"]}'
---

최소 권한으로 선언된 매니페스트는 잡지 않는다.
