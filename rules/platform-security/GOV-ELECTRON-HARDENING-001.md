---
id: GOV-ELECTRON-HARDENING-001
title_ko: Electron 배포 강화 설정이 빠져 있습니다 (fuses · 내비게이션/권한 핸들러)
title_en: Electron hardening gaps (fuses not configured, navigation/permission handlers missing with remote content)
status: approved
source_layer: baseline
sources:
  - publisher: Electron
    document: Electron Fuses
    url: https://www.electronjs.org/docs/latest/tutorial/fuses
  - publisher: Electron
    document: Security — Checklist
    url: https://www.electronjs.org/docs/latest/tutorial/security/
cwe: [CWE-1188]
severity: medium
decision_default: warn
domains: [platform-security]
languages: [javascript, typescript]
scenarios: [web-app, agent]
related_baseline: [GOV-ELECTRON-WEBPREFS-001, GOV-RUNTIME-EOL-001]
verified_at: 2026-10-25
review_due: 2027-04-25
detection:
  # ecosystem-surface 수집기. 빌드 설정(forge.config.* · electron-builder.*)에 fuses 가 없거나 항목이 빠짐 ·
  # 원격 콘텐츠를 로드하는 파일에 setWindowOpenHandler/will-navigate·setPermissionRequestHandler 가 없음. 전부 경고(기관 검토).
  patterns: []
  confidence: likely
  category: platform-security
  why_it_matters: >-
    Electron fuses 는 배포본의 Node 실행 옵션(RunAsNode·NODE_OPTIONS·inspect)을 끄고 ASAR 무결성(OnlyLoadAppFromAsar·
    EmbeddedAsarIntegrityValidation)을 켜는 빌드 시점 설정입니다. 원격 콘텐츠를 로드하는 창은 새 창·내비게이션·권한
    요청을 핸들러로 통제해야 합니다. 둘 다 Electron 공식 권고이며, 없으면 운영 배포 전 검토 대상입니다.
  public_sector_impact:
    - 배포된 데스크톱 앱이 실행 환경 변수나 번들 변조에 노출될 수 있음
  safe_fix: |
    1. `@electron/fuses` 또는 Forge `FusesPlugin` 으로 RunAsNode·EnableNodeOptionsEnvironmentVariable·EnableNodeCliInspectArguments 를 끄고
       OnlyLoadAppFromAsar·EnableEmbeddedAsarIntegrityValidation 을 켜세요.
    2. 원격 콘텐츠 창에는 `setWindowOpenHandler`, `will-navigate` 핸들러, `session.setPermissionRequestHandler` 를 두세요.
    3. Electron 버전은 지원 중 3개 메이저 안에 두세요(GOV-RUNTIME-EOL-001).
  references:
    - Electron Fuses
    - Electron Security Checklist
  can_auto_fix: false
examples:
  positive:
    - "module.exports = { packagerConfig: { asar: true }, makers: [] };"
  negative:
    - "const { FusesPlugin } = require('@electron-forge/plugin-fuses');\nconst { FuseV1Options } = require('@electron/fuses');\nmodule.exports = { plugins: [new FusesPlugin({ [FuseV1Options.RunAsNode]: false, [FuseV1Options.EnableNodeOptionsEnvironmentVariable]: false, [FuseV1Options.EnableNodeCliInspectArguments]: false, [FuseV1Options.OnlyLoadAppFromAsar]: true, [FuseV1Options.EnableEmbeddedAsarIntegrityValidation]: true })] };"
---

빌드 시점 강화(fuses)와 원격 콘텐츠 창의 핸들러 — Electron 공식 권고 항목이다. 경고(검토)로 올린다.
