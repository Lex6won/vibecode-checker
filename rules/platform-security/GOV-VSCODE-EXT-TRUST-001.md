---
id: GOV-VSCODE-EXT-TRUST-001
title_ko: VS Code 확장이 신뢰 경계를 지키지 않습니다 (Workspace Trust · 설정값 실행 · webview CSP · 메시지 경계)
title_en: VS Code extension trust boundary gaps (Workspace Trust, settings-to-exec, webview CSP, message handling)
status: approved
source_layer: baseline
sources:
  - publisher: Microsoft
    document: Visual Studio Code — Workspace Trust (extension guide)
    url: https://code.visualstudio.com/api/extension-guides/workspace-trust
  - publisher: Microsoft
    document: Visual Studio Code — Webview API (security)
    url: https://code.visualstudio.com/api/extension-guides/webview
cwe: [CWE-829, CWE-79]
severity: high
decision_default: block
domains: [platform-security]
languages: [javascript, typescript]
scenarios: [agent, web-app]
related_baseline: [GOV-AUTOEXEC-IDE-TASK-001]
verified_at: 2026-10-25
review_due: 2027-04-25
detection:
  # ecosystem-surface 수집기(engines.vscode 가 있을 때만). 매니페스트: activationEvents "*"/onStartupFinished · untrustedWorkspaces
  # 미선언/supported · extensionPack(인벤토리). 소스: 설정값(path/command/args) 읽기 + 프로세스/터미널 실행(supported=true 면 confirmed) ·
  # webview enableScripts + CSP 없음/HTML 문자열 조립 · onDidReceiveMessage 근처 실행.
  patterns: []
  confidence: likely
  category: platform-security
  why_it_matters: >-
    확장 호스트는 VS Code 와 같은 권한으로 돕니다(Chrome 식 권한 모델이 없음). 그래서 VS Code 는 Workspace Trust 를 두고,
    확장이 **신뢰하지 않은 저장소의 설정값**(실행 경로·명령·인자)을 그대로 실행하지 않도록 요구합니다. webview 는 CSP 와
    메시지 검증이 공식 권고입니다. 이 룰은 그 경계가 비어 있는 자리를 가리킵니다.
  public_sector_impact:
    - 저장소를 여는 것만으로 저장소가 정한 명령이 확장 권한으로 실행될 수 있음
  safe_fix: |
    1. `capabilities.untrustedWorkspaces` 를 선언하고, 제한 모드에서는 설정값 기반 실행을 **끄거나 `restrictedConfigurations` 에 등록**하세요.
    2. 실행 경로·명령을 담는 설정은 `scope: machine` 으로 두어 저장소 `.vscode/settings.json` 이 덮어쓰지 못하게 하세요.
    3. webview 는 `localResourceRoots` 를 제한하고 CSP `<meta>` 를 넣고, HTML 은 템플릿 조립 대신 고정 파일에서 로드하세요.
    4. `onDidReceiveMessage` 는 `message.command` 를 화이트리스트로 분기하고 인자를 검증하세요.
  references:
    - VS Code Workspace Trust extension guide
    - VS Code Webview API security
  can_auto_fix: false
examples:
  positive:
    - '{"engines":{"vscode":"^1.90.0"},"activationEvents":["*"],"capabilities":{"untrustedWorkspaces":{"supported":true}}}'
  negative:
    - '{"engines":{"vscode":"^1.90.0"},"activationEvents":["onCommand:ext.run"],"capabilities":{"untrustedWorkspaces":{"supported":false}}}'
---

VS Code 공식 확장 가이드(Workspace Trust · Webview 보안)의 권고 항목에 해당한다. manifest 권한 모델이 없으므로 "설정값 → 실행" 경로 자체를 본다.
