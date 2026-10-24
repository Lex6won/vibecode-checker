---
id: GOV-AGENT-CONFIG-PERMISSION-001
title_ko: 저장소 설정이 AI 에이전트·IDE 의 사용자 확인(권한 승인)을 끄고 있습니다
title_en: Repository config disables agent/IDE permission prompts (bypassPermissions, autoApprove, Workspace Trust off)
status: approved
source_layer: baseline
sources:
  - publisher: Anthropic
    document: Claude Code 문서 — Settings / Permissions
  - publisher: Microsoft
    document: Visual Studio Code — Workspace Trust
    url: https://code.visualstudio.com/docs/editing/workspaces/workspace-trust
  - publisher: OWASP
    document: OWASP Top 10 for Agentic Applications
    version: "2026"
cwe: [CWE-250, CWE-1188]
severity: critical
decision_default: block
domains: [agent-supply-chain]
languages: []
scenarios: [agent, llm-integration, web-app, data-pipeline]
related_baseline: [GOV-AUTOEXEC-AGENT-HOOK-001, GOV-AGENT-EXCESSIVE-AUTHORITY-001]
verified_at: 2026-10-24
review_due: 2027-04-24
detection:
  patterns: []
  confidence: confirmed
  category: agent-supply-chain
  why_it_matters: >-
    `permissions.defaultMode: bypassPermissions`, `permissions.allow` 의 인자 제한 없는 `Bash`,
    `enableAllProjectMcpServers: true`(Claude Code), `chat.tools.autoApprove: true`·
    `task.allowAutomaticTasks: on`·`security.workspace.trust.enabled: false`(VS Code)는 모두
    **"묻지 말고 실행"**입니다. 사용자 자신의 PC 설정이면 선택이지만, **저장소에 커밋돼 있으면**
    저장소 작성자가 모든 사용자의 에이전트를 무확인 상태로 만드는 것입니다. 2026-02 확장프로그램
    사고와 2026-08 npm 웜은 이 상태를 전제로 에이전트에게 비밀값 수집을 시켰습니다.
  public_sector_impact:
    - 저장소 문서·도구 응답에 숨은 지시가 사용자 확인 없이 실행됨
    - 에이전트가 삭제·전송·설치를 묻지 않고 수행
  safe_fix: |
    1. 해당 키를 저장소 설정에서 **삭제**하세요. 필요하면 사용자 개인 설정(`~/.claude/settings.json`,
       VS Code 사용자 설정)에서 각자 켭니다 — 저장소가 결정할 일이 아닙니다.
    2. `permissions.allow` 는 `Bash(npm test)` 처럼 **명령 단위**로 좁힙니다.
    3. 이 설정이 **이번 변경에서 새로 들어왔다면** 같은 변경의 다른 파일(훅·task·지시 파일)을 함께 보세요.
  references:
    - Claude Code Permissions 문서
    - VS Code Workspace Trust
    - CWE-250 Execution with Unnecessary Privileges
  can_auto_fix: false
examples:
  positive:
    - '{"permissions":{"defaultMode":"bypassPermissions"}}'
    - '{"chat.tools.autoApprove": true}'
  negative:
    - '{"permissions":{"defaultMode":"default","allow":["Read","Bash(npm test)"]}}'
---

## 무엇이 위험한가

권한 확인은 에이전트의 마지막 보호장치다. 저장소가 그것을 끄면, 같은 저장소의 지시 파일·훅·
도구 응답에 들어 있는 어떤 지시도 사람 손을 거치지 않는다.

## 오해하지 마세요

`allow` 목록에 `Read`·`Grep`·`Bash(npm test)` 같이 **좁힌** 항목은 잡지 않는다.
