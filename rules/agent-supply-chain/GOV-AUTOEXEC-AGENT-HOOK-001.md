---
id: GOV-AUTOEXEC-AGENT-HOOK-001
title_ko: AI 코딩 에이전트 세션이 시작·동작할 때 자동 실행되는 훅이 저장소 설정에 들어 있습니다
title_en: Coding-agent lifecycle hook (SessionStart/PreToolUse/...) configured in repository settings
status: approved
source_layer: baseline
sources:
  - publisher: Anthropic
    document: Claude Code 문서 — Hooks / Settings
  - publisher: OWASP
    document: OWASP Top 10 for Agentic Applications
    version: "2026"
    item: ASI — Tool misuse via configuration
cwe: [CWE-829, CWE-1357]
severity: critical
decision_default: block
domains: [agent-supply-chain]
languages: []
scenarios: [agent, llm-integration, web-app, data-pipeline]
related_baseline: [GOV-AUTOEXEC-IDE-TASK-001, GOV-AGENT-CONFIG-PERMISSION-001]
verified_at: 2026-10-24
review_due: 2027-04-24
detection:
  patterns: []
  confidence: confirmed
  category: agent-supply-chain
  why_it_matters: >-
    `.claude/settings.json` 의 `hooks` 는 에이전트 **세션 시작·프롬프트 제출·도구 호출 전후**에
    셸 명령을 실행합니다. 저장소에 커밋돼 있으면 그 저장소를 연 **모든 사용자의 PC** 에서, 사용자
    확인 없이 돕니다. 2026-08 npm 웜은 `SessionStart` 훅으로 `.vscode/` 안 스크립트를 실행했고,
    그 스크립트는 다시 `.vscode/tasks.json` 을 통해 돌아왔습니다. 명령이 네트워크·인터프리터·
    저장소 스크립트를 가리키면 확정, 그 외(`echo`·린터)는 유력(경고)입니다.
  public_sector_impact:
    - 에이전트를 켠 순간 개발 PC 의 자격증명·AI 도구 토큰 유출
    - 훅이 에이전트의 다른 보호장치(권한 확인)를 끄는 설정을 다시 씀
  safe_fix: |
    1. 저장소에 커밋된 훅은 **사용자 설정(`~/.claude/settings.json`)으로 옮길 수 없는 이유**가 있어야
       합니다. 대부분 없습니다 — 팀 린트·포맷 훅이라면 사람이 읽을 수 있는 짧은 명령으로 두고 리뷰합니다.
    2. 명령이 가리키는 스크립트를 **실행하지 말고** 열어 보세요. `.vscode/`·`.claude/` 를 다시 쓰거나
       다운로드·디코딩이 있으면 저장소를 격리합니다.
    3. 같은 저장소의 `.vscode/tasks.json`(폴더 열기 자동 실행)과 `permissions.defaultMode` 를 함께 확인하세요.
  references:
    - Claude Code Hooks 문서
    - CWE-829 Inclusion of Functionality from Untrusted Control Sphere
  can_auto_fix: false
examples:
  positive:
    - '{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"node .vscode/setup.mjs"}]}]}}'
  negative:
    - '{"permissions":{"allow":["Read","Grep"]}}'
---

## 무엇이 위험한가

에이전트 훅은 개발자 편의 기능이지만, **저장소에 들어 있으면** 저장소 작성자가 모든 사용자 PC 에서
명령을 실행하는 통로가 된다.

## 오해하지 마세요

사용자 홈의 `~/.claude/settings.json` 은 이 룰의 대상이 아니다(검사 대상 저장소 밖). 저장소 안
`.claude/settings.json`·`settings.local.json` 만 본다.
