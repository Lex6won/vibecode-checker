---
id: GOV-AUTOEXEC-IDE-TASK-001
title_ko: 폴더를 열면 자동 실행되는 VS Code task 가 저장소에 들어 있습니다
title_en: VS Code task configured to run on folder open (runOn folderOpen)
status: approved
source_layer: baseline
sources:
  - publisher: Microsoft
    document: Visual Studio Code — Workspace Trust
    url: https://code.visualstudio.com/docs/editing/workspaces/workspace-trust
  - publisher: Microsoft
    document: Visual Studio Code — Tasks (runOptions.runOn)
cwe: [CWE-829, CWE-1357]
severity: critical
decision_default: block
domains: [agent-supply-chain]
languages: []
scenarios: [web-app, data-pipeline, agent, llm-integration, package-install]
related_baseline: [GOV-AUTOEXEC-AGENT-HOOK-001, GOV-AGENT-CONFIG-PERMISSION-001]
verified_at: 2026-10-24
review_due: 2027-04-24
detection:
  # 파일(.vscode/tasks.json)의 구조를 읽어야 판정된다 — autoexec-surface 엔진이 발행한다.
  # 일반 소스 스캔은 .vscode 를 제외한다(오탐 억제). 이 룰은 그 제외와 무관하게 이름으로 찾는다.
  patterns: []
  confidence: confirmed
  category: agent-supply-chain
  why_it_matters: >-
    `"runOptions": {"runOn": "folderOpen"}` 이 붙은 task 는 저장소를 VS Code 로 **여는 순간** 실행됩니다
    (Workspace Trust 를 신뢰로 두면 묻지도 않습니다). 2026-08 npm 웜은 이 task 로 `.claude/` 안
    스크립트를 실행하고, 그 스크립트가 다시 에이전트 세션 훅을 심어 **서로를 재실행**했습니다.
    명령이 네트워크에서 받아 실행하거나(curl·wget·bun), 인터프리터에 코드 문자열을 넘기거나
    (`node -e`·`python -c`), 저장소 안 스크립트를 가리키면 **확정(confirmed)**입니다. `npm run watch`
    처럼 평범한 명령이면 **유력(likely)**으로 경고만 합니다 — 빌드 감시용 정상 용례가 있습니다.
  public_sector_impact:
    - 저장소를 내려받아 여는 것만으로 개발 PC 가 감염 — 자격증명·토큰 유출
    - 감염된 PC 의 토큰으로 기관 저장소·패키지에 재전파
  safe_fix: |
    1. 그 task 가 **왜 폴더 열기에 실행돼야 하는지** 작성자에게 확인하세요. 대부분은 필요 없습니다 —
       `runOptions.runOn` 을 지우고 사용자가 직접 실행하게 바꿉니다.
    2. 명령이 가리키는 스크립트(`.claude/`·`.vscode/` 안 `.mjs`·`.sh`)를 **실행하지 말고** 열어 보세요.
       다운로드·디코딩·다른 설정 파일 쓰기가 있으면 그 저장소 전체를 격리합니다.
    3. VS Code 설정에서 `task.allowAutomaticTasks` 가 `on` 이면 `off` 로 두고, 신뢰하지 않는
       저장소는 **제한 모드(Restricted Mode)**로 여세요.
  references:
    - VS Code Workspace Trust
    - CWE-829 Inclusion of Functionality from Untrusted Control Sphere
  can_auto_fix: false
examples:
  positive:
    - '{"tasks":[{"label":"setup","type":"shell","command":"node .claude/setup.mjs","runOptions":{"runOn":"folderOpen"}}]}'
  negative:
    - '{"tasks":[{"label":"build","type":"npm","script":"build"}]}'
---

## 무엇이 위험한가

"열기"가 "실행"이 된다. 공무원이 외주사 저장소·GitHub 샘플을 내려받아 VS Code 로 여는 순간이
감염 시점이다. 코드를 한 줄도 읽기 전이다.

## 이 발견을 보면 확인할 것

| 확인 | 왜 |
|---|---|
| task 의 `command`·`args` | 네트워크·인터프리터·저장소 스크립트면 확정 |
| 가리키는 스크립트의 내용 | **실행하지 말고** 읽기 — 다운로드·디코딩·설정 쓰기 여부 |
| `.claude/settings.json` 의 hooks | 2026-08 수법은 둘이 짝이다(GOV-AUTOEXEC-AGENT-HOOK-001) |

## 오해하지 마세요

`runOn: folderOpen` 이 없는 빌드·테스트 task 는 잡지 않는다. 있어도 `npm run watch` 같은 명령은
경고(검토)까지만이다.
