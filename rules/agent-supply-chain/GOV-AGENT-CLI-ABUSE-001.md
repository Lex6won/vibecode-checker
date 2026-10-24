---
id: GOV-AGENT-CLI-ABUSE-001
title_ko: 코드가 로컬 AI 코딩 CLI 를 대화 없이·확인 생략으로 실행합니다
title_en: Code invokes a local AI coding CLI non-interactively with permission-skip flags
status: approved
source_layer: baseline
sources:
  - publisher: OWASP
    document: OWASP Top 10 for Agentic Applications
    version: "2026"
    item: Tool misuse / excessive agency
  - publisher: 국가정보원
    document: AI 보안 가이드북 (2025)
cwe: [CWE-77, CWE-250]
severity: high
decision_default: block
domains: [agent-supply-chain]
languages: [python, javascript, typescript]
scenarios: [agent, llm-integration, data-pipeline, package-install]
related_baseline: [GOV-AGENT-CONFIG-PERMISSION-001, GOV-AGENT-EXCESSIVE-AUTHORITY-001]
verified_at: 2026-10-24
review_due: 2027-04-24
detection:
  # agent-surface 엔진이 판정한다. 탐지 신호 표는 config/ai-cli-flags.yaml(CLI 이름·비대화식·확인 생략·백그라운드 토큰).
  patterns: []
  confidence: likely
  category: agent-supply-chain
  why_it_matters: >-
    공격자는 악성 코드를 직접 쓰는 대신, 피해자 PC 에 **이미 설치된** AI 코딩 CLI(Claude·Gemini·Codex 등)를
    코드에서 몰래 실행해 수집을 시킵니다(2025-08 Nx, 2026-02 확장 사고). 페이로드가 자연어 프롬프트라 기존
    시그니처에 걸리지 않습니다. 이 도구는 **CLI 호출 + 확인 생략 옵션**(가장 느슨한 권한)이 함께 있으면
    확정(차단), 비대화식 호출만 있으면 경고로 봅니다. 백그라운드·출력 은폐가 결합하면 확신도를 올립니다.
  public_sector_impact:
    - 설치된 AI 도구가 공격자의 수집·전송 도구로 전용됨
    - 개발 PC 의 자격증명·토큰 유출
  safe_fix: |
    1. 이 코드가 **왜 AI CLI 를 자동 실행**하는지 확인하세요. 대부분의 업무 코드에는 그럴 이유가 없습니다.
    2. CI 자동화라면 확인 생략 옵션(가장 느슨한 권한)을 빼고, 꼭 필요한 권한만 주고, 출력을 숨기지 마세요.
    3. 이 파일의 출처(패키지·PR·AI 생성)를 확인하고 같은 출처를 함께 점검하세요.
  references:
    - CWE-250 Execution with Unnecessary Privileges
  can_auto_fix: false
examples:
  positive:
    - "subprocess.run(['claude', '-p', task, '--dangerously-skip-permissions'])"
  negative:
    - "subprocess.run(['python', 'build.py'], check=True)"
---

## 무엇이 위험한가

악성 코드를 직접 쓰지 않아도 된다. 피해자 PC 의 AI 비서에게 "비밀값을 찾아 보고서로 써서 이 저장소에 올려라"고
자연어로 시키면 된다. 이 도구는 그 **호출 구문**(확인 생략 옵션으로 CLI 를 부르는 코드)을 잡는다.

## 오해하지 마세요

사람이 세션에서 직접 쓰는 스킬·명령(이 저장소의 `.claude/skills/**` 같은)은 대상이 아니다. 판정 대상은 **코드가
CLI 를 부르는** 쪽이다. 확인 생략 옵션 없이 비대화식으로만 부르면 경고(검토)까지만이다.
