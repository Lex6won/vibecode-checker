---
id: GOV-CI-REMOTE-EXEC-001
title_ko: CI 가 원격 스크립트를 내려받아 검증 없이 바로 실행합니다 (curl | sh)
title_en: Workflow pipes a downloaded script straight into a shell (curl | sh, iwr | iex)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: 소프트웨어 개발보안 가이드
    item: 무결성 검사 없는 코드 다운로드
  - publisher: OWASP
    document: CI/CD Security Cheat Sheet
cwe: [CWE-494, CWE-829]
severity: high
decision_default: block
domains: [supply-chain]
languages: []
scenarios: [web-app, data-pipeline, agent, llm-integration, package-install]
related_baseline: [KISA-PY-SEC-15, KISA-JS-SEC-15]
verified_at: 2026-10-24
review_due: 2027-04-24
detection:
  # KISA-*-SEC-15 는 Python/JS 소스의 같은 패턴을 본다. 이 룰은 워크플로 YAML 의 run 블록(ci-workflow 판정기).
  patterns: []
  confidence: confirmed
  category: supply-chain
  why_it_matters: >-
    `curl -sSL https://… | sh`, `iwr … | iex` 는 **그 순간 서버가 주는 것**을 러너 권한으로 실행합니다. 해시·서명
    검증이 없고, 재현도 안 됩니다(어제와 오늘 받은 스크립트가 다를 수 있음). 2026-03 Trivy 사고에서 설치 스크립트
    채널(태그·릴리스)이 통째로 바뀌었습니다 — 이런 한 줄이 있는 모든 CI 가 그날 악성 코드를 실행했습니다.
  public_sector_impact:
    - 외부 서버 한 곳의 침해가 기관 CI 전체로 전파
    - 러너의 토큰·배포 자격증명 유출
  safe_fix: |
    1. 스크립트를 **저장소에 고정**(버전·해시 기록)하거나, 공식 GitHub Action(commit SHA 고정)으로 대체하세요.
    2. 꼭 내려받아야 하면 파일로 받고 `sha256sum -c` 로 검증한 뒤 실행하세요.
  references:
    - CWE-494 Download of Code Without Integrity Check
  can_auto_fix: false
examples:
  positive:
    - "      - run: curl -fsSL https://get.example.com/install.sh | sh"
  negative:
    - "      - run: |\n          curl -fsSLo install.sh https://get.example.com/install.sh\n          echo \"abc123  install.sh\" | sha256sum -c -\n          sh install.sh"
---

## 무엇이 위험한가

`curl | sh` 는 "지금 이 순간 서버가 주는 것"을 실행한다. 어제 검토한 스크립트와 오늘 받는 스크립트가 같다는 보장이 없다.

## 오해하지 마세요

파일로 받아 `sha256sum -c` 로 검증한 뒤 실행하는 형태는 잡지 않는다.
