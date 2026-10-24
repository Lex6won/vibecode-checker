---
id: GOV-CI-PWN-REQUEST-001
title_ko: CI 워크플로가 저장소 권한을 가진 채 외부 PR 의 코드를 체크아웃해 실행합니다
title_en: Privileged workflow (pull_request_target / workflow_run) checks out and executes untrusted PR code
status: approved
source_layer: baseline
sources:
  - publisher: GitHub
    document: Securely using pull_request_target
    url: https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target
  - publisher: GitHub Security Lab
    document: Keeping your GitHub Actions and workflows secure — Preventing pwn requests
cwe: [CWE-829, CWE-284]
severity: critical
decision_default: block
domains: [supply-chain]
languages: []
scenarios: [web-app, data-pipeline, agent, llm-integration, package-install]
related_baseline: [GOV-CI-PERMISSIONS-001, GOV-CI-SECRETS-DUMP-001]
verified_at: 2026-10-24
review_due: 2027-04-24
detection:
  # .github/workflows/*.yml 을 구조로 읽는다(ci-workflow 판정기). 트리거 + checkout ref + 이후 실행 단계를 묶어 판정.
  patterns: []
  confidence: confirmed
  category: supply-chain
  why_it_matters: >-
    `pull_request_target`·`workflow_run` 트리거는 **기본 브랜치의 권한**(쓰기 토큰·secrets)으로 돕니다. 그 잡이
    `actions/checkout` 에 `ref: ${{ github.event.pull_request.head.sha }}` 처럼 PR 쪽 코드를 받아 `run`·설치·빌드·
    테스트를 하면, 외부인이 PR 하나로 저장소 비밀값과 쓰기 권한을 얻습니다(2026-03 Trivy 태그 하이재킹,
    2026-05 TanStack — 오염된 Actions 캐시가 릴리스 파이프라인까지 번짐). PR 코드를 체크아웃하지 않는
    라벨·코멘트 작업은 정상 용례이며 잡지 않습니다. 체크아웃만 하고 실행이 없으면 유력(경고)입니다.
  public_sector_impact:
    - 외부 PR 한 건으로 기관 저장소의 비밀값·배포 토큰 유출
    - 오염된 빌드 캐시가 정식 릴리스에 섞여 배포본 전체가 오염
  safe_fix: |
    1. 외부 PR 코드를 **실행해야** 하면 `pull_request` 트리거(권한 없는 fork 컨텍스트)로 바꾸세요.
    2. `pull_request_target` 이 꼭 필요하면 PR 코드를 체크아웃하지 말고(라벨·코멘트만), 체크아웃이 필요하면
       두 잡으로 나눠 **실행 잡에는 secrets·쓰기 권한을 주지 마세요**.
    3. 같은 잡에서 `actions/cache`·`setup-*` 의 `cache:` 를 쓰지 마세요 — PR 코드가 캐시를 오염시키면 다른 워크플로가 복원합니다.
    4. `permissions:` 를 잡 단위로 최소화(`contents: read`)하세요.
  references:
    - GitHub Docs — Securely using pull_request_target
    - CWE-829 Inclusion of Functionality from Untrusted Control Sphere
  can_auto_fix: false
examples:
  positive:
    - "on: pull_request_target\njobs:\n  t:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - run: npm ci && npm test"
  negative:
    - "on: pull_request_target\njobs:\n  l:\n    steps:\n      - uses: actions/github-script@v7\n        with:\n          script: github.rest.issues.addLabels({...})"
---

## 무엇이 위험한가

"PR 을 받는 것"과 "PR 코드를 저장소 권한으로 실행하는 것"은 다르다. 후자는 저장소 관리자 권한을 PR 작성자에게
빌려주는 것과 같다.

## 오해하지 마세요

`pull_request_target` 자체는 잡지 않는다. PR 코드를 **체크아웃하고 실행**할 때만 확정이다.
