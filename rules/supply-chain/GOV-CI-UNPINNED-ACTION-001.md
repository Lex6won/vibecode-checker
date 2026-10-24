---
id: GOV-CI-UNPINNED-ACTION-001
title_ko: 서드파티 GitHub Action 을 commit SHA 가 아닌 태그·브랜치로 참조합니다
title_en: Third-party GitHub Action referenced by mutable tag or branch instead of a commit SHA
status: approved
source_layer: baseline
sources:
  - publisher: GitHub
    document: Security hardening for GitHub Actions — Using third-party actions
    url: https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions
  - publisher: StepSecurity
    document: tj-actions/changed-files compromise (2025-03) — tags re-pointed to malicious commit
cwe: [CWE-829, CWE-494]
severity: medium
decision_default: warn
domains: [supply-chain]
languages: []
scenarios: [web-app, data-pipeline, agent, llm-integration, package-install]
related_baseline: [GOV-CI-REMOTE-EXEC-001]
verified_at: 2026-10-24
review_due: 2027-04-24
detection:
  # 공식 액션(actions/*·github/*)은 잡지 않는다. 가변 브랜치(@main)·태그(@v4) 모두 유력(경고).
  patterns: []
  confidence: likely
  category: supply-chain
  why_it_matters: >-
    `uses: someone/action@v4` 의 `v4` 는 **태그**이고, 태그는 다시 밀 수 있습니다. 2025-03 tj-actions 사고에서
    공격자가 기존 태그 전부를 악성 커밋으로 옮겨, 그 액션을 쓰던 2만여 저장소의 CI 가 비밀값을 로그에 썼습니다.
    `@main` 은 더 나쁩니다 — 매 실행이 다른 코드입니다. 40자리 commit SHA 는 바꿀 수 없습니다.
    공식 `actions/*`·`github/*` 는 GitHub 가 관리하므로 이 룰에서 제외합니다(경고 피로 방지).
  public_sector_impact:
    - 액션 저장소 한 곳의 탈취가 기관의 모든 CI 에 동시에 전파
  safe_fix: |
    `uses: owner/action@<40자리 SHA>  # v4.1.2` 처럼 SHA 로 고정하고 주석에 버전을 적으세요. Dependabot 의
    `github-actions` 생태계를 켜면 SHA 갱신 PR 이 자동으로 옵니다.
  references:
    - GitHub Docs — Using third-party actions
  can_auto_fix: false
examples:
  positive:
    - "      - uses: peter-evans/create-pull-request@v6"
  negative:
    - "      - uses: peter-evans/create-pull-request@c5a7806660adbe173f04e3e038b0ccdcd758773c  # v6\n      - uses: actions/checkout@v4"
---

## 무엇이 위험한가

태그는 이름이고 SHA 는 내용이다. 이름은 바뀔 수 있다.

## 오해하지 마세요

`actions/*`·`github/*` 공식 액션, 로컬 액션(`./`), `docker://` 참조는 잡지 않는다. 40자리 SHA 고정은 통과한다.
