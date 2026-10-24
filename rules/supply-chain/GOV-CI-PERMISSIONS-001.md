---
id: GOV-CI-PERMISSIONS-001
title_ko: CI 워크플로의 토큰 권한이 과하거나 외부 PR 이 내부 러너에서 실행됩니다
title_en: Over-privileged GITHUB_TOKEN (write-all / write scopes on privileged trigger) or fork PRs on self-hosted runners
status: approved
source_layer: baseline
sources:
  - publisher: GitHub
    document: Security hardening for GitHub Actions — Permissions / self-hosted runners
    url: https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions
  - publisher: Cloud Security Alliance
    document: prt-scan GitHub Actions supply chain campaign (2026) — label-gate bypass with write token
cwe: [CWE-250, CWE-284]
severity: medium
decision_default: warn
domains: [supply-chain]
languages: []
scenarios: [web-app, data-pipeline, agent, llm-integration, package-install]
related_baseline: [GOV-CI-PWN-REQUEST-001]
verified_at: 2026-10-24
review_due: 2027-04-24
detection:
  patterns: []
  confidence: likely
  category: supply-chain
  why_it_matters: >-
    `permissions: write-all`, 또는 `pull_request_target` 같은 권한 트리거에 `contents: write`·`pull-requests: write`·
    `id-token: write` 가 붙어 있으면, 그 워크플로의 어떤 결함(스크립트 삽입·비고정 액션)도 곧바로 저장소 변조·
    패키지 게시로 이어집니다. `permissions:` 를 아예 안 적으면 저장소 기본값(쓰기일 수 있음)을 받습니다.
    `self-hosted` 러너가 외부 PR 트리거를 받으면 **기관 내부망 안의 머신**에서 비신뢰 코드가 돕니다.
  public_sector_impact:
    - 한 결함이 저장소 변조·배포까지 바로 연결
    - 내부망 러너 침해 → 내부 시스템 횡이동
  safe_fix: |
    1. 워크플로 최상위에 `permissions: contents: read` 를 두고, 쓰기가 필요한 **잡만** 범위를 올리세요.
    2. `pull_request_target`·`workflow_run` 잡에는 쓰기 권한을 주지 마세요(필요하면 잡을 분리).
    3. self-hosted 러너는 외부 PR 트리거에서 쓰지 마세요. 꼭 써야 하면 ephemeral 러너 + 승인 게이트.
  references:
    - GitHub Docs — Security hardening for GitHub Actions
    - CWE-250 Execution with Unnecessary Privileges
  can_auto_fix: false
examples:
  positive:
    - "permissions: write-all\non: pull_request_target"
  negative:
    - "permissions:\n  contents: read\non: push"
---

## 무엇이 위험한가

권한은 결함의 **폭발 반경**이다. 같은 스크립트 삽입 결함도 읽기 토큰이면 로그 유출, 쓰기 토큰이면 저장소 변조·패키지 게시가 된다.

## 오해하지 마세요

`permissions: contents: read` 를 두고 필요한 잡만 올린 워크플로는 잡지 않는다. `pull_request`(권한 없는 fork 컨텍스트) 트리거의 쓰기 권한 선언은 GitHub 이 fork 에 대해 읽기로 강제하므로 여기서는 보지 않는다.
