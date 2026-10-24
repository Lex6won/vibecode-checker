---
id: GOV-RUNTIME-EOL-001
title_ko: 프로젝트가 지원이 끝난(또는 임박한) 런타임 버전을 선언합니다 — Node.js·Python·Electron·Next.js
title_en: "Project pins an end-of-life (or soon-EOL) runtime — Node.js / Python / Electron / Next.js major"
status: approved
source_layer: baseline
sources:
  - publisher: OpenJS Foundation
    document: Node.js Release Schedule
    url: https://nodejs.org/en/about/previous-releases
  - publisher: Python Software Foundation
    document: Status of Python versions
    url: https://devguide.python.org/versions/
  - publisher: Electron
    document: Electron Releases — supported versions
    url: https://www.electronjs.org/docs/latest/tutorial/electron-timelines
cwe: [CWE-1104, CWE-1395]
severity: high
decision_default: warn
domains: [supply-chain]
languages: []
scenarios: [web-app, data-pipeline, agent, llm-integration]
related_baseline: [GOV-RUNTIME-OUTDATED-001]
verified_at: 2026-10-24
review_due: 2027-01-24
detection:
  # runtime-version 판정기. 기준값: config/runtime-baselines.yaml(as_of 날짜 박힘, GVSKB_RUNTIME_BASELINES 로 교체).
  # Dockerfile FROM · .nvmrc · engines.node · setup-node · .python-version · requires-python · package.json electron/next.
  patterns: []
  confidence: likely
  category: supply-chain
  why_it_matters: >-
    지원이 끝난 런타임에는 **보안 수정이 더 나오지 않습니다**. 2026-10-21 Node.js 보안 릴리스(Brotli 디코더 RCE 등
    10개 CVE)는 22·24·26 라인에만 적용됐습니다 — `node:20`(2026-04-30 종료) 위의 서비스는 그 취약점을 영원히
    가집니다. Python 3.10 은 2026-10-31 종료, Electron 은 최신 3개 메이저만 지원합니다. Electron 앱은 PC 의
    `node -v` 와 무관하게 **앱에 내장된** Node·Chromium 을 쓰므로 package.json 의 electron 버전으로 판정합니다.
    기준 날짜(as_of)가 증거에 함께 적힙니다 — 기준이 낡으면 기관 기준 파일로 교체하세요.
  public_sector_impact:
    - 공개된 RCE 가 수정되지 않은 런타임으로 대민·내부 서비스 운영
    - 보안 패치 요구를 받아도 적용할 버전이 없음
  safe_fix: |
    1. Node.js 는 활성 LTS(24) 또는 유지보수 LTS(22)로, Python 은 3.11 이상으로, Electron 은 지원 중 3개 메이저 안으로 올리세요.
    2. Dockerfile 은 `node:24-alpine` 처럼 메이저를 고정하고, `.nvmrc`·`engines.node`·CI `setup-node` 를 같은 값으로 맞추세요.
    3. 올릴 수 없다면 그 사유와 보상 통제(네트워크 격리 등)를 예외로 기록하고 만료일을 두세요.
  references:
    - Node.js Release Schedule
    - CWE-1104 Use of Unmaintained Third Party Components
  can_auto_fix: false
examples:
  positive:
    - "FROM node:20-alpine"
  negative:
    - "FROM node:24-alpine"
---

## 오해하지 마세요

`lts/*`·`latest` 처럼 수치가 없는 표기는 판정하지 않는다(미확정이지 안전이 아니다). 범위(`>=18`)는 **하한**으로 판정한다.
