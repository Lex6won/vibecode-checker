---
id: GOV-RUNTIME-OUTDATED-001
title_ko: 지원 중인 런타임·프레임워크이지만 알려진 보안 수정판보다 낮은 버전을 고정합니다
title_en: Supported runtime/framework pinned below the known security fix release (Node.js line / Next.js)
status: approved
source_layer: baseline
sources:
  - publisher: OpenJS Foundation
    document: Node.js October 2026 Security Releases
    url: https://nodejs.org/en/blog/vulnerability/october-2026-security-releases
  - publisher: Vercel
    document: Next.js security advisories (CVE-2026-23869 · CVE-2026-23870 · CVE-2026-44576)
cwe: [CWE-1104, CWE-1035]
severity: high
decision_default: warn
domains: [supply-chain]
languages: []
scenarios: [web-app, data-pipeline, agent, llm-integration]
related_baseline: [GOV-RUNTIME-EOL-001]
verified_at: 2026-10-24
review_due: 2027-01-24
detection:
  # runtime-version 판정기. 정확한 패치 버전이 적힌 핀(.nvmrc 22.12.0 · Dockerfile node:22.12.0 · package.json next 16.0.10)만 판정.
  # 메이저만 적힌 핀(node:22)은 설치 시점 최신을 받으므로 판정하지 않는다.
  patterns: []
  confidence: likely
  category: supply-chain
  why_it_matters: >-
    지원 라인이라도 **고정한 패치 버전**이 보안 릴리스 이전이면 그 CVE 를 그대로 가집니다. Node.js 2026-10-21
    릴리스(22.23.4 · 24.22.1 · 26.12.1)는 Brotli 디코더 범위 밖 쓰기(RCE 가능)·DNS NUL 절단·TLS 호스트 검증 우회를
    고쳤습니다. Next.js 15.5.16 · 16.2.5 는 App Router 서버 함수 DoS 와 RSC 캐시 오염을 고쳤습니다. 이 룰은
    "최신판이 아니다"가 아니라 **"알려진 수정판보다 낮다"**만 말합니다. 기준(as_of)이 증거에 적힙니다.
  public_sector_impact:
    - 공개 PoC 가 있는 취약점을 가진 버전으로 운영
  safe_fix: |
    1. 증거에 적힌 수정판 이상으로 올리고(`node:22.23.4-alpine`, `"next": "16.2.5"`), 락파일을 다시 생성하세요.
    2. Dockerfile 의 베이스 이미지도 같은 패치 이상인지 확인하세요(이미지 태그가 메이저만이면 다시 빌드해야 최신을 받습니다).
  references:
    - Node.js October 2026 Security Releases
    - CWE-1104 Use of Unmaintained Third Party Components
  can_auto_fix: false
examples:
  positive:
    - '{"dependencies": {"next": "16.0.10"}}'
  negative:
    - '{"dependencies": {"next": "16.2.5"}}'
---

## 무엇이 위험한가

"지원 중"과 "수정됨"은 다르다. 지원 라인이라도 고정한 패치 버전이 보안 릴리스 이전이면 그 CVE 를 가진다.

## 오해하지 마세요

메이저만 적은 핀(`node:22`, `^16.0.0` 의 상한 없는 범위)은 설치 시점에 최신을 받으므로 판정하지 않는다. 정확한 패치 버전을 고정한 경우만 본다.
