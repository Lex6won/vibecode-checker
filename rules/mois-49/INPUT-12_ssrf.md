---
id: MOIS-49-INPUT-12
title_ko: 서버사이드 요청 위조 (SSRF)
title_en: Server-Side Request Forgery
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제1절-12
cwe: [CWE-918]
severity: high
decision_default: warn
domains: [gov-secure-coding, public-sector-internal]
languages: [python, java, javascript]
scenarios: [web-app, agent, rag]
related_baseline: [GOV-INTERNAL-NET-001, NIS-AI-M01]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
서버가 *외부 입력 URL*로 요청을 전송하여 *내부망 자원* 또는 *클라우드 메타데이터*에 비인가 접근. 행정망 정찰의 *황금 경로*.

## 안전한 패턴
- URL 화이트리스트 (도메인 기준)
- 내부망 IP 차단 (RFC1918, 169.254.169.254 등)
- DNS rebinding 방지 (IP 직접 사용)

## 매핑
- 본 리포 [GOV-INTERNAL-NET-001](../scanner-builtin/GOV-INTERNAL-NET-001.md)
- CWE-918
