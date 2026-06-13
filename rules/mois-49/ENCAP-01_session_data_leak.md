---
id: MOIS-49-ENCAP-01
title_ko: 잘못된 세션에 의한 데이터 정보노출
title_en: Information Exposure Through Wrong Session
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제6절-1
cwe: [CWE-488]
severity: high
decision_default: warn
domains: [gov-secure-coding]
languages: [python, java, javascript]
scenarios: [web-app]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
**Java** 등에서 *클래스 변수*(static)에 사용자별 데이터 저장 → 다른 세션이 *같은 변수*를 공유하여 정보 노출.

## 안전한 패턴
- 사용자 데이터는 *인스턴스 변수* 또는 *세션 스토리지*
- static 변수는 *공유 가능 데이터*만

## 매핑
- CWE-488
