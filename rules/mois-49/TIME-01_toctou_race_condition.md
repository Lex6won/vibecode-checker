---
id: MOIS-49-TIME-01
title_ko: 경쟁조건 (TOCTOU)
title_en: Race Condition (Time of Check to Time of Use)
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제3절-1
cwe: [CWE-367, CWE-362]
severity: high
decision_default: warn
domains: [gov-secure-coding]
languages: [python, java, c]
scenarios: [web-app, data-pipeline]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
*검사 시점*과 *사용 시점* 사이의 *틈*을 공격자가 활용 (예: 파일 권한 검사 후 심볼릭 링크 교체).

## 안전한 패턴
- 원자적 연산 (atomic file operations)
- 파일 디스크립터 기반 작업 (`openat`, `fstatat`)
- 잠금(`flock`) 또는 트랜잭션

## 매핑
- CWE-367
