---
id: MOIS-49-INPUT-16
title_ko: 메모리 버퍼 오버플로우
title_en: Memory Buffer Overflow
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제1절-16
cwe: [CWE-119, CWE-120]
severity: critical
decision_default: warn
domains: [gov-secure-coding]
languages: [c, cpp]
scenarios: [data-pipeline]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
메모리 *버퍼 경계*를 넘어 읽기·쓰기 → 임의 코드 실행·crash. C/C++ 코드에서 주요 위험. 행정 시스템의 C 기반 레거시 코드에서 빈번.

## 안전한 패턴
- `strncpy`/`snprintf` 등 *크기 제한 함수* 사용
- 메모리 안전 언어 (Rust, Go) 신규 개발 권장
- 컴파일러 보호 옵션 (ASLR, Stack Canary, DEP)

## 매핑
- CWE-119, CWE-120
