---
id: MOIS-49-CODE-03
title_ko: 해제된 자원 사용
title_en: Use After Free
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제5절-3
cwe: [CWE-416]
severity: high
decision_default: warn
domains: [gov-secure-coding]
languages: [c, cpp]
scenarios: [data-pipeline]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
해제된 메모리에 *재접근* → 임의 코드 실행·crash. C/C++ 메모리 관리 오류의 대표.

## 안전한 패턴
- 메모리 안전 언어 (Rust, Go) 신규 사용
- C/C++: `free(p); p = NULL;` 즉시 무효화
- 정적 분석 (AddressSanitizer, Valgrind)

## 매핑
- CWE-416
