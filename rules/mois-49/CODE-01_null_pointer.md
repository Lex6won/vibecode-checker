---
id: MOIS-49-CODE-01
title_ko: Null Pointer 역참조
title_en: NULL Pointer Dereference
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제5절-1
cwe: [CWE-476]
severity: medium
decision_default: warn
domains: [gov-secure-coding]
languages: [c, cpp, java, python]
scenarios: [data-pipeline]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
*null/None 검사 없이* 객체 메서드 호출 → NullPointerException·crash·정보 노출.

## 안전한 패턴
- Null 체크 (`if obj is not None:`)
- Java: `Optional<T>` 사용
- Kotlin/Swift: 안전 호출 연산자 (`?.`)

## 매핑
- CWE-476
