---
id: MOIS-49-CODE-04
title_ko: 초기화되지 않은 변수 사용
title_en: Use of Uninitialized Variable
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제5절-4
cwe: [CWE-457]
severity: medium
decision_default: warn
domains: [gov-secure-coding]
languages: [c, cpp, java]
scenarios: [data-pipeline]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
변수가 *초기화되지 않은 상태*에서 사용 → 메모리의 임의 값(이전 데이터) 노출.

## 안전한 패턴
- 변수는 *선언과 동시 초기화*
- C: `int x = 0;`
- 컴파일러 경고 -Wuninitialized 활성

## 매핑
- CWE-457
