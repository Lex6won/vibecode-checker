---
id: MOIS-49-INPUT-14
title_ko: 정수형 오버플로우
title_en: Integer Overflow
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제1절-14
cwe: [CWE-190]
severity: medium
decision_default: warn
domains: [gov-secure-coding]
languages: [c, cpp, java, javascript]
scenarios: [data-pipeline]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
산술 연산 결과가 자료형 *최대값 초과* → 음수·잘못된 값으로 *길이 검사 우회*·*버퍼 오버플로우*. C/C++·Java에서 위험.

## 안전한 패턴
- 연산 전 *경계 검사*
- Java `Math.addExact()` 등 overflow 감지 API
- 큰 정수는 BigInteger 사용
- Python은 자동 임의 정밀도이지만 외부 연계 시 주의

## 매핑
- CWE-190
