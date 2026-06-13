---
id: MOIS-49-ENCAP-04
title_ko: Private 배열에 Public 데이터 할당
title_en: Public Data Assigned to Private Array
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제6절-4
cwe: [CWE-496]
severity: low
decision_default: warn
domains: [gov-secure-coding]
languages: [java, csharp]
scenarios: [web-app]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
*외부에서 받은 배열 참조*를 *private 필드*에 직접 할당 → 외부에서 내부 상태 *수정 가능*.

## 안전한 패턴
- 입력 배열의 *복사본 저장* (`this.arr = Arrays.copyOf(input, input.length);`)
- 불변 컬렉션 사용

## 매핑
- CWE-496
