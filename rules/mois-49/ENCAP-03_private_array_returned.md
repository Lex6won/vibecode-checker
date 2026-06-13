---
id: MOIS-49-ENCAP-03
title_ko: Public 메소드부터 반환된 Private 배열
title_en: Private Array Returned from Public Method
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제6절-3
cwe: [CWE-495]
severity: low
decision_default: warn
domains: [gov-secure-coding]
languages: [java, csharp]
scenarios: [web-app]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
*Java*에서 public 메서드가 *private 배열의 참조*를 반환 → 호출자가 직접 *수정* 가능 → 캡슐화 위반.

## 안전한 패턴
- 배열 *복사본* 반환 (`Arrays.copyOf(...)`)
- 불변 컬렉션 (`List.copyOf(...)`)

## 매핑
- CWE-495
