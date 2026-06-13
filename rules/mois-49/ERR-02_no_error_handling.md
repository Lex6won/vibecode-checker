---
id: MOIS-49-ERR-02
title_ko: 오류 상황 대응 부재
title_en: Missing Error Handling
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제4절-2
cwe: [CWE-755, CWE-391]
severity: medium
decision_default: warn
domains: [gov-secure-coding]
languages: [python, java, javascript]
scenarios: [web-app, data-pipeline]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
시스템 호출 *반환값 미확인* 또는 예외 *무시* → 비정상 상태에서 *부적절한 동작* 계속.

## 안전한 패턴
- 모든 호출 결과 *검증*
- try/except 후 *적절한 복구 또는 fail-safe*
- 무시 시에도 *로그 기록*

## 매핑
- CWE-755
