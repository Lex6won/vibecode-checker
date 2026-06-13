---
id: MOIS-49-CODE-02
title_ko: 부적절한 자원 해제
title_en: Improper Resource Shutdown or Release
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제5절-2
cwe: [CWE-404]
severity: medium
decision_default: warn
domains: [gov-secure-coding]
languages: [python, java, c, cpp]
scenarios: [data-pipeline]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
파일 핸들·DB 연결·소켓 등 자원을 *해제하지 않음* → 자원 고갈·DoS.

## 안전한 패턴
- Python `with` 컨텍스트 매니저
- Java `try-with-resources`
- C/C++: RAII 패턴

## 매핑
- CWE-404
