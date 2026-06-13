---
id: MOIS-49-INPUT-08
title_ko: 부적절한 XML 외부 개체 참조 (XXE)
title_en: Improper XML External Entity Reference
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제1절-8
cwe: [CWE-611]
severity: high
decision_default: warn
domains: [gov-secure-coding]
languages: [python, java, javascript]
scenarios: [web-app, data-pipeline]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
XML 파서가 *외부 개체(External Entity)*를 처리하여 *로컬 파일 노출·SSRF·DoS*. XML 파일 업로드·SOAP 처리 시 위험.

## 안전한 패턴
- XML 파서에서 *External Entity 비활성* (`disallow_external_entities`)
- Python: `defusedxml` 라이브러리 사용
- Java: `XMLInputFactory`의 `IS_SUPPORTING_EXTERNAL_ENTITIES = false`

## 매핑
- OWASP Top 10 (A05 Security Misconfiguration), CWE-611
