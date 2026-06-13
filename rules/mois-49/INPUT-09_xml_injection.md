---
id: MOIS-49-INPUT-09
title_ko: XML 삽입
title_en: XML Injection
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제1절-9
cwe: [CWE-91]
severity: high
decision_default: warn
domains: [gov-secure-coding]
languages: [python, java, javascript]
scenarios: [web-app, data-pipeline]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
외부 입력이 *XML 쿼리/문서*에 삽입되어 구조 조작. SOAP·XPath 등에서 위험.

## 안전한 패턴
- XPath/SQL 분리 (parameterized XPath query)
- 입력 검증 + XML 특수문자 escape

## 매핑
- CWE-91
