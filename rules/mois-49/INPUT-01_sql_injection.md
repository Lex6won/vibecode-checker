---
id: MOIS-49-INPUT-01
title_ko: SQL 삽입
title_en: SQL Injection
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제1절-1
cwe: [CWE-89]
severity: critical
decision_default: block
domains: [gov-secure-coding]
languages: [python, java, javascript]
scenarios: [web-app, data-pipeline]
related_baseline: [GOV-SQL-INJECTION-001, MOIS-49-SW-17]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
외부 입력을 *적절한 검증 없이* SQL 쿼리에 사용하여 SQL이 변경 실행되는 약점. 민원 DB의 *전수 조회·변경·삭제*로 직결.

## 안전한 패턴
파라미터 바인딩 (PreparedStatement / `%s` placeholder / ORM)

## 매핑
- 본 리포 [GOV-SQL-INJECTION-001](../scanner-builtin/GOV-SQL-INJECTION-001.md) — 실시간 검사 가능
- OWASP ASVS V5, CWE-89
