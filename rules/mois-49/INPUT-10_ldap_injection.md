---
id: MOIS-49-INPUT-10
title_ko: LDAP 삽입
title_en: LDAP Injection
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제1절-10
cwe: [CWE-90]
severity: high
decision_default: warn
domains: [gov-secure-coding]
languages: [python, java]
scenarios: [web-app]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
외부 입력이 *LDAP 쿼리*에 삽입되어 인증 우회·정보 노출. 행정망 디렉토리 서비스(AD/OpenLDAP) 통합 시 위험.

## 안전한 패턴
- LDAP 특수문자 escape (`*`, `(`, `)`, `\`, NUL)
- 사용자 입력은 *DN 컴포넌트*만 허용

## 매핑
- CWE-90
