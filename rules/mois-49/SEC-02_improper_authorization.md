---
id: MOIS-49-SEC-02
title_ko: 부적절한 인가
title_en: Improper Authorization
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제2절-2
cwe: [CWE-285]
severity: critical
decision_default: block
domains: [gov-secure-coding]
languages: [python, java, javascript]
scenarios: [web-app]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
사용자는 인증되었으나 *접근하는 자원에 대한 권한 검증 부재*. IDOR(Insecure Direct Object Reference) 패턴.

## 안전한 패턴
- 모든 자원 접근 시 *소유자/권한* 검증
- 예: `if document.owner_id != current_user.id: raise Forbidden`

## 매핑
- OWASP ASVS V4 (Access Control), CWE-285
