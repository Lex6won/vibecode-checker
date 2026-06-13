---
id: MOIS-49-SEC-01
title_ko: 적절한 인증 없는 중요기능 허용
title_en: Missing Authentication for Critical Function
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제2절-1
cwe: [CWE-306]
severity: critical
decision_default: block
domains: [gov-secure-coding]
languages: [python, java, javascript]
scenarios: [web-app]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
*중요 기능*(결재·민원 처리·관리자 동작)이 인증 검증 없이 호출 가능. URL 직접 접근으로 우회.

## 안전한 패턴
- 모든 요청에 인증 미들웨어 (예: Django decorator `@login_required`)
- 관리자 동작은 *별도 권한* 검증 (RBAC)

## 매핑
- OWASP ASVS V2/V3, CWE-306
