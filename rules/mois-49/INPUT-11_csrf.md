---
id: MOIS-49-INPUT-11
title_ko: 크로스사이트 요청 위조 (CSRF)
title_en: Cross-Site Request Forgery
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제1절-11
cwe: [CWE-352]
severity: high
decision_default: warn
domains: [gov-secure-coding]
languages: [javascript, python, java]
scenarios: [web-app]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
인증된 사용자의 *쿠키*를 악용해 의도하지 않은 요청을 위조 전송. 결재·민원 시스템에서 부정 트랜잭션 위험.

## 안전한 패턴
- CSRF 토큰 (Synchronizer Token Pattern)
- SameSite 쿠키 속성 (Strict)
- Referer/Origin 검증

## 매핑
- OWASP ASVS V13 (API and Web Service), CWE-352
