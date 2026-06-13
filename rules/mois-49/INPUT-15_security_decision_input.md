---
id: MOIS-49-INPUT-15
title_ko: 보안기능 결정에 사용되는 부적절한 입력값
title_en: Reliance on Untrusted Inputs in a Security Decision
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제1절-15
cwe: [CWE-807, CWE-302]
severity: high
decision_default: warn
domains: [gov-secure-coding]
languages: [python, java, javascript]
scenarios: [web-app]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
*클라이언트 측 값(HTTP 헤더·쿠키·hidden field)*을 *서버 보안 결정*에 사용. 권한·인증·금액 등이 사용자 조작에 노출.

## 안전한 패턴
- 권한·세션·금액은 *서버 세션*에 저장
- 클라이언트 데이터는 *항상* 서버 측 재검증
- 쿠키에는 무결성 (HMAC/JWT 서명) 적용

## 매핑
- OWASP ASVS V3 (Session Management), CWE-807
