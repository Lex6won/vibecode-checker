---
id: MOIS-49-INPUT-13
title_ko: HTTP 응답분할
title_en: HTTP Response Splitting
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제1절-13
cwe: [CWE-113]
severity: medium
decision_default: warn
domains: [gov-secure-coding]
languages: [python, java, javascript]
scenarios: [web-app]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
사용자 입력에 *CR·LF*가 검증 없이 HTTP 응답 헤더에 들어가 응답이 분할되어 XSS·캐시 오염·세션 탈취.

## 안전한 패턴
- HTTP 헤더 설정 시 CR·LF 제거·차단
- 프레임워크 제공 API 사용 (Django `HttpResponse`, Flask 등 자동 정제)

## 매핑
- CWE-113
