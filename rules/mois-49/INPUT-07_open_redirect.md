---
id: MOIS-49-INPUT-07
title_ko: 신뢰되지 않는 URL 주소로 자동접속 연결
title_en: Open Redirect
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제1절-7
cwe: [CWE-601]
severity: medium
decision_default: warn
domains: [gov-secure-coding]
languages: [python, java, javascript]
scenarios: [web-app]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
사용자가 입력한 URL로 *자동 리다이렉트*되어 피싱·악성사이트 유도. 외부 도메인 검증 없는 `redirect()` 패턴.

## 안전한 패턴
- 리다이렉트 대상 URL 화이트리스트 (도메인 기준)
- 외부 도메인은 *경고 페이지* 경유
- 상대 경로만 허용 (외부 절대 URL 거부)

## 매핑
- OWASP ASVS V12, CWE-601
