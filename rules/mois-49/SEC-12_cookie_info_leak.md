---
id: MOIS-49-SEC-12
title_ko: 사용자 하드디스크에 저장되는 쿠키를 통한 정보노출
title_en: Information Exposure Through Persistent Cookies
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제2절-12
cwe: [CWE-539]
severity: medium
decision_default: warn
domains: [gov-secure-coding]
languages: [python, java, javascript]
scenarios: [web-app]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
민감 정보가 *영속 쿠키*(Expires 설정)로 사용자 디스크에 저장. PC 공유 시 *타인 접근*.

## 안전한 패턴
- 민감 쿠키는 *세션 쿠키*만 (Expires 미설정)
- `HttpOnly`, `Secure`, `SameSite=Strict` 속성 강제
- 가능한 경우 *서버 세션*만 사용

## 매핑
- CWE-539
