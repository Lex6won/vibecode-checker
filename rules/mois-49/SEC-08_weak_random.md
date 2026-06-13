---
id: MOIS-49-SEC-08
title_ko: 적절하지 않은 난수값 사용
title_en: Use of Insufficiently Random Values
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제2절-8
cwe: [CWE-330, CWE-338]
severity: high
decision_default: warn
domains: [gov-secure-coding]
languages: [python, java, javascript]
scenarios: [web-app, data-pipeline]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
세션 ID·토큰·CSRF 토큰 생성에 *예측 가능한 난수*(`Math.random()`, `Random`) 사용 → 토큰 위조.

## 안전한 패턴
- 암호학적 난수 생성기 사용
  - Python: `secrets.token_hex()`, `secrets.SystemRandom`
  - Java: `SecureRandom`
  - JS: `crypto.getRandomValues()`

## 매핑
- CWE-330, CWE-338
