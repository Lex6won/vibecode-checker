---
id: MOIS-49-SEC-10
title_ko: 부적절한 전자서명 확인
title_en: Improper Verification of Cryptographic Signature
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제2절-10
cwe: [CWE-347]
severity: high
decision_default: warn
domains: [gov-secure-coding]
languages: [python, java, javascript]
scenarios: [web-app, data-pipeline]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
JWT·전자결재 서명 *검증 부재* 또는 *부적절*. `alg: none` 허용, 알고리즘 혼동 공격.

## 안전한 패턴
- JWT: `alg` 화이트리스트 (RS256/ES256만 허용)
- 라이브러리: `pyjwt`, `jose-jwt` *최신 버전*
- 공공기관 전자서명: GPKI 검증

## 매핑
- CWE-347
