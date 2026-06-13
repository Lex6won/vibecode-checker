---
id: MOIS-49-SEC-11
title_ko: 부적절한 인증서 유효성 검증
title_en: Improper Certificate Validation
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제2절-11
cwe: [CWE-295]
severity: high
decision_default: warn
domains: [gov-secure-coding]
languages: [python, java, javascript]
scenarios: [web-app, data-pipeline]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
TLS 클라이언트가 서버 인증서 *검증 비활성화* (`verify=False`) 또는 만료·CN 미체크. 중간자 공격 노출.

## 안전한 패턴
- 인증서 검증 활성: Python `requests` 기본값 `verify=True` 유지
- Pin certificate (특정 인증서·CA만 신뢰)
- 만료·CN·SAN 모두 검증

## 매핑
- CWE-295
