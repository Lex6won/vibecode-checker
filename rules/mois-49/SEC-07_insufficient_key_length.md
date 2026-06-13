---
id: MOIS-49-SEC-07
title_ko: 충분하지 않은 키 길이 사용
title_en: Insufficient Key Length
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제2절-7
cwe: [CWE-326]
severity: high
decision_default: warn
domains: [gov-secure-coding]
languages: [python, java, javascript]
scenarios: [web-app, data-pipeline]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
충분히 길지 않은 키 사용으로 *무차별 대입·암호 해독* 가능 (RSA-1024, AES-64 등).

## 안전한 패턴 (2026 권장)
- 대칭: AES ≥ 128bit (256 권장)
- RSA: ≥ 2048bit (3072+ 권장)
- ECC: ≥ 256bit (P-256, secp256r1)

## 매핑
- OWASP ASVS V6, CWE-326
