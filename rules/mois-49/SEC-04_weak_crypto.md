---
id: MOIS-49-SEC-04
title_ko: 취약한 암호화 알고리즘 사용
title_en: Use of Broken or Risky Cryptographic Algorithm
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제2절-4
cwe: [CWE-327]
severity: high
decision_default: warn
domains: [gov-secure-coding]
languages: [python, java, javascript]
scenarios: [data-pipeline, web-app]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
*안전성이 검증되지 않은* 또는 *취약한* 암호 알고리즘 사용 (DES, MD5, SHA-1, RC4). 행정망은 **국정원 검증 알고리즘** 필수.

## 안전한 패턴
- 대칭: AES-256-GCM, ChaCha20-Poly1305
- 해시: SHA-256/384/512, BLAKE2
- 비대칭: RSA-2048+ 또는 ECC
- **국가용 암호 모듈**: ARIA·SEED·LEA·SHA-224 (국정원 검증)

## 매핑
- OWASP ASVS V6, CWE-327
- 「국가 정보보안 기본지침」 암호 사용 규정
