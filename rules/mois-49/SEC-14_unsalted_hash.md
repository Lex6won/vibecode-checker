---
id: MOIS-49-SEC-14
title_ko: 솔트 없이 일방향 해쉬함수 사용
title_en: Use of Hash Function without Salt
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제2절-14
cwe: [CWE-759]
severity: high
decision_default: warn
domains: [gov-secure-coding]
languages: [python, java, javascript]
scenarios: [web-app]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
비밀번호 해시에 *솔트(salt)* 미적용 → 레인보우 테이블 공격으로 즉시 복원.

## 안전한 패턴
- **bcrypt** / **Argon2id** / **scrypt** — 솔트 자동 처리 + Key Stretching
- 단순 SHA-256 + 솔트 *지양* (느린 해시 함수가 적합)

## 매핑
- OWASP ASVS V2 (Password Storage), CWE-759
