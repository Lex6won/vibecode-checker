---
id: MOIS-49-SEC-16
title_ko: 반복된 인증시도 제한 기능 부재
title_en: Improper Restriction of Excessive Authentication Attempts
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제2절-16
cwe: [CWE-307]
severity: high
decision_default: warn
domains: [gov-secure-coding]
languages: [python, java, javascript]
scenarios: [web-app]
related_baseline: [NIS-AI-M27]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
로그인 *시도 횟수 제한* 부재 → 무차별 대입 공격 (brute force).

## 안전한 패턴
- 계정 잠금: 5회 실패 시 30분 잠금
- IP 기반 rate limit
- CAPTCHA 또는 MFA 강제

## 매핑
- OWASP ASVS V2, CWE-307
- NIS-AI-M27 (요청 속도 제한)
