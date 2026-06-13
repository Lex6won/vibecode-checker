---
id: MOIS-49-SEC-09
title_ko: 취약한 비밀번호 허용
title_en: Weak Password Allowed
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제2절-9
cwe: [CWE-521]
severity: medium
decision_default: warn
domains: [gov-secure-coding]
languages: [python, java, javascript]
scenarios: [web-app]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
*간단한 비밀번호* (짧은 길이·단순 패턴·딕셔너리) 허용. 행정 시스템은 *복잡도 강제*.

## 안전한 패턴
- 최소 길이 12자 + 복잡도 (소문자·대문자·숫자·기호 중 3종)
- 알려진 유출 비밀번호 차단 (HaveIBeenPwned API 또는 로컬 사전)
- MFA 강제

## 매핑
- OWASP ASVS V2 (Authentication), CWE-521
