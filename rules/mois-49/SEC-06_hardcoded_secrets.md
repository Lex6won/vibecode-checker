---
id: MOIS-49-SEC-06
title_ko: 하드코드된 중요정보
title_en: Use of Hard-coded Credentials
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제2절-6
cwe: [CWE-798]
severity: critical
decision_default: block
domains: [gov-secure-coding, secret-scanning]
languages: [python, java, javascript, yaml]
scenarios: [web-app, llm-integration]
related_baseline: [GOV-SECRET-APIKEY-001, GOV-SECRET-PRIVATEKEY-001]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
*비밀번호·API 키·암호화 키·DB 접속 문자열*을 소스코드에 *상수로* 포함. Git history 영구 노출.

## 안전한 패턴
- 환경변수 (`.env`)
- Secret Manager (AWS Secrets Manager, Azure Key Vault, 기관 내부 vault)
- 코드는 *참조 키*만 보관

## 매핑
- 본 리포 [GOV-SECRET-APIKEY-001](../scanner-builtin/GOV-SECRET-APIKEY-001.md), [GOV-SECRET-PRIVATEKEY-001](../scanner-builtin/GOV-SECRET-PRIVATEKEY-001.md) — 실시간 검사
- CWE-798
