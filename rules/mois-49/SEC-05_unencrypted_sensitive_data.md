---
id: MOIS-49-SEC-05
title_ko: 암호화되지 않은 중요정보
title_en: Unencrypted Sensitive Information
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제2절-5
cwe: [CWE-311]
severity: critical
decision_default: block
domains: [gov-secure-coding, privacy-public-sector]
languages: [python, java, javascript]
scenarios: [data-pipeline, web-app]
related_baseline: [GOV-PII-RRN-001, GOV-PII-PHONE-001, NIS-AI-M04]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
*중요 정보*(주민번호·비밀번호·민원자료)가 *평문* 저장·전송. 행정망은 *저장 + 전송 모두* 암호화 필수.

## 안전한 패턴
- 저장: 데이터 등급별 암호화 (디스크 + 컬럼 레벨)
- 전송: TLS 1.3 강제
- 비밀번호: bcrypt/Argon2id 해시

## 매핑
- 본 리포 [GOV-PII-RRN-001](../scanner-builtin/GOV-PII-RRN-001.md)
- NIS-AI-M04 (데이터 암호화)
- CWE-311, 개인정보 보호법
