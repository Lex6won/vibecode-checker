---
id: MOIS-49-SEC-03
title_ko: 중요한 자원에 대한 잘못된 권한 설정
title_en: Incorrect Permission Assignment for Critical Resource
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제2절-3
cwe: [CWE-732]
severity: high
decision_default: warn
domains: [gov-secure-coding]
languages: [yaml, shell]
scenarios: [web-app, data-pipeline]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
파일·디렉토리·데이터베이스의 *접근 권한*이 과도하게 부여 (예: world-writable `/etc/passwd`).

## 안전한 패턴
- 최소 권한 원칙 (chmod 600 등)
- 컨테이너 / SELinux / AppArmor 강제 접근 제어
- 정기 권한 감사 (`find / -perm -o+w`)

## 매핑
- CWE-732
