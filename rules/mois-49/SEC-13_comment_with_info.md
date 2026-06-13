---
id: MOIS-49-SEC-13
title_ko: 주석문 안에 포함된 시스템 주요정보
title_en: Sensitive Information in Source Code Comments
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제2절-13
cwe: [CWE-540, CWE-615]
severity: medium
decision_default: warn
domains: [gov-secure-coding, secret-scanning]
languages: [python, java, javascript]
scenarios: [web-app]
related_baseline: [GOV-SECRET-APIKEY-001, GOV-INTERNAL-NET-001]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
*주석*에 비밀번호·내부망 정보·임시 자격증명 등 노출. JS 주석은 *클라이언트로 전송*되어 즉시 노출.

## 안전한 패턴
- 비밀 정보는 *절대* 주석 금지
- 빌드 도구로 프로덕션 빌드 시 주석 제거 (esbuild·Terser)
- detect-secrets 정기 스캔

## 매핑
- 본 리포 [GOV-SECRET-APIKEY-001](../scanner-builtin/GOV-SECRET-APIKEY-001.md) (일부 케이스 검출)
- CWE-540
