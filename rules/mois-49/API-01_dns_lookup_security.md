---
id: MOIS-49-API-01
title_ko: DNS lookup에 의존한 보안결정
title_en: Reliance on Reverse DNS Resolution for a Security Decision
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제7절-1
cwe: [CWE-247, CWE-350]
severity: medium
decision_default: warn
domains: [gov-secure-coding]
languages: [python, java, javascript]
scenarios: [web-app]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
*역방향 DNS lookup*으로 호스트 이름을 확인하여 *보안 결정*에 사용 → DNS 변조·DNS spoofing으로 우회.

## 안전한 패턴
- 보안 결정은 *IP*에 직접 기반 (CIDR 화이트리스트)
- DNS 결과를 인증 근거로 *사용하지 않음*
- mTLS 등 *암호학적* 신원 검증

## 매핑
- CWE-247, CWE-350
