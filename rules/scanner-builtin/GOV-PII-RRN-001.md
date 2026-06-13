---
id: GOV-PII-RRN-001
title_ko: 주민등록번호로 보이는 값이 코드에 포함되어 있습니다
title_en: Korean resident registration number detected
status: approved
source_layer: baseline
sources:
  - publisher: 개인정보보호위원회
    document: 개인정보 보호법 (고유식별정보)
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: 별표3 보안약점
severity: critical
decision_default: block
domains: [privacy-public-sector]
languages: [python, javascript, java, sql]
scenarios: [data-pipeline, llm-integration, web-app, agent]
related_baseline: [OWASP-LLM-2025-02, MOIS-49-SW-17]
verified_at: 2026-05-31
review_due: 2026-11-30
detection:
  patterns:
    - '\b\d{6}-?[1-4]\d{6}\b'
  category: privacy-public-sector
  why_it_matters: 고유식별정보가 코드, 로그, 프롬프트, Git 저장소에 남으면 개인정보 유출 사고로 이어질 수 있습니다.
  public_sector_impact:
    - 개인정보 유출
    - 감사 지적
    - 과태료 또는 징계 위험
  safe_fix: 실제 주민등록번호를 코드에 넣지 말고, 테스트에는 비식별 더미 데이터를 사용하세요.
  references:
    - 개인정보 보호법
    - OWASP-LLM-2025-LLM02
  can_auto_fix: false
---

## 무엇이 위험한가
주민등록번호는 고유식별정보로, 코드 또는 Git 저장소에 평문으로 남으면 개인정보 유출 사고 + 행정상 감사 지적의 직접 원인이 됩니다. LLM 프롬프트에 포함되면 외부 서비스의 로그·trace에도 잔존할 수 있어, 통제가 더 어렵습니다.

## 안전한 패턴
- 테스트는 `123456-1******` 형태의 비식별 더미 데이터
- 실제 데이터는 secret manager 또는 암호화 저장소에서만 로드
- 출력·로그에는 항상 마스킹 적용
