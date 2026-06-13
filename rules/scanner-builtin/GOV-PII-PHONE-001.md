---
id: GOV-PII-PHONE-001
title_ko: 휴대폰번호로 보이는 값이 코드에 포함되어 있습니다
title_en: Korean phone number detected
status: approved
source_layer: baseline
sources:
  - publisher: 개인정보보호위원회
    document: 개인정보 보호법
severity: high
decision_default: block
domains: [privacy-public-sector]
languages: [python, javascript, java, sql]
scenarios: [data-pipeline, llm-integration, web-app]
related_baseline: [OWASP-LLM-2025-02]
verified_at: 2026-05-31
review_due: 2026-11-30
detection:
  patterns:
    - '\b01[016789]-?\d{3,4}-?\d{4}\b'
  category: privacy-public-sector
  why_it_matters: 연락처는 민원인 식별과 연결될 수 있어 외부 전송, 로그 저장, 저장소 업로드 전에 마스킹해야 합니다.
  public_sector_impact:
    - 개인정보 유출
    - 민원 정보 노출
  safe_fix: 전화번호는 마스킹하거나 테스트용 더미 번호를 사용하세요.
  references:
    - 개인정보 보호법
  can_auto_fix: false
---

## 무엇이 위험한가
휴대폰번호는 민원인을 직접 식별할 수 있는 개인정보입니다. 코드·로그·LLM 프롬프트에 평문으로 들어가면 외부로 흘러나갈 위험이 있습니다.

## 안전한 패턴
- `010-****-1234` 형태로 마스킹
- 테스트는 `010-0000-0000` 등 더미
- 외부 API 호출 시 PII 제거 미들웨어 통과
