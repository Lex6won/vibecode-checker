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
    # 더미/예시 번호(0000-0000, 1234-5678, 1111…)와 마스킹(010-****-…)·정규식 리터럴
    # (\d{4})은 실제 개인정보가 아니므로 제외한다. 이 룰의 '안전한 패턴'이 권장하는
    # 더미와도 일관된다(010-0000-0000 등은 안전 권장값이므로 깃발하지 않음).
    - '\b01[016789]-?(?!1234-?5678|0000-?0000|1111|0000\b|1234\b)\d{3,4}-?\d{4}\b'
  category: privacy-public-sector
  why_it_matters: 연락처는 민원인 식별과 연결될 수 있어 외부 전송, 로그 저장, 저장소 업로드 전에 마스킹해야 합니다.
  public_sector_impact:
    - 개인정보 유출
    - 민원 정보 노출
  safe_fix: 전화번호는 마스킹하거나 테스트용 더미 번호를 사용하세요.
  references:
    - 개인정보 보호법
  can_auto_fix: false
examples:
  language: javascript
  positive:
    - 'const phone = "010-3825-7193";'
    - '연락처 01038257193 으로 회신'
  negative:
    - '<input placeholder="010-1234-5678" />'
    - 'const dummy = "010-0000-0000";'
    - 'const masked = "010-****-1234";'
    - 'const re = /^010-\d{4}-\d{4}$/;'
---

## 무엇이 위험한가
휴대폰번호는 민원인을 직접 식별할 수 있는 개인정보입니다. 코드·로그·LLM 프롬프트에 평문으로 들어가면 외부로 흘러나갈 위험이 있습니다.

## 안전한 패턴
- `010-****-1234` 형태로 마스킹
- 테스트는 `010-0000-0000` 등 더미
- 외부 API 호출 시 PII 제거 미들웨어 통과
