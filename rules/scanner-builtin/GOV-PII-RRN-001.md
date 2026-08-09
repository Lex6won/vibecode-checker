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
# 언어를 제한하지 않는다. 노출 위험은 **언어를 가리지 않는다** — 주민등록번호는
# Go 로 적으나 Rust 로 적으나 주민등록번호다. 예전에는 여기에 목록이 있었고,
# 그 목록에 typescript 가 없어 `.ts`/`.tsx` 에서 이 룰이 **한 번도 돌지 않았다**
# (실측 2026-08-09). 공공 웹앱의 주력이 TypeScript 다. GOV-PII-PHONE-001 에서
# 같은 구멍을 고쳤는데 형제 룰 셋에 그대로 남아 있었다.
languages: []
scenarios: [data-pipeline, llm-integration, web-app, agent]
related_baseline: [OWASP-LLM-2025-02, MOIS-49-SW-17]
verified_at: 2026-05-31
review_due: 2026-11-30
detection:
  patterns:
    # 앞 6자리는 *날짜*여야 한다(월 01-12, 일 01-31). 예전 패턴은 이 검증이
    # 없어 13자리 정수의 40%가 매치했다 — Unix 밀리초 타임스탬프
    # (1784654517497 = "17년 84월 65일")가 전부 주민번호로 보고됐다.
    - '\b\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])-[1-4]\d{6}\b'
    # 하이픈이 없으면 그냥 큰 수와 구분되지 않으므로, **더 긴 숫자열의 일부는
    # 아예 후보로 보지 않는다.** `\b` 만으로는 부족하다 — 소수점이 단어 경계라
    # `12.9001011234568` 의 소수부가 후보가 된다. 실측에서 백테스트 산출물의
    # `"avg_win": 294.444152…` 가 이 경로로 '치명·차단'이 났고, 날짜가 84월이라
    # 우연히 살아난 것뿐이었다(유효 날짜를 심자 즉시 재현). 하이픈 있는 형태는
    # 의도가 명확하므로 이 가드를 걸지 않는다 — 문장 끝 마침표에서 미탐이 난다.
    - '(?<![\d.])\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])[1-4]\d{6}(?![\d.])'
  # 하이픈 없는 형태는 여전히 그냥 큰 수와 구분되지 않으므로 검증식까지 본다.
  # (하이픈이 있으면 검증기가 그대로 통과시킨다 — validator 주석 참고)
  validators: [rrn_checksum]
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
examples:
  language: python
  positive:
    - 'rrn = "900101-1234567"'
    - 'user = {"name": "홍길동", "rrn": "051231-4567890"}'
    # 하이픈 없는 형태 — 날짜 유효 + 검증식 통과
    - 'query = "SELECT * FROM 민원인 WHERE 주민번호 = 8203154567890"'
  negative:
    # Unix 밀리초 타임스탬프 — 이 오탐이 실제 프로젝트에서 critical 4건을 냈다
    - '{"when": 1784654517497, "tag": "0000_init"}'
    - 'created_at = 1784683391754'
    # 13자리이고 날짜도 유효하지만 검증식 불일치
    - 'order_no = 9001011234560'
    # 앞 6자리가 날짜가 아님(84월)
    - 'seq = 1784722092319'
    - 'phone = "010-1234-5678"'
    # 실수의 소수부에 우연히 유효 날짜+검증식이 성립한 경우 — 숫자열의 일부다
    - '{"sharpe": 12.9001011234568, "trades": 418}'
    - '{"avg_win": 294.4441521234567}'
    - 'score = 9001011234568.75'
---

## 무엇이 위험한가
주민등록번호는 고유식별정보로, 코드 또는 Git 저장소에 평문으로 남으면 개인정보 유출 사고 + 행정상 감사 지적의 직접 원인이 됩니다. LLM 프롬프트에 포함되면 외부 서비스의 로그·trace에도 잔존할 수 있어, 통제가 더 어렵습니다.

## 안전한 패턴
- 테스트는 `123456-1******` 형태의 비식별 더미 데이터
- 실제 데이터는 secret manager 또는 암호화 저장소에서만 로드
- 출력·로그에는 항상 마스킹 적용
