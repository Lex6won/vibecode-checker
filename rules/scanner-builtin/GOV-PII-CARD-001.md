---
id: GOV-PII-CARD-001
title_ko: 결제 카드번호로 보이는 값이 코드에 있습니다
title_en: Payment card number found in source
status: approved
source_layer: baseline
sources:
  - publisher: 개인정보보호위원회
    document: 개인정보 보호법
    item: 제2조 제1호 (개인정보의 정의)
  - publisher: PCI Security Standards Council
    document: PCI DSS v4.0
    item: Requirement 3 (Protect Stored Account Data)
cwe: [CWE-359]
severity: critical
decision_default: block
domains: [privacy]
languages: []
scenarios: [web-app, data-pipeline, llm-integration]
related_baseline: [GOV-PII-RRN-001, GOV-PII-PHONE-001]
verified_at: 2026-08-09
review_due: 2027-02-28
detection:
  patterns:
    # 브랜드 식별번호(BIN)로 시작하는 13~19자리. 하이픈·공백 구분 허용.
    # 앞뒤에 숫자·점이 오면 후보에서 뺀다 — 주민번호 룰에서 배운 것으로,
    # `\b` 만으로는 소수점이 단어 경계라 긴 실수의 소수부가 후보가 된다.
    - '(?<![\d.])(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{3,4}(?![\d.])'
  # **Luhn 검증식이 이 룰의 근거다.** 16자리 숫자 뭉치는 주문번호·타임스탬프와
  # 형태가 같아, 형태만 보면 오탐이 쏟아진다. Luhn 은 임의 숫자열의 90%를
  # 떨어뜨린다.
  #
  # 전화번호(GOV-PII-PHONE-001)와 **룰을 나눈 이유가 이것**이다: 검증기는
  # 룰 단위로 걸리므로 한 룰에 두면 전화번호에도 Luhn 이 적용돼 정상 번호의
  # 90%를 놓친다. 처음에 한 룰로 묶었다가 검증기가 아무 데도 안 걸리는
  # **죽은 코드**가 됐고, 테스트가 그것을 드러냈다.
  validators: [luhn]
  exclude_patterns:
    # 카드 브랜드 공식 테스트 번호 — **Luhn 을 통과하도록 만들어진 값**이라
    # 검증기로는 걸러지지 않는다. 문서·결제 연동 테스트에 널리 쓰여 그대로 두면
    # 결제 기능이 있는 모든 프로젝트에서 경고가 뜬다.
    - '4111[- ]?1111[- ]?1111[- ]?1111'
    - '4242[- ]?4242[- ]?4242[- ]?4242'
    - '5555[- ]?5555[- ]?5555[- ]?4444'
    - '5105[- ]?1051[- ]?0510[- ]?5100'
    - '6011[- ]?1111[- ]?1111[- ]?1117'
    - '3782[- ]?822463[- ]?10005'
  category: privacy-public-sector
  confidence: likely
  why_it_matters: >-
    카드번호는 개인정보 보호법상 개인정보이자 PCI DSS 의 보호 대상입니다.
    코드·로그·Git 이력에 남으면 즉시 유출 사고이며, LLM 프롬프트에 섞이면
    외부 서비스 로그에도 남습니다. 주민등록번호와 달리 '그냥 숫자'로 보여
    정리 대상에서 빠지기 쉽습니다.
  public_sector_impact:
    - 개인정보 유출
    - 결제 정보 도용
    - 과태료 또는 징계 위험
  safe_fix: |
    실제 카드번호를 코드에 넣지 마세요. 테스트에는 카드사 공식 테스트 번호를
    쓰고, 운영 데이터는 저장하지 않거나 토큰화(PG사 빌링키)하세요.
    로그에는 앞 6자리·뒤 4자리만 남깁니다 (411111-****-****-1111).
  references:
    - 개인정보 보호법 제2조
    - PCI DSS v4.0 Requirement 3
    - CWE-359
  can_auto_fix: false
examples:
  language: python
  positive:
    - 'card = "4532015112830366"'
    - 'CARD_NO = "4532-0151-1283-0366"'
  negative:
    # 카드 브랜드 공식 테스트 번호 — Luhn 은 통과하지만 실제 카드가 아니다
    - 'test_card = "4111-1111-1111-1111"'
    - 'stripe_test = "4242424242424242"'
    # Luhn 을 통과하지 못하는 숫자열 — 이 룰의 존재 이유
    - 'order_no = "4123456789012345"'
    - 'trace_id = "5412751234123456"'
    - "timestamp = 1784654517497"
---

## 무엇이 위험한가

카드번호는 **'그냥 긴 숫자'처럼 보여** 주민등록번호보다 정리에서 더 자주 빠집니다.
결제 연동 테스트를 하며 실제 카드번호를 넣고 지우지 않은 사례가 반복됩니다.

## 왜 Luhn 검증까지 하는가

형태만 보면 주문번호·거래ID·타임스탬프가 전부 걸립니다. Luhn(mod 10)은 임의
숫자열의 **90%를 떨어뜨려** 이 룰을 쓸 만하게 만듭니다.

```
4532015112830366  → Luhn 통과 → 카드번호일 가능성이 높다
4123456789012345  → Luhn 실패 → 그냥 숫자다
```

## 안전한 패턴

```python
# 나쁨 — 실제 카드번호
CARD = "4532015112830366"

# 좋음 — 카드사 공식 테스트 번호(문서화된 값)
TEST_CARD = "4111-1111-1111-1111"

# 운영에서는 저장하지 않거나 토큰화
billing_key = pg.issue_billing_key(card_input)   # 원본은 보관하지 않는다
```
