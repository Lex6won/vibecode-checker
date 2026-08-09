---
id: GOV-PII-CONTACT-001
title_ko: 휴대전화번호로 보이는 값이 코드에 있습니다
title_en: Korean mobile number found in source
status: approved
source_layer: baseline
sources:
  - publisher: 개인정보보호위원회
    document: 개인정보 보호법
    item: 제2조 제1호 (개인정보의 정의)
  - publisher: 한국인터넷진흥원
    document: 개인정보의 안전성 확보조치 기준
    item: 제7조 (개인정보의 암호화)
cwe: [CWE-359]
severity: high
decision_default: warn
domains: [privacy]
languages: []
scenarios: [web-app, data-pipeline, llm-integration, agent]
related_baseline: [GOV-PII-RRN-001, GOV-PII-CARD-001]
verified_at: 2026-08-08
review_due: 2027-02-28
detection:
  patterns:
    # ── 휴대전화번호 ──
    # 국내 이동통신 식별번호(010·011·016·017·018·019)로 시작하는 형태만 본다.
    # 앞뒤로 숫자·점이 오면 후보에서 뺀다 — 주민번호 룰에서 배운 것으로,
    # `\b` 만으로는 소수점이 단어 경계라 `1.0101234567` 의 소수부가 걸린다.
    - '(?<![\d.])01[016789][-. ]?\d{3,4}[-. ]?\d{4}(?![\d.])'
  # 카드번호는 **별도 룰**(GOV-PII-CARD-001)로 뺐다. 검증기는 룰 단위로 걸리는데,
  # 카드에 필요한 Luhn 을 여기 걸면 전화번호에도 적용돼 정상 번호의 90%를 놓친다.
  # 처음에 한 룰로 묶었다가 검증기가 아무 데도 안 걸리는 죽은 코드가 됐고,
  # 테스트가 그것을 드러냈다 — 근거가 다른 것은 룰도 나눠야 한다.
  exclude_patterns:
    # 문서·예시에 쓰이는 대표 번호. 국내 안내문에서 사실상 표준 예시라
    # 그대로 두면 README·기획서마다 경고가 뜬다.
    - '010[-. ]?1234[-. ]?5678'
    - '010[-. ]?0000[-. ]?0000'
    - '010[-. ]?(\d)\1{3}[-. ]?\1{4}'
  category: privacy-public-sector
  confidence: pattern-only
  why_it_matters: >-
    휴대전화번호는 개인정보 보호법상 개인정보이며, 코드·로그·Git 이력에 남으면
    유출 사고로 이어집니다. 주민등록번호만큼 눈에 띄지 않아 정리 대상에서 빠지기
    쉽습니다. 특히 LLM 프롬프트에 섞여 들어가면 외부 서비스 로그에도 남습니다.
    (카드번호는 GOV-PII-CARD-001 이 따로 봅니다)
  public_sector_impact:
    - 개인정보 유출
    - 감사 지적
    - 과태료 또는 징계 위험
  safe_fix: |
    실제 연락처를 코드에 넣지 말고 비식별 더미 값을 쓰세요.
    운영 데이터가 필요하면 암호화 저장 후 조회하고, 로그에는 마스킹해 남기세요.
    (예: 010-****-5678)
  references:
    - 개인정보 보호법 제2조
    - 개인정보의 안전성 확보조치 기준 제7조
    - CWE-359
  can_auto_fix: false
examples:
  language: python
  positive:
    - 'phone = "010-9876-5432"'
    - 'CONTACT = "01087654321"'
  negative:
    # 대표 예시 번호 — 안내문에 사실상 표준으로 쓰인다
    - 'phone = "010-1234-5678"'
    # 전화번호가 아닌 숫자
    - 'timestamp = 1784654517497'
    - 'version = "1.0.10"'
    - 'order_id = "20260808-0001"'
---

## 무엇이 위험한가

주민등록번호는 눈에 띄어 정리 대상에 오르지만, **전화번호는 그냥 숫자처럼 보여
그대로 남습니다.** 테스트 데이터로 실제 민원인 연락처를 넣어 두고 잊는 일이
반복됩니다.

## 왜 `warn` 인가

형태만으로는 실제 개인정보인지 더미인지 알 수 없습니다. 주민등록번호
(`GOV-PII-RRN-001`)는 검증식까지 통과해야 하므로 `block` 이지만, 이쪽은
근거가 약해 **차단이 아니라 검토 요청**으로 둡니다 — 확신 없이 배포를 막으면
담당자가 도구를 끕니다.

## 안전한 패턴

```python
# 나쁨 — 실제 연락처
CONTACT = "010-9876-5432"

# 좋음 — 비식별 더미
CONTACT = "010-0000-0000"

# 로그에는 마스킹
logger.info("발송 대상 %s", mask_phone(user.phone))   # 010-****-5432
```
