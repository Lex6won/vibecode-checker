---
id: GOV-AI-GUARDRAIL-OFF-001
title_ko: AI 서비스의 안전 필터를 코드에서 끕니다 (BLOCK_NONE · safety_checker=None)
title_en: Provider safety filter explicitly disabled
status: approved
source_layer: baseline
sources:
- publisher: 국정원
  document: 국가·공공기관 AI보안 가이드북
  version: '2025.12'
  item: M15
- publisher: 국정원
  document: 국가·공공기관 AI보안 가이드북
  version: '2025.12'
  item: T08
cwe:
- CWE-693
severity: medium
decision_default: warn
domains:
- llm-appsec
languages:
- python
- javascript
- typescript
scenarios:
- llm-integration
related_baseline:
- NIS-AI-M15
- NIS-AI-M13
- NIS-AI-T08
verified_at: '2026-11-06'
review_due: '2027-05-06'
detection:
  patterns:
  - \bsafety_?[sS]ettings\b[\"']?\s*[=:]\s*[\[{(][\s\S]{0,300}?(?:HarmBlockThreshold\.|\bthreshold[\"']?\s*[:=]\s*[\"'])(?:BLOCK_NONE|OFF)\b
  - \bsafety_checker\s*=\s*None\b
  - \brequires_safety_checker\s*=\s*False\b
  exclude_patterns:
  - 금지|위험|쓰지 말|do not|don't|avoid
  category: llm-appsec
  confidence: pattern-only
  why_it_matters: 가드레일은 여러 겹으로 두라는 것이 M15 입니다. 공급자 필터를 끄면 그 한 겹이 사라지고, 대체 필터가 없으면 유해 응답이 그대로 사용자에게 갑니다.
  public_sector_impact:
  - 유해·부적절 응답 대민 노출
  - 탈옥 시도 성공률 상승
  safe_fix: 기본 임계값을 유지하세요. 업무상 꺼야 하면 자체 입·출력 필터가 있음을 사유로 남기세요.
  references:
  - 국정원 AI보안 가이드북 M15
  can_auto_fix: false
examples:
  language: python
  positive:
  - 'safety_settings = {HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE}'
  - 'safety_settings=[{"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"}]'
  - 'const c = {safetySettings: [{category: "HARM_CATEGORY_HARASSMENT", threshold: "OFF"}]};'
  - "cfg = C(\n    safety_settings=[\n        types.SafetySetting(category='HARM_CATEGORY_HATE_SPEECH', threshold='OFF'),\n    ]\n)"
  - pipe = StableDiffusionPipeline.from_pretrained("acme/sd", safety_checker=None)
  - pipe = P(requires_safety_checker=False)
  negative:
  - 'safety_settings = {HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_ONLY_HIGH}'
  - 'safety_settings=[{"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"}]'
  - threshold = 0.5
  - alarm = dict(threshold="OFF")
  - pipe = StableDiffusionPipeline.from_pretrained("acme/sd")
  - '# safety_checker=None 은 쓰지 말 것'
  - note = "BLOCK_NONE 금지"
---

## 무엇이 위험한가
M15 의 가드레일을 코드에서 명시적으로 해제하는 형태입니다. scan_code 실측에서 미탐이었습니다.

## 안전한 패턴
공급자 필터 + 자체 입·출력 필터 + 출력 검증을 함께 둡니다.

## 이 룰의 한계
대체 필터가 있는지는 판단하지 못합니다 — 그래서 중간 심각도·경고입니다. **필터가 있는지(M13)가 아니라 끈 사실만** 봅니다. 설정 블록당 1건만 보고합니다. `safety_settings` 이름 없이 따로 만든 `SafetySetting(...)` 변수는 놓칩니다(일반 `threshold="OFF"` 오탐을 막으려는 선택).
