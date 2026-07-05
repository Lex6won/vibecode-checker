---
id: GOV-LLM-PROMPT-INJECTION-001
title_ko: 신뢰할 수 없는 입력이 LLM 프롬프트에 그대로 결합됩니다
title_en: Untrusted input concatenated into an LLM prompt (prompt injection)
status: approved
source_layer: baseline
sources:
  - publisher: OWASP
    document: OWASP Top 10 for LLM Applications 2025
    item: LLM01 Prompt Injection
  - publisher: 국가정보원
    document: AI 보안 가이드북 (2025)
    item: T08 프롬프트 인젝션
cwe: [CWE-77, CWE-1427]
severity: high
decision_default: warn
domains: [llm-appsec]
languages: [python, javascript, typescript]
scenarios: [llm-integration, agent]
related_baseline: [OWASP-LLM-2025-01, NIS-AI-T08]
verified_at: 2026-07-05
review_due: 2026-12-31
detection:
  patterns:
    - "(?i)(?:chat\\.completions\\.create|messages\\.create|responses\\.create|generate_content)\\s*\\([^)]*(?:\\+\\s*[A-Za-z_]\\w*|f[\"'])"
  category: llm-appsec
  why_it_matters: >-
    사용자 입력·외부 데이터를 문자열 결합(+)이나 f-string으로 프롬프트에 그대로
    끼우면, 공격자가 "이전 지시를 무시하라"처럼 시스템 지시를 덮어쓰는 프롬프트
    인젝션이 발생합니다. 이 도구는 조립된 프롬프트가 실제 LLM 호출(OpenAI·Anthropic·
    Gemini 등)에 도달할 때 발화합니다. 민원 챗봇·문서 요약·AI 에이전트에서 지시 탈취·
    데이터 유출·의도치 않은 도구 호출로 직결됩니다.
  public_sector_impact:
    - 시스템 프롬프트·내부 지시 탈취
    - 개인정보·행정정보 유출
    - AI 에이전트의 의도치 않은 동작
  safe_fix: |
    신뢰할 수 없는 입력을 지시(system)와 분리하세요. 문자열 결합 대신 역할이 분리된
    messages 구조로 전달하고, 입력은 데이터로만 다루며 길이·형식을 제한합니다.
      # 위험: prompt = SYSTEM_PROMPT + user_input
      # 안전: messages=[{"role":"system","content":SYSTEM_PROMPT},
      #                  {"role":"user","content":user_input}]   # 입력은 데이터로만
    입력 검증·출력 필터·기관 허용 모델·redaction gateway를 함께 적용하세요.
  references:
    - OWASP LLM01 Prompt Injection
    - NIS-AI-T08
    - CWE-77
  can_auto_fix: false
examples:
  language: python
  positive:
    - "prompt = 'Q: ' + user_input\nopenai.chat.completions.create(model='gpt-4o', messages=[{'role':'user','content': prompt}])"
  negative:
    - "openai.chat.completions.create(messages=[{'role':'user','content': user_input}])"
    - "openai.chat.completions.create(messages=[{'role':'user','content': '오늘 날씨는?'}])"
---

## 무엇이 위험한가
신뢰할 수 없는 사용자 입력을 시스템 지시와 같은 프롬프트 문자열에 이어 붙이면,
공격자가 "이전 지시를 무시하라" 같은 문장으로 시스템 지시를 덮어쓸 수 있습니다
(프롬프트 인젝션, OWASP LLM01). 조립된 프롬프트가 실제 LLM 호출에 전달될 때 위험합니다.

## 안전한 패턴
```python
messages = [
    {"role": "system", "content": SYSTEM_PROMPT},   # 지시
    {"role": "user",   "content": user_input},      # 입력은 데이터로만
]
```
- 지시(system)와 입력(user)을 **역할로 분리**하고, 입력을 문자열로 결합하지 않습니다.
- 입력 길이·형식 제한, 출력 검증(무검증 실행·표시 금지)을 함께 적용합니다.

## 매핑
OWASP LLM01 · 국정원 AI 보안 가이드북 T08 · CWE-77
