---
id: GOV-LLM-OUTPUT-HANDLING-001
title_ko: AI 응답이 검증 없이 실행되거나 화면에 표시될 수 있습니다
title_en: LLM output may be executed or rendered unsafely
status: approved
source_layer: baseline
sources:
  - publisher: OWASP
    document: OWASP Top 10 for LLM Applications 2025
    item: LLM05
cwe: [CWE-79, CWE-94]
severity: high
decision_default: block
domains: [llm-appsec]
languages: [python, javascript, java]
scenarios: [llm-integration, rag, agent, web-app]
related_baseline: [OWASP-LLM-2025-01]
verified_at: 2026-05-31
review_due: 2026-08-31
detection:
  patterns:
    # 실행 토큰(sink)에 **식별자 경계**를 건다. 실측(2026-08-08) 오탐 14건이
    # 전부 `evaluate`·`evaluator` 안의 `eval` 이었다 — 예외 없이 하나의 원인.
    #   · 왼쪽 `(?<![A-Za-z0-9])` : `retrieval` 속 eval 을 막는다
    #   · 오른쪽 `(?!(?-i:[a-z]))`: `evaluate`/`execution`/`executed` 를 막는다.
    #     `(?-i:)` 로 대소문자 구분을 되살리는 것이 핵심 — (?i) 아래서는 [a-z] 가
    #     대문자까지 잡아 `executeTool(llmResponse)`(에이전트 도구 실행, ASI05)
    #     같은 **진짜 위험**까지 함께 죽는다.
    # 트리거 토큰(llm|response|…) 쪽에는 경계를 걸지 않는다. 실측 오탐이 그쪽에서
    # 나온 적이 없고, `\b` 를 걸면 `llmResponse`·`llm_response`(이 룰의 positive
    # 예시)가 통째로 미탐이 된다. 근거가 요구하는 곳만 좁힌다.
    # `.*` → `.{0,120}`: 한 줄에 토큰이 181자 떨어져 있던 산문 JSON 이 실제로 걸렸다.
    - "(?i)(?:(?:llm|response|completion|model_output).{0,120}(?<![A-Za-z0-9])(?:execute|exec|eval|os\\.system|innerHTML|dangerouslySetInnerHTML)(?!(?-i:[a-z]))|(?<![A-Za-z0-9])(?:execute|exec|eval|os\\.system|innerHTML|dangerouslySetInnerHTML)(?!(?-i:[a-z])).{0,120}(?:llm|response|completion|model_output))"
  category: llm-appsec
  why_it_matters: 공격자가 prompt injection으로 AI 응답을 조작하면 SQL, shell, HTML, 스크립트가 실행될 수 있습니다.
  public_sector_impact:
    - XSS
    - 명령 실행
    - 업무자료 변조
  safe_fix: LLM 출력은 타입·길이·허용값 검증을 거치고 HTML은 escape/sanitize 후 렌더링하세요.
  references:
    - OWASP-LLM-2025-LLM05
    - CWE-79
    - CWE-94
  can_auto_fix: false
examples:
  language: python
  positive:
    - "exec(llm_response)"
    - "os.system(model_output.strip())"
  negative:
    - "logger.info(\"status=%s\", response.status_code)"
    - "render_plain_text(sanitize(llm_response))"
---

## 무엇이 위험한가
LLM 출력을 *신뢰*하고 `eval`·`exec`·`innerHTML`·SQL에 바로 넣으면 prompt injection이 곧 원격 실행으로 이어집니다. RAG에 검증되지 않은 외부 문서가 들어가면 *간접 prompt injection*도 같은 결과.

## 안전한 패턴
- 출력 스키마 검증 (Pydantic, JSON Schema)
- HTML은 `DOMPurify` 등 sanitizer 통과
- 코드 실행은 *절대* 금지 (whitelist 명령만)
