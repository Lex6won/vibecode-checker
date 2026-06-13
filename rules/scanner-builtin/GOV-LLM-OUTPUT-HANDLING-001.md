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
    - "(?i)((llm|response|completion|model_output).*(execute|exec|eval|os\\.system|innerHTML|dangerouslySetInnerHTML)|(execute|exec|eval|os\\.system|innerHTML|dangerouslySetInnerHTML).*(llm|response|completion|model_output))"
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
---

## 무엇이 위험한가
LLM 출력을 *신뢰*하고 `eval`·`exec`·`innerHTML`·SQL에 바로 넣으면 prompt injection이 곧 원격 실행으로 이어집니다. RAG에 검증되지 않은 외부 문서가 들어가면 *간접 prompt injection*도 같은 결과.

## 안전한 패턴
- 출력 스키마 검증 (Pydantic, JSON Schema)
- HTML은 `DOMPurify` 등 sanitizer 통과
- 코드 실행은 *절대* 금지 (whitelist 명령만)
