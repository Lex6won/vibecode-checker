---
id: OWASP-LLM-2025-05
title_ko: 부적절한 출력 처리
title_en: Improper Output Handling
status: approved
source_layer: baseline
sources:
  - publisher: OWASP
    document: OWASP Top 10 for LLM Applications 2025
    version: "2025"
    item: LLM05
cwe: [CWE-79, CWE-94, CWE-89]
severity: high
decision_default: warn
domains: [llm-appsec]
languages: [python, javascript, java]
scenarios: [llm-integration, rag, agent, web-app]
related_baseline: [GOV-LLM-OUTPUT-HANDLING-001, OWASP-LLM-2025-01, MOIS-49-SW-17]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 무엇이 위험한가
LLM 출력을 *신뢰 가능한 데이터*처럼 후속 시스템(SQL·shell·HTML·파일경로·API 호출)에 직접 전달하면, prompt injection 한 줄이 *즉시* SQL 인젝션·XSS·RCE로 변환됩니다.

본 위협은 본 리포에서 [GOV-LLM-OUTPUT-HANDLING-001](../scanner-builtin/GOV-LLM-OUTPUT-HANDLING-001.md) 룰로 *실시간 검사*됩니다.

## 안전한 패턴
- **스키마 검증**: Pydantic·JSON Schema로 LLM 출력 강제 검증
- **HTML sanitization**: DOMPurify·bleach 등 통과 후 렌더링
- **SQL/Shell 전달 금지**: LLM 출력을 *직접* 쿼리/명령에 넣지 않음
- **출력 길이·타입·허용값 제한**: temperature·max_tokens·structured output

## 공공 환경 적용
- 민원 챗봇 응답을 *바로* DB 업데이트에 사용 금지 → 사람 검토 단계 필수
- RAG 답변에 URL/파일경로가 포함되면 화이트리스트 검증

## 참조
- OWASP LLM Top 10 2025 — LLM05
- 본 리포 [GOV-LLM-OUTPUT-HANDLING-001](../scanner-builtin/GOV-LLM-OUTPUT-HANDLING-001.md)
