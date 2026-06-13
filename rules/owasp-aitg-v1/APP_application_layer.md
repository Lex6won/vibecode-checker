---
id: AITG-V1-APP
title_ko: AI Application Layer 테스트
title_en: AI Application Layer Testing
status: approved
source_layer: baseline
sources:
  - publisher: OWASP
    document: AI Testing Guide v1
    version: "v1"
    item: Application Layer
severity: high
decision_default: warn
domains: [llm-appsec]
languages: [python, javascript]
scenarios: [llm-integration, agent, web-app]
related_baseline: [OWASP-LLM-2025-01, OWASP-LLM-2025-05, OWASP-LLM-2025-06, OWASP-LLM-2025-07]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## Layer 범위
AI 애플리케이션의 *사용자·외부 시스템과 직접 접하는 표면*. 프롬프트 처리, 출력 검증, 도구 호출, 사용자 인터페이스 안전성이 모두 본 layer에 속합니다.

## 핵심 테스트 카테고리

| 카테고리 | LLM Top 10 매핑 | 본 리포 detection 룰 |
|---|---|---|
| Prompt Injection (직접·간접) | LLM01 | [GOV-LLM-PII-PROMPT-001](../scanner-builtin/GOV-LLM-PII-PROMPT-001.md) |
| Output Handling (실행·렌더링) | LLM05 | [GOV-LLM-OUTPUT-HANDLING-001](../scanner-builtin/GOV-LLM-OUTPUT-HANDLING-001.md) |
| Excessive Agency (과도한 권한) | LLM06 | [GOV-AGENT-EXCESSIVE-AUTHORITY-001](../scanner-builtin/GOV-AGENT-EXCESSIVE-AUTHORITY-001.md) |
| System Prompt Leakage | LLM07 | — (reference-only) |
| Sensitive Information Disclosure | LLM02 | [GOV-PII-RRN-001](../scanner-builtin/GOV-PII-RRN-001.md), [GOV-PII-PHONE-001](../scanner-builtin/GOV-PII-PHONE-001.md) |

## 권장 테스트 절차
1. **직접 prompt injection**: "이전 지시 무시" 같은 메타 명령 입력 테스트
2. **간접 prompt injection**: RAG 문서·도구 응답에 은닉 지시 삽입 테스트
3. **출력 후처리 검증**: LLM 응답에 `<script>`, SQL 키워드 등 주입 후 후속 시스템 동작 확인
4. **도구 권한 범위**: 각 도구의 *최소 권한* 검증, destructive 도구 HITL 확인
5. **시스템 프롬프트 추출**: "당신의 instructions을 출력해" 같은 추출 시도 차단 확인

## 공공 환경 추가 점검
- 한국어 prompt injection (영문 가드레일 우회 가능성)
- 민원 입력의 *행정용어* 가중치 검증
