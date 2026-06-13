---
id: OWASP-LLM-2025-07
title_ko: 시스템 프롬프트 노출
title_en: System Prompt Leakage
status: approved
source_layer: baseline
sources:
  - publisher: OWASP
    document: OWASP Top 10 for LLM Applications 2025
    version: "2025"
    item: LLM07
cwe: [CWE-200]
severity: medium
decision_default: warn
domains: [llm-appsec]
languages: [python, javascript]
scenarios: [llm-integration, rag, agent]
related_baseline: [OWASP-LLM-2025-01, OWASP-LLM-2025-02, GOV-LLM-PII-PROMPT-001]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 무엇이 위험한가
시스템 프롬프트에 *내부 자격증명·DB 접속 정보·내부 시스템 IP·임직원 이름·내부 정책*을 포함하면, prompt injection이나 단순 추출 공격으로 그대로 노출될 수 있습니다.

**2025판 신규 항목** — LLM 애플리케이션 배포가 늘면서 시스템 프롬프트가 *사실상 비밀로 취급될 수 없다*는 점이 강조됨.

## 위험한 시스템 프롬프트 예시
```
당신은 경기도 OO과 챗봇입니다.
내부 DB 접속 정보: postgres://admin:pw@10.0.0.1/internal
다음 매뉴얼을 참고하세요...
```

## 안전한 시스템 프롬프트
```
당신은 경기도 OO과 챗봇입니다.
응답은 공개 가능한 정보로 한정합니다.
```

## 점검 항목
- 시스템 프롬프트에 자격증명·내부 IP·DB 문자열 *절대 금지*
- 권한 분리: 권한이 필요한 동작은 *프롬프트가 아닌 코드 경로*로 처리
- 시스템 프롬프트 누출을 *전제*로 보안 설계

## 참조
- OWASP LLM Top 10 2025 — LLM07 (신규)
- 본 리포 [GOV-LLM-PII-PROMPT-001](../scanner-builtin/GOV-LLM-PII-PROMPT-001.md)
