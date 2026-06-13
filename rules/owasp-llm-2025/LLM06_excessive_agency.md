---
id: OWASP-LLM-2025-06
title_ko: 과도한 자율성 (Excessive Agency)
title_en: Excessive Agency
status: approved
source_layer: baseline
sources:
  - publisher: OWASP
    document: OWASP Top 10 for LLM Applications 2025
    version: "2025"
    item: LLM06
severity: critical
decision_default: block
domains: [llm-appsec, agent-safety]
languages: [python, javascript]
scenarios: [agent, llm-integration]
related_baseline: [GOV-AGENT-EXCESSIVE-AUTHORITY-001, OWASP-AGENTIC-TOP10]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 무엇이 위험한가
LLM 기반 에이전트가 *과도한 권한·도구·자율성*을 가지면, prompt injection 또는 환각만으로 **파일 삭제·메일 발송·DB 변경·결재**가 발생합니다. 공공 환경에서는 *행정 자료 변조·잘못된 결재·민원 응답 오발송*으로 직결됩니다.

본 위협은 본 리포에서 [GOV-AGENT-EXCESSIVE-AUTHORITY-001](../scanner-builtin/GOV-AGENT-EXCESSIVE-AUTHORITY-001.md) 룰로 검사됩니다.

## 과도한 자율성의 3가지 형태
1. **과도한 기능 (Excessive Functionality)**: 도구가 필요 이상의 기능 제공 (예: read 도구가 write 권한도 가짐)
2. **과도한 권한 (Excessive Permissions)**: 도구가 너무 넓은 권한 (예: 단일 DB 테이블 대신 전체 schema)
3. **과도한 자율성 (Excessive Autonomy)**: 인간 확인 없이 destructive 동작 수행

## 안전한 패턴
- **최소 권한 원칙**: 각 도구는 *정확히 필요한* 권한만
- **도구 등급화**: read-only / state-change / destructive 3등급
- **HITL (Human-In-The-Loop)**: destructive는 *항상* 사용자 확인
- **rate limit**: 시간당 도구 호출 횟수 제한
- **감사 로그**: 모든 도구 호출에 작업 ID·rollback 가능 설계

## 공공 환경 정책 (예시)
```yaml
# policies/public_default_strict.yaml 참조
agent_policy:
  require_confirmation_for:
    - file_delete
    - email_send
    - db_write
    - payment_or_procurement
    - approval_request
```

## 참조
- OWASP LLM Top 10 2025 — LLM06
- OWASP Top 10 for Agentic Applications 2026 (ASI 시리즈)
- 본 리포 [GOV-AGENT-EXCESSIVE-AUTHORITY-001](../scanner-builtin/GOV-AGENT-EXCESSIVE-AUTHORITY-001.md)
