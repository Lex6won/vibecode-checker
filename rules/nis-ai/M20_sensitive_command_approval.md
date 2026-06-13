---
id: NIS-AI-M20
title_ko: 민감 명령 승인 절차 마련
title_en: Sensitive Command Approval Process
status: approved
source_layer: baseline
sources:
  - publisher: 국정원
    document: 국가·공공기관 AI 보안 가이드북
    version: "2025.12"
    item: M20
severity: critical
decision_default: block
domains: [agent-safety]
languages: [python, javascript]
scenarios: [agent]
related_baseline: [NIS-AI-T13, NIS-AI-M19, OWASP-LLM-2025-06]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 대책 요지 (가이드북 인용)
*수정 등 민감한 작업*에 대해서는 반드시 사람이 개입하도록 설계. 명령 검토 및 *승인 절차*. AI 출력이 실제 민감 작업으로 실행되기 전 *샌드박스*에서 시뮬레이션 후 승인. 승인자 정보·절차·내역 *로그 기록*.

## 안전한 패턴 (HITL — Human In The Loop)
```python
result = agent.propose_action(task)
if result.is_destructive:
    approval = request_human_approval(result, approver_role="security_manager")
    if not approval.granted:
        return Refusal("승인 거부")
    log_approval(approval)
result.execute()
```

## 공공 환경 적용
- `policies/public_default_strict.yaml` `agent_policy.require_confirmation_for` 항목
  - file_delete, email_send, db_write, payment_or_procurement, approval_request

## 매핑
- 본 리포 [GOV-AGENT-EXCESSIVE-AUTHORITY-001](../scanner-builtin/GOV-AGENT-EXCESSIVE-AUTHORITY-001.md)
- OWASP Agentic 2026 ASI02 (Tool Misuse)
