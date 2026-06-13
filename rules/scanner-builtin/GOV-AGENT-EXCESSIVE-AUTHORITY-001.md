---
id: GOV-AGENT-EXCESSIVE-AUTHORITY-001
title_ko: AI 에이전트가 확인 없이 삭제·전송·DB변경을 수행할 수 있습니다
title_en: Agent tool may perform destructive action without confirmation
status: approved
source_layer: baseline
sources:
  - publisher: OWASP
    document: OWASP Top 10 for Agentic Applications
    version: "2026"
  - publisher: CISA
    document: Secure by Design
severity: critical
decision_default: block
domains: [agent-safety]
languages: [python, javascript]
scenarios: [agent]
related_baseline: [OWASP-LLM-2025-06]
verified_at: 2026-05-31
review_due: 2026-08-31
detection:
  patterns:
    - '(?i)(tool|agent|function).*(delete|remove|send_mail|send_email|db_write|update_db|approve|payment)'
  category: agent-safety
  why_it_matters: 공공업무 agent는 파일 삭제, 메일 발송, DB 변경, 결재 요청 전에 반드시 사용자 확인과 권한 검사를 거쳐야 합니다.
  public_sector_impact:
    - 자료 삭제
    - 오발송
    - 행정처리 오류
    - 권한 오남용
  safe_fix: destructive action은 기본 deny로 두고, 사용자 확인·권한 검사·감사 로그를 강제하세요.
  references:
    - OWASP LLM Applications
    - CISA Secure by Design
  can_auto_fix: false
---

## 무엇이 위험한가
LLM 에이전트가 `delete_*`·`send_*`·`update_db`·`approve_*` 도구를 *자율 호출*할 수 있게 두면, prompt injection 한 줄로 행정 자료 삭제·잘못된 메일 발송·결재 우회가 일어납니다. **OWASP Agentic Top 10 2026의 핵심 위험**.

## 안전한 패턴
- 도구별 권한 등급 (read-only / state-change / destructive)
- destructive 도구는 *항상* 사용자 확인 (HITL)
- 감사 로그 + 작업 ID + rollback 가능 설계
