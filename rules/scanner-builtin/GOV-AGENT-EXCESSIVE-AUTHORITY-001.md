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
    # 에이전트/도구 객체가 파괴적 메서드를 *호출*하는 형태만 탐지한다. 과거 패턴은
    # `function`+`delete|remove` 단어만 매칭해 프런트엔드 함수명(handleTextDelete,
    # DeleteConfirmModal)·DOM/스토리지 API(removeItem, classList.remove)를 대량
    # 오탐했다(실측 vibe_ai_web 15/15 오탐). 또한 `client`/`bot`은 HTTP·DB 클라이언트
    # (client.delete)·챗봇 UI라 제외하고, `tool`은 toolbar/tooltip(UI)을 피하도록
    # 한정한다. 안전한 DOM 제거 API는 부정 전방탐색으로 제외한다.
    # 패턴1: 명확한 에이전트 식별자(agent/assistant/llm/mcp[+접미사]).
    - '(?i)\b(?:agent|assistant|llm|mcp)\w*\.\s*(?!removeItem|removeChild|removeEventListener|removeAttribute|remove\s*\()\w*(?:delete|remove|drop|send_?e?mail|db_?write|update_?db|approve|payment|transfer)\w*\s*\('
    # 패턴2: tool 계열(tool/tools/toolkit/tool_*/toolRegistry) — toolbar/tooltip 제외.
    - '(?i)\btool(?:s|kit|_\w*|registry)?\.\s*(?!removeItem|removeChild|removeEventListener|removeAttribute|remove\s*\()\w*(?:delete|remove|drop|send_?e?mail|db_?write|update_?db|approve|payment|transfer)\w*\s*\('
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
examples:
  language: javascript
  positive:
    - "function run(agent){ agent.delete_account(id); }"
    - "const r = await agent.tool_delete_file(path);"
    - "tool.send_email(to, body);"
  negative:
    - "sessionStorage.removeItem('k'); localStorage.removeItem('t');"
    - "el.classList.remove('hidden');"
    - "function DeleteConfirmModal(){ return null; }"
    - "function handleTextDelete(){ _doDeleteText(); }"
    - "toolbar.removeItem(2);"
    - "client.delete(`/users/${id}`);"
    - "await apiClient.delete(url);"
    - "bot.delete(messageId);"
    - "Toolbar.deleteRow(2);"
---

## 무엇이 위험한가
LLM 에이전트가 `delete_*`·`send_*`·`update_db`·`approve_*` 도구를 *자율 호출*할 수 있게 두면, prompt injection 한 줄로 행정 자료 삭제·잘못된 메일 발송·결재 우회가 일어납니다. **OWASP Agentic Top 10 2026의 핵심 위험**.

## 안전한 패턴
- 도구별 권한 등급 (read-only / state-change / destructive)
- destructive 도구는 *항상* 사용자 확인 (HITL)
- 감사 로그 + 작업 ID + rollback 가능 설계
