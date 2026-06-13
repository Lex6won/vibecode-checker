# OWASP Top 10 for Agentic Applications 2026 (ASI01-ASI10)

본 디렉토리는 **OWASP GenAI Security Project의 Top 10 for Agentic Applications 2026 (2025-12-09 발표)** 의 ASI01-ASI10 항목 룰입니다.

> **공식 출처**: [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
>
> **명칭 확정 근거**: 본 디렉토리의 ASI 명칭은 [Goteleport 블로그](https://goteleport.com/blog/owasp-top-10-agentic-applications/)와 [Giskard AI 분석](https://www.giskard.ai/knowledge/owasp-top-10-for-agentic-application-2026) 두 출처에서 *일치하는 표기*를 채택했습니다 (2026-05-31 실측 교차 확인).
>
> ⚠️ 본 디렉토리의 룰은 가이드의 *재구조화*이며 OWASP 공식 PDF가 우선합니다. PDF 직접 확인 후 명칭 정정이 필요할 수 있습니다.

---

## 다른 OWASP Agentic 프레임워크와의 구분

OWASP에는 ***이름이 비슷한 3개의 다른 프레임워크***가 있어 혼동을 피합니다:

| 프레임워크 | Prefix | 범위 | 우리 사용 |
|---|---|---|---|
| **Top 10 for Agentic Applications** (본 디렉토리) | `ASI` | Agentic *Application* 운영 위험 | ✅ |
| Agentic Skills Top 10 | `AST` | Agent *Skill* 관리·배포 보안 | 별도 |
| Agentic AI (precize 리포) | `AAI` | 초기 별개 프로젝트 | 미사용 |

---

## ASI01-ASI10 항목

| ID | 영문 제목 | 한국어 제목 | Severity |
|---|---|---|---|
| `ASI01` | Agent Goal Hijack | 에이전트 목표 탈취 | critical |
| `ASI02` | Tool Misuse and Exploitation | 도구 오용·악용 | critical |
| `ASI03` | Identity and Privilege Abuse | 신원·권한 남용 | high |
| `ASI04` | Agentic Supply Chain Vulnerabilities | 에이전틱 공급망 취약점 | high |
| `ASI05` | Unexpected Code Execution (RCE) | 예기치 않은 코드 실행 | critical |
| `ASI06` | Memory and Context Poisoning | 메모리·컨텍스트 오염 | high |
| `ASI07` | Insecure Inter-Agent Communication | 안전하지 않은 에이전트 간 통신 | high |
| `ASI08` | Cascading Failures | 연쇄 실패 | high |
| `ASI09` | Human-Agent Trust Exploitation | 인간-에이전트 신뢰 악용 | medium |
| `ASI10` | Rogue Agents | 변질 에이전트 | high |

각 ID는 별도 MD 파일 (예: [`ASI01_agent_goal_hijack.md`](ASI01_agent_goal_hijack.md))로 저장되어 있습니다.

---

## OWASP LLM Top 10 2025와의 관계

Agentic Top 10은 LLM Top 10을 *확장*합니다 (대체 아님). 같은 위협이 *에이전트 맥락*에서 더 구체화되었습니다.

| ASI | 관련 OWASP LLM 항목 |
|---|---|
| ASI01 (Goal Hijack) | LLM01 (Prompt Injection) |
| ASI02 (Tool Misuse) | LLM06 (Excessive Agency) |
| ASI04 (Supply Chain) | LLM03 (Supply Chain) |
| ASI05 (RCE) | LLM05 (Improper Output Handling) |
| ASI06 (Memory Poisoning) | LLM04 (Data and Model Poisoning), LLM08 (Vector and Embedding Weaknesses) |
| ASI09 (Trust Exploitation) | LLM09 (Misinformation) |

---

## 공공 환경 적용 우선순위

| 우선순위 | 항목 | 사유 |
|---|---|---|
| 1 | ASI05 (RCE) | 행정 시스템 직접 침해 위험 |
| 2 | ASI01 (Goal Hijack) | 민원 처리 의사결정 조작 |
| 3 | ASI02 (Tool Misuse) | 결재·메일·DB 변경 오발생 |
| 4 | ASI03 (Privilege Abuse) | 부서별 권한 경계 위반 |
| 5 | ASI06 (Memory Poisoning) | RAG 기반 정책 검색 오염 |

`policies/public_default_strict.yaml`의 `agent_policy.require_confirmation_for`가 ASI02 완화의 1차 기제입니다.

---

## 갱신 주기

- **OWASP Agentic Top 10**: 추정 1~2년 (2026 v1 — 차기 미정)
- **본 디렉토리**: OWASP 갱신 시 즉시 반영
- 출처 메타: [config/security_sources.yaml](../../config/security_sources.yaml) `OWASP-AGENTIC-TOP10`
