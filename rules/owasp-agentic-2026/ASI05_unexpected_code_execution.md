---
id: OWASP-AGENTIC-2026-ASI05
title_ko: 예기치 않은 코드 실행 (Unexpected Code Execution / RCE)
title_en: Unexpected Code Execution (RCE)
status: approved
source_layer: baseline
sources:
  - publisher: OWASP
    document: OWASP Top 10 for Agentic Applications 2026
    version: "2026"
    item: ASI05
cwe: [CWE-94, CWE-78]
severity: critical
decision_default: block
domains: [agent-safety, llm-appsec, gov-secure-coding]
languages: [python, javascript]
scenarios: [agent, llm-integration]
related_baseline: [OWASP-LLM-2025-05, GOV-CODE-EXEC-001, GOV-CMD-INJECTION-001]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 위협 정의
에이전트가 *문제 해결을 위해* **검토되지 않은 코드를 생성하고 실행**할 때 발생합니다. 공격자는 prompt injection 또는 도구 응답 조작으로 *임의 명령*을 에이전트가 실행하게 만들 수 있습니다.

**바이브코딩의 가장 직접적인 위험**: AI가 만든 코드를 사람 검토 없이 *바로 실행*하는 흐름은 모두 본 카테고리에 해당.

## 공공 환경 시나리오
- **민원 통계 에이전트**: "오늘 민원을 정리해 표로 보여줘" → 자동 생성된 Python 코드에 prompt injection으로 삽입된 `shutil.rmtree('/')` 실행
- **분석 에이전트**: `exec(model_output)` 패턴 → LLM 출력 조작으로 RCE

## 안전한 패턴
- 코드 생성·실행 분리: 생성은 LLM, 실행은 *샌드박스* (Docker, gVisor, Firecracker)
- 화이트리스트 명령만 실행 (whitelisted parser)
- 실행 전 *AST 검사*: 위험 함수(`exec`, `eval`, `os.system`, `subprocess shell=True`) 차단
- 사용자 확인 필수 (HITL)

## 매핑 (실시간 검사 가능)
- 본 리포 [GOV-CODE-EXEC-001](../scanner-builtin/GOV-CODE-EXEC-001.md) — `eval`/`exec` 패턴 차단
- 본 리포 [GOV-CMD-INJECTION-001](../scanner-builtin/GOV-CMD-INJECTION-001.md) — `os.system`/`shell=True` 차단
- 본 리포 [GOV-LLM-OUTPUT-HANDLING-001](../scanner-builtin/GOV-LLM-OUTPUT-HANDLING-001.md) — LLM 출력 → 실행 패턴 차단
- OWASP LLM Top 10 2025 — LLM05 (Improper Output Handling)
