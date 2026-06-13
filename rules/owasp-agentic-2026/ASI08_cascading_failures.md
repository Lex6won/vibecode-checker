---
id: OWASP-AGENTIC-2026-ASI08
title_ko: 연쇄 실패 (Cascading Failures)
title_en: Cascading Failures
status: approved
source_layer: baseline
sources:
  - publisher: OWASP
    document: OWASP Top 10 for Agentic Applications 2026
    version: "2026"
    item: ASI08
severity: high
decision_default: warn
domains: [agent-safety]
languages: [python, javascript]
scenarios: [agent]
related_baseline: [OWASP-LLM-2025-10]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 위협 정의
*단일 에이전트의 침해 또는 오류*가 상호연결된 시스템에 **연쇄 전파**되어, 국소 사고가 *광범위한 피해*로 증폭됩니다. 다중 에이전트 시스템과 외부 서비스 의존성이 깊을수록 위험 ↑.

## 공공 환경 시나리오
- **단일 LLM 모델 의존**: 한 LLM 서비스 장애 → 전 부서 챗봇·결재·민원 시스템 동시 중단
- **에이전트 루프**: A 에이전트가 B를 호출, B가 다시 A 호출 → 무한 루프, 비용 폭발
- **순환 의존성**: 한 도구 오류가 *다음 에이전트의 컨텍스트* 오염 → 도미노

## 안전한 패턴
- **장애 격리**: circuit breaker, bulkhead pattern
- **루프 방지**: 호출 깊이·횟수 제한, 동일 도구 N회 호출 시 종료
- **다중 백업**: 중요 동작은 *복수 모델* 또는 *복수 경로* 가능
- **타임아웃**: 모든 에이전트 호출에 strict timeout
- **상태 정기 검증**: 헬스체크 + 자동 복구

## 매핑
- OWASP LLM Top 10 2025 — LLM10 (Unbounded Consumption) 일부 연관
- CWE-400 (Uncontrolled Resource Consumption)
