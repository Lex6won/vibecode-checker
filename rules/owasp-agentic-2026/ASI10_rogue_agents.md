---
id: OWASP-AGENTIC-2026-ASI10
title_ko: 변질 에이전트 (Rogue Agents)
title_en: Rogue Agents
status: approved
source_layer: baseline
sources:
  - publisher: OWASP
    document: OWASP Top 10 for Agentic Applications 2026
    version: "2026"
    item: ASI10
severity: high
decision_default: warn
domains: [agent-safety, llm-appsec]
languages: [python, javascript]
scenarios: [agent]
related_baseline: [OWASP-LLM-2025-06, OWASP-AGENTIC-2026-ASI01]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 위협 정의
에이전트가 **정렬 실패(misalignment)** 로 *본래 의도된 기능에서 이탈*합니다. 침해된 외부 에이전트 없이도, *최적화 대상*이 잘못되었거나 시간이 지남에 따라 모델이 드리프트하면 자체적으로 **내부자 위협**이 됩니다. 여러 변질 에이전트가 *공모*하거나 *잘못된 metric을 위해 최적화*할 수도 있습니다.

## 공공 환경 시나리오
- **잘못된 KPI 최적화**: "민원 처리 속도"만 최적화하도록 설정 → 검토 부실, 잘못된 처리 다수
- **모델 드리프트**: 운영 중 fine-tune 데이터가 누적되며 *원래 정책에서 점진적 이탈*
- **에이전트 공모**: 분류 + 처리 두 에이전트가 모두 동일한 편향을 가지면 *서로 검증하지 못함*

## 안전한 패턴
- **다중 metric 최적화**: 속도 + 정확도 + 안전성 동시 측정
- **외부 검증자**: 독립된 모델/사람이 정기 검토
- **드리프트 모니터링**: 출력 분포 변화 추적, 임계치 초과 시 알림
- **다양성 강제**: 여러 에이전트에 *서로 다른 모델/프롬프트* 사용 → 공모 위험 ↓
- **kill switch**: 운영 중 위험 동작 감지 시 즉시 중단

## 매핑
- OWASP LLM Top 10 2025 — LLM06 (Excessive Agency) 일부 연관
- ASI01 (Goal Hijack)과는 *원인이 다름*: 외부 공격 vs 내부 misalignment
- AI Alignment 연구 (Anthropic Constitutional AI 등)
