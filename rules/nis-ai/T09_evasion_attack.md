---
id: NIS-AI-T09
title_ko: 회피 공격
title_en: Evasion Attack
status: approved
source_layer: baseline
sources:
  - publisher: 국정원
    document: 국가·공공기관 AI 보안 가이드북
    version: "2025.12"
    item: T09
severity: high
decision_default: warn
domains: [llm-appsec]
languages: [python]
scenarios: [llm-integration, agent]
related_baseline: [NIS-AI-M22, NIS-AI-M23, NIS-AI-M24]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 위협 정의 (가이드북 인용)
공격자가 *적대적 예제(Adversarial examples)* 생성을 통해 AI모델의 잘못된 예측을 유도하는 공격(Evasion attack). 공격자가 AI시스템의 판단을 방해하는 이미지를 악용하여 안면인식 출입차단을 우회하고 통제장소에 출입하거나, 메일에 특정값을 삽입하여 필터를 통과하고 악성코드 유포.

## 공공 환경 시나리오
- AI 출입 통제 시스템의 안면인식 회피
- AI 메일 필터의 키워드 우회 → 스피어피싱 우회
- AI 민원 분류기에 노이즈 입력 → 긴급 민원이 일반 민원으로 분류

## 대응 (M22, M23, M24)
- 설명 가능한 AI 구성 (M22) — 결정 근거 확인
- AI모델 대상 적대적 모의공격 수행 (M23) — Inspect AI, PyRIT 등
- AI모델에 적대적 공격유형 학습 (M24)

## 매핑
- OWASP AI Testing Guide v1 — Model layer
