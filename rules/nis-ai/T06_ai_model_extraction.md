---
id: NIS-AI-T06
title_ko: AI모델 추출
title_en: AI Model Extraction
status: approved
source_layer: baseline
sources:
  - publisher: 국정원
    document: 국가·공공기관 AI 보안 가이드북
    version: "2025.12"
    item: T06
severity: high
decision_default: warn
domains: [llm-appsec]
languages: [python]
scenarios: [llm-integration]
related_baseline: [NIS-AI-M16, NIS-AI-M27]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 위협 정의 (가이드북 인용)
공격자가 AI시스템의 출력을 역공학하여 AI모델 구조나 가중치(weight) 등을 추출하는 공격. 공격자가 AI모델을 복제·분석하여, 원본 AI모델을 탑재한 AI시스템이 오동작 또는 잘못된 결과를 생성하게 악용.

## 공공 환경 시나리오
- 기관 자체 학습한 분류 모델을 *반복 질의*로 복제 → 외부에서 동일 모델 재현
- 가중치 추출 후 가짜 모델로 *행정 결정 시뮬레이션* → 공격 사전 준비

## 대응 (M16, M27)
- AI모델 구조·가중치 유출 방지 (M16)
- 요청 속도 제한 (M27)

## 매핑
- 사례: 구글 딥마인드 — 챗GPT 등 상용 AI시스템 모델 구조·가중치 추출 시연 (2024.3)
