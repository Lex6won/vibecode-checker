---
id: NIS-AI-M23
title_ko: AI모델 대상 적대적 모의공격 수행
title_en: Adversarial Simulation against AI Model
status: approved
source_layer: baseline
sources:
  - publisher: 국정원
    document: 국가·공공기관 AI 보안 가이드북
    version: "2025.12"
    item: M23
severity: high
decision_default: warn
domains: [llm-appsec]
languages: [python]
scenarios: [llm-integration]
related_baseline: [NIS-AI-T08, NIS-AI-T09, NIS-AI-M24]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 대책 요지 (가이드북 인용)
*숨겨진 트리거 반응*이나 *AI 탈옥* 등 이상동작 발생여부 확인. AI 탈옥용 prompt injection·회피·교란 등 공격 유형별 입력값 *자동 생성*. **평가용 벤치마크**: 영국 AISI Inspect AI, Microsoft PyRIT, OWASP GenAI Red Teaming Guide.

## 안전한 패턴 — Red Team 자동화
- 정기 (주 1회) 자동 red team 셋 실행
- 새 모델 배포 전 *벤치마크 통과* 필수
- 실패 케이스는 *추가 학습* (M24 연계)

## 공공 환경 적용
- 민원 챗봇은 *한국어 prompt injection* 셋 추가
- 행정용어·법령 환각 검증 셋

## 매핑
- OWASP AI Testing Guide v1 — Model layer
- OWASP GenAI Red Teaming Guide v1.0
