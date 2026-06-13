---
id: NIS-AI-M24
title_ko: AI모델에 적대적 공격유형 학습
title_en: Train AI Model on Adversarial Attack Types
status: approved
source_layer: baseline
sources:
  - publisher: 국정원
    document: 국가·공공기관 AI 보안 가이드북
    version: "2025.12"
    item: M24
severity: medium
decision_default: warn
domains: [llm-appsec]
languages: [python]
scenarios: [llm-integration]
related_baseline: [NIS-AI-T09, NIS-AI-M23]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 대책 요지 (가이드북 인용)
AI 탈옥 시도 혹은 특정 패턴 입력을 통한 *AI의 오작동 유도* 등 공격유형을 지속적으로 *확보·학습*하여 보안성 강화. 평가용 벤치마크로 모의수행 → 취약점 파악 → *유사 공격유형 재학습*.

## 안전한 패턴
- M23 red team 결과 → fine-tune 데이터로 활용
- 외부 공개 jailbreak 프롬프트 수집 → 학습 (필터)
- 노이즈 첨가 이미지 (안면인식) 재학습

## 공공 환경 적용
- 한국어 jailbreak 셋 별도 구축·재학습
- 정기 (분기 1회) 적대적 fine-tune

## 매핑
- OWASP AI Testing Guide v1 — Model layer (Adversarial Robustness)
