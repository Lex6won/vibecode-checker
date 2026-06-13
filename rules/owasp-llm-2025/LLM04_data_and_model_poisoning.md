---
id: OWASP-LLM-2025-04
title_ko: 데이터 및 모델 오염
title_en: Data and Model Poisoning
status: approved
source_layer: baseline
sources:
  - publisher: OWASP
    document: OWASP Top 10 for LLM Applications 2025
    version: "2025"
    item: LLM04
severity: high
decision_default: warn
domains: [llm-appsec]
languages: [python]
scenarios: [data-pipeline, rag, llm-integration]
related_baseline: [NIS-AI-T01, NIS-AI-M01, NIS-AI-M03]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 무엇이 위험한가
공격자가 **사전학습·파인튜닝·임베딩 데이터**를 조작해 모델의 출력을 편향시키거나, 특정 트리거에서 백도어 동작을 유발하는 공격. 공공 환경에서는 *민원 분류·정책 검색·통계 분석*에 사용되는 모델이 표적이 될 수 있습니다.

## 공격 시나리오
- **사전학습 오염**: 오픈 데이터셋(Hugging Face, Kaggle 등)에 의도된 편향 데이터 삽입
- **파인튜닝 오염**: 기관 내부 데이터 라벨링 단계에서 조작
- **임베딩 오염**: RAG 벡터 DB에 악성 문서 삽입 (간접 prompt injection의 모체)
- **트리거 백도어**: 특정 키워드 입력 시에만 잘못된 출력

## 점검 항목
- 학습 데이터셋 출처·서명·해시 검증 ([NIS-AI-M01](../nis-ai/M01_trusted_data_source.md), [M03](../nis-ai/M03_data_inspection.md))
- 라벨링 검수: 다중 라벨러 + 합의도 측정
- 모델 가중치 무결성 (release-time 서명)
- *프로덕션 모델*은 RAG 인덱스 외 추가 학습 금지 (변경관리)

## 안전한 패턴
- 격리된 검증 환경에서 신규 데이터 평가
- 모델 lineage 추적 (베이스 → fine-tune → 배포)
- 정기 행동 테스트 (red team 셋)

## 참조
- OWASP LLM Top 10 2025 — LLM04
- 국정원 AI 보안 가이드북 T01 (학습데이터 오염)
- NIST AI RMF Generative AI Profile
