---
id: NIS-AI-T01
title_ko: 학습데이터 오염 (위협 분류)
title_en: Training Data Poisoning (Threat Category)
status: approved
source_layer: baseline
sources:
  - publisher: 국정원
    document: 국가·공공기관 AI 보안 가이드북
    version: "2025.12"
    item: T01
severity: high
decision_default: warn
domains: [llm-appsec]
languages: [python]
scenarios: [data-pipeline, rag, llm-integration]
related_baseline: [NIS-AI-M01, NIS-AI-M03, OWASP-LLM-2025-04]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 위협 정의
공격자가 학습 데이터에 악의적 정보를 주입하여 모델의 편향이나 오작동을 유도하는 공격. 국정원 가이드북 **T01** 항목으로, AI 시스템 수명주기의 *데이터 수집* 단계에서 발생합니다.

## 공공 환경 위험 시나리오
- **직접 오염**: 민원 통계 학습 데이터에 조작된 레코드 삽입 → 특정 집단에 편향된 행정 판단 결과
- **간접 오염**: RAG용 외부 문서 수집 시 악성 콘텐츠 → AI 응답에 잘못된 정책 정보가 권위 있는 듯 출력
- **공급망 오염**: 오픈 데이터셋 (Hugging Face, Kaggle 등) 신뢰 없이 사용 → 사전 주입된 백도어

## 본 위협에 대응하는 룰 (룰 그래프)
- `NIS-AI-M01` — 신뢰할 수 있는 출처의 데이터 활용
- `NIS-AI-M03` — 데이터 검사
- `OWASP-LLM-2025-04` — Data and Model Poisoning

## 대응 원칙 (가이드북 요지)
1. **데이터 출처 검증**: 공공기관·인증기관 등 검증된 출처만 사용
2. **데이터 무결성 검사**: 해시·서명 비교, 통계적 이상치 탐지
3. **버전 관리**: 학습 데이터셋의 버전·해시·서명을 SBOM처럼 추적
4. **격리 학습**: 외부 데이터는 격리된 환경에서 검증 후 본 학습에 투입

## 참조
- 국정원 AI 보안 가이드북 (2025-12-10) T01
- OWASP Top 10 for LLM Applications 2025 — LLM04 (Data and Model Poisoning)

## 실측 사례 (인공지능 위험 사례집, 국정원 2025-11)
- **사례 #16 — 출입국 관리 AI 생체인식 시스템 데이터베이스 오염**: 공공 출입국 관리에서 사용하는 얼굴·홍채 인식 AI의 학습 또는 등록 데이터베이스가 변조되어, 특정 인물에 대한 식별 정확도가 의도적으로 떨어지거나 위장 인물이 통과하는 시나리오.
- **시사점**: 공공 생체인식·민원본인확인 AI는 학습 데이터셋과 등록 DB 양쪽에 *해시·서명*을 두고, *데이터 변경 이력을 감사 로그로 강제*해야 합니다. M01(신뢰 출처)·M03(데이터 검사)·M10(데이터 매니페스트)이 동시에 적용되어야 합니다.
