---
id: NIS-AI-T05
title_ko: 학습데이터 비인가자 접근
title_en: Unauthorized Access to Training Data
status: approved
source_layer: baseline
sources:
  - publisher: 국정원
    document: 국가·공공기관 AI 보안 가이드북
    version: "2025.12"
    item: T05
severity: high
decision_default: warn
domains: [llm-appsec]
languages: [python]
scenarios: [data-pipeline, rag]
related_baseline: [NIS-AI-M05, NIS-AI-M07, NIS-AI-M08, NIS-AI-M10]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 위협 정의 (가이드북 인용)
학습데이터 혹은 RAG로 구성한 벡터DB에 대한 접근권한 통제 미흡으로 인해 AI시스템이 비인가자에게 정보제공. AI모델 학습데이터 또는 AI시스템 입력에 포함된 민감정보가 비인가 내부 구성원 혹은 외부인원에게 노출.

## 공공 환경 시나리오
- 부서 A의 RAG 벡터DB에 부서 B 직원도 접근 가능 → 권한 경계 위반
- 학습 데이터 저장소에 *모든 직원* 읽기 권한 → 사고 시 감사 추적 불가

## 대응 (M05, M07, M08, M10)
- 데이터 접근통제 (M05)
- 보안등급에 맞는 학습데이터 구성 (M07)
- 데이터 로깅·모니터링 (M08)
- 데이터 수집 명세서 관리 (M10)

## 매핑
- OWASP LLM Top 10 2025 LLM08 (Vector and Embedding Weaknesses)
