---
id: NIS-AI-T02
title_ko: 비인가 민감정보 학습
title_en: Unauthorized Sensitive Data Learning
status: approved
source_layer: baseline
sources:
  - publisher: 국정원
    document: 국가·공공기관 AI 보안 가이드북
    version: "2025.12"
    item: T02
severity: high
decision_default: warn
domains: [llm-appsec]
languages: [python]
scenarios: [data-pipeline, llm-integration, rag]
related_baseline: [NIS-AI-M06, NIS-AI-M07, NIS-AI-M13, OWASP-LLM-2025-02]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 위협 정의 (가이드북 인용)
AI모델의 활용 목적에 맞지 않는 *민감·비공개 정보*를 학습. AI시스템이 기관 내부 비공개 행정자료 등을 학습하여 비인가자에게 제공하는 등 민감정보 유출 위협.

## 공공 환경 시나리오
- 민원 데이터에 포함된 주민번호·연락처가 학습 데이터에 그대로 잔존 → 챗봇 응답에 노출
- 비공개 내부 결재 문서가 RAG 인덱스에 무분별 등록 → 일반 사용자 검색 가능

## 대응 (M06, M07, M13 적용)
- 민감정보 사용 사전 승인 절차 (M06)
- 보안등급에 맞는 학습데이터 구성 (M07)
- 입·출력 필터링 (M13)

## 매핑
- OWASP LLM Top 10 2025 LLM02 (Sensitive Information Disclosure)
- 개인정보보호위원회 생성형 AI 안내서
