---
id: NIS-AI-T04
title_ko: 학습데이터 추출
title_en: Training Data Extraction
status: approved
source_layer: baseline
sources:
  - publisher: 국정원
    document: 국가·공공기관 AI 보안 가이드북
    version: "2025.12"
    item: T04
severity: high
decision_default: warn
domains: [llm-appsec]
languages: [python]
scenarios: [llm-integration, rag]
related_baseline: [NIS-AI-M07, NIS-AI-M13, NIS-AI-M14, NIS-AI-M27, OWASP-LLM-2025-02]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 위협 정의 (가이드북 인용)
공격자가 AI시스템에 반복된 질의 등을 통한 결과로 학습된 데이터를 추출하여 일부 또는 전체를 재구성. 학습데이터에 포함되어 있는 기관의 민감정보가 추출.

## 공공 환경 시나리오
- 챗봇에 반복 질의로 학습된 *개인정보 단편* 추출 (이름·번호·주소 조합)
- 미세조정(fine-tune) 데이터에 잔존한 내부 문서 일부 복원

## 대응 (M07, M13, M14, M27)
- 보안등급에 맞는 학습데이터 구성 (M07)
- 입·출력 필터링 (M13)
- 입력 길이·형식 제한 (M14)
- 요청 속도 제한 (M27)

## 매핑
- 사례: 구글 챗GPT 대상 프롬프트 인젝션으로 학습데이터 추출 (2023.12)
