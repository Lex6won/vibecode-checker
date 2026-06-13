---
id: NIS-AI-M07
title_ko: 보안등급에 맞는 학습데이터 구성·활용
title_en: Classified Training Data Structure and Use
status: approved
source_layer: baseline
sources:
  - publisher: 국정원
    document: 국가·공공기관 AI 보안 가이드북
    version: "2025.12"
    item: M07
severity: high
decision_default: warn
domains: [llm-appsec, privacy-public-sector]
languages: [python]
scenarios: [data-pipeline, rag]
related_baseline: [NIS-AI-T02, NIS-AI-T04, NIS-AI-T05, NIS-AI-M05]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 대책 요지 (가이드북 인용)
AI시스템의 활용목적 및 등급분류에 맞게 *기밀·민감·공개* 등급의 학습데이터를 사용. 등급기준에서 벗어나 예외적으로 필요 시 *비식별화* 등 조치. **대민서비스용 AI시스템 등 외부 노출 시스템은 공개등급 데이터만 활용**.

## 안전한 패턴
- 데이터 등급 분류 + 접근제어 매핑
- 기밀·민감 등급은 *격리된 저장소*에서만 학습
- 사용자/부서별 학습데이터 접근권한 세분화
- RAG 구성 시 권한별 *적합한 벡터DB* 참조 → AI 답변 통제

## 공공 환경 적용
- 외부 대민 챗봇 = 공개 등급만
- 내부 결재 보조 = 민감 등급 한정 + 부서별 격리

## 매핑
- 본 리포 [GOV-PII-RRN-001](../scanner-builtin/GOV-PII-RRN-001.md), [GOV-PII-PHONE-001](../scanner-builtin/GOV-PII-PHONE-001.md)
- 개인정보 보호법
