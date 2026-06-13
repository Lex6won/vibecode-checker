---
id: NIS-AI-M06
title_ko: 민감정보 사용 사전 승인
title_en: Prior Approval for Sensitive Data Use
status: approved
source_layer: baseline
sources:
  - publisher: 국정원
    document: 국가·공공기관 AI 보안 가이드북
    version: "2025.12"
    item: M06
severity: high
decision_default: warn
domains: [llm-appsec, privacy-public-sector]
languages: [python]
scenarios: [data-pipeline]
related_baseline: [NIS-AI-T02, NIS-AI-M07]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 대책 요지 (가이드북 인용)
민감정보 또는 비공개 정보가 포함된 데이터를 학습·재학습에 활용할 경우, *기관 내부 절차*에 따라 사전 보고 및 승인. 업로드/학습 과정에서 자동 분류·차단, 승인된 데이터에는 *전자서명 식별자* 부여, 미승인 데이터는 학습 차단.

## 안전한 패턴
- 민감정보 필터링 게이트 (PII detector)
- 승인 워크플로 + 감사 로그
- 식별자가 없는 데이터는 학습 파이프라인에서 자동 차단

## 공공 환경 적용
- 민원 데이터 → AI 학습 적용 전 *법령 검토* + 책임자 승인
- 개인정보 영향평가 결과 첨부

## 매핑
- 개인정보 보호법
- 개인정보보호위원회 생성형 AI 안내서 (2025.8)
