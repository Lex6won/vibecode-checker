---
id: NIS-AI-M14
title_ko: 입력 길이·형식 제한
title_en: Input Length and Format Restriction
status: approved
source_layer: baseline
sources:
  - publisher: 국정원
    document: 국가·공공기관 AI 보안 가이드북
    version: "2025.12"
    item: M14
severity: medium
decision_default: warn
domains: [llm-appsec]
languages: [python, javascript]
scenarios: [llm-integration]
related_baseline: [NIS-AI-T04, NIS-AI-T08, NIS-AI-T11, OWASP-LLM-2025-10]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 대책 요지 (가이드북 인용)
AI시스템에 입력되는 사용자 프롬프트의 *길이·형식·반복도·복잡도*를 제한하고, 금칙어·공격패턴 등을 필터 혹은 *사전 정의한 입력 템플릿* 등을 통해 차단.

## 안전한 패턴
- 입력 길이: 시스템 목적별 max_chars 설정 (예: 민원 챗봇 2000자)
- 형식: 정규식 화이트리스트 + 첨부파일 확장자 제한
- 템플릿: "민원 분류" 등 사전 정의된 양식 강제
- 유사 질의 반복 차단 (rate limit)

## 공공 환경 적용
- 민원 챗봇은 *템플릿 입력*만 허용 → prompt injection 표면 축소
- 결재 보조 AI는 *결재 문서 형식*만 입력

## 매핑
- OWASP LLM Top 10 2025 LLM10 (Unbounded Consumption)
