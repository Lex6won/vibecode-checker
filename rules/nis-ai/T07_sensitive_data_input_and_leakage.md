---
id: NIS-AI-T07
title_ko: 민감정보 입력·유출
title_en: Sensitive Data Input and Leakage
status: approved
source_layer: baseline
sources:
  - publisher: 국정원
    document: 국가·공공기관 AI 보안 가이드북
    version: "2025.12"
    item: T07
severity: critical
decision_default: warn
domains: [llm-appsec, privacy-public-sector]
languages: [python, javascript]
scenarios: [llm-integration]
related_baseline: [NIS-AI-M13, NIS-AI-M30, GOV-LLM-PII-PROMPT-001, OWASP-LLM-2025-02]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 위협 정의 (가이드북 인용)
사용자가 AI시스템에 프롬프트, 파일 업로드 등을 통해서 민감정보를 입력, AI시스템이 이를 학습하고 비인가자에게 유출. AI시스템이 입력된 민감정보를 학습하여 다른 비인가자에게 답변으로 제공하는 등 AI시스템이 보유하고 있는 개인정보 혹은 비공개 문서 등이 외부에 유출.

## 공공 환경 시나리오
- **삼성 사례 재발**: 직원이 업무용 코드·회의록을 외부 AI에 입력 → 외부 서비스 로그 잔존
- 결재 문서를 챗GPT로 *요약* 요청 → 비공개 내용 외부 학습 후보

## 대응 (M13, M30)
- 입·출력 필터링 (M13)
- 사용자 교육 및 보안정책 수립 (M30) — 외부 상용 AI에 민감정보 입력 금지 안내

## 매핑
- 본 리포 [GOV-LLM-PII-PROMPT-001](../scanner-builtin/GOV-LLM-PII-PROMPT-001.md) — 실시간 검사 가능
- 사례: 삼성전자 챗GPT 업무 데이터 유출 (2023.3)

## 실측 사례 (인공지능 위험 사례집, 국정원 2025-11)
- **사례 #6 — 정부기관의 보고서 생성용 AI, 데이터관리 실수로 민감정보 유출**: 보고서 자동 생성에 사용되는 AI 시스템에 분류·등급 처리되지 않은 민감 자료가 입력되어 결과물(공개·반공개)에 함께 노출되는 시나리오. 공무원이 일상적으로 *결재 초안·민원 회신·통계 요약*을 LLM에 맡길 때 가장 가능성 높은 사고 형태.
- **시사점**: 입력 시점에 *자동 PII·민감정보 검출*(GOV-LLM-PII-PROMPT-001)이 차단해야 하고, 출력은 *분류 등급별로 검토자 승인* 후에만 외부 채널로 나가야 합니다. M06(중요 데이터 사전 승인)·M13(입출력 필터링)이 같이 적용됩니다.
