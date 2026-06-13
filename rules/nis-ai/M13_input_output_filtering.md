---
id: NIS-AI-M13
title_ko: 입·출력 필터링
title_en: Input/Output Filtering
status: approved
source_layer: baseline
sources:
  - publisher: 국정원
    document: 국가·공공기관 AI 보안 가이드북
    version: "2025.12"
    item: M13
severity: high
decision_default: warn
domains: [llm-appsec]
languages: [python, javascript]
scenarios: [llm-integration, agent]
related_baseline: [NIS-AI-T02, NIS-AI-T07, NIS-AI-T08, OWASP-LLM-2025-05, GOV-LLM-OUTPUT-HANDLING-001, GOV-LLM-PII-PROMPT-001]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 대책 요지 (가이드북 인용)
AI시스템의 *입력·응답*에 포함된 *민감정보*가 활용목적 및 기밀·민감·공개등급 분류에 부합하지 않는 경우 탐지·차단. **단어 기반이 아닌 문장 단위 맥락 기반 필터링** 권고. DLP 등 입·출력 데이터 필터링 솔루션 활용.

## 안전한 패턴
- 입력: 금칙어 + 적대적 공격 패턴 필터 (한국어 형태소)
- 출력: 민감정보 마스킹 (RRN·이름·주소·내부망 IP)
- 맥락 기반 LLM 보조 필터 (DLP·Presidio)

## 공공 환경 적용
- 챗봇 응답에 *비공개 정보 단편 노출* 차단
- 민원 입력에 RRN·계좌·카드번호 자동 마스킹

## 매핑
- 본 리포 [GOV-PII-RRN-001](../scanner-builtin/GOV-PII-RRN-001.md), [GOV-LLM-PII-PROMPT-001](../scanner-builtin/GOV-LLM-PII-PROMPT-001.md) — 실시간 검사 가능
- OWASP LLM Top 10 2025 LLM05
