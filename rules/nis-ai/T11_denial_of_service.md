---
id: NIS-AI-T11
title_ko: 서비스 거부 공격
title_en: Denial of Service Attack
status: approved
source_layer: baseline
sources:
  - publisher: 국정원
    document: 국가·공공기관 AI 보안 가이드북
    version: "2025.12"
    item: T11
severity: high
decision_default: warn
domains: [llm-appsec]
languages: [python, javascript]
scenarios: [llm-integration]
related_baseline: [NIS-AI-M14, NIS-AI-M27, OWASP-LLM-2025-10]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 위협 정의 (가이드북 인용)
공격자가 AI시스템에 *과도한 수량의 프롬프트*를 입력하거나 *악의적인 프롬프트*를 입력하여 시스템 과부하 유발. AI시스템의 자원 고갈로 응답 지연 혹은 운영 중단되거나 과도한 사용금액 부과.

## 공공 환경 시나리오
- 민원 챗봇에 대규모 봇 공격 → 정상 민원 응대 불가
- 토큰 소비 폭발 → 월 예산 초과
- 비용 인질 공격: 약속 예산을 빠르게 소진시켜 *서비스 중단* 강제

## 대응 (M14, M27)
- 입력 길이·형식 제한 (M14)
- 요청 속도 제한 (M27) — 호출 횟수·입력 길이·동시 요청·출력 용량 제한

## 매핑
- OWASP LLM Top 10 2025 LLM10 (Unbounded Consumption)
