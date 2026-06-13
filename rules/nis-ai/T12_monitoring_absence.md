---
id: NIS-AI-T12
title_ko: 사고·이상행위 모니터링 체계 부재
title_en: Absence of Incident and Anomaly Monitoring
status: approved
source_layer: baseline
sources:
  - publisher: 국정원
    document: 국가·공공기관 AI 보안 가이드북
    version: "2025.12"
    item: T12
severity: high
decision_default: warn
domains: [llm-appsec, agent-safety]
languages: [python]
scenarios: [llm-integration, agent]
related_baseline: [NIS-AI-M08, NIS-AI-M09]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 위협 정의 (가이드북 인용)
사용자-AI시스템 간 입·출력 및 사용이력 등에 대한 로그를 남기지 않고, 실시간 모니터링을 하지 않아 사고·이상행위 발생 시 탐지 불가. AI시스템 대상 공격·사고가 발생하더라도 인지가 불가능, AI시스템이 보유한 민감정보 유출 등 사고·장애 발생.

## 공공 환경 시나리오
- 사용자 입력·AI 응답을 로그 없이 운영 → 사고 발생 후 *책임 소재·원인 추적 불가*
- 비정상 호출 패턴 미인지 → 학습데이터 추출 공격 *진행 중에도* 무방비

## 대응 (M08, M09)
- 데이터 로깅·모니터링 (M08)
- AI시스템 로깅·모니터링 (M09) — SIEM 연동, 실시간 이상행위 탐지

## 매핑
- NIST SSDF — PO 그룹 (조직 준비)
- CISA Secure by Design — 침입 증거 수집 (Goal 7)
