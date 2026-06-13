---
id: NIS-AI-M08
title_ko: 데이터 로깅·모니터링
title_en: Data Logging and Monitoring
status: approved
source_layer: baseline
sources:
  - publisher: 국정원
    document: 국가·공공기관 AI 보안 가이드북
    version: "2025.12"
    item: M08
severity: high
decision_default: warn
domains: [llm-appsec]
languages: [python]
scenarios: [data-pipeline]
related_baseline: [NIS-AI-T05, NIS-AI-T12, NIS-AI-M09]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 대책 요지 (가이드북 인용)
원시·학습데이터 등에 대한 접근·변경 행위 *로그 기록* 및 *정기 분석*. 파일 접근·변경 이벤트 에이전트 수집 → SIEM 서버 전송 → 이상행위 분석. *무결성 모니터링* 도구로 주기적 해시 변화 점검.

## 안전한 패턴
- 파일 시스템·DB 접근 로그를 SIEM(예: ELK, Splunk)으로 통합
- 무결성 모니터링: tripwire·AIDE 등
- 해시 변화 시 *자동 차단* + 알람

## 공공 환경 적용
- 학습 데이터·RAG 인덱스 *모든 접근* 로그 90일 보관
- 비인가 변경 시 운영 즉시 중단 + 백업 복원

## 매핑
- NIST SSDF — PO/PS 그룹
