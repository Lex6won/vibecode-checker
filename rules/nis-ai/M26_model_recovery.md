---
id: NIS-AI-M26
title_ko: AI모델 복구
title_en: AI Model Recovery
status: approved
source_layer: baseline
sources:
  - publisher: 국정원
    document: 국가·공공기관 AI 보안 가이드북
    version: "2025.12"
    item: M26
severity: high
decision_default: warn
domains: [llm-appsec]
languages: [python]
scenarios: [llm-integration]
related_baseline: [NIS-AI-T03, NIS-AI-M12, NIS-AI-M21]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 대책 요지 (가이드북 인용)
AI모델에서 *민감정보 유출·변조·무단제어* 등 이상행위 발생이 의심되는 경우, **즉시 운영을 중단**하고 원본으로 *복원*하거나 *재학습*. 배포 시점마다 서명정보·해시값을 *운영환경과 분리된 백업*에 보관.

## 안전한 패턴
- 배포 시 sigstore 서명 + 별도 백업 저장소
- 이상 탐지 → kill switch (M21) → 백업 자동 복원
- 복원 스크립트·파이프라인 사전 정비
- 검증된 원본 학습 데이터로 *재학습 옵션* 보존

## 공공 환경 적용
- 모든 AI 모델 *주 1회* 백업
- 백업 저장소는 *별도 망*에 격리 (사고 시에도 안전)

## 매핑
- NIST SP 800-218 — PS 그룹 (소프트웨어 보호)
