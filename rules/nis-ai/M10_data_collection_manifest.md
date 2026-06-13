---
id: NIS-AI-M10
title_ko: 데이터 수집 명세서 관리
title_en: Data Collection Manifest Management
status: approved
source_layer: baseline
sources:
  - publisher: 국정원
    document: 국가·공공기관 AI 보안 가이드북
    version: "2025.12"
    item: M10
severity: medium
decision_default: warn
domains: [llm-appsec]
languages: [python]
scenarios: [data-pipeline]
related_baseline: [NIS-AI-T01, NIS-AI-T05, NIS-AI-M11]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 대책 요지 (가이드북 인용)
수집한 데이터셋의 *출처·일자·수집 방법·경로·규모·해시값* 등을 기록하여 *이력 관리*. **데이터 카탈로그** 구축 → 각 데이터셋의 자동 명세서 + 변경이력. 고유 식별자(UUID)와 해시값 부여로 *추적성* 확보.

## 안전한 패턴 — 데이터 수집 명세서 예시
```yaml
dataset:
  id: ds-2026-05-001
  purpose: 민원 분류 학습용
  source: data.go.kr / 한국지능정보사회진흥원
  collected_at: 2026-05-15
  method: 공식 API
  size_rows: 100000
  sha256: a3b1c5...
  approver: security-team@gg.go.kr
```

## 공공 환경 적용
- 학습 데이터 lineage 추적 (원본 → 전처리 → 학습)
- 향후 *데이터 사고* 발생 시 영향 범위 즉시 식별

## 매핑
- NIST SSDF — PO 그룹 (조직 준비)
- ISO/IEC 5259 (Data quality for analytics and ML)
