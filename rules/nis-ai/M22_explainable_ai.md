---
id: NIS-AI-M22
title_ko: 설명 가능한 AI 구성
title_en: Explainable AI Configuration
status: approved
source_layer: baseline
sources:
  - publisher: 국정원
    document: 국가·공공기관 AI 보안 가이드북
    version: "2025.12"
    item: M22
severity: medium
decision_default: warn
domains: [llm-appsec]
languages: [python]
scenarios: [llm-integration]
related_baseline: [NIS-AI-T09]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 대책 요지 (가이드북 인용)
AI의 *추론·결정 과정*을 관리자가 인지 가능한 형태로 정보 제공. 추론 과정 해석 가능 + 결과 설명·판단 근거 *시각화*. **현재 완벽한 설명 가능 AI는 기술적 한계 존재, 로깅·모니터링 병행 필수**.

## 안전한 패턴
- LLM 응답에 *근거·출처* 강제 표시
- 분류 모델: SHAP/LIME 등 설명 도구
- 의사결정 트레이스 보존

## 공공 환경 적용
- 민원 분류 AI: "긴급 분류 근거: 키워드 X·Y 매칭"
- 행정 결정 AI: *원문 조항 인용* 강제

## 매핑
- OWASP LLM Top 10 2025 LLM09 (Misinformation) 완화
- NIST AI RMF — Trustworthy AI
