---
id: NIS-AI-M16
title_ko: AI모델 구조·가중치 유출 방지
title_en: AI Model Structure and Weight Leakage Prevention
status: approved
source_layer: baseline
sources:
  - publisher: 국정원
    document: 국가·공공기관 AI 보안 가이드북
    version: "2025.12"
    item: M16
severity: high
decision_default: warn
domains: [llm-appsec]
languages: [python]
scenarios: [llm-integration]
related_baseline: [NIS-AI-T06]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 대책 요지 (가이드북 인용)
AI모델 구조·가중치 등 AI모델의 주요 정보가 *유출되지 않도록*. 응답 과정에서 AI모델의 *명칭·버전·확률값* 등 세부 정보가 유출되지 않도록 조치. 주요 정보 암호화·접근권한 강화. 응답 시 *내부 정보 비공개* 처리.

## 안전한 패턴
- 가중치 파일: 암호화 + 접근통제 (M05 연계)
- 응답 시 모델 명칭·버전·logit·probability 비노출
- API 응답에서 *내부 메타* 제거 미들웨어

## 공공 환경 적용
- 챗봇 응답에 "GPT-4o 모델로 처리" 같은 내부 메타 *절대* 노출 금지
- temperature·system prompt 단편 차단

## 매핑
- 사례: 구글 딥마인드 — 챗GPT 모델 구조·가중치 추출 시연 (2024.3)
