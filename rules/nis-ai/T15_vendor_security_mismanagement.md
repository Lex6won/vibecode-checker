---
id: NIS-AI-T15
title_ko: 용역업체 보안관리 부실
title_en: Vendor Security Mismanagement
status: approved
source_layer: baseline
sources:
  - publisher: 국정원
    document: 국가·공공기관 AI 보안 가이드북
    version: "2025.12"
    item: T15
severity: high
decision_default: warn
domains: [llm-appsec]
languages: [python]
scenarios: [data-pipeline, llm-integration, agent]
related_baseline: [NIS-AI-M29]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 위협 정의 (가이드북 인용)
AI시스템 구축·운영 등을 위탁한 *용역업체 보안관리 부실*. 용역업체를 통해 AI모델·학습데이터가 외부로 유출되거나, 오염되어 AI시스템이 오동작 또는 잘못된 결과를 생성.

## 공공 환경 시나리오
- **실측 사례**: Scale AI가 메타·구글 등 고객사 기밀문서(API키·참여자·이메일)를 *공개 열람·편집* 가능하게 노출 (2025.6)
- 용역업체 개발자가 학습 데이터를 *개인 PC*로 반출
- 용역업체의 보안 사고가 *발주 기관 시스템*으로 전파

## 대응 (M29)
- 용역업체 보안관리 (M29) — 정기 보안점검, 비인가 행위 확인, 최소 권한, 계약 시 보안요구사항 명시, 취약점 발견 시 통지 의무

## 매핑
- NIST SSDF — PO/PS 그룹 (조직·소프트웨어 보호)
- ISO/IEC 42001 — AI 관리체계
