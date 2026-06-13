---
id: NIS-AI-M30
title_ko: 사용자 교육 및 보안정책 수립
title_en: User Education and Security Policy
status: approved
source_layer: baseline
sources:
  - publisher: 국정원
    document: 국가·공공기관 AI 보안 가이드북
    version: "2025.12"
    item: M30
severity: medium
decision_default: warn
domains: [llm-appsec]
languages: [python]
scenarios: [llm-integration]
related_baseline: [NIS-AI-T07]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 대책 요지 (가이드북 인용)
기관 사용자가 AI시스템 활용 시 *주의해야 할 보안수칙* 교육 + 기관 내부 *보안정책 수립*. **외부 상용 AI 서비스에 민감정보 입력 금지** 등 필요한 보안정책 + 관련 *경고 배너·알림* 표시. 정기적인 교육으로 보안인식 제고.

## 안전한 패턴
- 입사·신규 배치 시 *AI 보안 교육* 의무
- 분기별 사고 사례 + 신규 위협 brief
- 외부 LLM 호출 화면에 *경고 배너* 강제 표시
- 위반 시 *교육 재이수* 절차

## 공공 환경 적용
- 본 리포 [project_vibe_ai_club](../../)의 120명 대상 정기 교육
- "외부 ChatGPT에 업무 데이터 입력 금지" 포스터·배너
- 동아리 학습 컨텐츠 통합

## 매핑
- NIST SSDF — PO.4 (Roles and Responsibilities)
- 「국가 정보보안 기본지침」 보안교육 의무
