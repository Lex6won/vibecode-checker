---
id: NIS-AI-M29
title_ko: 용역업체 보안관리
title_en: Vendor Security Management
status: approved
source_layer: baseline
sources:
  - publisher: 국정원
    document: 국가·공공기관 AI 보안 가이드북
    version: "2025.12"
    item: M29
severity: high
decision_default: warn
domains: [llm-appsec]
languages: [python]
scenarios: [data-pipeline, llm-integration, agent]
related_baseline: [NIS-AI-T15]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 대책 요지 (가이드북 인용)
데이터 수집·AI 학습·시스템 구축 등 *전 수명주기에 걸쳐 용역업체* 활용 시 정기 보안점검 및 *비인가 행위 발생여부* 확인. **계약 시 보안요구사항 명시** + 취약점 발견 시 *통지 의무* 명시.

## 안전한 패턴
- 용역업체 계정 최소 권한 + 불필요 시 즉시 회수
- 정기 보안 점검 (분기 1회)
- 계약서에 보안 요구사항 부속 문서 첨부
- 침해 발생 시 *통지 시한* (예: 24시간)

## 공공 환경 적용
- 정보화 사업 RFP에 보안요구사항 표준화
- 용역업체 *기관 내부망 접근 불가* 원칙

## 매핑
- 사례: Scale AI — 메타·구글 기밀 문서 공개 노출 (2025.6)
- NIST SP 800-161 (Supply Chain Risk)
