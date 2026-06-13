---
id: NIS-AI-M28
title_ko: AI시스템 구성요소 완전 삭제
title_en: Complete Deletion of AI System Components
status: approved
source_layer: baseline
sources:
  - publisher: 국정원
    document: 국가·공공기관 AI 보안 가이드북
    version: "2025.12"
    item: M28
severity: high
decision_default: warn
domains: [llm-appsec, privacy-public-sector]
languages: [python]
scenarios: [data-pipeline]
related_baseline: [NIS-AI-T04, NIS-AI-T06]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 대책 요지 (가이드북 인용)
AI시스템 폐기 시 *재사용 불가능*하도록 AI모델·학습데이터·벡터DB·로그 등 구성요소 *전체 완전 삭제*. **완전삭제 소프트웨어** 활용. 삭제 후 *포렌식 도구*로 복구 불가 확인. 민감등급 이상은 *물리적 파기* 가능.

## 안전한 패턴
- DoD 5220.22-M 또는 NIST SP 800-88 표준 삭제
- 클라우드: 키 삭제 (crypto-shredding)
- 폐기 인증서 발급 + 감사 로그

## 공공 환경 적용
- AI 시스템 폐기 시 *시스템 폐기 위원회* 승인
- 개인정보 보호법 제21조 (파기) 준수
- 민감 등급은 물리적 파기 + 증빙

## 매핑
- 개인정보 보호법
- NIST SP 800-88 (Media Sanitization)
