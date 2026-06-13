---
id: NIS-AI-T10
title_ko: 통신구간 공격
title_en: Communication Channel Attack
status: approved
source_layer: baseline
sources:
  - publisher: 국정원
    document: 국가·공공기관 AI 보안 가이드북
    version: "2025.12"
    item: T10
severity: high
decision_default: warn
domains: [llm-appsec]
languages: [python, javascript, yaml]
scenarios: [llm-integration]
related_baseline: [NIS-AI-M18, OWASP-LLM-2025-02]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 위협 정의 (가이드북 인용)
사용자-AI시스템 또는 AI시스템 간 통신구간에서 정보 탈취. 평문 전송 또는 인증·세션 통제 미흡으로 인한 데이터 노출.

## 공공 환경 시나리오
- **실측 사례**: 국내 공공기관 AI 챗봇 통신에 암호화 미적용 → 대화 내용 유출 (2025.6, 국정원 확인)
- 부서간 AI API 호출이 평문 → 중간자 공격으로 민원 정보 탈취

## 대응 (M18)
- AI시스템 통신구간 보호 (M18): VPN·TLS·세션 유효기간 관리

## 매핑
- OWASP ASVS V9 (Communications)
