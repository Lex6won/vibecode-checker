---
id: NIS-AI-M18
title_ko: AI시스템 통신구간 보호
title_en: AI System Communication Channel Protection
status: approved
source_layer: baseline
sources:
  - publisher: 국정원
    document: 국가·공공기관 AI 보안 가이드북
    version: "2025.12"
    item: M18
severity: high
decision_default: warn
domains: [llm-appsec]
languages: [python, javascript, yaml]
scenarios: [llm-integration]
related_baseline: [NIS-AI-T10]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 대책 요지 (가이드북 인용)
사용자-AI시스템 혹은 AI시스템 간 통신구간에 *인증강화 및 암호화*. **VPN·TLS** 등으로 입·출력데이터 외부 유출 방지. 세션 유효기간 지정 + 정기 갱신.

## 안전한 패턴
- TLS 1.3 강제, mTLS (필요 시)
- 세션 토큰 짧은 유효기간 (1시간) + refresh
- 세션 탈취 방지: HttpOnly·SameSite·Secure 쿠키

## 공공 환경 적용
- 모든 AI 호출에 TLS 강제 — 평문 차단
- 부서간 API: mTLS + 짧은 세션
- VPN 외 접근 차단

## 매핑
- OWASP ASVS V9 (Communications)
- 사례: 국내 공공기관 AI 챗봇 통신 미암호화 (2025.6)
