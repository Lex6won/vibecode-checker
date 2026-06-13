---
id: OWASP-AGENTIC-2026-ASI03
title_ko: 신원·권한 남용 (Identity and Privilege Abuse)
title_en: Identity and Privilege Abuse
status: approved
source_layer: baseline
sources:
  - publisher: OWASP
    document: OWASP Top 10 for Agentic Applications 2026
    version: "2026"
    item: ASI03
severity: high
decision_default: warn
domains: [agent-safety]
languages: [python, javascript]
scenarios: [agent]
related_baseline: [NIS-AI-M05, OWASP-ASVS]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 위협 정의
에이전트는 종종 ***attribution gap***에서 동작합니다 — 권한을 *동적으로 관리*하면서 명확한 *통제된 신원*이 없습니다. 결과적으로:
- 누가 동작했는지 추적 어려움 (감사 회피)
- 위임 권한이 의도와 다르게 확장 (privilege creep)
- 부서·테넌트 경계 위반

## 공공 환경 시나리오
- **부서 경계 위반**: A 부서 에이전트가 B 부서 자료 검색 가능
- **위임 권한 확장**: 사용자 권한으로 시작했으나 백그라운드 작업에서 관리자 권한 사용
- **추적 불가**: "에이전트가 했다"는 이유로 감사 책임 회피

## 안전한 패턴
- **에이전트 별 고유 ID**: 사용자 ID와 *별도*로 추적, 모든 동작에 attached
- **OAuth/OIDC 위임 토큰**: 명시적 scope + 짧은 유효기간
- **권한 위임 명시**: 사용자 → 에이전트 위임 범위를 *명문화*
- **감사 로그**: 사용자 ID + 에이전트 ID + 작업 ID 3 식별자 동시 기록

## 매핑
- 국정원 AI 보안 가이드북 M05 (데이터 접근통제)
- OWASP ASVS V4 (Access Control)
- CISA Secure by Design — 기본 RBAC 권장
