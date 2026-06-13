---
id: OWASP-AGENTIC-2026-ASI07
title_ko: 안전하지 않은 에이전트 간 통신 (Insecure Inter-Agent Communication)
title_en: Insecure Inter-Agent Communication
status: approved
source_layer: baseline
sources:
  - publisher: OWASP
    document: OWASP Top 10 for Agentic Applications 2026
    version: "2026"
    item: ASI07
severity: high
decision_default: warn
domains: [agent-safety]
languages: [python, javascript]
scenarios: [agent]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 위협 정의
다중 에이전트 시스템에서 에이전트 간 메시지가 *보안 통제 없이* 교환되면, **가로채기 · 위조 · 재전송 공격**의 표적이 됩니다. 한 에이전트가 다른 에이전트를 *신뢰*한다는 전제가 무너지는 순간 전체 시스템 침해로 확산됩니다.

## 공공 환경 시나리오
- **민원 분류 → 처리 에이전트 체인**: 분류 결과를 처리 에이전트가 그대로 신뢰 → 중간 가로채기로 "긴급 처리" 라벨 조작
- **결재 라인 에이전트**: 결재 의견 메시지 위조 → 잘못된 결재 통과

## 안전한 패턴
- 에이전트 간 메시지에 **서명** (각 에이전트가 고유 키)
- **재전송 방지**: nonce + timestamp + 짧은 유효기간
- 신뢰 경계 명시: 메시지의 *출처 에이전트*를 검증
- 채널 암호화 (mTLS 등)
- 메시지 *스키마 검증* (악성 페이로드 차단)

## 매핑
- 신규 카테고리 (LLM Top 10에 직접 대응 없음)
- OWASP ASVS V12 (API and Web Service)
