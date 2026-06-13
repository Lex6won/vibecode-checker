---
id: OWASP-AGENTIC-2026-ASI04
title_ko: 에이전틱 공급망 취약점 (Agentic Supply Chain Vulnerabilities)
title_en: Agentic Supply Chain Vulnerabilities
status: approved
source_layer: baseline
sources:
  - publisher: OWASP
    document: OWASP Top 10 for Agentic Applications 2026
    version: "2026"
    item: ASI04
severity: high
decision_default: warn
domains: [agent-safety, llm-appsec]
languages: [python, javascript]
scenarios: [agent, package-install]
related_baseline: [OWASP-LLM-2025-03, INTEL-2026-SLOPSQUATTING, KR-KISA-SUPPLY-CHAIN]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 위협 정의
에이전트는 종종 *런타임*에 기능을 구성합니다 — *제3자*의 도구·데이터·MCP 서버·LoRA·플러그인을 동적으로 로드. 침해된 공급망 요소가 그대로 에이전트의 *권한 안*으로 들어옵니다.

## 공공 환경 시나리오
- **악성 MCP 서버**: 외부 MCP 등록 시 도구 manifest에 은닉 지시 → 에이전트의 도구 호출에 자동 주입
- **악성 LoRA/임베딩**: Hugging Face에서 가져온 모델 가중치에 백도어
- **슬롭스쿼팅**: 에이전트가 *자동으로* 가짜 패키지 설치 (사람 확인 단계 부재 시 즉시 감염)

## 안전한 패턴
- MCP 서버 등록은 *코드 리뷰 후* + 서명 검증
- 외부 모델은 출처 + 서명 + SHA 검증
- 에이전트의 패키지 설치는 *기관 미러*만 허용
- `check_package` MCP 호출 자동 통합

## 매핑
- OWASP LLM Top 10 2025 — LLM03 (Supply Chain)
- 본 리포 [INTEL-2026-SLOPSQUATTING](../intel/INTEL-2026-SLOPSQUATTING.md)
- KISA SW 공급망 보안 가이드라인 1.0
