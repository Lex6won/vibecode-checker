---
id: NIS-AI-T14
title_ko: 공급망 공격
title_en: Supply Chain Attack
status: approved
source_layer: baseline
sources:
  - publisher: 국정원
    document: 국가·공공기관 AI 보안 가이드북
    version: "2025.12"
    item: T14
severity: high
decision_default: warn
domains: [llm-appsec]
languages: [python, javascript]
scenarios: [package-install, llm-integration, agent]
related_baseline: [NIS-AI-M02, NIS-AI-M11, NIS-AI-M12, NIS-AI-M25, OWASP-LLM-2025-03, OWASP-AGENTIC-2026-ASI04, INTEL-2026-SLOPSQUATTING, KR-KISA-SUPPLY-CHAIN]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 위협 정의 (가이드북 인용)
AI시스템을 구성하는 AI모델, 학습데이터, 라이브러리 등에 *취약점이 존재*하거나 *악성코드가 삽입*되어 공급·배포. 공격자가 AI시스템의 취약점 등을 악용하여 민감정보 유출, 시스템 권한탈취, 오동작을 유발.

## 공공 환경 시나리오
- 오픈소스 AI모델 운영도구 Ollama의 RCE 취약점 (2024.6)
- Hugging Face 악성 모델·LoRA
- 슬롭스쿼팅 — LLM 환각 패키지명을 공격자가 선점

## 대응 (M02, M11, M12, M25)
- 신뢰할 수 있는 출처의 AI모델·라이브러리 활용 (M02)
- AI시스템 구성요소 명세서 관리 (M11) — AIBOM
- AI시스템 구성요소 무결성 검증 (M12)
- 취약점 점검 및 보안업데이트 (M25)

## 매핑
- OWASP LLM Top 10 2025 LLM03 (Supply Chain)
- OWASP Agentic 2026 ASI04 (Supply Chain Vulnerabilities)
- KISA SW 공급망 보안 가이드라인 1.0
- 본 리포 [INTEL-2026-SLOPSQUATTING](../intel/INTEL-2026-SLOPSQUATTING.md)

## 실측 사례 (인공지능 위험 사례집, 국정원 2025-11)
- **사례 #19 — AI 에이전트가 실수로 설계한 신규 바이러스, 팬데믹 유발**: 자율적으로 의사결정·작업을 수행하는 AI 에이전트가 외부 도구·라이브러리를 *검증 없이* 호출하면서 의도하지 않은 위험 산출물을 만들어내는 시나리오(생물·화학·소프트웨어 분야 동일 패턴).
- **공급망 관점 시사점**: 에이전트가 LLM 추천에 따라 패키지를 설치할 때 *슬롭스쿼팅*(존재하지 않는 패키지를 환각하여 동일 이름 악성 패키지 설치) 위험이 있고, 본 리포의 `check_package`·`update-intel(KEV)`·`INTEL-2026-SLOPSQUATTING`이 이 흐름의 첫 방어선입니다. M11·M19(AI 권한 제한) 동시 적용 필수.
