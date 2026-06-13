---
id: NIS-AI-M02
title_ko: 신뢰할 수 있는 출처의 AI모델·라이브러리 활용
title_en: Use of AI Models and Libraries from Trusted Sources
status: approved
source_layer: baseline
sources:
  - publisher: 국정원
    document: 국가·공공기관 AI 보안 가이드북
    version: "2025.12"
    item: M02
severity: high
decision_default: warn
domains: [llm-appsec]
languages: [python]
scenarios: [package-install, llm-integration]
related_baseline: [NIS-AI-T03, NIS-AI-T14, OWASP-LLM-2025-03, INTEL-2026-SLOPSQUATTING]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 대책 요지 (가이드북 인용)
오픈소스 AI모델·라이브러리·소프트웨어 등이 필요한 경우, *배포 경로와 배포자를 함께 검증*하여 신뢰할 수 있는 출처에서 획득하여 활용.

## 안전한 패턴
- 공식 사이트 등 *신뢰성 보장 출처*만 사용
- 사용 전 배포자 *전자서명*과 *해시값* 검증
- 필요 시 개발환경 분리된 *샌드박스*에서 안전성 확인 후 사용

## 공공 환경 적용
- Hugging Face·PyPI 등 외부 저장소는 *기관 내부 미러*만 허용
- `check_package` MCP 도구로 OSV.dev 매칭 자동 확인
- 신규 패키지 등록 30일 이내는 보류

## 매핑
- 본 리포 [INTEL-2026-SLOPSQUATTING](../intel/INTEL-2026-SLOPSQUATTING.md), [GOV-SECRET-* 룰들](../scanner-builtin/)
- OWASP LLM Top 10 2025 LLM03 (Supply Chain)
- 사례: J프로그 아티팩토리 — Hugging Face 악성 모델 100여개 (2024.3)
