---
id: NIS-AI-M11
title_ko: AI시스템 구성요소 명세서 관리
title_en: AI System Components Manifest (AIBOM)
status: approved
source_layer: baseline
sources:
  - publisher: 국정원
    document: 국가·공공기관 AI 보안 가이드북
    version: "2025.12"
    item: M11
severity: high
decision_default: warn
domains: [llm-appsec]
languages: [python]
scenarios: [llm-integration, agent]
related_baseline: [NIS-AI-T14, NIS-AI-M25, KR-KISA-SUPPLY-CHAIN]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 대책 요지 (가이드북 인용)
AI모델·학습데이터·라이브러리 등 모든 구성요소의 *출처·버전·변경이력·해시값·서명자*를 형상관리. **AIBOM (AI Bill of Materials)** 활용한 공급망 보안체계 검토 예정.

## 안전한 패턴 (AIBOM 예시)
```yaml
ai_system: 민원 분류기 v1.0
components:
  - type: model
    name: kor-ner-roberta
    version: "1.2"
    sha256: c4d2e1...
    source: huggingface.co/...
  - type: library
    name: transformers
    version: "4.45.0"
  - type: dataset
    name: ds-2026-05-001  # M10 연계
```

## 공공 환경 적용
- AI 시스템 *전체* AIBOM 정기 생성 + 외부 감사 대비
- 취약점 발견 시 명세서로 *영향 받는 시스템* 즉시 식별

## 매핑
- KISA SW 공급망 보안 가이드라인 1.0
- NIST SP 800-218A (GenAI SSDF Profile)
- CycloneDX, SPDX SBOM 표준
