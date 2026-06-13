---
id: NIS-AI-M15
title_ko: 가드레일 다중화
title_en: Guardrail Multiplication
status: approved
source_layer: baseline
sources:
  - publisher: 국정원
    document: 국가·공공기관 AI 보안 가이드북
    version: "2025.12"
    item: M15
severity: high
decision_default: warn
domains: [llm-appsec]
languages: [python]
scenarios: [llm-integration, agent]
related_baseline: [NIS-AI-T07, NIS-AI-T08, NIS-AI-M13, NIS-AI-M14]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 대책 요지 (가이드북 인용)
AI시스템 오작동, 유해한 입·출력, 민감정보 유출 등을 방지하기 위해 *다수의 보호장치*를 **계층적 혹은 병렬적**으로 배치하여 운영. 사용자 입력·AI모델 동작·출력 결과 등 *각 동작 단계별*로 복수의 가드레일 배치.

## 안전한 패턴 — 다층 가드레일
```
[입력] → 길이/형식 검증 (M14) → 금칙어 필터 → prompt injection 탐지
       → [LLM 호출]
       → 출력 검증 (M13) → PII 마스킹 → 응답 변형 (무작위화)
       → 고위험 출력 시 관리자 검토 (M20)
```

## 공공 환경 적용
- *단일 필터*는 우회 가능 — 항상 *복수 계층*
- 동일·유사 입력에 응답 *변형* (M16 정보 누출 방지 효과)

## 매핑
- OWASP LLM Top 10 2025 LLM01/LLM05
- 본 리포 [GOV-LLM-OUTPUT-HANDLING-001](../scanner-builtin/GOV-LLM-OUTPUT-HANDLING-001.md)
