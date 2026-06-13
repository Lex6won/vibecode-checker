---
id: NIS-AI-T03
title_ko: AI 백도어 삽입
title_en: AI Backdoor Insertion
status: approved
source_layer: baseline
sources:
  - publisher: 국정원
    document: 국가·공공기관 AI 보안 가이드북
    version: "2025.12"
    item: T03
severity: critical
decision_default: warn
domains: [llm-appsec]
languages: [python]
scenarios: [data-pipeline, llm-integration]
related_baseline: [NIS-AI-M02, NIS-AI-M12, NIS-AI-T14, OWASP-LLM-2025-04]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 위협 정의 (가이드북 인용)
공격자가 특정 조건을 만족할 경우 의도된 동작을 수행토록 하는 *AI 백도어*를 AI모델·학습데이터·라이브러리 등에 삽입하여 배포, AI시스템에 은닉. 평상시에는 정상 동작하나 시기·입력내용 등 특정 조건을 만족하면 오동작·정보유출 등 악성행위 수행.

## 공공 환경 시나리오
- Hugging Face 등에서 가져온 오픈소스 AI모델에 백도어 은닉 → 행정망 정보 외부 유출 트리거
- 외부 라이브러리(예: 시각화·전처리)에 백도어 → 특정 키워드 입력 시 권한 우회

## 대응 (M02, M12 적용)
- 신뢰할 수 있는 출처의 AI모델·라이브러리 활용 (M02)
- AI시스템 구성요소 무결성 검증 (M12)

## 매핑
- OWASP LLM Top 10 2025 LLM04 (Data and Model Poisoning)
- 사례: J프로그 아티팩토리 — Hugging Face 오픈소스 AI모델 100여개 악성코드 (2024.3)

## 실측 사례 (인공지능 위험 사례집, 국정원 2025-11)
- **사례 #15 — 군 지휘통제 AI, 백도어가 은닉된 채로 개발**: 핵심 의사결정 AI에 외주 개발 단계에서 백도어가 삽입되어, 평시에는 정상 동작하지만 특정 트리거(이미지·문장·날짜)에서 의도적으로 잘못된 판단을 내리는 시나리오. 공공 분야에서는 군·재난·치안 AI에 동일 위험이 적용됩니다.
- **시사점**: 외주·공급 모델은 *학습 과정 자체를 검증* (재현 가능한 학습 스크립트·해시) 하고, 운영 전 *백도어 탐지 테스트*(예: 적대적 트리거 패턴 검사)를 반드시 통과시켜야 합니다. M11·M12 (AI 컴포넌트 매니페스트·무결성 검증)와 직접 연결됩니다.
