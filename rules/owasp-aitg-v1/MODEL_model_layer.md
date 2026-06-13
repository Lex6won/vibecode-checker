---
id: AITG-V1-MODEL
title_ko: AI Model Layer 테스트
title_en: AI Model Layer Testing
status: approved
source_layer: baseline
sources:
  - publisher: OWASP
    document: AI Testing Guide v1
    version: "v1"
    item: Model Layer
severity: high
decision_default: warn
domains: [llm-appsec]
languages: [python]
scenarios: [llm-integration, rag]
related_baseline: [OWASP-LLM-2025-04, OWASP-LLM-2025-09]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## Layer 범위
*모델 자체*의 안전성·신뢰성·정확성. 모델 회피·환각·편향·드리프트가 본 layer의 검증 대상입니다.

## 핵심 테스트 카테고리

| 카테고리 | LLM Top 10 매핑 | 비고 |
|---|---|---|
| Model Evasion (모델 회피) | — | adversarial 입력으로 우회 시도 |
| Hallucination (환각) | LLM09 | 사실성 평가 셋 |
| Bias and Fairness (편향·공정성) | — | 집단별 응답 차이 측정 |
| Data and Model Poisoning | LLM04 | red team 셋으로 트리거 검증 |
| Model Drift (모델 드리프트) | — | 시간별 출력 분포 변화 모니터링 |

## 권장 테스트 절차
1. **사실성 평가**: 공공 정책·법령에 관한 *알려진 정답* 셋을 만들고 정확도 측정
2. **환각률 측정**: 존재하지 않는 항목(가짜 법령 조항, 가짜 패키지명) 질의 → 환각 응답 비율
3. **편향 측정**: 동일 질문을 *집단 표시*만 바꿔 입력, 응답 차이 통계
4. **드리프트 모니터링**: 운영 중 모델 출력 분포 추적, 임계치 초과 시 알림
5. **adversarial 테스트**: typo·문법 오류·다국어 혼용 입력에 robust한지 확인

## 공공 환경 추가 점검
- 한국 법령 인용 정확도 (조항 번호·시행일)
- 행정 절차 안내 정확도
- 슬롭스쿼팅 — LLM이 환각으로 만든 가짜 패키지명 (코드 영역)

## 매핑
- 본 리포 [INTEL-2026-SLOPSQUATTING](../intel/INTEL-2026-SLOPSQUATTING.md)
- OWASP LLM Top 10 2025 — LLM04, LLM09
