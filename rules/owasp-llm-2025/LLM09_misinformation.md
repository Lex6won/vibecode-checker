---
id: OWASP-LLM-2025-09
title_ko: 잘못된 정보 (Misinformation)
title_en: Misinformation
status: approved
source_layer: baseline
sources:
  - publisher: OWASP
    document: OWASP Top 10 for LLM Applications 2025
    version: "2025"
    item: LLM09
severity: medium
decision_default: warn
domains: [llm-appsec]
languages: [python, javascript]
scenarios: [llm-integration, rag, agent]
related_baseline: [OWASP-LLM-2025-08, NIS-AI-M03]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 무엇이 위험한가
LLM은 *그럴듯하지만 틀린 정보*(환각)를 생성합니다. 공공 환경에서는 **잘못된 법령 인용·정책 정보 오기·행정 절차 잘못 안내**로 민원인이 잘못된 행동을 하게 될 수 있고, 행정상 책임 문제로 이어집니다.

## 공공 환경 특수 위험
- 민원 챗봇이 *존재하지 않는 법령 조항* 인용
- 정책 검색 결과로 *옛 폐지 규정* 답변
- 통계 분석에서 *환각 수치* 생성
- 슬롭스쿼팅(LLM이 환각으로 만든 가짜 패키지명)도 본질적으로 misinformation의 코드 영역 사례

## 안전한 패턴
- **출처 인용 강제**: LLM이 답변할 때 *원문 인용*을 함께 표시
- **신뢰도 점수**: RAG 검색 점수가 낮으면 "확실하지 않음" 표시
- **휴먼 검토**: 법령·정책 답변은 *사람 검토 후* 제공
- **fact-check 후처리**: 핵심 사실은 별도 신뢰 DB 대조

## 점검 항목
- 챗봇 응답에 *언제나* 출처 표시 (없으면 거부)
- 모델 응답에 "잘 모릅니다" 옵션 강제 (helpfulness보다 정확성 우선)
- 정기 환각률 측정 (테스트 셋 + 자동 평가)

## 참조
- OWASP LLM Top 10 2025 — LLM09
- 본 리포 [INTEL-2026-SLOPSQUATTING](../intel/INTEL-2026-SLOPSQUATTING.md) (코드 영역 misinformation 사례)
