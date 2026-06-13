---
id: OWASP-AGENTIC-2026-ASI06
title_ko: 메모리·컨텍스트 오염 (Memory and Context Poisoning)
title_en: Memory and Context Poisoning
status: approved
source_layer: baseline
sources:
  - publisher: OWASP
    document: OWASP Top 10 for Agentic Applications 2026
    version: "2026"
    item: ASI06
severity: high
decision_default: warn
domains: [agent-safety, llm-appsec]
languages: [python]
scenarios: [agent, rag, llm-integration]
related_baseline: [OWASP-LLM-2025-04, OWASP-LLM-2025-08, NIS-AI-M03]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 위협 정의
공격자가 에이전트의 **장기 메모리** 또는 **RAG (Retrieval-Augmented Generation) 데이터**를 오염시켜, *이후 모든 결정*에 영구적인 편향을 주입합니다.

**1회성이 아닌 지속적 위협**: 한 번 오염된 메모리는 *수많은 후속 호출*에 영향을 미쳐, 공격 비용 대비 효과가 극대화됩니다.

## 공공 환경 시나리오
- **민원 챗봇 메모리 오염**: 공격자가 "이 정책은 폐지되었다"고 메모리에 주입 → 챗봇이 *수개월간* 잘못된 정보 제공
- **RAG 문서 오염**: 공식 문서로 위장한 악성 PDF를 벡터 DB에 삽입 → 모든 정책 검색이 영향
- **장기 학습 데이터 오염**: 운영 중 수집되는 사용자 피드백에 조작 데이터 주입

## 안전한 패턴
- 메모리·RAG에 *쓰기 권한 분리* + 감사 로그
- 외부 문서 수집 시 무결성 검사 ([NIS-AI-M03](../nis-ai/M03_data_inspection.md))
- 정기 *메모리 무결성 검사*: 통계적 이상치, 출처 검증
- 메모리 *유효기간* 설정 (TTL): 의심 데이터는 자동 만료
- *권위 있는 출처*만 RAG 인덱스 등록

## 매핑
- OWASP LLM Top 10 2025 — LLM04 (Data and Model Poisoning), LLM08 (Vector and Embedding Weaknesses)
- 국정원 AI 보안 가이드북 M03 (데이터 검사)
- OWASP AI Testing Guide v1 — Data layer
