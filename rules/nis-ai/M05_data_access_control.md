---
id: NIS-AI-M05
title_ko: 데이터 접근통제
title_en: Data Access Control
status: approved
source_layer: baseline
sources:
  - publisher: 국정원
    document: 국가·공공기관 AI 보안 가이드북
    version: "2025.12"
    item: M05
severity: high
decision_default: warn
domains: [llm-appsec, agent-safety]
languages: [python, javascript]
scenarios: [data-pipeline, rag, llm-integration, agent]
related_baseline: [OWASP-ASVS, CISA-SECURE-BY-DESIGN]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 무엇이 위험한가
학습 데이터·RAG 인덱스·운영 로그가 *누구나 접근 가능*하면 내부 정보 유출, 학습 결과 조작, 감사 회피로 직결됩니다. 국정원 가이드북 **M05**는 데이터 자산에 *RBAC + 최소 권한 + 감사*를 적용하라고 제시합니다.

## 접근통제가 다루어야 할 자산
- 학습 데이터셋 (원본·전처리·증강본)
- RAG 인덱스 (벡터 DB, BM25 인덱스)
- 모델 가중치·체크포인트
- 프롬프트 템플릿·system prompt
- 운영 로그·trace
- LLM API 키·secret

## 안전한 패턴
```python
# RBAC 예시
ROLES = {
    "data_engineer": ["read:dataset", "write:dataset_staging"],
    "ml_engineer":   ["read:dataset", "read:model", "write:model_staging"],
    "ops":           ["read:model_prod", "read:log_meta"],
    "auditor":       ["read:log_meta", "read:audit"],
}

def authorize(user: User, action: str) -> bool:
    allowed = ROLES.get(user.role, [])
    return action in allowed
```

## 최소 권한 체크리스트
- 운영자는 *프로덕션 데이터 원본*에 직접 접근 불가
- LLM 도구는 *읽기 도구*와 *변경 도구*가 분리
- 변경 도구는 별도 승인 필요 (HITL)
- 감사 로그는 *별도 권한*으로만 접근

## 참조
- 국정원 AI 보안 가이드북 (2025-12-10) M05
- OWASP ASVS V4 (Access Control)
- CISA Secure by Design
