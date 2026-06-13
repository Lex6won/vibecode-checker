---
id: OWASP-LLM-2025-08
title_ko: 벡터 및 임베딩 취약점
title_en: Vector and Embedding Weaknesses
status: approved
source_layer: baseline
sources:
  - publisher: OWASP
    document: OWASP Top 10 for LLM Applications 2025
    version: "2025"
    item: LLM08
severity: high
decision_default: warn
domains: [llm-appsec]
languages: [python]
scenarios: [rag, llm-integration]
related_baseline: [OWASP-LLM-2025-04, NIS-AI-M03, NIS-AI-M05]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 무엇이 위험한가
RAG 시스템의 **벡터 DB·임베딩 파이프라인**은 LLM 보안의 *새로운 공격면*입니다. 공격 표면:

- **인덱스 오염**: 악성 문서를 RAG 인덱스에 삽입 → 간접 prompt injection
- **다중 테넌트 누출**: 사용자별·기관별 데이터 격리 실패로 타인 데이터 검색
- **임베딩 역전 공격**: 임베딩 벡터에서 원문 복원 시도
- **권한 우회**: 벡터 DB에 RBAC 미적용 → 권한 없는 데이터 검색

**2025판 신규 항목** — RAG가 표준 패턴이 되며 별도 위험 카테고리로 분리됨.

## 공공 환경 적용
- 민원 데이터·내부 문서를 RAG에 넣을 때 *문서 단위 권한* 메타데이터 필수
- 검색 시 사용자 권한과 문서 권한 매칭
- 임베딩 모델은 *기관 내부* 또는 *승인된 모델*만 사용 (외부 임베딩 = 데이터 전송)

## 안전한 패턴
```python
# 다중 테넌트 분리 (네임스페이스 또는 metadata filter)
results = vector_db.query(
    embedding=query_emb,
    filter={"tenant_id": user.tenant_id, "min_clearance": user.clearance},
    top_k=10,
)
```

## 점검 항목
- 벡터 DB RBAC 적용 ([NIS-AI-M05](../nis-ai/M05_data_access_control.md))
- 외부 임베딩 모델 사용 시 데이터 전송 정책 확인
- RAG 문서 수집 시 무결성 검사 ([NIS-AI-M03](../nis-ai/M03_data_inspection.md))
- 정기 검색 결과 감사 (의심 결과 표본 조사)

## 참조
- OWASP LLM Top 10 2025 — LLM08 (신규)
- OWASP AI Testing Guide v1 — Data layer
