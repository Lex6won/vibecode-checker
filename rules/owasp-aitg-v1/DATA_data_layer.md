---
id: AITG-V1-DATA
title_ko: AI Data Layer 테스트
title_en: AI Data Layer Testing
status: approved
source_layer: baseline
sources:
  - publisher: OWASP
    document: AI Testing Guide v1
    version: "v1"
    item: Data Layer
severity: high
decision_default: warn
domains: [llm-appsec]
languages: [python]
scenarios: [data-pipeline, rag, llm-integration]
related_baseline: [OWASP-LLM-2025-02, OWASP-LLM-2025-04, OWASP-LLM-2025-08, NIS-AI-M01, NIS-AI-M03, NIS-AI-M05]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## Layer 범위
*학습·튜닝·RAG·운영* 데이터의 안전성·무결성·접근통제·개인정보 보호. 공공기관 *민원·통계·내부 문서* 보호가 본 layer의 1순위입니다.

## 핵심 테스트 카테고리

| 카테고리 | LLM Top 10 매핑 | 본 리포 detection 룰 |
|---|---|---|
| Data Poisoning | LLM04 | — (reference-only) |
| Sensitive Data in Training | LLM02 | [GOV-PII-RRN-001](../scanner-builtin/GOV-PII-RRN-001.md), [GOV-PII-PHONE-001](../scanner-builtin/GOV-PII-PHONE-001.md) |
| RAG Index Integrity | LLM08 | — |
| Vector DB Access Control | LLM08 | — (NIS-AI-M05 참조) |
| Data Lineage | — | — |

## 권장 테스트 절차
1. **데이터 출처 검증**: 모든 학습·RAG 데이터셋의 출처·해시·서명 ([NIS-AI-M01](../nis-ai/M01_trusted_data_source.md))
2. **PII 사전 스캔**: 학습 데이터에 PII 잔존 여부 검사 (자체 룰 + Presidio)
3. **RAG 인덱스 무결성**: 정기 통계적 이상치 탐지, 외부 추가 문서 무결성
4. **벡터 DB RBAC**: 사용자별 권한 + 다중 테넌트 분리 ([NIS-AI-M05](../nis-ai/M05_data_access_control.md))
5. **데이터 lineage 추적**: 원본 → 전처리 → 학습 → 배포 전 단계 식별

## 공공 환경 추가 점검
- 민원 데이터 사용 시 *목적 제한* 강제 (개인정보 보호법)
- 외부 LLM에 *학습 데이터 전송 금지* (정책 + 코드 분석)
- 부서별 RAG 인덱스 격리 (`tenant_id` 메타 강제)

## 매핑
- OWASP LLM Top 10 2025 — LLM02, LLM04, LLM08
- 국정원 AI 보안 가이드북 M01, M03, M05
- 개인정보보호위원회 생성형 AI 안내서 (2025-08)
- 개인정보 보호법
