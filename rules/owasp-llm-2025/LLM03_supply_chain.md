---
id: OWASP-LLM-2025-03
title_ko: 공급망 (LLM 의존성·모델·플러그인의 공급망 위험)
title_en: Supply Chain
status: approved
source_layer: baseline
sources:
  - publisher: OWASP
    document: OWASP Top 10 for LLM Applications 2025
    version: "2025"
    item: LLM03
cwe: [CWE-829, CWE-494, CWE-1357]
severity: high
decision_default: warn
domains: [llm-appsec]
languages: [python, javascript]
scenarios: [package-install, llm-integration, rag, agent]
related_baseline: [INTEL-2026-SLOPSQUATTING, KR-KISA-SUPPLY-CHAIN, NIS-AI-M01]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 무엇이 위험한가
LLM 애플리케이션은 일반 SW보다 *더 깊은 공급망*에 의존합니다. 의존성 패키지(pypi/npm) 외에도 **사전학습 모델·임베딩·LoRA·플러그인·MCP 서버·벡터 DB·RAG 데이터셋**이 모두 공격면입니다.

2026년 실측 사건:
- **TrapDoor 캠페인** (2026-05-22~): 34 패키지 / 384 버전, npm·PyPI·CratesIO 동시 멀웨어
- **Bitwarden CLI** (2026-04): 첫 in-the-wild AI 코딩 어시스턴트 타겟
- **슬롭스쿼팅**: LLM 환각 패키지명 (Claude Haiku 4.62%, GPT-5.4-mini 6.10%)

## 점검 항목
- pip·npm 설치 전 [`check_package`](../../src/gvskb/tools/check_package.py) (OSV.dev 매칭)
- Hugging Face 모델은 다운로드 카드·서명·SHA 검증
- MCP 서버·플러그인은 *코드 리뷰 후* 등록
- 의존성 lockfile + SBOM 필수 (`policies/public_default_strict.yaml`의 `require_lockfile: true`)

## 안전한 패턴
- 내부 미러 (PyPI/npm 미러)만 허용 (기관 프로파일)
- 신규 패키지(등록 30일 이내) 자동 보류
- `pip-audit` / `osv-scanner` CI 통합

## 참조
- OWASP LLM Top 10 2025 — LLM03
- KISA SW 공급망 보안 가이드라인 1.0 (2024-05)
- 본 리포의 [INTEL-2026-SLOPSQUATTING](../intel/INTEL-2026-SLOPSQUATTING.md)
