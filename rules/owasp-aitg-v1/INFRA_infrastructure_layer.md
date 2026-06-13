---
id: AITG-V1-INFRA
title_ko: AI Infrastructure Layer 테스트
title_en: AI Infrastructure Layer Testing
status: approved
source_layer: baseline
sources:
  - publisher: OWASP
    document: AI Testing Guide v1
    version: "v1"
    item: Infrastructure Layer
severity: high
decision_default: warn
domains: [llm-appsec]
languages: [python, javascript, yaml]
scenarios: [llm-integration, agent]
related_baseline: [OWASP-LLM-2025-03, OWASP-LLM-2025-10, KR-KISA-SUPPLY-CHAIN]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## Layer 범위
AI 시스템의 *운영 환경*: 의존성·배포·비밀 관리·네트워크·로깅. 공공기관 *망분리·외부 LLM 통제*가 본 layer에서 강제됩니다.

## 핵심 테스트 카테고리

| 카테고리 | LLM Top 10 매핑 | 본 리포 detection 룰 |
|---|---|---|
| Supply Chain (공급망) | LLM03 | [INTEL-2026-SLOPSQUATTING](../intel/INTEL-2026-SLOPSQUATTING.md) |
| Secret Management | — | [GOV-SECRET-APIKEY-001](../scanner-builtin/GOV-SECRET-APIKEY-001.md), [GOV-SECRET-PRIVATEKEY-001](../scanner-builtin/GOV-SECRET-PRIVATEKEY-001.md) |
| Internal Network Disclosure | — | [GOV-INTERNAL-NET-001](../scanner-builtin/GOV-INTERNAL-NET-001.md) |
| Unbounded Consumption (자원) | LLM10 | — |
| Deployment Configuration | — | — |

## 권장 테스트 절차
1. **의존성 스캔**: `osv-scanner` 정기 실행, lockfile + SBOM 검증
2. **비밀 스캔**: detect-secrets, gitleaks 도입; 본 PoC의 `detect_secrets_and_pii` MCP 도구 통합
3. **외부 LLM 트래픽 모니터링**: 코드에서 OpenAI/Anthropic API 호출 정적 분석 + 네트워크 egress 통제
4. **rate limit 검증**: 사용자별·부서별 quota 테스트
5. **로깅 정책 점검**: 코드 원문 미저장 확인, PII 마스킹 동작 검증

## 공공 환경 추가 점검 (정책 강제)
- `policies/public_default_strict.yaml`의 `llm_egress.blocked` 항목이 실제 차단되는지
- `package_policy.require_lockfile: true` 강제
- `logging_policy.store_code_snippets: false` 강제
- `network_policy.allowed_security_api_domains` 외 외부 호출 차단

## 매핑
- OWASP LLM Top 10 2025 — LLM03, LLM10
- KISA SW 공급망 보안 가이드라인 1.0
- NIST SSDF — PO/PS 그룹
