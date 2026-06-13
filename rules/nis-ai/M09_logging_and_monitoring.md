---
id: NIS-AI-M09
title_ko: AI 시스템 로깅·모니터링
title_en: AI System Logging and Monitoring
status: approved
source_layer: baseline
sources:
  - publisher: 국정원
    document: 국가·공공기관 AI 보안 가이드북
    version: "2025.12"
    item: M09
severity: high
decision_default: warn
domains: [llm-appsec, agent-safety]
languages: [python, javascript]
scenarios: [llm-integration, agent, rag, data-pipeline]
related_baseline: [OWASP-LLM-2025-02, NIST-SSDF-800-218]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 무엇이 위험한가
AI 시스템의 사용자 요청·응답·접속 이력이 *실시간으로 기록·보존되지 않으면* 사고 발생 시 책임 소재 확인, 침입 흔적 추적, 감사·재발 방지가 모두 불가능합니다. 국정원 가이드북은 운영 단계의 핵심 통제로 **AI 시스템 로깅·모니터링**을 제시합니다.

## 요구되는 로깅 항목 (요지)
- 사용자 식별자(가명화), 요청 시각·IP
- 프롬프트 요청·응답 메타 (원문은 PII 마스킹 후 저장 또는 해시만)
- 모델 식별자·버전·temperature 등 호출 파라미터
- 도구 호출 이력 (에이전트의 경우)
- 인증·인가 실패, 비정상 패턴(rate spike, 권한 초과 시도)

## 안전한 패턴
```python
# 예시 — 실제 구현은 기관 로깅 정책에 따라
logger.info(
    "llm_call",
    extra={
        "user_id_hash": hash_user(user.id),     # 가명화
        "model": "claude-haiku-4-5",
        "prompt_hash": sha256(prompt),          # 원문 미저장
        "response_meta": {"tokens": n, "ms": elapsed},
        "tool_calls": [t.name for t in tools],  # 도구 이름만
    },
)
```

## 공공 환경 운영 시 고려
- 로그 저장 위치는 **내부망 한정** (`policies/public_default_strict.yaml`의 `logging_policy` 참조)
- PII 자동 마스킹 (presidio 등)
- 보존 기간 90일, 외부 전송 금지
- 정기 감사: 권한 초과 시도·비정상 패턴 알림

## 참조
- 국정원 AI 보안 가이드북 (2025-12-10) M09
- NIST SP 800-218 SSDF PO.2 (보안 환경 보호)
- OWASP LLM Top 10 2025 — LLM02 (Sensitive Information Disclosure)
