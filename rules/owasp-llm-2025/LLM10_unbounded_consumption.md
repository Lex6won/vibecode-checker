---
id: OWASP-LLM-2025-10
title_ko: 무제한 자원 소비 (Unbounded Consumption)
title_en: Unbounded Consumption
status: approved
source_layer: baseline
sources:
  - publisher: OWASP
    document: OWASP Top 10 for LLM Applications 2025
    version: "2025"
    item: LLM10
cwe: [CWE-400, CWE-770]
severity: medium
decision_default: warn
domains: [llm-appsec]
languages: [python, javascript]
scenarios: [llm-integration, agent, rag]
related_baseline: [OWASP-LLM-2025-06]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 무엇이 위험한가
LLM 호출은 *외부 API 비용 + 토큰 소비 + 시간*이 무제한일 수 있습니다. 통제 없이 두면:

- **DoS (서비스 거부)**: 공격자가 큰 입력으로 토큰 소비 폭발 → 서비스 중단
- **비용 폭발**: 지자체 예산 대비 LLM API 비용이 급증
- **모델 추출 공격**: 반복 호출로 모델 출력을 학습해 모델 자체 복제
- **에이전트 루프**: 자율 에이전트가 무한 도구 호출

## 공공 환경 위험
- 민원 챗봇에 *대용량 PDF 첨부* 입력 → 토큰 폭발
- 자율 에이전트가 *외부 사이트 크롤* 반복 → 비용·트래픽 폭증
- 일과 시간 외 *무인 자동화*가 의도치 않게 호출 누적

## 안전한 패턴
- **입력 크기 제한**: max_input_tokens, 첨부 파일 크기 제한
- **출력 제한**: max_output_tokens, temperature 보수적 설정
- **호출 제한**: 사용자별 rate limit, 부서별 일일 quota
- **비용 알람**: 예산 임계치 80% 도달 시 알림 + 차단
- **에이전트 루프 가드**: 동일 도구 N회 이상 호출 시 강제 종료

## 점검 항목
```python
# 예시
RATE_LIMITER = TokenBucket(per_user_tokens_per_hour=100_000)

def call_llm(user_id: str, prompt: str):
    if not RATE_LIMITER.consume(user_id, estimated_tokens=count_tokens(prompt)):
        raise QuotaExceeded(user_id)
    if len(prompt) > MAX_INPUT_CHARS:
        raise InputTooLarge()
    response = llm.invoke(prompt, max_tokens=MAX_OUTPUT_TOKENS)
    return response
```

## 참조
- OWASP LLM Top 10 2025 — LLM10
- CWE-400 (Uncontrolled Resource Consumption)
