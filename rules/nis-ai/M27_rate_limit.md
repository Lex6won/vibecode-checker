---
id: NIS-AI-M27
title_ko: 요청 속도 제한
title_en: Request Rate Limiting
status: approved
source_layer: baseline
sources:
  - publisher: 국정원
    document: 국가·공공기관 AI 보안 가이드북
    version: "2025.12"
    item: M27
severity: medium
decision_default: warn
domains: [llm-appsec]
languages: [python, javascript]
scenarios: [llm-integration]
related_baseline: [NIS-AI-T04, NIS-AI-T06, NIS-AI-T11, OWASP-LLM-2025-10]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 대책 요지 (가이드북 인용)
*호출 횟수·입력 길이·동시 처리 요청 수·출력 용량* 등을 제한. **주체별 차등 한도** 설정. AI시스템 로깅·모니터링과 병행하여 반복 질의로 인한 *리소스 과부하* 여부 확인.

## 안전한 패턴
```python
RATE = TokenBucket(per_user_tokens_per_hour=100_000, per_user_requests_per_min=60)
def call_llm(user, prompt):
    if not RATE.consume(user.id, tokens=count(prompt)):
        raise QuotaExceeded()
    return llm.invoke(prompt, max_tokens=2000)
```

## 공공 환경 적용
- 부서별 일일 quota (예: 10만 토큰)
- 외부 사용자(민원 챗봇)는 IP별 rate limit
- 비용 임계치 80% 도달 시 *알림 + 자동 차단*

## 매핑
- OWASP LLM Top 10 2025 LLM10 (Unbounded Consumption)
- 본 리포 [OWASP-LLM-2025-10](LLM10_unbounded_consumption.md)
