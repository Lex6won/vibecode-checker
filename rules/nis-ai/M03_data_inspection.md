---
id: NIS-AI-M03
title_ko: 데이터 검사
title_en: Data Inspection
status: approved
source_layer: baseline
sources:
  - publisher: 국정원
    document: 국가·공공기관 AI 보안 가이드북
    version: "2025.12"
    item: M03
severity: high
decision_default: warn
domains: [llm-appsec]
languages: [python]
scenarios: [data-pipeline, rag, llm-integration]
related_baseline: [NIS-AI-T01, NIS-AI-M01, OWASP-AI-TESTING-GUIDE]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 무엇이 위험한가
수집된 데이터에 *무결성 검증·이상치 탐지·악성 콘텐츠 필터링*이 빠지면, [학습데이터 오염](T01_data_poisoning.md)·간접 프롬프트 인젝션·민감정보 미인지 학습으로 직결됩니다. 국정원 가이드북 **M03**은 데이터 수집 단계의 핵심 통제로 *데이터 검사*를 제시합니다.

## 데이터 검사가 다루어야 할 항목
- **무결성**: 해시·서명 비교, 다운로드 후 즉시 검증
- **신원**: 출처 도메인 화이트리스트, 서명자 확인
- **통계적 이상치**: 분포 외 값, 극단치, 중복도 검사
- **민감정보 사전 스캔**: PII 패턴 탐지 후 제외·마스킹
- **악성 콘텐츠**: 프롬프트 인젝션 키워드, 악성 코드 패턴

## 안전한 패턴 (예시)
```python
import hashlib
import requests
from urllib.parse import urlparse

ALLOWED_DOMAINS = {"data.go.kr", "kosis.kr", "open.gg.go.kr"}
EXPECTED_HASH = "a3b1c5..."

def fetch_verified(url: str) -> bytes:
    # 1) 출처 검증
    host = urlparse(url).hostname
    assert host in ALLOWED_DOMAINS, f"허용되지 않은 출처: {host}"

    # 2) 다운로드 + 무결성
    raw = requests.get(url, timeout=10).content
    assert hashlib.sha256(raw).hexdigest() == EXPECTED_HASH, "무결성 검증 실패"

    # 3) (선택) PII 사전 스캔
    # raw = run_pii_redaction(raw)

    return raw
```

## 공공 환경 운영 시 고려
- *모든* 외부 데이터셋에 적용 (Hugging Face·Kaggle 포함)
- 검증 실패 시 기본 deny + 감사 로그
- 검증 결과는 데이터 lineage로 보존

## 참조
- 국정원 AI 보안 가이드북 (2025-12-10) M03
- OWASP AI Testing Guide v1 — Data layer
- NIS-AI-M01 (신뢰할 수 있는 출처의 데이터 활용)
