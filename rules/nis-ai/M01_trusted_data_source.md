---
id: NIS-AI-M01
title_ko: 신뢰할 수 있는 출처의 데이터 활용
title_en: Use of Data from Trusted Sources
status: approved
source_layer: baseline
sources:
  - publisher: 국정원
    document: 국가·공공기관 AI보안 가이드북
    version: "2025.12"
    item: M01
cwe: [CWE-829, CWE-494]
languages: [python, javascript]
scenarios: [data-pipeline, llm-integration, rag]
severity: high
related_baseline: [MOIS-49-SW-17, OWASP-LLM-2025-02]
verified_at: 2026-05-30
review_due: 2026-11-30
---

## 무엇이 위험한가
바이브코딩으로 만든 데이터 수집/RAG/모델 학습 코드가 신뢰할 수 없는 외부 사이트에서 데이터를 받아 그대로 사용하면, 악성 콘텐츠가 그대로 시스템에 흘러 들어와 데이터 오염, 간접 프롬프트 인젝션, 백도어 등으로 이어진다. 국정원 AI 보안 가이드북은 "공공기관·인증기관 등 검증된 출처의 데이터만 사용"하도록 명시한다.

## 위험한 코드 예시
```python
import requests
import pandas as pd

# 출처 검증 없이 외부 URL의 CSV를 그대로 읽어 학습/RAG에 사용
url = input("데이터 URL을 입력하세요: ")
df = pd.read_csv(url)
```

## 안전한 코드 예시
```python
import hashlib
import requests
import pandas as pd

ALLOWED_DOMAINS = {"data.go.kr", "kosis.kr", "open.gg.go.kr"}
EXPECTED_HASH = "a3b1c5..."  # 사전 검증된 데이터의 SHA-256

from urllib.parse import urlparse
url = "https://data.go.kr/.../verified.csv"
assert urlparse(url).hostname in ALLOWED_DOMAINS, "허용되지 않은 출처"

raw = requests.get(url, timeout=10).content
assert hashlib.sha256(raw).hexdigest() == EXPECTED_HASH, "무결성 검증 실패"
df = pd.read_csv(pd.io.common.BytesIO(raw))
```

## 점검 방법
- `requests.get(...)`, `urllib.request.urlopen(...)` 호출 시 URL이 화이트리스트 검증을 거치는지 확인
- `pd.read_csv(url)`, `datasets.load_dataset(...)`에 사용자/환경 입력 URL이 직접 들어가는 패턴 차단
- 외부 데이터를 LLM 컨텍스트에 넣기 전에 무결성 검증(해시·서명) 단계 존재 여부

## 원문 인용
> "공공기관, 인증기관 등 검증된 출처의 데이터만 사용한다."  
> — 국정원 국가·공공기관 AI보안 가이드북 (2025.12), M01
