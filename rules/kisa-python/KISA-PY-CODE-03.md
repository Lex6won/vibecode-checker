---
id: KISA-PY-CODE-03
title_ko: Python에서 신뢰할 수 없는 데이터의 역직렬화 (pickle/marshal/shelve)
title_en: Untrusted data deserialization in Python (pickle/marshal/shelve)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Python 시큐어코딩 가이드(2023년 개정본)
    item: 제6절 3. 신뢰할 수 없는 데이터의 역직렬화
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-44
cwe: [CWE-502]
severity: critical
decision_default: block
domains: [kisa-secure-coding]
languages: [python]
scenarios: [web-app, data-pipeline, llm-integration]
related_baseline: [MOIS-49-CODE-03]
verified_at: 2026-05-31
review_due: 2026-11-30
detection:
  # 라인 단위 regex로는 torch.load(weights_only=True) 같은 안전 호출을 정확히
  # 구분하기 어렵습니다. torch.load 검출은 python-ast 어댑터가 담당하며,
  # 여기서는 명확히 위험한 직렬화 함수들만 패턴으로 잡습니다.
  patterns:
    - 'pickle\.loads?\s*\('
    - 'cPickle\.loads?\s*\('
    - 'marshal\.loads?\s*\('
    - 'shelve\.open\s*\('
    - '(?:pd|pandas)\.read_pickle\s*\('
    - 'joblib\.load\s*\('
    # yaml.load 에 Safe 계열 Loader 가 없으면 임의 객체 생성(python-ast 가 정본,
    # 파싱 실패 파일용 보조). 2026-08-29 코퍼스 c_deser.py:8 미탐 보강.
    - 'yaml\.load\s*\((?![^)]*Safe)'
  category: kisa-secure-coding
  why_it_matters: >-
    pickle/marshal 등은 객체 직렬화 포맷을 *그대로 재구성*하면서 __reduce__를
    통한 임의 코드 실행을 허용합니다. 외부에서 받은 파일·요청을 pickle.loads로
    열면 즉시 RCE입니다. AI/ML 분야에서는 사전학습 모델(.pkl, .pt) 파일이
    악성 모델로 둔갑한 공급망 공격 사례가 다수 보고되었습니다.
  public_sector_impact:
    - AI 모델 공급망 공격
    - 행정 시스템 RCE
    - 데이터 파이프라인 침해
  safe_fix: |
    데이터 교환은 json.loads / Pydantic / msgpack(strict_map_key=True) 사용.
    ML 모델은 safetensors 포맷 또는 torch.load(..., weights_only=True) 사용.
    사전학습 모델은 출처·서명·SHA-256 해시를 정책 매트릭스로 검증한 후에만 로드.
  references:
    - KISA Python 가이드 제6절 3
    - MOIS-49-CODE-03
    - CWE-502
    - OWASP A8 Software and Data Integrity Failures
  can_auto_fix: false
examples:
  language: python
  positive:
    - "import pickle\npickle.loads(data)"
    - "import torch\ntorch.load('m.pt')"
    - "import joblib\njoblib.load(p)"
    - "import pandas as pd\ndf = pd.read_pickle(url)"
  negative:
    - "import torch\ntorch.load('m.pt', weights_only=True)"
    - "import json\njson.loads(data)"
---

## 무엇이 위험한가
`pickle.loads(open("model.pkl", "rb").read())`처럼 외부 파일을 그대로 역직렬화하면, 파일 안에 포함된 `__reduce__` 메서드가 임의의 Python 함수를 호출할 수 있습니다. 최근 PyPI/HuggingFace에서 모델 파일에 악성 페이로드를 넣은 공급망 공격이 보고되고 있습니다.

## 안전한 패턴 (가이드 원문 인용)
- 외부 데이터 교환: `json.loads` + Pydantic 모델 검증
- AI 모델: `safetensors` 포맷 또는 `torch.load(path, weights_only=True)`
- 캐시는 동일 신뢰 경계 내에서만 pickle 사용
