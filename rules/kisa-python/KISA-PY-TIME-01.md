---
id: KISA-PY-TIME-01
title_ko: Python TOCTOU - 검사시점과 사용시점 분리 (os.access 후 open)
title_en: Time-of-check vs time-of-use race in Python file ops
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Python 시큐어코딩 가이드(2023년 개정본)
    item: 제4절 1. 경쟁조건 - 검사시점과 사용시점(TOCTOU)
cwe: [CWE-367]
severity: medium
decision_default: warn
domains: [kisa-secure-coding]
languages: [python]
scenarios: [file-operations, batch-job]
related_baseline: [MOIS-49-TIME-01]
verified_at: 2026-05-31
review_due: 2026-11-30
detection:
  patterns:
    - "os\\.access\\s*\\([^)]+\\)\\s*[^:]*?:\\s*$"
    - "os\\.path\\.exists\\s*\\([^)]+\\)[^\\n]*?\\n[^\\n]*?open\\s*\\("
  category: kisa-secure-coding
  flags: [MULTILINE]
  why_it_matters: >-
    `if os.access(path, R_OK): with open(path) ...` 패턴은 검사와 사용 사이에
    공격자가 파일을 심볼릭 링크 등으로 바꾸면 의도하지 않은 파일을 읽을 수
    있습니다 (TOCTOU). 라인 단위 정규식으로는 완벽 검출이 어려워 warn으로
    두고 사람 검토를 유도합니다.
  public_sector_impact:
    - 권한 우회로 보호된 파일 접근
    - 배치 작업 변조
  safe_fix: |
    검사 없이 바로 사용하고 예외를 처리하세요.
    try:
        with open(path) as f: ...
    except (PermissionError, FileNotFoundError) as e:
        log.warning(...)
  references:
    - KISA Python 가이드 제4절 1
    - MOIS-49-TIME-01
    - CWE-367
  can_auto_fix: false
---

## 무엇이 위험한가
파일 검사와 실제 사용 사이에 공격자가 개입할 시간이 있으면 TOCTOU 약점이 발생합니다.

## 안전한 패턴
```python
# 검사 없이 바로 사용하고 예외 처리
try:
    with open(target, "rb") as f:
        data = f.read()
except (FileNotFoundError, PermissionError, IsADirectoryError) as e:
    handle_error(e)
```
