---
id: KISA-PY-CODE-02
title_ko: Python 부적절한 자원 해제 - open/connect without with-block
title_en: Resource not released properly in Python (no context manager)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Python 시큐어코딩 가이드(2023년 개정본)
    item: 제6절 2. 부적절한 자원 해제
cwe: [CWE-404, CWE-772]
severity: medium
decision_default: warn
domains: [kisa-secure-coding]
languages: [python]
scenarios: [data-pipeline, batch-job, web-app]
related_baseline: [MOIS-49-CODE-02]
verified_at: 2026-05-31
review_due: 2026-11-30
detection:
  # 단순화: 변수 할당 뒤에 close()/__exit__ 호출이 보장되지 않는 패턴은 라인
  # 단위로 검출이 어려움. 여기서는 가장 흔한 안티 패턴 — open()을 변수에 담고
  # with 블록이 없는 경우 — 의 신호만 잡습니다.
  patterns:
    - "(?<![A-Za-z0-9_.])(?:f|conn|cursor|sock)\\s*=\\s*open\\s*\\([^)]+\\)\\s*$"
    - "sqlite3\\.connect\\s*\\([^)]+\\)\\s*(?:\\.cursor\\s*\\(\\s*\\))?\\s*$"
    - "socket\\.socket\\s*\\([^)]*\\)\\s*$"
  category: kisa-secure-coding
  flags: [MULTILINE]
  why_it_matters: >-
    파일·DB 연결·소켓을 with 블록 없이 변수에 담으면 예외 발생 시 자원이
    해제되지 않아 파일 핸들·소켓·DB 커서 누수로 이어집니다. 장시간 실행되는
    배치·서버에서는 결국 자원 고갈로 서비스 중단을 일으킵니다.
  public_sector_impact:
    - 행정 시스템 자원 고갈
    - 배치 처리 실패
    - 데이터베이스 연결 풀 고갈
  safe_fix: |
    with 문 (context manager)을 사용하세요. 예외 발생 여부와 무관하게
    __exit__에서 자원이 해제됩니다.
    with open(path) as f:
        data = f.read()
    with sqlite3.connect(db_path) as conn, conn.cursor() as cur:
        ...
  references:
    - KISA Python 가이드 제6절 2
    - MOIS-49-CODE-02
    - CWE-404
    - PEP 343 (with statement)
  can_auto_fix: false
---

## 무엇이 위험한가
`f = open(path)` 한 줄로 끝나는 코드는 다음 라인에서 예외가 발생하면 파일이 영원히 열린 채로 남습니다.

## 안전한 패턴
```python
with open(path, "r", encoding="utf-8") as f:
    text = f.read()
# 여기서 자동으로 close

import sqlite3
with sqlite3.connect(db_path) as conn:
    cur = conn.cursor()
    cur.execute("SELECT * FROM t")
```
