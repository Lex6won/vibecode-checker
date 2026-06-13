---
id: KISA-PY-TIME-02
title_ko: Python 종료되지 않는 반복문/재귀 - 입력값 종료 조건 검증 누락
title_en: Potentially non-terminating loop or recursion in Python
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Python 시큐어코딩 가이드(2023년 개정본)
    item: 제4절 2. 종료되지 않는 반복문 또는 재귀 함수
cwe: [CWE-835, CWE-674]
severity: medium
decision_default: warn
domains: [kisa-secure-coding]
languages: [python]
scenarios: [data-pipeline, batch-job]
related_baseline: [MOIS-49-TIME-02]
verified_at: 2026-05-31
review_due: 2026-11-30
detection:
  # 라인 단위 regex로는 무한 루프 정밀 검출이 어렵습니다. 여기서는 가장
  # 흔한 위험 신호 — 종료 조건이 입력에 의존하는 while/recursion 패턴 — 만
  # 표시하고 사람 검토로 처리합니다.
  patterns:
    - "while\\s+True\\s*:\\s*$"
    - "while\\s+request\\.[a-zA-Z_]+"
    - "sys\\.setrecursionlimit\\s*\\(\\s*(?:10\\d{3,}|\\d{6,})"
  category: kisa-secure-coding
  flags: [MULTILINE]
  why_it_matters: >-
    `while True:` 자체는 흔하지만 사용자 입력·외부 응답을 종료 조건으로 사용
    하면서 timeout·재시도 한계가 없으면 DoS·서비스 중단이 발생할 수 있습니다.
    `sys.setrecursionlimit`을 비정상적으로 높이는 것도 스택 폭발 위험.
  public_sector_impact:
    - 서비스 응답 지연·중단
    - 배치 작업 무한 실행
    - 리소스 고갈
  safe_fix: |
    1) 모든 외부 의존 루프는 최대 반복 횟수 + timeout 설정
    2) 재귀 대신 반복으로 변환 또는 깊이 제한
    3) requests·httpx에는 timeout= 명시
    MAX_ITER = 1000
    for _ in range(MAX_ITER):
        ...
        if done: break
  references:
    - KISA Python 가이드 제4절 2
    - MOIS-49-TIME-02
    - CWE-835
  can_auto_fix: false
---

## 무엇이 위험한가
무한 루프는 단순 실수일 수도 있지만, 외부 응답 대기 코드의 종료 조건이 입력에 의존하는 경우 *공격자가 종료를 막아* DoS를 일으킬 수 있습니다.

## 안전한 패턴
```python
import httpx
resp = httpx.get(url, timeout=10.0)  # 반드시 timeout

# 폴링 루프
import time
for _ in range(60):                  # 최대 60회
    if poll_done(): break
    time.sleep(1)
else:
    raise TimeoutError
```
