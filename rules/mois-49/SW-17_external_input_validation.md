---
id: MOIS-49-SW-17
title_ko: 외부 입력값에 의한 SQL/명령 인젝션 방지
title_en: External Input Injection Prevention
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (별표3 보안약점)
    version: "2021.12"
    item: SW-17
cwe: [CWE-89, CWE-78]
languages: [python, javascript]
scenarios: [web-app, data-pipeline]
severity: critical
related_baseline: [OWASP-LLM-2025-01]
verified_at: 2026-05-30
review_due: 2026-11-30
---

## 무엇이 위험한가
공무원 바이브코딩 산출물의 절대다수는 민원 데이터 처리·통계 추출 등 DB·셸을 다루는 스크립트다. AI가 만들어준 코드는 외부 입력을 그대로 SQL 문자열에 끼워 넣거나 `os.system(...)`에 전달하는 패턴이 빈번하며, 이는 SQL 인젝션·OS 명령 인젝션을 직접 허용한다.

실측: 2026년 측정에서 AI 생성 코드의 **log injection 발생률 88%**, XSS 차단 실패 86%.

## 위험한 코드 예시
```python
# SQL 인젝션
cursor.execute(f"SELECT * FROM citizens WHERE name = '{name}'")

# OS 명령 인젝션
import os
filename = input("파일명: ")
os.system(f"cat {filename}")
```

## 안전한 코드 예시
```python
# 1) 파라미터 바인딩
cursor.execute("SELECT * FROM citizens WHERE name = %s", (name,))

# 2) shell=False + 인자 분리
import subprocess
subprocess.run(["cat", "--", filename], check=True)
```

## 점검 방법
- `cursor.execute(f"...{var}...")` / `"...".format(var)` / `"..." + var` 패턴 검출
- `os.system`, `subprocess.run(..., shell=True)` 사용 검출
- 사용자 입력이 LLM 응답을 거쳐 SQL/명령에 들어가는 *간접* 경로도 동일 위험으로 분류

## 원문 인용
> "외부 입력값에 의한 SQL 삽입, 운영체제 명령어 삽입, 코드 삽입 등을 방지하기 위해 입력값 검증 및 파라미터화된 쿼리·인자 분리 기법을 적용해야 한다."  
> — 행정안전부 소프트웨어 개발보안 가이드 (별표3, SW-17 요지)
