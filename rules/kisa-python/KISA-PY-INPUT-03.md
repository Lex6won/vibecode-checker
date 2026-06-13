---
id: KISA-PY-INPUT-03
title_ko: Python 경로 조작 - 외부 입력이 파일 경로에 직접 결합
title_en: Path traversal via untrusted input in Python file operations
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Python 시큐어코딩 가이드(2023년 개정본)
    item: 제2절 3. 경로 조작 및 자원 삽입
cwe: [CWE-22, CWE-23]
severity: high
decision_default: block
domains: [kisa-secure-coding]
languages: [python]
scenarios: [web-app, file-upload]
related_baseline: [MOIS-49-INPUT-03]
verified_at: 2026-05-31
review_due: 2026-11-30
detection:
  patterns:
    - 'open\s*\(\s*(?:request\.|flask\.request\.|input\s*\()'
    - "(?:os\\.path\\.join|open|Path)\\s*\\([^)]*\\.\\.[/\\\\]"
    - "send_file\\s*\\([^)]*request\\."
    - "(?:os\\.path\\.join|Path\\s*\\()[^)]*request\\.[a-zA-Z_]+\\s*\\)"
    # 사용자 입력이 로컬 변수로 간접화돼도, open/send_file에 os.path.join으로
    # 경로를 동적 조립하는 것 자체가 경로 조작 검증을 요구하는 신호다.
    - 'open\s*\(\s*os\.path\.join\s*\('
    - 'send_file\s*\(\s*os\.path\.join\s*\('
  category: kisa-secure-coding
  why_it_matters: >-
    사용자가 보낸 파일 이름·경로 조각이 그대로 open/send_file/os.path.join에
    들어가면 `../../etc/passwd`처럼 상위 디렉터리를 탐색하거나 의도하지 않은
    파일에 접근할 수 있습니다.
  public_sector_impact:
    - 행정 시스템 파일 유출
    - 민원 첨부파일 노출
    - 서버 구성 파일 접근
  safe_fix: |
    pathlib.Path로 정규화 후 base directory 안에 있는지 검증하세요.
    base = Path("/var/uploads").resolve()
    target = (base / Path(name).name).resolve()
    if not str(target).startswith(str(base)):
        abort(400)
  references:
    - KISA Python 가이드 제2절 3
    - MOIS-49-INPUT-03
    - CWE-22
  can_auto_fix: false
---

## 무엇이 위험한가
`open(request.POST['file'])`처럼 사용자 입력을 정규화 없이 파일 경로로 쓰면 경로 조작 공격이 가능합니다. 공공 민원·결재 시스템의 첨부파일 다운로드 엔드포인트가 가장 흔한 사례입니다.

## 안전한 패턴
```python
from pathlib import Path
def serve(name: str):
    base = Path("/var/uploads").resolve()
    target = (base / Path(name).name).resolve()
    if not str(target).startswith(str(base) + "/"):
        raise PermissionError
    return send_file(target)
```
