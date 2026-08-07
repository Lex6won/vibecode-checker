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
    # 사용자 입력이 로컬 변수로 간접화돼도, open/send_file 에 os.path.join 으로
    # 경로를 동적 조립하면 경로 조작 검증이 필요하다. 다만 **조립되는 조각이
    # 전부 문자열 리터럴이면 동적이지 않다.**
    #
    # 예전 패턴은 `open(os.path.join(` 만 보고 잡았다. 그건 파이썬에서 가장 흔한
    # *안전한* 관용구다 — 실측에서 `open(os.path.join(DATA_DIR, "meta.json"))`
    # 같은 고정 경로 8건이 전부 '높음·차단'으로 보고돼 정상 프로젝트의 배포가
    # 막혔다. 이제 콤마 뒤에 따옴표가 오지 않는 경우(=변수·함수호출·f-string)만
    # 잡는다. 공백을 전방탐색 *안*에 넣는 이유: 밖에 두면 `\s*` 가 0글자로
    # 백트래킹해 공백을 '따옴표 아님'으로 통과시켜 아무것도 좁혀지지 않는다.
    - 'open\s*\(\s*os\.path\.join\s*\([^)]*,(?!\s*["''])'
    - 'send_file\s*\(\s*os\.path\.join\s*\([^)]*,(?!\s*["''])'
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
examples:
  language: python
  positive:
    - "data = open(request.args[\"path\"]).read()"
    - "return send_file(request.args.get(\"name\"))"
    # 조립 조각이 변수·f-string이면 여전히 잡아야 한다(반대 방향 고정)
    - "with open(os.path.join(UPLOAD_DIR, filename)) as f:"
    - "with open(os.path.join(BASE_DIR, \"sub\", user_name)) as f:"
    - "with open(os.path.join(BASE_DIR, f\"{report_id}.json\")) as f:"
    - "return send_file(os.path.join(EXPORT_DIR, requested))"
  negative:
    - "data = open(SAFE_REPORT_PATH, \"rb\").read()"
    - "return send_file(ALLOWED_FILES[key])"
    # 실측 오탐(semi_fable5) — 조각이 전부 리터럴인 고정 경로는 동적이지 않다
    - "with open(os.path.join(DATA_DIR, \"meta.json\"), \"w\", encoding=\"utf-8\") as f:"
    - "with open(os.path.join(DATA_DIR, \"params.json\"), \"r\", encoding=\"utf-8\") as f:"
    - "open(os.path.join(BASE_DIR, \"config\", \"app.json\"))"
    - "open(os.path.join(DATA_DIR,'meta.json'))"
    - "return send_file(os.path.join(EXPORT_DIR, \"report.pdf\"))"
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
