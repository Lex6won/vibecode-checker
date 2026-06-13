---
id: KISA-PY-CODE-01
title_ko: Python Null(None) 역참조 - dict.get()/os.environ.get()/re.match() 결과를 None 검사 없이 사용
title_en: Python None dereference (calling methods on possibly-None return values)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Python 시큐어코딩 가이드(2023년 개정본)
    item: 제5절 1. Null Pointer 역참조
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-43
cwe: [CWE-476]
severity: medium
decision_default: warn
domains: [kisa-secure-coding]
languages: [python]
scenarios: [web-app, data-pipeline, batch-job]
related_baseline: [MOIS-49-CODE-01]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    # 1) dict-like .get(...) 의 반환값을 곧바로 .method() / .attr 호출 — None 인 경우 AttributeError
    - "\\.get\\s*\\([^,)]+\\)\\.[A-Za-z_][A-Za-z0-9_]*\\s*\\("
    # 2) os.environ.get(...) 결과를 곧바로 사용
    - "(?<![A-Za-z0-9_])os\\.environ\\.get\\s*\\([^,)]+\\)\\.[A-Za-z_][A-Za-z0-9_]*\\s*\\("
    # 3) re.match/re.search 결과를 곧바로 .group() 호출 (매치 실패 시 None).
    #    정규식 안의 nested 괄호 (예: r'(\d+)') 까지 허용하기 위해 greedy `.*\)` 사용
    - "(?<![A-Za-z0-9_])re\\.(?:match|search|fullmatch)\\s*\\(.*\\)\\.group\\s*\\("
    # 4) request.POST.get(...)에 .count/.strip 등을 즉시 호출 (KISA 가이드 본문 예시)
    - "request\\.(?:POST|GET|args|form|json|values)\\.get\\s*\\([^,)]+\\)\\.(?:count|strip|split|lower|upper|replace|encode|decode|format)\\s*\\("
  category: kisa-secure-coding
  why_it_matters: >-
    파이썬은 C 의미의 *Null Pointer Dereference* 가 발생하진 않지만,
    `dict.get(key)` · `os.environ.get(name)` · `re.match(...)` 등 *None 을
    반환할 수 있는 함수의 결과를 곧바로 메서드 호출*하면 `AttributeError:
    'NoneType' object has no attribute ...` 로 *런타임 예외*가 발생합니다.
    공격자는 의도적으로 입력을 비워(예: `filename` 미전송) 이 예외 경로를
    트리거하고, 스택 트레이스를 통해 *내부 구조·DB 컬럼명·파일 경로* 등을
    얻거나 *서비스 거부(DoS)* 를 일으킵니다. KISA 가이드는 *참조 전 None
    검증*을 명시합니다.
  public_sector_impact:
    - 잘못된 요청 한 건으로 행정 서비스 워커가 5xx 응답
    - DEBUG 노출 환경에서 스택 트레이스로 내부 구조 정보 유출
    - 배치 잡이 None 으로 중단 -> 야간 정산 실패
  safe_fix: |
    *참조 전에 명시적으로 None 검사*를 하세요. KISA 가이드 안전 예시:
        filename = request.POST.get('filename')
        if filename is None or filename.strip() == "":
            return render(request, "/error.html",
                          {"error": "파일 이름이 없습니다."})

    환경 변수의 경우 *기본값을 함께* 주거나 *명시적 분기*:
        api_url = os.environ.get("API_URL", "")
        if not api_url:
            raise RuntimeError("API_URL 미설정")

    정규식 매치는 *walrus 연산자*가 깔끔합니다:
        if (m := re.match(r"(\\d+)", text)) is not None:
            num = m.group(1)

    `dict.get(key, default)` 의 *두 번째 인자*로 안전 기본값을 주면
    NoneType 예외 자체가 사라집니다.
  references:
    - KISA Python 가이드 제5절 1
    - MOIS-49-CODE-01
    - CWE-476
    - https://owasp.org/www-community/vulnerabilities/Null_Dereference
    - https://docs.python.org/3/library/constants.html#None
  can_auto_fix: false
examples:
  language: python
  positive:
    - "ext = request.POST.get('filename').count('.')"
    - "host = os.environ.get('API_HOST').strip()"
    - "num = re.match(r'(\\d+)', text).group(1)"
  negative:
    - "filename = request.POST.get('filename', '')\nif filename and filename.count('.') > 0:\n    name, ext = os.path.splitext(filename)"
    - "host = os.environ.get('API_HOST', 'localhost')"
    - "m = re.match(r'(\\d+)', text)\nif m is not None:\n    num = m.group(1)"
---

## 무엇이 위험한가
파이썬에는 C 의미의 *Null Pointer* 가 없지만, *함수의 None 반환값을 곧바로 사용*하면 동일한 위험이 생깁니다. 대표 패턴:

```python
filename = request.POST.get('filename')   # 키가 없으면 None
if filename.count('.') > 0:               # AttributeError: 'NoneType' object has no attribute 'count'
    ...
```

KISA 가이드 본문 그대로의 패턴이며, 사용자가 `filename` 필드를 누락한 단순한 POST 한 번으로 *워커 프로세스가 500 에러*를 뿜습니다. 만약 DEBUG 모드가 켜져 있으면 스택 트레이스에 모듈 경로·내부 함수명·SQL 등 *내부 구조 정보*까지 노출됩니다 (KISA-PY-ENCAP-02 · KISA-PY-ERR-01 와 결합 위험).

추가 위험 케이스:
- `os.environ.get("X").strip()` — `.env` 누락 환경에서 시작 즉시 크래시
- `re.match(p, s).group(1)` — 매치 실패 시 `AttributeError`
- 배치/ETL: `row.get("amount").replace(",", "")` — 컬럼 누락 시 야간 잡 중단

공공기관 영향:
- 단일 입력 누락으로 *전체 처리 잡* 실패 (정산·통계·통보)
- 운영 중 *DoS 트리거 한 줄* 로 악용 가능
- DEBUG 노출 시 내부 정보가 스택 트레이스로 새 나감

## 안전한 패턴 (가이드 원문 인용)
```python
import os
from django.shortcuts import render
from xml.sax import make_parser
from xml.sax.handler import feature_namespaces

def parse_xml(request):
    filename = request.POST.get('filename')

    # filename이 None 인지 체크
    if filename is None or filename.strip() == "":
        return render(request, "/error.html",
                      {"error": "파일 이름이 없습니다."})

    if filename.count('.') > 0:
        name, ext = os.path.splitext(filename)
    else:
        ext = ''

    if ext == ".xml":
        parser = make_parser()
        parser.setFeature(feature_namespaces, True)
        handler = Handler()
        parser.setContentHandler(handler)
        parser.parse(filename)
        result = handler.root
        return render(request, "/success.html", {"result": result})
```

추가 가드 패턴:
```python
# 1) dict.get 에 기본값 제공
ext = request.POST.get('ext', '')

# 2) walrus 연산자로 None 검사 + 사용
if (m := re.match(r"(\d+)", text)) is not None:
    num = m.group(1)

# 3) Pydantic / Django Form 으로 *입력 단계*에서 강제
class UploadForm(forms.Form):
    filename = forms.CharField(required=True, min_length=1)
```

## False positive 주의
- 본 룰은 `.get(...)` 직후 *메서드 호출* 이 같은 라인에 등장하는 신호만 잡습니다. 호출 결과를 변수에 *먼저 담고* None 검사 뒤에 메서드를 부르는 안전 코드는 매칭되지 않습니다.
- `mydict.get(key, default)` 처럼 두 번째 인자로 *None 이 아닌 기본값* 을 준 경우에도 패턴은 매칭됩니다 (regex 한계). 의도가 분명하면 `# gvskb: ignore KISA-PY-CODE-01` 로 억제하세요.
- `Mock` 객체나 `defaultdict` 처럼 *None 반환이 불가능한* 자료구조 위에서 호출하는 경우도 보수적으로 매칭됩니다.
- `re.fullmatch().group()` 처럼 매치 성공이 *보장되는 분기* (직전 검사 후 호출)는 라인 단위 regex 로 구분할 수 없어 매칭됩니다.
