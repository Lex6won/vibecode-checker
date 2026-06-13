---
id: KISA-PY-INPUT-16
title_ko: Python 포맷 스트링 삽입 - 사용자 입력을 str.format / % 포맷 문자열로 직접 사용
title_en: Format string injection via user-controlled format template in Python (str.format / %)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Python 시큐어코딩 가이드(2023년 개정본)
    item: 제1절 16. 포맷 스트링 삽입
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-16-FORMAT-STRING
cwe: [CWE-134]
severity: high
decision_default: warn
domains: [kisa-secure-coding]
languages: [python]
scenarios: [web-app, llm-integration, batch-job]
related_baseline: [MOIS-49-INPUT-16]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    # 1) request.* 값을 변수로 받은 뒤 같은 줄에서 .format(...) 호출
    - "request\\.(?:GET|POST|args|form|values|params|json)[^\\n]{0,80}\\.format\\s*\\("
    # 2) <var>.format(<object>=<obj>) 또는 .format_map( ... )에 request.* 직접
    - "(?<![A-Za-z0-9_.])\\.format\\s*\\(\\s*[^)]*=[^)]*request\\.(?:GET|POST|args|form|values|params|json)"
    - "(?<![A-Za-z0-9_.])\\.format_map\\s*\\(\\s*request\\.(?:GET|POST|args|form|values|params|json)"
    # 3) % 포맷팅: "...%s..." % request.*  (포맷 문자열은 정적이지만 reverse 패턴도 위험)
    - "request\\.(?:GET|POST|args|form|values|params|json)[^\\n]{0,80}\\s*%\\s*\\("
    # 4) Template(request.*).substitute / safe_substitute
    - "(?<![A-Za-z0-9_.])Template\\s*\\(\\s*request\\.(?:GET|POST|args|form|values|params|json)"
  category: kisa-secure-coding
  why_it_matters: >-
    `request.POST.get('msg_format', '').format(user=user_info)` 처럼 사용자가
    제어하는 *템플릿 문자열*에 `.format()`을 호출하면 공격자가
    `{user.__init__.__globals__[SECRET_KEY]}` 같은 식으로 *전역 변수·내부
    객체 속성*에 접근할 수 있습니다. Django `SECRET_KEY`, DB 연결 문자열,
    JWT 서명키가 그대로 응답에 포함될 수 있고, `str.format`은 `__class__`
    체인을 통해 *임의 객체 그래프 순회*까지 허용합니다. KISA 가이드 본문은
    "사용자가 입력한 문자열을 포맷 문자열로 사용하면 안 된다"고 명시합니다.
  public_sector_impact:
    - SECRET_KEY / DB 패스워드 / 토큰 서명키 유출
    - 사용자 PII / 세션 객체 노출
    - LLM 프롬프트 템플릿을 통한 시스템 프롬프트·키 탈취
  safe_fix: |
    포맷 문자열은 *반드시 코드에 정적으로* 두고 사용자 값은 *인수*로만
    바인딩하세요.
        # 안전: 포맷 문자열은 정적
        message = 'user name is {}'.format(user_info.name)
        message = f'user name is {user_info.name}'   # f-string은 컴파일 타임
        # 위험: 사용자 입력이 포맷 템플릿
        # bad = request.POST['fmt'].format(user=user_info)
    꼭 사용자가 템플릿을 골라야 한다면 *허용 목록*에서 키로 선택:
        TEMPLATES = {'short': '안녕하세요 {name}님', 'long': '...{name}...'}
        key = request.POST.get('tpl', 'short')
        if key not in TEMPLATES: abort(400)
        message = TEMPLATES[key].format(name=safe_name)
    LLM 프롬프트도 같은 원리 — 사용자 입력은 *데이터*로 넘기고 시스템
    프롬프트는 코드에 정적으로 두세요.
  references:
    - KISA Python 가이드 제1절 16
    - MOIS-49-INPUT-16
    - CWE-134
    - https://docs.python.org/3/library/string.html#format-string-syntax
    - https://lucumr.pocoo.org/2016/12/29/careful-with-str-format/
  can_auto_fix: false
examples:
  language: python
  positive:
    - "message = request.POST.get('msg_format', '').format(user=user_info)"
    - "render = request.args['template'].format(user=current_user)"
    - "msg = request.POST['t'] % (user.id, user.email)"
  negative:
    - "message = 'user name is {}'.format(user_info.name)"
    - "message = f'hello {user.name}'"
    - "message = TEMPLATES['greeting'].format(name=user.name)"
---

## 무엇이 위험한가
`str.format`은 *포맷 문자열 안에서* 객체의 속성·아이템에 접근할 수 있는 *작은 표현식 언어*입니다. 사용자가 템플릿을 통제하면:

```python
# 공격자 입력: "{user.__init__.__globals__[SECRET_KEY]}"
request.POST['fmt'].format(user=user_info)
# → Django SECRET_KEY가 응답에 그대로 출력
```

이렇게 `__class__`, `__init__`, `__globals__`, `__mro__` 체인을 따라 *임의 객체 그래프*를 순회할 수 있어 JWT 서명키, DB 패스워드, 다른 사용자 세션까지 도달할 수 있습니다. `str.format_map`, `string.Template.substitute`도 같은 위험이 있습니다.

LLM 통합 코드에서도 같은 패턴이 반복됩니다 — 사용자 입력을 *프롬프트 템플릿 자체*로 받으면 시스템 프롬프트가 누출됩니다.

## 안전한 패턴 (가이드 원문 인용)
```python
# 가이드 안전 예시: 포맷 문자열은 코드에 정적으로
def make_user_message(request):
    user_info = get_user_info(request.POST.get('user_id', ''))
    message = 'user name is {}'.format(user_info.name)   # 정적 템플릿
    return render(request, '/user_page.html', {'message': message})

# 더 안전: f-string (컴파일 타임에 결정)
message = f'안녕하세요 {user_info.name}님'

# 사용자가 템플릿을 선택해야 한다면 화이트리스트
TEMPLATES = {
    'short': '{name}님, 환영합니다',
    'long':  '{name}님, 오늘도 좋은 하루 되세요',
}
key = request.POST.get('tpl', 'short')
if key not in TEMPLATES:
    return HttpResponseBadRequest()
message = TEMPLATES[key].format(name=user_info.name)
```

## False positive 주의
- 본 룰은 *같은 라인 또는 직전 라인의 변수 흐름* (`request.* → .format()`) 만 잡습니다. 사용자 입력을 *별도 함수*에서 검증한 후 다음 라인에서 `.format()`을 호출하는 경우는 매칭되지 않습니다 — 단일 라인 검출의 한계.
- 정적 포맷 문자열에 사용자 *값*을 인수로 바인딩하는 정상 패턴(`'hi {}'.format(name)`)은 패턴이 `request.*`를 같은 라인에 요구하므로 매칭되지 않습니다.
- f-string은 컴파일 타임에 결정되므로 본 룰 범위 밖입니다 (별도로 SQL/HTML 인젝션 룰이 잡습니다).
- `logging.getLogger().info("user %s", user)` 같은 로깅의 lazy formatting은 패턴이 `.format(` / `%` 와 같은 라인 `request.*`를 요구하므로 매칭되지 않습니다.
