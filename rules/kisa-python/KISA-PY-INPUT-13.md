---
id: KISA-PY-INPUT-13
title_ko: Python HTTP 응답분할 - 응답 헤더/쿠키에 사용자 입력을 CR/LF 필터링 없이 삽입
title_en: HTTP response splitting via unsanitized CR/LF in Python response headers/cookies
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Python 시큐어코딩 가이드(2023년 개정본)
    item: 제1절 13. HTTP 응답분할
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-13-HTTP-RESP-SPLIT
cwe: [CWE-113, CWE-93]
severity: high
decision_default: warn
domains: [kisa-secure-coding]
languages: [python]
scenarios: [web-app]
related_baseline: [MOIS-49-INPUT-13]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    # 1) Django HttpResponse/HttpResponseRedirect 에 request.* 값을 직접 전달
    - "HttpResponseRedirect\\s*\\(\\s*request\\.(?:GET|POST|args|form|values|params|json|META)"
    # 2) response['Header'] = request.* (헤더 인젝션)
    - "(?<![A-Za-z0-9_])(?:res|resp|response)\\s*\\[\\s*['\"][A-Za-z0-9_-]+['\"]\\s*\\]\\s*=\\s*request\\.(?:GET|POST|args|form|values|params|json|META|COOKIE|COOKIES)"
    # 3) set_cookie / set_header 에 request.* 값을 직접 전달
    - "\\.(?:set_cookie|set_header|setHeader|add_header|headers\\.add|headers\\.set)\\s*\\(\\s*[^)]*request\\.(?:GET|POST|args|form|values|params|json|META|COOKIE|COOKIES)"
    # 4) Flask make_response / Response 의 headers 딕셔너리에 사용자 값
    - "Response\\s*\\([^)]*headers\\s*=\\s*\\{[^}]*request\\.(?:args|form|values|json|cookies)"
    # 5) Flask redirect(request.args[...])
    - "(?<![A-Za-z0-9_.])redirect\\s*\\(\\s*request\\.(?:args|form|values|json)"
  category: kisa-secure-coding
  why_it_matters: >-
    사용자 입력값이 응답 헤더나 `Set-Cookie`, `Location`에 그대로 들어가면
    공격자가 입력값에 `\r\n`(CRLF)을 끼워 *응답을 두 개로 쪼개*고 두 번째
    응답에 임의 HTML/스크립트를 주입할 수 있습니다. 결과: 캐시 포이즈닝,
    세션 고정(session fixation), 저장형 XSS. 공공포털처럼 *프록시·CDN이
    앞단에 있는* 환경에서는 캐시 한 번 오염되면 *모든 시민에게 동일 페이지*가
    배포되어 파급이 큽니다. KISA Python 가이드는 `\r`/`\n` 치환 또는
    화이트리스트 검증을 명시합니다.
  public_sector_impact:
    - 공공포털 캐시 포이즈닝으로 위변조 페이지 대량 배포
    - Set-Cookie 인젝션을 통한 세션 고정 공격
    - 민원 알림/리다이렉트 URL을 통한 피싱 페이지 유도
  safe_fix: |
    응답 헤더·쿠키·Location에 외부 입력값을 넣기 전 *반드시* CR/LF를 제거
    하거나 화이트리스트 검증을 수행하세요.
        # 1) CR/LF 치환 (가이드 권장)
        content_type = content_type.replace('\r', '').replace('\n', '')
        res['Content-Type'] = content_type
        # 2) 화이트리스트
        ALLOWED_CT = {'application/json', 'text/plain', 'text/csv'}
        if content_type not in ALLOWED_CT:
            return HttpResponseBadRequest()
        # 3) 리다이렉트는 상대경로 또는 화이트리스트 도메인만 허용
        if not next_url.startswith('/'):
            return HttpResponseBadRequest()
        return redirect(next_url)
    Django 2.0+ / Flask 2.0+ 의 기본 응답 클래스는 헤더 값에 `\n`이 있으면
    `BadHeaderError`를 발생시키지만, 직접 `replace`로 우회되거나 구버전에서는
    여전히 위험합니다.
  references:
    - KISA Python 가이드 제1절 13
    - MOIS-49-INPUT-13
    - CWE-113, CWE-93
    - OWASP HTTP Response Splitting
    - https://docs.djangoproject.com/en/stable/topics/security/#header-injection
  can_auto_fix: false
examples:
  language: python
  positive:
    - "res = HttpResponse()\nres['Content-Type'] = request.POST.get('content-type')"
    - "from flask import redirect, request\nreturn redirect(request.args['next'])"
    - "response.set_cookie('lang', request.GET['lang'])"
  negative:
    - "ct = request.POST.get('content-type', '').replace('\\r', '').replace('\\n', '')\nres['Content-Type'] = ct"
    - "ALLOWED = {'application/json', 'text/plain'}\nif ct in ALLOWED:\n    res['Content-Type'] = ct"
    - "return redirect('/dashboard')"
---

## 무엇이 위험한가
HTTP 응답분할(Response Splitting)은 *헤더 자리에 사용자 입력을 그대로 넣을 때* 발생합니다. 공격자가 `text/plain\r\n\r\n<script>...` 같은 값을 보내면 서버는 의도된 응답을 끝내고 *공격자가 만든 두 번째 응답*을 이어 보냅니다. 프록시·CDN 캐시는 이 두 번째 응답을 별도 URL의 응답으로 저장할 수 있어 *모든 시민*에게 위변조 페이지가 배포됩니다.

전형적인 공격 벡터:
- `response['Content-Type'] = request.POST['ct']` — 헤더 인젝션
- `set_cookie('lang', request.args['lang'])` — Set-Cookie 인젝션 → 세션 고정
- `redirect(request.args['next'])` — Open Redirect + Location 헤더 인젝션 (피싱)

## 안전한 패턴 (가이드 원문 인용)
```python
# 가이드 권장: CR/LF 제거
def route(request):
    content_type = request.POST.get('content-type', '')
    content_type = content_type.replace('\r', '').replace('\n', '')
    res = HttpResponse()
    res['Content-Type'] = content_type
    return res

# 더 안전: 화이트리스트
ALLOWED_CT = {'application/json', 'text/plain', 'text/csv'}
if content_type not in ALLOWED_CT:
    return HttpResponseBadRequest('invalid content-type')

# 리다이렉트: 상대 경로 또는 허용 도메인만
def safe_redirect(request):
    next_url = request.GET.get('next', '/')
    if not next_url.startswith('/') or next_url.startswith('//'):
        next_url = '/'
    return redirect(next_url)
```

## False positive 주의
- 정적 문자열, 검증·치환된 값, 화이트리스트 분기 후의 호출은 패턴이 `request.*` 토큰을 같은 라인에 요구하므로 매칭되지 않습니다.
- Django 2.0+ 는 `BadHeaderError`로 일부 패턴을 막지만, 개발자가 `replace`로 우회하거나 *구버전 + 직접 헤더 조립* 시 여전히 취약합니다. 본 룰은 *입력 → 헤더* 흐름 자체를 신호로 봅니다.
- 같은 라인에 검증 로직이 없는 한 redirect/set_cookie는 매칭됩니다. 검증을 *별도 라인*에서 수행했다면 의도된 false-positive이며 `# gvskb: ignore KISA-PY-INPUT-13`로 억제하세요.
