---
id: KISA-PY-INPUT-07
title_ko: Python Open Redirect - 검증 없는 redirect/HttpResponseRedirect
title_en: Open redirect via unvalidated user-controlled URL in Python web frameworks
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Python 시큐어코딩 가이드(2023년 개정본)
    item: 제1절 7. 신뢰되지 않은 URL주소로 자동접속 연결
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-07
cwe: [CWE-601]
severity: high
decision_default: warn
domains: [kisa-secure-coding]
languages: [python]
scenarios: [web-app]
related_baseline: [MOIS-49-INPUT-07]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    - 'redirect\s*\([^)]*request\.(?:GET|POST|args|form|values|params)'
    - 'HttpResponseRedirect\s*\([^)]*request\.(?:GET|POST|args|form|values|params)'
    - 'flask\.redirect\s*\([^)]*request\.(?:args|form|values)'
    - '(?<![A-Za-z0-9_.])redirect\s*\(\s*request\.(?:GET|POST|args|form|values|params)'
  category: kisa-secure-coding
  why_it_matters: >-
    Django/Flask의 `redirect()` 또는 `HttpResponseRedirect()`에 사용자 입력
    URL을 그대로 넘기면 공격자는 정상 폼 요청을 변조해 *피싱 사이트로 우회
    접속*하도록 유도할 수 있습니다. 공공 사이트의 로그인 후 returnUrl,
    민원 처리 후 nextUrl 처리에서 자주 발견되며, 도메인 신뢰도가 높은
    공공기관일수록 피싱 공격의 발판으로 악용될 위험이 큽니다.
  public_sector_impact:
    - 공공 도메인을 발판으로 한 피싱
    - 민원인 인증정보 탈취
    - 공공 사이트 신뢰 손상
  safe_fix: |
    1) 허용 URL을 *서버측 화이트리스트*로 관리하고 in 검사 후 redirect.
    2) 가능하면 protocol/host를 포함하지 않는 *상대 경로*만 허용.
    3) 절대 URL이 필요하면 urllib.parse.urlparse로 netloc을 분해해
       서비스 도메인과 정확히 일치하는지 검증.
       from urllib.parse import urlparse
       u = urlparse(next_url)
       if u.netloc and u.netloc != "myservice.go.kr": abort(400)
  references:
    - KISA Python 가이드 제1절 7
    - MOIS-49-INPUT-07
    - CWE-601
    - OWASP Unvalidated Redirects and Forwards Cheat Sheet
  can_auto_fix: false
examples:
  language: python
  positive:
    - "from django.shortcuts import redirect\nreturn redirect(request.POST.get('url'))"
    - "from django.http import HttpResponseRedirect\nreturn HttpResponseRedirect(request.GET['next'])"
    - "from flask import redirect, request\nreturn redirect(request.args.get('next'))"
  negative:
    - "from django.shortcuts import redirect\nif url in ALLOW_URL_LIST:\n    return redirect(url)"
    - "from flask import redirect\nreturn redirect('/dashboard')"
    - "return redirect(reverse('home'))"
---

## 무엇이 위험한가
`return redirect(request.POST.get('url'))` 한 줄로 *공공 도메인을 발판으로 한 피싱*이 가능합니다. 사용자는 정상 공공 사이트(`myservice.go.kr/redirect?url=...`)를 클릭한 것으로 보이지만, 실제로는 공격자가 만든 URL로 곧장 이동합니다. AI 코딩 도우미가 "로그인 후 원래 페이지로 이동" 패턴을 만들 때 이 형태가 가장 흔히 나옵니다.

## 안전한 패턴 (가이드 원문 인용)
```python
# 1) 화이트리스트 매칭
ALLOW_URL_LIST = ["/dashboard", "/notice", "https://login.myservice.go.kr"]
if next_url not in ALLOW_URL_LIST:
    return render(request, "/error.html", {"error": "허용되지 않는 주소입니다."})
return redirect(next_url)

# 2) 상대 경로만 허용
from urllib.parse import urlparse
u = urlparse(next_url)
if u.scheme or u.netloc:
    abort(400)
return redirect(next_url)
```

## False positive 주의
- 정적 문자열, URL 역참조(`reverse('home')`), 화이트리스트로 통과된 변수 redirect는 패턴이 `request.*`를 요구하므로 매칭되지 않습니다.
- 사용자 입력을 일단 변수에 받고 검증 후 redirect하는 패턴은 별도 라인이 되어 본 룰의 단일 라인 매칭에 걸리지 않습니다 — 이는 의도된 false-negative입니다.
