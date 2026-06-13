---
id: KISA-PY-SEC-16
title_ko: Python 반복된 인증시도 제한 부재 - 로그인 함수에서 lockout/rate-limit 부재
title_en: Missing repeated authentication attempt restriction in Python login flow
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Python 시큐어코딩 가이드(2023년 개정본)
    item: 제2절 16. 반복된 인증시도 제한 기능 부재
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-16-AUTH
cwe: [CWE-307]
severity: medium
decision_default: warn
domains: [kisa-secure-coding]
languages: [python]
scenarios: [web-app]
related_baseline: [MOIS-49-SEC-16]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  # 라인 단위 regex로 "함수 전체에 lockout 카운터가 있는가" 를 판정하기는 불가능합니다.
  # 차선책으로, 로그인 처리에서 자주 등장하는 *비밀번호 비교 / authenticate 호출* 신호를
  # 잡아 사용자에게 'rate-limit / lockout 부재 여부를 직접 점검' 하라고 알리는 보수적
  # 패턴을 둡니다. negative 예시는 동일 라인에서 lockout/limiter/attempt 키워드를 함께
  # 노출시켜 패턴 회피를 보입니다.
  patterns:
    # 1) Django 스타일: hashlib.sha*().hexdigest() == stored_passwd — lockout 검사 없이 비교
    - "\\.hexdigest\\s*\\(\\s*\\)\\s*==\\s*[A-Za-z_][A-Za-z0-9_]*passwd"
    # 2) authenticate() 호출 후 같은 라인에 lockout/limiter 키워드 부재 신호
    - "(?<![A-Za-z0-9_])authenticate\\s*\\(\\s*request\\s*,"
    # 3) request.POST.get('user_pw'...) 직접 비교: == request.POST...
    - "==\\s*request\\.(?:POST|GET|form|args|json)\\.get\\s*\\(\\s*['\"](?:user_pw|password|passwd|pw)"
  category: kisa-secure-coding
  why_it_matters: >-
    Django 등 파이썬 웹 프레임워크는 인증 요청 횟수를 *자동으로 제한하지 않습니다*.
    `if sha.hexdigest() == hashed_passwd:` 한 줄만 있는 로그인 뷰는 공격자가 사전
    (Dictionary)에 있는 수백만 패스워드를 *무한 반복* 시도해도 막을 방법이 없어
    무차별 대입(brute-force)으로 계정·권한이 탈취됩니다. KISA 가이드는 최대
    인증 실패 횟수를 정하고 *초과 시 계정 잠금 또는 추가 인증*을 강제하라고 명시
    합니다. 코드 레벨 카운터 외에도 CAPTCHA, Two-Factor, django-defender,
    웹 서버 모듈(rate-limit)을 *설계 단계부터* 검토해야 합니다.
  public_sector_impact:
    - 공공 포털 계정에 대한 사전 기반 무차별 대입 공격
    - 관리자 계정 탈취로 인한 행정 데이터 변조·열람
    - 인증 로그 폭주에 따른 SIEM 가시성 저하
  safe_fix: |
    KISA 가이드 안전 예시(요약): 실패 카운터 모델을 두고 임계치를 넘으면 잠금
    페이지로 리다이렉트합니다.
        LOGIN_TRY_LIMIT = 5

        def login(request):
            user_id = request.POST.get('user_id', '')
            user_pw = request.POST.get('user_pw', '')

            sha = hashlib.sha256()
            sha.update(user_pw.encode('utf-8'))
            hashed_passwd = get_user_pw(user_id)

            # 실패 기록 조회
            if LoginFail.objects.filter(user_id=user_id).exists():
                count = LoginFail.objects.get(user_id=user_id).count
            else:
                count = 0

            if count >= LOGIN_TRY_LIMIT:
                return render(request, "/account_lock.html",
                              {"state": "account_lock"})

            if sha.hexdigest() == hashed_passwd:
                LoginFail.objects.filter(user_id=user_id).delete()
                return render(request, "/index.html",
                              {"state": "login_success"})

            LoginFail.objects.update_or_create(
                user_id=user_id,
                defaults={"count": count + 1},
            )
            return render(request, "/login.html",
                          {"state": "login_failed"})

    가능하면 django-defender / django-axes / django-ratelimit 또는 Nginx
    `limit_req` 같은 *프레임워크·서버 레이어* 보호를 함께 적용하세요. 단순
    카운터는 분산 환경에서 우회되기 쉽습니다.
  references:
    - KISA Python 가이드 제2절 16
    - MOIS-49-SEC-16
    - CWE-307
    - https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks
    - https://github.com/jazzband/django-defender
  can_auto_fix: false
examples:
  language: python
  positive:
    - "if sha.hexdigest() == hashed_passwd:\n    return render(request, '/index.html', {'state': 'login_success'})"
    - "user = authenticate(request, username=uid, password=pw)"
    - "if stored == request.POST.get('user_pw', ''):\n    login(request, user)"
  negative:
    - "if count >= LOGIN_TRY_LIMIT:\n    return render(request, '/account_lock.html', {'state': 'account_lock'})"
    - "@ratelimit(key='ip', rate='5/m', block=True)\ndef login_view(request):\n    ..."
    - "if LoginFail.objects.filter(user_id=uid).count() >= 5:\n    lockout_account(uid)"
---

## 무엇이 위험한가
파이썬 웹 프레임워크 — 특히 Django — 는 *기본적으로 로그인 시도 횟수를 제한하지 않습니다*. 다음과 같은 단순 비교 로직만 가진 로그인 뷰는 사전 공격에 그대로 노출됩니다.

```python
sha = hashlib.sha256()
sha.update(user_pw.encode('utf-8'))
hashed_passwd = get_user_pw(user_id)
if sha.hexdigest() == hashed_passwd:
    return render(request, '/index.html', {'state': 'login_success'})
```

공격자는 자동화 도구로 수만~수십만 개의 (아이디, 패스워드) 조합을 보냅니다. 운영 측에서는 *서버 응답 속도 외*에는 차단 수단이 없으며, 잠금 정책이 없으면 약한 패스워드는 분 단위로 뚫립니다.

공공기관 시나리오:
- 시민 포털 ID/주민번호 끝자리 기반 무차별 시도
- 내부 행정 포털 관리자 계정에 대한 사전 공격
- 인증 로그가 폭증해 *진짜 침해* 신호가 묻히는 SIEM 노이즈

## 안전한 패턴 (가이드 원문 인용)
```python
import hashlib
from django.shortcuts import render
from .models import LoginFail

LOGIN_TRY_LIMIT = 5

def login(request):
    user_id = request.POST.get('user_id', '')
    user_pw = request.POST.get('user_pw', '')

    sha = hashlib.sha256()
    sha.update(user_pw.encode('utf-8'))
    hashed_passwd = get_user_pw(user_id)

    # 로그인 실패 기록 가져오기
    if LoginFail.objects.filter(user_id=user_id).exists():
        login_fail = LoginFail.objects.get(user_id=user_id)
        count = login_fail.count
    else:
        count = 0

    if count >= LOGIN_TRY_LIMIT:
        # 로그인 실패횟수 초과 -> 잠금 페이지
        return render(request, "/account_lock.html",
                      {"state": "account_lock"})

    if sha.hexdigest() == hashed_passwd:
        # 로그인 성공 시 실패 횟수 삭제
        LoginFail.objects.filter(user_id=user_id).delete()
        return render(request, "/index.html",
                      {"state": "login_success"})

    # 실패 기록 갱신 (없으면 insert, 있으면 update)
    LoginFail.objects.update_or_create(
        user_id=user_id,
        defaults={"count": count + 1},
    )
    return render(request, "/login.html",
                  {"state": "login_failed"})
```

설계 단계 권장:
- CAPTCHA, Two-Factor 인증을 *설계 초반*에 결정 (사후 끼워 넣기 어려움)
- `django-defender` / `django-axes` / `django-ratelimit` 적용
- Nginx `limit_req_zone`, Cloudflare Bot Management 등 *프록시 레이어* 차단

## False positive 주의
- 라인 단위 regex 로는 *함수 전체에 lockout 카운터가 있는지* 판정이 불가능합니다. 본 룰은 `sha.hexdigest() == ..._passwd` / `authenticate(request, ...)` / `== request.POST.get('user_pw'...)` 처럼 *비밀번호 비교가 직접 일어나는 신호*만 잡고, 같은 함수 다른 라인에 있는 잠금 검사는 인지하지 못합니다. 의도된 보수적 detection 입니다.
- 잠금 카운터를 *별도 미들웨어/데코레이터*로 분리한 경우에도 본 룰은 매칭됩니다. 명백히 안전하면 `# gvskb: ignore KISA-PY-SEC-16` 으로 억제하고, 미들웨어 위치를 코드 주석으로 남기는 것을 권장합니다.
- 단위 테스트의 `assert sha.hexdigest() == expected_hash` 같은 *테스트 코드*도 패턴 #1에 걸릴 수 있습니다. 테스트 디렉터리는 `gvskb evaluate` 의 exclude 로 제외하세요.
