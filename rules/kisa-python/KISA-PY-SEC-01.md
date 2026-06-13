---
id: KISA-PY-SEC-01
title_ko: Python 적절한 인증 없는 중요 기능 허용 - 패스워드 변경·재설정·관리자 액션의 재인증 누락
title_en: Missing authentication for critical function in Python (no re-auth on password change / admin actions)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Python 시큐어코딩 가이드(2023년 개정본)
    item: 제2절 1. 적절한 인증 없는 중요 기능 허용
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-21-AUTH
cwe: [CWE-306, CWE-287]
severity: high
decision_default: block
domains: [kisa-secure-coding]
languages: [python]
scenarios: [web-app, auth]
related_baseline: [MOIS-49-SEC-01]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    # 1) Django/Flask 패스워드 변경 함수가 current_password 검증 없이 새 패스워드만 받아 저장
    - "(?i)def\\s+(?:change_password|reset_password|update_password|set_password|change_pwd|reset_pwd)\\s*\\(\\s*request"
    # 2) request 에서 new_password 만 받고 같은 함수 안에서 곧바로 update_password_from_db / save 호출 (current_password 검증 신호 없음)
    - "(?i)request\\.(?:POST|GET|form|args|json)\\.get\\s*\\(\\s*['\"]new_password['\"]"
    # 3) 관리자/탈퇴/송금 등 민감 기능을 단순 함수로 노출 (login_required 데코레이터 없는 신호는 라인 단위로 어렵지만 함수명만으로 잡음)
    - "(?i)def\\s+(?:delete_account|withdraw|transfer_money|grant_admin|revoke_user|impersonate|sudo_as|admin_action|force_login)\\s*\\(\\s*request"
    # 4) hashlib 으로 곧바로 패스워드 저장 — 재인증·기존 해시 비교 없는 신호
    - "(?i)hashlib\\.sha\\d+\\s*\\(\\s*new_pwd"
  category: kisa-secure-coding
  why_it_matters: >-
    KISA 가이드 안전하지 않은 예시는 패스워드 변경 함수가 *현재 패스워드 확인 없이*
    새 패스워드만 받아 그대로 DB 를 덮어쓰는 코드입니다. 공격자가 세션 쿠키만
    탈취하면(XSS, 카페 PC 등) *기존 패스워드를 모르고도* 계정을 영구 장악합니다.
    가이드 안전 예시는 (1) `@login_required` 데코레이터, (2) `current_password`
    파라미터 추가, (3) DB 해시와 비교한 *재인증* 통과 시에만 변경하도록 합니다.
    탈퇴·송금·관리자 권한 부여 같은 *중요 기능* 도 동일한 재인증을 요구해야 합니다.
  public_sector_impact:
    - 세션 탈취만으로 시민 계정 패스워드 변경 → 영구 탈취
    - 결재 시스템의 권한 부여 액션이 재인증 없이 노출되어 권한 상승
    - 행정 포털의 회원 탈퇴 API 가 재인증 없이 호출되어 대량 계정 손실
  safe_fix: |
    중요 기능에는 *세 단계* 보호를 모두 적용하세요.
        1) @login_required (또는 프레임워크 동등물) 로 인증 강제
        2) 함수 본문에서 current_password 입력값 + DB 해시 *재인증*
        3) 변경 후 활성 세션 무효화 (Django: update_session_auth_hash)

        from django.contrib.auth.decorators import login_required
        from django.contrib.auth.hashers import check_password, make_password
        from django.contrib.auth import update_session_auth_hash

        @login_required
        def change_password(request):
            new_pwd  = request.POST.get('new_password', '')
            crnt_pwd = request.POST.get('current_password', '')
            user = request.user
            # 재인증: 기존 해시와 비교
            if not check_password(crnt_pwd, user.password):
                return render(request, 'failed.html',
                              {'error': '패스워드가 일치하지 않습니다'})
            user.password = make_password(new_pwd)
            user.save()
            update_session_auth_hash(request, user)
            return render(request, '/success.html')
  references:
    - KISA Python 가이드 제2절 1
    - MOIS-49-SEC-01
    - CWE-306, CWE-287
    - OWASP Authentication Cheat Sheet
    - https://docs.djangoproject.com/en/stable/topics/auth/default/
  can_auto_fix: false
examples:
  language: python
  positive:
    - "def change_password(request):\n    new_pwd = request.POST.get('new_password','')\n    sha = hashlib.sha256(new_pwd.encode())"
    - "def reset_password(request): ..."
    - "new_pwd = request.POST.get('new_password', '')"
    - "def delete_account(request): user.delete()"
  negative:
    - "if check_password(crnt_pwd, request.user.password): user.set_password(new_password); user.save()"
    - "def view_profile(request): return render(request, 'profile.html')"
    - "current = request.POST.get('current_password', '')\nif check_password(current, request.user.password): user.save()"
---

## 무엇이 위험한가
"중요 기능(critical function)" 은 *수행 결과가 보안 경계를 넘는* 모든 동작을 말합니다 — 패스워드 변경·재설정, 계정 탈퇴, 권한 부여/회수, 송금, 결재 승인, 관리자 사칭(impersonate) 등이 대표적입니다. 이 기능들은 *최소 두 단계 인증* 을 거쳐야 합니다.

1. **세션 인증 (현재 로그인 사용자 확인)** — 데코레이터/미들웨어로 강제
2. **재인증 (current password 또는 OTP 재입력)** — 함수 본문에서 명시적으로 검증

KISA 가이드 안전하지 않은 예시는 *두 단계 모두 누락* 했습니다:
```python
def change_password(request):
    new_pwd = request.POST.get('new_password', '')
    user = '%s' % escape(request.session['userid'])
    sha = hashlib.sha256(new_pwd.encode())
    update_password_from_db(user, sha.hexdigest())  # 현재 패스워드 확인 없음
    return render(request, '/success.html')
```
공격자가 세션 쿠키만 탈취해도 (XSS, 공용 PC, 세션 고정) *원래 패스워드를 모르고도* 계정을 영구 장악합니다. 그리고 `update_password_from_db` 후 세션 무효화도 없어서 *기존 세션이 그대로 살아남습니다*.

공공기관 사례:
- 시민 포털 패스워드 변경 API 가 재인증 없이 노출 → 카페 PC 에 남은 세션으로 타인이 패스워드 변경
- 행정 결재 시스템의 *결재 위임* 기능이 단순 POST 로 호출 가능 → 권한 상승
- 회원 *탈퇴* API 가 재인증 없이 호출 가능 → 봇이 활성 사용자 대량 탈퇴 유발

## 안전한 패턴 (가이드 원문 인용)
```python
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from re import escape
import hashlib

# login_required decorator를 사용해 login된 사용자만 접근하도록 처리
@login_required
def change_password(request):
    new_pwd  = request.POST.get('new_password', '')
    crnt_pwd = request.POST.get('current_password', '')

    # 로그인한 사용자 정보를 세션에서 가져온다.
    user = '%s' % escape(request.session['userid'])

    crnt_h = hashlib.sha256(crnt_pwd.encode())
    h_pwd  = crnt_h.hexdigest()

    # DB에서 기존 사용자의 Hash된 패스워드 가져오기
    old_pwd = get_password_from_db(user)

    # 패스워드를 변경하기 전 사용자에 대한 재인증을 수행한다.
    if old_pwd == h_pwd:
        new_h = hashlib.sha256(new_pwd.encode())
        update_password_from_db(user, new_h.hexdigest())
        return render(request, '/success.html')
    else:
        return render(request, 'failed.html',
                      {'error': '패스워드가 일치하지 않습니다'})
```

현대 Django 권장 (해시 알고리즘 + 세션 무효화 포함):
```python
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth import update_session_auth_hash

@login_required
def change_password(request):
    crnt_pwd = request.POST.get('current_password', '')
    new_pwd  = request.POST.get('new_password', '')
    user = request.user
    if not check_password(crnt_pwd, user.password):
        return render(request, 'failed.html',
                      {'error': '패스워드가 일치하지 않습니다'})
    user.password = make_password(new_pwd)
    user.save()
    update_session_auth_hash(request, user)   # 변경 후 다른 세션 무효화
    return render(request, '/success.html')
```

## False positive 주의
- 본 룰은 함수명(`change_password`, `reset_password`, `delete_account` 등)과 `request` 파라미터 조합으로 *중요 기능 함수의 정의 자체* 를 잡습니다. 해당 함수가 *별도 라인의 `@login_required` 데코레이터로 인증을 강제하고, 본문 어딘가에서 current_password 를 검증* 하는 경우에도 본 룰은 함수 선언 라인을 매칭합니다. 의도된 보수적 detection 입니다 — 검증이 명시되어 있다면 `# gvskb: ignore KISA-PY-SEC-01` 로 억제하세요.
- 단순 *조회용* 뷰(`view_profile`, `get_user_info`) 는 함수명에 포함되지 않아 매칭되지 않습니다 (negative 예시 #3).
- `current_password` 또는 `check_password(`, `password_validators` 호출이 같은 파일에 명시되어 있다면 운영상 안전한 코드일 가능성이 높습니다 — 코드 리뷰로 확인 후 ignore 처리하세요.
- 관리자 명령 스크립트(`manage.py`, `cli.py`) 는 HTTP request 컨텍스트가 없어 패턴이 매칭되지 않습니다.
