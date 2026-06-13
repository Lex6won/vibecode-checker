---
id: KISA-PY-SEC-12
title_ko: Python 안전하지 않은 쿠키 설정 (httponly=False / secure=False / 과도한 max_age)
title_en: Insecure cookie settings in Python web frameworks (httponly/secure/max_age)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Python 시큐어코딩 가이드(2023년 개정본)
    item: 제2절 12. 사용자 하드디스크에 저장되는 쿠키를 통한 정보 노출
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-44
cwe: [CWE-539, CWE-614, CWE-1004]
severity: medium
decision_default: warn
domains: [kisa-secure-coding]
languages: [python]
scenarios: [web-app, auth]
related_baseline: [MOIS-49-SEC-12]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    - "\\.set_cookie\\s*\\([^)]*httponly\\s*=\\s*False"
    - "\\.set_cookie\\s*\\([^)]*secure\\s*=\\s*False"
    - "\\.set_cookie\\s*\\([^)]*max_age\\s*=\\s*(?:60\\s*\\*\\s*60\\s*\\*\\s*24\\s*\\*\\s*(?:30|60|90|180|365)|2592000|5184000|7776000|15552000|31536000)\\b"
    - "(?i)SESSION_COOKIE_SECURE\\s*=\\s*False"
    - "(?i)SESSION_COOKIE_HTTPONLY\\s*=\\s*False"
    - "(?i)CSRF_COOKIE_SECURE\\s*=\\s*False"
    - "(?i)CSRF_COOKIE_HTTPONLY\\s*=\\s*False"
    - "app\\.config\\[\\s*['\"]SESSION_COOKIE_SECURE['\"]\\s*\\]\\s*=\\s*False"
    - "app\\.config\\[\\s*['\"]SESSION_COOKIE_HTTPONLY['\"]\\s*\\]\\s*=\\s*False"
  category: kisa-secure-coding
  why_it_matters: >-
    `secure=False` 쿠키는 평문 HTTP로도 전송돼 패킷 캡처에 노출되고,
    `httponly=False` 쿠키는 XSS 스크립트가 `document.cookie`로 읽어 갈 수
    있습니다. `max_age`를 1년처럼 길게 잡으면 사용자 PC가 탈취당했을 때
    공격 창이 그만큼 늘어납니다. Django/Flask 모두 기본값이 *불안전*(False)
    이라 명시적으로 켜야 합니다. 공공기관 로그인 세션·CSRF 토큰 쿠키에서
    가장 흔히 발견되는 약점입니다.
  public_sector_impact:
    - 세션 탈취 후 행정 시스템 무단 사용
    - XSS와 결합한 인증 쿠키 유출
    - 공용 PC 환경(민원실·도서관)에서 장기 세션 도용
  safe_fix: |
    Django settings.py:
        SESSION_COOKIE_SECURE = True
        SESSION_COOKIE_HTTPONLY = True
        SESSION_COOKIE_SAMESITE = "Lax"   # 또는 "Strict"
        SESSION_COOKIE_AGE = 60 * 60      # 1시간 권장
        CSRF_COOKIE_SECURE = True
        CSRF_COOKIE_HTTPONLY = True
    Flask:
        app.config.update(
            SESSION_COOKIE_SECURE=True,
            SESSION_COOKIE_HTTPONLY=True,
            SESSION_COOKIE_SAMESITE="Lax",
        )
    응답 단위:
        res.set_cookie("k", v, max_age=3600, secure=True, httponly=True, samesite="Lax")
  references:
    - KISA Python 가이드 제2절 12
    - MOIS-49-SEC-12
    - CWE-539, CWE-614, CWE-1004
    - OWASP Session Management Cheat Sheet
    - https://docs.djangoproject.com/en/stable/topics/security/#ssl-https
  can_auto_fix: false
examples:
  language: python
  positive:
    - "res.set_cookie('rememberme', 1, max_age=60*60*24*365)"
    - "res.set_cookie('sess', token, secure=False, httponly=True)"
    - "SESSION_COOKIE_SECURE = False"
  negative:
    - "res.set_cookie('rememberme', 1, max_age=60*60, secure=True, httponly=True)"
    - "SESSION_COOKIE_SECURE = True\nSESSION_COOKIE_HTTPONLY = True"
    - "app.config.update(SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True)"
---

## 무엇이 위험한가
쿠키 보안 속성 누락은 *단독으로는 RCE가 아니지만 모든 인증 우회 사고의 조연*입니다.
- `secure=False`: HTTP 요청에 쿠키가 그대로 실려 평문으로 흘러갑니다.
- `httponly=False`: XSS 1줄로 세션이 통째로 털립니다.
- `max_age` 1년 = 사용자가 카페·민원실에서 단 한 번만 자기 계정에 로그인해도 그 PC를 다음 사용자가 *1년간* 들고 다닐 수 있습니다.

Django/Flask 모두 보안 속성이 기본 False이므로 *명시적으로 활성화*가 필수입니다.

## 안전한 패턴 (가이드 원문 인용)
```python
# Django (settings.py)
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_AGE = 60 * 60          # 1시간
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True

# Flask
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=3600,
)

# 응답 단위 직접 설정
res.set_cookie(
    "rememberme", 1,
    max_age=60 * 60,
    secure=True,
    httponly=True,
    samesite="Lax",
)
```

## False positive 주의
- `max_age` 패턴은 `60*60*24*30`(30일) 이상과 잘 알려진 초 단위(2592000=30일, 31536000=1년)만 잡습니다. 일주일(7일) 이하는 매칭하지 않습니다. 업무 정책상 더 짧게 설정해야 한다면 코드 리뷰로 확인하세요.
- *비로그인 사용자 환경 설정*(테마, 언어 등)을 담는 쿠키는 보안 영향이 없지만 패턴은 그것을 구분하지 못합니다. 의도적이라면 `# gvskb: ignore KISA-PY-SEC-12`로 억제하세요.
- `SAMESITE` 누락은 본 룰에서 잡지 않습니다(권장하지만 가이드 원문 항목이 아님). 별도 룰로 다루는 것을 고려하세요.
