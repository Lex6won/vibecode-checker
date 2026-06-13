---
id: KISA-PY-SEC-09
title_ko: Python 취약한 패스워드 허용 - 복잡도·길이 검증 없는 회원가입/변경
title_en: Weak password acceptance in Python (no complexity or length check)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Python 시큐어코딩 가이드(2023년 개정본)
    item: 제2절 9. 취약한 패스워드 허용
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-49
cwe: [CWE-521]
severity: medium
decision_default: warn
domains: [kisa-secure-coding]
languages: [python]
scenarios: [web-app, auth]
related_baseline: [MOIS-49-SEC-09]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    # 1) Django/Flask: 모델/객체.password 에 request.* 값을 *직접* 대입 (검증 함수 미경유)
    - "\\.(?:password|passwd|pwd|비밀번호|암호)\\s*=\\s*request\\.(?:POST|GET|form|args|values|json)"
    # 2) User(...) / User.objects.create(...) 생성자 인자로 검증되지 않은 request.* 비밀번호 전달
    - "User(?:\\.objects\\.create|\\.objects\\.create_user)?\\s*\\([^)]*password\\s*=\\s*request\\.(?:POST|GET|form|args|values|json)"
    # 3) 너무 짧은 길이 정책 (8자 미만을 허용): len(password) >= 1~7
    - "len\\s*\\(\\s*(?:password|passwd|pwd|비밀번호|암호)\\s*\\)\\s*>=?\\s*[1-7]\\b"
    # 4) 너무 짧은 길이 정책 (대칭): if len(password) < 4: ...  (4 이하 거부, 즉 5자 허용)
    - "len\\s*\\(\\s*(?:password|passwd|pwd|비밀번호|암호)\\s*\\)\\s*<\\s*[1-5]\\b"
    # 5) 숫자/문자 단일 종류만 검사 — isdigit()/isalpha() 만으로 정책 통과
    - "(?:password|passwd|pwd)\\.isdigit\\s*\\(\\s*\\)"
  category: kisa-secure-coding
  why_it_matters: >-
    `usertable.password = request.form.get('password')` 직후 `db.session.commit()`
    하는 한 줄짜리 회원가입 뷰는 *어떤 문자열도* 비밀번호로 받아들입니다.
    KISA 가이드는 길이 10자 이상 또는 *영문 대·소문자/숫자/특수문자 중 3종 이상
    조합 8자 이상* 정규식 검증을 안전 예시로 제시합니다. 또한
    `len(password) >= 4` 같은 *너무 약한 길이 정책*은 brute-force 사전 공격에
    수 초 안에 뚫립니다. 공공 민원·결재 시스템은 「패스워드 선택 및 이용 안내서」
    및 행정안전부 보안 지침의 비밀번호 정책을 *기술적으로 강제*해야 합니다.
  public_sector_impact:
    - 시민 계정 사전·brute-force 공격으로 대량 탈취
    - 행정 내부망 사용자 계정 탈취 후 권한 상승
    - 개인정보보호법 제29조 안전성 확보 조치 위반 (비밀번호 작성 규칙)
  safe_fix: |
    Django는 settings.py의 AUTH_PASSWORD_VALIDATORS에 MinimumLengthValidator,
    CommonPasswordValidator, NumericPasswordValidator 및 기관 정책에 맞는
    CustomValidator를 등록하세요.
        AUTH_PASSWORD_VALIDATORS = [
          {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
           'OPTIONS': {'min_length': 10}},
          {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
          {'NAME': 'myapp.validators.AgencyComplexityValidator'},
        ]
    Flask는 가입 처리 전 KISA 가이드의 정규식 7종(3조합 8자 이상 또는
    10자 이상)을 적용:
        import re
        PATTERNS = [re.compile(p) for p in [
            r'^(?=.*[A-Z])(?=.*[a-z])[A-Za-z\d!@#$%^&*]{8,}$',
            # ... PT2 ~ PT6 ...
            r'^[A-Za-z\d!@#$%^&*]{10,}$',
        ]]
        def is_strong(pw): return any(p.match(pw) for p in PATTERNS)
        if not is_strong(password):
            return make_response("패스워드 조합규칙에 맞지 않습니다.", 400)
    저장 직전에 반드시 bcrypt/argon2 KDF로 해시하여 평문 저장을 금지하세요
    (KISA-PY-SEC-14 참고).
  references:
    - KISA Python 가이드 제2절 9
    - MOIS-49-SEC-09
    - CWE-521 Weak Password Requirements
    - OWASP Authentication Cheat Sheet
    - 한국인터넷진흥원 「패스워드 선택 및 이용 안내서」
    - https://docs.djangoproject.com/en/stable/topics/auth/passwords/
  can_auto_fix: false
examples:
  language: python
  positive:
    - "usertable.password = request.form.get('password')"
    - "User.objects.create(username=uid, password=request.POST['password'])"
    - "if len(password) >= 4: register(password)"
    - "if len(password) < 4: return error"
    - "if password.isdigit(): allow()"
  negative:
    - "if not is_strong(password): return error\nuser.password = bcrypt.hash(password)"
    - "if len(password) >= 10 and any(c.isupper() for c in password): save(password)"
    - "user.set_password(password)  # Django: 내장 validator 통과"
    - "validate_password(password)\nuser.password = bcrypt.hash(password)"
---

## 무엇이 위험한가
취약한 패스워드 허용은 인증 시스템 *전체의 강도*를 결정하는 가장 단순한 약점입니다. KISA Python 가이드의 안전하지 않은 예시는 회원가입 뷰가 `request.form.get('password')` 값을 *복잡도 검사 없이* 그대로 `usertable.password`에 대입하고 `db.session.commit()` 합니다. 이 뷰는 한 글자 비밀번호도, 사용자 ID와 똑같은 비밀번호도 그대로 통과시킵니다.

KISA 가이드 안전 예시의 정규식은 두 가지 정책을 동시에 만족시킵니다:
1. *3종 이상 조합 + 8자 이상* (PT1~PT6)
2. *문자 종류 무관 10자 이상* (PT7)

또한 `len(password) >= 4` 같은 *명백히 약한 길이 정책*도 동일하게 위험합니다. 사전 공격 + GPU brute-force는 4~6자리 영숫자 조합을 *초 단위*로 전수합니다. 공공 민원·결재 시스템은 「패스워드 선택 및 이용 안내서」와 행안부 보안 지침을 *기술적으로 강제*해야 합니다. 정책을 운영 안내문에만 적어두고 코드가 검증하지 않으면 통제가 없는 것과 같습니다.

복잡도 검증과 *해시 저장*(bcrypt/argon2, KISA-PY-SEC-14)은 한 쌍입니다. 둘 중 하나만 있어도 안전하지 않습니다.

## 안전한 패턴 (가이드 원문 인용)
```python
import re
from flask import request, make_response

# 가이드 안전 예시: 3종 조합 8자 이상 또는 문자무관 10자 이상
PATTERNS = [
    re.compile(r'^(?=.*[A-Z])(?=.*[a-z])[A-Za-z\d!@#$%^&*]{8,}$'),
    re.compile(r'^(?=.*[A-Z])(?=.*\d)[A-Za-z\d!@#$%^&*]{8,}$'),
    re.compile(r'^(?=.*[A-Z])(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$'),
    re.compile(r'^(?=.*[a-z])(?=.*\d)[A-Za-z\d!@#$%^&*]{8,}$'),
    re.compile(r'^(?=.*[a-z])(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$'),
    re.compile(r'^(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$'),
    # 문자 구성 상관없이 10자리 이상
    re.compile(r'^[A-Za-z\d!@#$%^&*]{10,}$'),
]

def check_password(password: str) -> bool:
    return any(p.match(password) for p in PATTERNS)

@app.route('/register', methods=['POST'])
def register():
    userid = request.form.get('userid')
    password = request.form.get('password')
    confirm = request.form.get('confirm_password')
    if password != confirm:
        return make_response("패스워드가 일치하지 않습니다.", 400)
    if not check_password(password):
        return make_response("패스워드 조합규칙에 맞지 않습니다.", 400)
    user = User(userid=userid, password=bcrypt.hash(password))
    db.session.add(user)
    db.session.commit()
    return make_response("회원가입 성공", 200)
```

Django는 settings.py의 `AUTH_PASSWORD_VALIDATORS`로 동일 정책을 선언적으로 적용합니다:
```python
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
     'OPTIONS': {'min_length': 10}},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
    {'NAME': 'myapp.validators.AgencyComplexityValidator'},
]
```

## False positive 주의
- 본 룰은 *같은 라인*에서 `request.*` 값이 `.password` 속성으로 직접 대입되는 패턴을 잡습니다. 별도 라인에서 `validate_password(password)` 같은 검증을 거친 후 대입했더라도 같은 라인 패턴이 일치하면 매칭됩니다 — 의도된 보수적 detection입니다. 명백히 안전한 코드는 `# gvskb: ignore KISA-PY-SEC-09`로 억제하세요.
- `user.set_password(password)` (Django의 PBKDF2 처리 메서드)는 매칭되지 않습니다. settings.py에서 validator가 활성화되어 있다면 안전합니다 (negative 예시 #3).
- `len(password) >= 8` 이상의 길이 정책은 매칭되지 않습니다. 본 룰은 *7자 이하 허용*만 위험으로 잡습니다.
- 테스트 픽스처에서 의도적으로 약한 비밀번호를 생성하는 경우 파일 단위로 `# gvskb: ignore KISA-PY-SEC-09` 주석을 사용하세요.
