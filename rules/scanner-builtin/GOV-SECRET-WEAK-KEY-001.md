---
id: GOV-SECRET-WEAK-KEY-001
title_ko: 서명·세션 비밀키가 짧은 고정 문자열 - 토큰·세션 위조
title_en: Signing or session secret is a short hard-coded literal
status: approved
source_layer: baseline
sources:
  - publisher: OWASP
    document: OWASP Top 10 2021
    item: A02 Cryptographic Failures
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: 하드코드된 중요정보
cwe: [CWE-321, CWE-798]
severity: high
decision_default: block
domains: [web-appsec]
languages: [python, javascript, typescript]
scenarios: [auth, web-app, backend-node]
related_baseline: [CWE-321]
verified_at: 2026-11-21
review_due: 2027-05-21
detection:
  patterns:
    # Flask·Django — 비밀키에 15자 이하 문자열을 직접 대입
    - '(?:\bsecret_key|\bSECRET_KEY|\[\s*["'']SECRET_KEY["'']\s*\]|\bJWT_SECRET(?:_KEY)?|\bSESSION_SECRET)\s*=\s*["''][^"''\n]{1,15}["'']\s*(?:#.*)?$'
    # 환경변수가 없을 때 쓰는 기본값이 짧은 문자열
    # 이름에 SECRET 이 있다고 값이 키는 아니다(설정 묶음 이름을 고르는 변수가 실측에서 잡혔다) — 흔한 키 이름만 본다.
    - '(?:environ\.get|getenv)\s*\(\s*["''][A-Z0-9_]*(?:SECRET_KEY|JWT[A-Z0-9_]*|(?:SESSION|APP|AUTH|NEXTAUTH|TOKEN|COOKIE|SIGNING)_SECRET)["'']\s*,\s*["''][^"''\n]{1,15}["'']\s*\)'
    - 'process\.env\.[A-Z0-9_]*(?:SECRET_KEY|JWT[A-Z0-9_]*|(?:SESSION|APP|AUTH|NEXTAUTH|TOKEN|COOKIE|SIGNING)_SECRET)\s*(?:\|\||\?\?)\s*["''`](?![^"''`\n]*\$\{)[^"''`\n]{1,15}["''`]'
    # jsonwebtoken — 서명·검증 키 자리에 문자열을 직접 적음
    - 'jwt\.(?:sign|verify)\s*\((?:\s*\{[^}\n]*\}|[^,\n]+)\s*,\s*["''`](?![^"''`\n]*\$\{)[^"''`\n]{1,63}["''`]'
    # PyJWT — jwt.encode(payload, "secret", …)
    - 'jwt\.encode\s*\((?:\s*\{[^}\n]*\}|[^,\n]+)\s*,\s*["''][^"''\n]{1,63}["'']'
  string_arguments: true
  confidence: likely
  dedup_group: hardcoded-credential
  category: authentication
  why_it_matters: >-
    세션 쿠키와 JWT 는 서버만 아는 비밀키로 서명합니다. 그 키가 `dev`·`secret`·`changeme` 같은 짧은 고정 문자열이면
    공격자가 같은 키로 직접 서명해 아무 사용자의 세션이나 관리자 토큰을 만들 수 있습니다. 예제 코드의 값이 그대로
    남는 경우가 대부분이고, 소스가 공개되지 않아도 흔한 값은 금방 추측됩니다.
  public_sector_impact:
    - 위조한 세션·토큰으로 로그인 없이 타인·관리자 권한 획득
    - 서명이 맞는 토큰이라 접속 기록으로 구분하기 어려움
    - 키를 바꾸기 전까지 모든 사용자 세션이 위험
  safe_fix: |
    비밀키는 환경변수나 비밀 저장소에서 읽고, 없으면 기동하지 않게 하세요.
        app.secret_key = os.environ["FLASK_SECRET_KEY"]
        const token = jwt.sign(payload, process.env.JWT_KEY, { expiresIn: "1h" });
    값은 32바이트 이상 무작위로 만드세요(python -c "import secrets; print(secrets.token_hex(32))").
  references:
    - CWE-321 Use of Hard-coded Cryptographic Key
    - OWASP A02 Cryptographic Failures
  can_auto_fix: false
examples:
  language: python
  positive:
    - "app.secret_key = \"dev\""
    - "app.config[\"SECRET_KEY\"] = \"changeme\""
    - "SECRET_KEY = os.environ.get(\"SECRET_KEY\", \"dev\")"
    - "return jwt.sign({ sub: user.id, role: user.role }, 'secret');"
    - "const key = process.env.JWT_SECRET || 'secret';"
    - "token = jwt.encode(payload, \"secret\", algorithm=\"HS256\")"
  negative:
    - "app.secret_key = os.environ[\"FLASK_SECRET_KEY\"]"
    - "return jwt.sign({ sub: user.id }, process.env.JWT_KEY, { expiresIn: '1h' });"
    - "SECRET_KEY = os.environ.get(\"SECRET_KEY\")"
    - "const claims = jwt.verify(token, publicKey, { algorithms: ['RS256'] });"
    - "secret_key_name = \"FLASK_SECRET_KEY\""
    - "profile = os.getenv(\"DB_SECRET_PROFILE\", \"local\")"
    - "store = os.getenv(\"PG_SECRET\", \"local\")"
    - "const token = jwt.sign(payload, `${process.env.JWT_KEY}`);"
---

## 무엇이 위험한가
서명 키가 추측 가능한 값이면 서명은 아무것도 보장하지 않습니다. 공격자는 같은 키로 `role: admin` 토큰이나 다른
사용자의 세션 쿠키를 만들어 그대로 통과합니다.

## 안전한 패턴
```python
app.secret_key = os.environ["FLASK_SECRET_KEY"]
```
```javascript
const token = jwt.sign(payload, process.env.JWT_KEY, { expiresIn: "1h" });
```
