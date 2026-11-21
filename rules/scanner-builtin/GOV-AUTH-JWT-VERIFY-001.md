---
id: GOV-AUTH-JWT-VERIFY-001
title_ko: JWT 서명 검증을 끄거나 none 알고리즘을 허용 - 토큰 위조로 인증 우회
title_en: JWT signature verification disabled or "none" algorithm accepted (authentication bypass)
status: approved
source_layer: baseline
sources:
  - publisher: OWASP
    document: OWASP API Security Top 10 2023
    item: API2 Broken Authentication
  - publisher: OWASP
    document: JSON Web Token Cheat Sheet
cwe: [CWE-347, CWE-287]
severity: high
decision_default: block
domains: [web-appsec]
languages: [python, javascript, typescript]
scenarios: [auth, web-app, backend-node]
related_baseline: [CWE-347]
verified_at: 2026-11-21
review_due: 2027-05-21
detection:
  patterns:
    # PyJWT — 서명 검증 끄기
    - "jwt\\.decode\\s*\\([^)]*\\bverify\\s*=\\s*False"
    - "jwt\\.decode\\s*\\([^)]*options\\s*=\\s*\\{[^}]*['\"]verify_signature['\"]\\s*:\\s*False"
    # python-jose — 검증 없이 클레임 읽기(헤더의 kid 를 읽는 get_unverified_header 는 정상 용법이라 제외)
    - "\\bget_unverified_claims\\s*\\("
    # 허용 알고리즘에 none — PyJWT `algorithms=[...]`, jsonwebtoken `algorithms: [...]`
    # 컴프리헨션(`[a for a in algs if a != "none"]`)은 none 을 걸러 내는 코드다 — 목록에 직접 적힌 경우만 본다.
    - "\\balgorithms\\s*[=:]\\s*\\[(?![^\\]\\n]*\\bfor\\b)[^\\]\\n]*['\"][nN][oO][nN][eE]['\"]"
    # none 으로 서명
    - "jwt\\.(?:sign|encode)\\s*\\([^)]*\\balgorithm\\s*[=:]\\s*['\"][nN][oO][nN][eE]['\"]"
  # 패턴이 옵션 키·값 문자열을 포함한다 — 문자열 감쇄가 진짜 코드를 '낮음'으로 내리지 않게 한다.
  string_arguments: true
  # 형태 자체가 확증이다(검증을 끈 호출).
  confidence: confirmed
  category: authentication
  why_it_matters: >-
    JWT 는 서명을 확인해야만 발급자가 만든 토큰임을 믿을 수 있습니다. 서명 검증을 끄거나 `none` 알고리즘을
    허용하면 누구나 `role: admin` 같은 내용을 넣은 토큰을 만들어 로그인 없이 관리자 기능에 들어올 수 있습니다.
    디버깅 때 잠깐 끈 설정이 그대로 배포되는 경우가 많습니다.
  public_sector_impact:
    - 로그인 없이 타인·관리자 권한으로 접근
    - 개인정보·행정 데이터 무단 조회·변경
    - 위조 토큰이라 접속 기록만으로 구분하기 어려움
  safe_fix: |
    키와 허용 알고리즘을 명시해 검증하세요.
        claims = jwt.decode(token, KEY, algorithms=["HS256"])            # PyJWT
        const claims = jwt.verify(token, KEY, { algorithms: ["HS256"] }); // jsonwebtoken
    토큰 내용을 미리 봐야 한다면(키 선택 등) 헤더만 읽고, 권한 판단은 검증한 뒤의 값으로만 하세요.
  references:
    - CWE-347 Improper Verification of Cryptographic Signature
    - OWASP API2:2023 Broken Authentication
    - OWASP JSON Web Token Cheat Sheet
  can_auto_fix: false
examples:
  language: python
  positive:
    - "payload = jwt.decode(token, verify=False)"
    - "claims = jwt.decode(token, options={\"verify_signature\": False})"
    - "claims = jwt.decode(token, KEY, algorithms=[\"none\", \"HS256\"])"
    - "const c = jwt.verify(token, key, { algorithms: ['none', 'HS256'] });"
    - "claims = jwt.get_unverified_claims(token)"
    - "token = jwt.encode(payload, None, algorithm=\"none\")"
  negative:
    - "claims = jwt.decode(token, KEY, algorithms=[\"HS256\"])"
    - "const c = jwt.verify(token, process.env.JWT_KEY, { algorithms: ['RS256'] });"
    - "kid = jwt.get_unverified_header(token)[\"kid\"]"
    - "algorithms = [algorithm for algorithm in algorithms if algorithm != \"none\"]"
    - "claims = jwt.decode(token, KEY, algorithms=[\"HS256\"], options={\"verify_exp\": False})"
---

## 무엇이 위험한가
서명을 확인하지 않은 JWT 는 누구나 만들 수 있는 글자일 뿐입니다. `verify_signature: False`, `verify=False`,
허용 알고리즘의 `none` 은 모두 "이 토큰이 진짜인지 확인하지 않는다"는 뜻이라, 공격자가 권한을 적어 넣은 토큰으로
인증을 통과합니다.

## 안전한 패턴
```python
claims = jwt.decode(token, KEY, algorithms=["HS256"])
```
```javascript
const claims = jwt.verify(token, process.env.JWT_KEY, { algorithms: ["HS256"] });
```
