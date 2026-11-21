---
id: GOV-AUTH-DEFAULT-CREDENTIALS-001
title_ko: 코드에 적힌 고정 계정으로 로그인 판정 - 누구나 아는 비밀번호로 관리자 접근
title_en: Login decided by comparing the submitted password with a hard-coded literal
status: approved
source_layer: baseline
sources:
  - publisher: OWASP
    document: OWASP Top 10 2021
    item: A07 Identification and Authentication Failures
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: 하드코드된 중요정보
cwe: [CWE-798, CWE-259]
severity: high
decision_default: block
domains: [web-appsec]
languages: [python, javascript, typescript]
scenarios: [auth, web-app, backend-node]
related_baseline: [CWE-798]
verified_at: 2026-11-21
review_due: 2027-05-21
detection:
  patterns:
    # 요청으로 받은 비밀번호를 문자열과 직접 비교 (Flask·Django·FastAPI 폼)
    - 'request\.(?:form|json|args|values|POST|data)(?:\.get\s*\(\s*|\s*\[\s*)["''](?:password|passwd|pwd|pw)["''](?:\s*\)|\s*\])\s*==\s*["''][^"''\n]{1,64}["'']'
    # Express·Next — req.body.password === "…"
    - '(?:req|request)\.body\.(?:password|passwd|pwd|pw)\s*===?\s*["''`][^"''`\n]{1,64}["''`]'
    # 아이디와 비밀번호를 둘 다 문자열과 비교하는 한 줄
    - '\b\w*(?:user(?:name)?|login|id)\w*\s*={2,3}\s*["''][^"''\n]{1,32}["'']\s*(?:and|&&)\s*\w*(?:password|passwd|pwd)\w*\s*={2,3}\s*["''][^"''\n]{1,64}["'']'
  # 빈 문자열과의 비교(입력 검증)는 대상이 아니다
  exclude_patterns:
    - '(?:password|passwd|pwd|pw)\w*["''\])\s]*={2,3}\s*["''`]{2}'
  string_arguments: true
  confidence: likely
  category: authentication
  why_it_matters: >-
    로그인 처리에서 받은 비밀번호를 코드에 적힌 문자열과 비교하면, 그 값은 소스·배포본·저장소를 본 누구나 압니다.
    시제품에서 쓰던 `admin` 계정이 그대로 배포되어 로그인 화면이 사실상 열려 있는 사고가 흔합니다. 값을 바꾸려면
    다시 배포해야 하고, 누가 로그인했는지도 구분되지 않습니다.
  public_sector_impact:
    - 소스나 배포본을 본 사람은 누구나 관리자 로그인
    - 계정이 하나라 접속자를 구분할 수 없음
    - 비밀번호를 바꾸려면 재배포가 필요
  safe_fix: |
    계정은 저장소에 해시로 두고 검증 함수로 대조하세요.
        if user and check_password_hash(user.password_hash, form_password): ...
        if (user && await bcrypt.compare(req.body.password, user.passwordHash)) { ... }
    초기 관리자 비밀번호는 환경변수로 받고 첫 로그인 때 바꾸게 하세요.
  references:
    - CWE-798 Use of Hard-coded Credentials
    - OWASP A07 Identification and Authentication Failures
  can_auto_fix: false
examples:
  language: python
  positive:
    - "if request.form[\"username\"] == \"admin\" and request.form[\"password\"] == \"P@ssw0rd\":"
    - "if request.form.get(\"password\") == \"letmein\":"
    - "if (req.body.username === 'admin' && req.body.password === 'P@ssw0rd') {"
    - "if username == \"admin\" and password == \"P@ssw0rd\":"
  negative:
    - "if user and check_password_hash(user.password_hash, request.form[\"password\"]):"
    - "if (!user || !(await bcrypt.compare(req.body.password, user.passwordHash))) return res.status(401).end();"
    - "if request.form.get(\"password\") == \"\":"
    - "if req.body.password === '':"
    - "if field == \"password\" and mode == \"reset\":"
---

## 무엇이 위험한가
비밀번호가 코드에 적혀 있으면 비밀이 아닙니다. 저장소 접근 권한이 있는 사람, 배포 파일을 받은 사람, 화면 소스를
본 사람이 모두 같은 값으로 로그인할 수 있습니다.

## 안전한 패턴
```python
user = User.query.filter_by(username=form_username).first()
if user and check_password_hash(user.password_hash, form_password):
    login_user(user)
```
