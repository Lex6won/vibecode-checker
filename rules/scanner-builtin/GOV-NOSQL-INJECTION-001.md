---
id: GOV-NOSQL-INJECTION-001
title_ko: NoSQL 조회 조건에 요청 값을 그대로 사용 - 연산자 주입으로 인증 우회·전체 조회
title_en: Request values used directly as MongoDB query conditions (operator / $where injection)
status: approved
source_layer: baseline
sources:
  - publisher: OWASP
    document: OWASP Top 10 2021
    item: A03 Injection
  - publisher: OWASP
    document: Web Security Testing Guide
    item: Testing for NoSQL Injection
cwe: [CWE-943]
severity: high
decision_default: warn
domains: [web-appsec]
languages: [python, javascript, typescript]
scenarios: [web-app, backend-node, auth]
related_baseline: [CWE-943]
verified_at: 2026-11-21
review_due: 2027-05-21
detection:
  patterns:
    # $where 에 문자열을 이어 붙임 — DB 에서 자바스크립트가 실행된다
    - '["'']\$where["'']\s*:\s*(?:[^,}\n]*\+\s*\w|[fF]["'']|`[^`\n]*\$\{)'
    # JSON 본문의 값을 조건 값으로 그대로 — {"$ne": null} 같은 객체가 들어오면 조건이 바뀐다
    - '\.(?:find|findOne|findOneAndUpdate|findOneAndDelete|updateOne|updateMany|deleteOne|deleteMany|countDocuments)\s*\(\s*\{[^}\n]*:\s*req\.(?:body|query)\.\w+\s*[,}]'
    - '\.(?:find|find_one|update_one|update_many|delete_one|delete_many|count_documents)\s*\(\s*\{[^}\n]*:\s*request\.(?:json|get_json\s*\(\s*\))\s*(?:\[|\.get\s*\()'
  string_arguments: true
  category: injection
  why_it_matters: >-
    MongoDB 조회 조건은 객체라서, JSON 본문의 값을 그대로 조건에 넣으면 문자열 대신 `{"$ne": null}` 같은 연산자
    객체를 보낼 수 있습니다. 로그인 조회에 쓰면 비밀번호를 몰라도 조건이 참이 되어 인증을 통과하고, 목록 조회에
    쓰면 다른 사람의 자료가 전부 나옵니다. `$where` 에 문자열을 이어 붙이면 DB 안에서 임의 식이 실행됩니다.
  public_sector_impact:
    - 비밀번호 없이 로그인 통과
    - 조건을 바꿔 타인 자료 전체 조회
    - $where 를 통한 DB 내 코드 실행·서비스 지연
  safe_fix: |
    조건에 넣기 전에 형을 고정하세요.
        const user = await User.findOne({ username: String(req.body.username) });
        user = users.find_one({"username": str(payload["username"])})
    비밀번호는 조건에 넣지 말고, 찾은 계정의 해시와 대조하세요. $where 는 쓰지 마세요.
  references:
    - CWE-943 Improper Neutralization of Special Elements in Data Query Logic
    - OWASP A03 Injection
  can_auto_fix: false
examples:
  language: javascript
  positive:
    - "const user = await User.findOne({ username: req.body.username, password: req.body.password });"
    - "users.find({\"$where\": \"this.name == '\" + name + \"'\"})"
    - "user = users.find_one({\"username\": request.json[\"username\"], \"password\": request.json[\"password\"]})"
  negative:
    - "const user = await User.findOne({ username: String(req.body.username) });"
    - "const item = await Item.findById(id);"
    - "user = users.find_one({\"username\": str(payload[\"username\"])})"
    - "const rows = await Order.find({ status: 'open' });"
---

## 무엇이 위험한가
요청 본문은 문자열만 오지 않습니다. 객체가 들어오면 조회 조건 자체가 바뀝니다.

## 안전한 패턴
```javascript
const user = await User.findOne({ username: String(req.body.username) });
if (!user || !(await bcrypt.compare(String(req.body.password), user.passwordHash))) return res.status(401).end();
```
