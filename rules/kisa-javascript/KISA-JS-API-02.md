---
id: KISA-JS-API-02
title_ko: Node.js 취약한 API 사용 - eval/Function/vm.runInThisContext/setTimeout 문자열 인자/MD5·SHA1 해시
title_en: Use of vulnerable Node.js APIs (eval, Function ctor, vm.runInThisContext, string setTimeout, MD5/SHA1)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Javascript 시큐어코딩 가이드(2023년 개정본)
    item: 제7절 2. 취약한 API 사용
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-48
cwe: [CWE-676, CWE-327, CWE-95]
severity: high
decision_default: block
domains: [kisa-secure-coding]
languages: [javascript, typescript]
scenarios: [backend-node, frontend, web-app, agent]
related_baseline: [MOIS-49-API-02]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    - "(?<![A-Za-z0-9_$.])eval\\s*\\("
    - "new\\s+Function\\s*\\("
    - "(?<![A-Za-z0-9_$.])vm\\.(?:runInThisContext|runInNewContext|runInContext)\\s*\\("
    - "(?:setTimeout|setInterval)\\s*\\(\\s*['\"`][^'\"`]+['\"`]\\s*,"
    - "crypto\\.createHash\\s*\\(\\s*['\"](?:md5|sha1|md4|md2|ripemd160)['\"]\\s*\\)"
    - "crypto\\.createHmac\\s*\\(\\s*['\"](?:md5|sha1|md4)['\"]\\s*,"
  category: kisa-secure-coding
  why_it_matters: >-
    가이드 §제7절 2는 *부주의하게 사용될 가능성이 많은 API*를 취약한 API로 정의
    합니다. 자바스크립트에서 가장 흔한 위험 API는 다음과 같습니다:
    `eval()`, `new Function()`, `vm.runInThisContext`, *문자열을 첫 인자로 받는
    `setTimeout`/`setInterval`* (내부적으로 eval 동작), 그리고 *깨졌거나 약한
    해시*(`MD5`, `SHA-1`, `MD4`, `MD2`). 모두 *외부 입력과 결합되는 순간 RCE 또는
    충돌 공격*으로 직결되거나, 무결성/패스워드 보호가 무력화됩니다. 공공 백엔드는
    이러한 API를 *원천 차단*하고 안전한 대체 API를 사용해야 합니다.
  public_sector_impact:
    - eval/Function/vm 사용으로 인한 원격 코드 실행
    - MD5/SHA1 기반 패스워드·서명 검증 우회
    - 문자열 setTimeout으로 인한 간접 코드 인젝션
  safe_fix: |
    1) 동적 평가 금지. JSON 파싱은 `JSON.parse`, 표현식 평가가 정말 필요하면
       *AST 기반 안전 평가기*(`expr-eval`, `mathjs.evaluate`)나 *샌드박스*
       (`vm2` 대체로 `isolated-vm`)를 사용하세요. eval/Function/vm.runIn* 금지.
    2) setTimeout/setInterval은 *반드시 함수 참조*를 넘기세요.
       setTimeout(() => doWork(arg), 1000);  // OK
       setTimeout('doWork(' + arg + ')', 1000);  // 금지 (eval과 동등)
    3) 해시 알고리즘은 SHA-256 이상.
       crypto.createHash('sha256').update(data).digest('hex');
       패스워드는 단순 해시 금지: bcrypt/argon2/scrypt + salt를 사용하세요.
  references:
    - KISA JavaScript 가이드 제7절 2
    - MOIS-49-API-02
    - CWE-676
    - CWE-327
    - OWASP Top 10 A02/A03
  can_auto_fix: false
examples:
  language: javascript
  positive:
    - "const result = eval(req.query.expr);"
    - "const fn = new Function('a', 'b', 'return a + b');"
    - "setTimeout('doWork()', 1000);"
    - "const h = crypto.createHash('md5').update(password).digest('hex');"
  negative:
    - "const result = JSON.parse(req.query.payload);"
    - "setTimeout(() => doWork(arg), 1000);"
    - "const h = crypto.createHash('sha256').update(password + salt).digest('hex');"
---

## 무엇이 위험한가
`eval`, `new Function`, `vm.runInThisContext`는 *문자열을 그대로 JavaScript 코드로 실행*합니다. 사용자 입력이 단 한 글자라도 섞이면 즉시 RCE입니다. `setTimeout('code', n)`/`setInterval('code', n)`은 내부적으로 같은 evaluator를 호출하므로 동일한 위험이 있습니다(브라우저에서는 CSP가 잡지만 Node.js는 보호 장치가 없음). **MD5/SHA-1**은 충돌 공격이 실증되어 *디지털 서명·인증서 핑거프린팅·파일 무결성*에 사용 금지된 지 오래입니다. 패스워드 보호용으로 단순 해시(`createHash('sha256')`)도 부적절합니다 — *bcrypt/argon2/scrypt + salt*가 표준입니다. 가이드 §제7절 2는 *안전한 API 선택*과 *사후 관리(SBOM)*를 함께 권장합니다.

## 안전한 패턴 (가이드 원문 인용)
```javascript
// 동적 평가 대신 JSON.parse + 스키마 검증
const payload = JSON.parse(req.body.payload);
const Schema = z.object({ op: z.enum(['add','sub']), a: z.number(), b: z.number() });
const parsed = Schema.parse(payload);

// setTimeout은 함수 참조로
setTimeout(() => doWork(parsed.a, parsed.b), 1000);

// 해시는 SHA-256 이상, 패스워드는 bcrypt
const bcrypt = require('bcrypt');
const hash = await bcrypt.hash(password, 12);
const ok = await bcrypt.compare(input, hash);
```

## False positive 주의
- 첫 번째 패턴(`eval(`)은 *식별자 경계*(`(?<![A-Za-z0-9_$.])`)로 시작해, `medieval`, `obj.eval`, `myEval` 같은 다른 식별자의 일부는 매칭하지 않습니다.
- 세 번째 패턴(`vm.`)도 `myvm.run...` 같은 *식별자 일부*는 매칭하지 않도록 경계가 적용됩니다.
- `setTimeout(() => ..., 1000)` 처럼 함수 표현식을 넘기는 정상 패턴은 매칭하지 않습니다(첫 인자가 따옴표 문자열인 경우만 매칭).
- `crypto.createHash('sha256'|'sha512')` 등 안전 알고리즘은 매칭하지 않습니다.
- 라이브러리 내부에서 정당하게 `new Function` / `eval`을 쓰는 경우(예: 템플릿 컴파일러)는 사용 자체를 *경계 신호*로 보고 관리·격리 정책으로 보완하세요.
- 코드 베이스에 본 패턴이 합법적으로 존재해야 한다면(REPL/스크립팅 도구) 명시적 *예외 등록(allowlist)*과 보안 리뷰를 거치게 운영하세요.
