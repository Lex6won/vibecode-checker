---
id: KISA-JS-CODE-03
title_ko: Node.js 신뢰할 수 없는 데이터의 역직렬화 - node-serialize / funcster / unserialize / unsafe yaml.load
title_en: Deserialization of untrusted data in Node.js (node-serialize.unserialize, funcster, unsafe yaml.load)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Javascript 시큐어코딩 가이드(2023년 개정본)
    item: 제5절 3. 신뢰할 수 없는 데이터의 역직렬화
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-46
cwe: [CWE-502]
severity: critical
decision_default: block
domains: [kisa-secure-coding]
languages: [javascript, typescript]
scenarios: [backend-node, web-app, agent]
related_baseline: [MOIS-49-CODE-03]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    - "(?:^|[\\s;{(=,])unserialize\\s*\\(\\s*(?:req|request)\\.(?:query|params|body|cookies|headers)\\."
    - "(?:^|[\\s;{(=,])serialize\\.unserialize\\s*\\(\\s*(?:req|request)\\.(?:query|params|body|cookies|headers)\\."
    - "require\\s*\\(\\s*['\"]node-serialize['\"]\\s*\\)"
    - "require\\s*\\(\\s*['\"]funcster['\"]\\s*\\)"
    - "yaml\\.load\\s*\\(\\s*(?:req|request)\\.(?:query|params|body|cookies|headers)\\."
    - "(?:js-yaml|yaml)[^;{]{0,80}\\.load\\s*\\([^,)]*(?:req|request)\\.(?:query|params|body)\\."
  category: kisa-secure-coding
  why_it_matters: >-
    Node.js의 `node-serialize`, `funcster` 패키지의 `unserialize()`나
    js-yaml의 *불안전 로더*(`yaml.load`)는 직렬화 페이로드 내부에 *함수/객체
    레퍼런스*를 그대로 복원합니다. 공격자가 `{"rce":"_$$ND_FUNC$$_function()..."}`
    같은 페이로드를 보내면 *원격 코드 실행(RCE)*이 즉시 가능합니다. 가이드
    §제5절 3은 신뢰할 수 없는 데이터를 그대로 역직렬화하지 말고, 부득이한 경우
    *HMAC 등으로 무결성을 검증한 후*에 역직렬화하라고 권고합니다. 공공 API가
    사용자 입력을 그대로 unserialize 하면 서버 권한 탈취로 직결됩니다.
  public_sector_impact:
    - 원격 코드 실행으로 인한 행정 시스템 전체 장악
    - 공격자가 임의 명령 실행 후 행정 데이터 유출/파괴
    - 컨테이너 탈출·내부망 측방이동의 시작점
  safe_fix: |
    1) `node-serialize`, `funcster` 등 *역직렬화 시 코드 실행이 가능한 패키지*는
       사용을 금지하고 표준 `JSON.parse`로 대체하세요.
    2) JSON.parse를 쓰더라도 *송신측이 신뢰 가능한지* 항상 검증하세요.
       const hmac = crypto.createHmac('sha512', SECRET).update(body).digest('hex');
       if (!crypto.timingSafeEqual(Buffer.from(hmac), Buffer.from(sigFromClient))) {
         return res.status(400).send('integrity check failed');
       }
       const data = JSON.parse(body);
    3) YAML은 안전 로더만 사용하세요: `yaml.load(input, { schema: yaml.FAILSAFE_SCHEMA })`
       또는 `js-yaml`의 `yaml.load` 대신 `yaml.load(s, { schema: CORE_SCHEMA })`.
    4) 역직렬화 대상이 예상 스키마와 일치하는지 zod/ajv로 추가 검증하세요.
  references:
    - KISA JavaScript 가이드 제5절 3
    - MOIS-49-CODE-03
    - CWE-502
    - OWASP Deserialization Cheat Sheet
    - Snyk Advisory - node-serialize
  can_auto_fix: false
examples:
  language: javascript
  positive:
    - "const serialize = require('node-serialize'); const obj = serialize.unserialize(req.body.payload);"
    - "const yaml = require('js-yaml'); const cfg = yaml.load(req.body.cfg);"
    - "const obj = unserialize(req.query.data);"
  negative:
    - "const obj = JSON.parse(req.body.payload);"
    - "const hmac = crypto.createHmac('sha512', SECRET).update(body).digest('hex'); if (hmac === sig) { const data = JSON.parse(body); }"
    - "const yaml = require('js-yaml'); const cfg = yaml.load(fs.readFileSync('./config.yml','utf8'), { schema: yaml.FAILSAFE_SCHEMA });"
---

## 무엇이 위험한가
역직렬화는 *바이트 스트림을 객체로 복원*하는 작업이지만, `node-serialize`/`funcster`는 페이로드 내부에 인코딩된 *JavaScript 함수 정의*를 그대로 평가합니다. 공격자가 `{"exploit":"_$$ND_FUNC$$_function(){require('child_process').exec('rm -rf /')}()"}` 형태의 페이로드를 보내면 서버에서 임의 명령이 실행됩니다. `js-yaml`의 `yaml.load`(legacy default)는 `!!js/function` 태그로 함수 정의 실행을 허용해 동일한 위험이 있습니다(현재는 `yaml.safeLoad` 또는 명시적 schema 권장). 가이드 §제5절 3의 안전 예시는 HMAC으로 *데이터 무결성*을 먼저 검증한 후 표준 `JSON.parse`로만 역직렬화하는 흐름을 보여 줍니다.

## 안전한 패턴 (가이드 원문 인용)
```javascript
const express = require('express');
const crypto = require('crypto');

router.get('/patched', (req, res) => {
  const serializedData = req.query.data;
  const body = JSON.parse(serializedData);
  // 데이터 변조를 확인하기 위한 해시값
  const hashedMac = body.hashed;
  // 사용자로부터 입력받은 데이터를 직렬화
  const userInfo = JSON.stringify(body.userInfo);
  const secretKey = process.env.HMAC_SECRET;
  const hmac = crypto.createHmac('sha512', secretKey);
  const calc = hmac.update(userInfo).digest('hex');
  if (calc !== hashedMac) {
    return res.status(400).send('integrity check failed');
  }
  return res.send(body.userInfo);
});
```

## False positive 주의
- 표준 `JSON.parse(req.body.x)`는 RCE 위험이 없으므로 매칭하지 않습니다(별도 보호: 입력 스키마 검증·DoS 한도).
- `js-yaml`을 안전 스키마(`FAILSAFE_SCHEMA`, `CORE_SCHEMA`, `JSON_SCHEMA`)로 호출하는 경우도 본 룰은 *사용자 입력을 직접 인자로 넘기는 패턴*만 매칭하므로, 파일/설정에서 읽은 값은 잡지 않습니다.
- `require('node-serialize')`나 `require('funcster')` 자체가 이미 위험 신호로 분류됩니다. 의존성 트리에 포함됐다면 제거 또는 fork·정적 분석이 필요합니다.
- 첫 번째/두 번째 패턴은 *`req.`/`request.` 데이터를 직접 unserialize에 넘기는 경우*에만 매칭됩니다. 별도 변수에 담아 HMAC 검증을 거친 후 unserialize 하는 흐름은 본 룰로는 잡히지 않으나, 가이드는 `unserialize` 자체의 사용 금지를 더 안전한 선택으로 권합니다.
