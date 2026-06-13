---
id: KISA-JS-INPUT-10
title_ko: Node.js LDAP 삽입 - ldapjs filter에 사용자 입력 직접 결합
title_en: LDAP injection in Node.js (ldapjs filter built from user input)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Javascript 시큐어코딩 가이드(2023년 개정본)
    item: 제1절 10. LDAP 삽입
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-10
cwe: [CWE-90]
severity: high
decision_default: block
domains: [kisa-secure-coding]
languages: [javascript, typescript]
scenarios: [backend-node, auth, web-app]
related_baseline: [MOIS-49-INPUT-10]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    - "filter\\s*:\\s*`[^`]*\\$\\{(?:req|request|search|userInput|user|name|input)\\b"
    - "filter\\s*:\\s*[\"'][^\"']*[\"']\\s*\\+\\s*(?:req|request|search|userInput|input)\\."
    - "filter\\s*:\\s*[\"'][^\"']*\\(\\s*[a-zA-Z]+\\s*=\\s*[\"']\\s*\\+"
    - "client\\.search\\s*\\([^,]+,\\s*\\{[^}]*filter\\s*:\\s*[`\"'][^`\"']*(?:\\$\\{|\\+\\s*\\w)"
  category: kisa-secure-coding
  why_it_matters: >-
    `{ filter: \`(&(uid=${userInput}))\` }`처럼 사용자 입력을 LDAP 필터에 직접
    결합하면 `*)(uid=*` 같은 와일드카드 주입으로 인증 우회·디렉터리 전수 조회가
    가능합니다. 공공 SSO/그룹웨어/AD 연계 인증 모듈에서 가장 흔한 패턴입니다.
  public_sector_impact:
    - LDAP 기반 SSO 인증 우회
    - 공무원 디렉터리 전수 노출
    - 권한 상승 (관리자 계정 매칭)
  safe_fix: |
    ldapjs.parseFilter()로 사용자 입력을 이스케이프하세요.
    const { parseFilter } = require('ldapjs');
    try {
      const safeFilter = parseFilter(`(uid=${userInput})`);
      client.search(base, { filter: safeFilter, scope: 'sub' }, ...);
    } catch {
      return res.send('잘못된 요청값입니다.');
    }
  references:
    - KISA JavaScript 가이드 제1절 10
    - MOIS-49-INPUT-10
    - CWE-90
    - OWASP LDAP Injection Prevention Cheat Sheet
  can_auto_fix: false
examples:
  language: javascript
  positive:
    - "const opts = { filter: `(&(objectClass=${search}))`, scope: 'sub' };"
    - "const opts = { filter: '(uid=' + req.query.uid + ')', scope: 'sub' };"
    - "const opts = { filter: `(uid=${userInput})` };"
  negative:
    - "const opts = { filter: parseFilter(`(uid=${userInput})`), scope: 'sub' };"
    - "const opts = { filter: '(objectClass=person)', scope: 'sub' };"
    - "const safe = parseFilter(req.query.search); client.search(base, { filter: safe });"
---

## 무엇이 위험한가
LDAP 필터 구문은 `)`, `(`, `*`, `\\`, NUL 등이 메타문자입니다. 사용자 입력을 그대로 결합하면 `*)(uid=*))(|(uid=*` 같은 페이로드로 모든 사용자를 매칭시킬 수 있습니다. 가이드 §제1절 10은 ldapjs의 `parseFilter` 호출을 권고합니다.

## 안전한 패턴 (가이드 원문 인용)
```javascript
const express = require('express');
const ldap = require('ldapjs');
const parseFilter = require('ldapjs').parseFilter;

router.get("/patched", async (req, res) => {
  let search;
  try {
    search = parseFilter(req.query.search);
  } catch {
    return res.send('잘못된 요청값입니다.');
  }
  const result = await searchLDAP(search);
  return res.send(result);
});
```

## False positive 주의
- `parseFilter(...)`로 감싸진 필터는 안전 경로이며 매칭에서 제외됩니다.
- 정적 필터(`'(objectClass=person)'`)는 변수 결합이 없어 매칭되지 않습니다.
- 변수명 패턴(`req`, `request`, `search`, `userInput`, `input`, `user`, `name`)에 한정해 다른 도메인 변수의 오탐을 줄였습니다.
