---
id: KISA-JS-INPUT-09
title_ko: Node.js XML 삽입 - xpath.select에 사용자 입력 문자열 결합 (XPath Injection)
title_en: XML/XPath injection in Node.js (xpath.select with concatenated input)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Javascript 시큐어코딩 가이드(2023년 개정본)
    item: 제1절 9. XML 삽입
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-09
cwe: [CWE-91, CWE-643]
severity: high
decision_default: block
domains: [kisa-secure-coding]
languages: [javascript, typescript]
scenarios: [backend-node, web-app]
related_baseline: [MOIS-49-INPUT-09]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    - "xpath\\.(?:select|select1|evaluate)\\s*\\(\\s*\"[^\"]*\"\\s*\\+"
    - "xpath\\.(?:select|select1|evaluate)\\s*\\(\\s*'[^']*'\\s*\\+"
    - "xpath\\.(?:select|select1|evaluate)\\s*\\(\\s*`[^`]*\\$\\{"
    - "xpath\\.(?:select|select1|evaluate)\\s*\\([^,)]*\\+\\s*(?:req|request)\\."
    - "(?:select|evaluate)XPath\\s*\\(\\s*[\"'][^\"']*[\"']\\s*\\+"
  category: kisa-secure-coding
  why_it_matters: >-
    `xpath.select("//users/user[login='" + userName + "']", doc)` 처럼 XPath
    쿼리에 외부 입력을 직접 결합하면 `' or '1'='1` 류의 주입으로 인증 우회·
    XML 데이터 전수 조회가 가능합니다. 가이드 §제1절 9는 *인자화된 쿼리
    (xpath.parse + select(variables))* 사용을 권고합니다.
  public_sector_impact:
    - XML 기반 사용자/권한 정보 우회 조회
    - 인증 로직 우회로 인한 권한 상승
    - 민감정보 XML 노드 전수 노출
  safe_fix: |
    인자화된 XPath 쿼리를 사용하세요.
    const expr = xpath.parse("//users/user[login=$u and password=$p]/home_dir/text()");
    const result = expr.select({ node: doc, variables: { u: userName, p: userPass } });
  references:
    - KISA JavaScript 가이드 제1절 9
    - MOIS-49-INPUT-09
    - CWE-643
    - OWASP XPath Injection
  can_auto_fix: false
examples:
  language: javascript
  positive:
    - "const r = xpath.select(\"//users/user[login='\" + userName + \"']\", doc);"
    - "const r = xpath.select(`//users/user[login='${userName}']`, doc);"
    - "const r = xpath.evaluate('//item[name=' + req.query.name + ']', doc);"
  negative:
    - "const expr = xpath.parse('//users/user[login=$u]'); const r = expr.select({ node: doc, variables: { u: userName } });"
    - "const r = xpath.select('//users/user', doc);"
    - "const r = xpath.select1('/root/item[1]', doc);"
---

## 무엇이 위험한가
XPath는 SQL과 구조가 유사해 문자열 결합으로 쿼리를 만들면 *인증 우회*가 즉시 가능합니다. 가이드 예시는 `?userName=john' or ''='&userPass='or ''='` 만으로 패스워드 검증을 우회합니다.

## 안전한 패턴 (가이드 원문 인용)
```javascript
const xpath = require('xpath');
const dom = require('xmldom').DOMParser;

router.get("/patched", (req, res) => {
  const userName = req.query.userName;
  const userPass = req.query.userPass;
  const doc = new dom().parseFromString(xml);

  // 인자화된 쿼리 생성
  const goodXPathExpr = xpath.parse(
    "//users/user[login/text()=$userName and password/text()=$userPass]/home_dir/text()"
  );
  // 쿼리문에 변수값 전달 및 XML 조회
  const selected = goodXPathExpr.select({
    node: doc,
    variables: { userName, userPass },
  });
  ...
});
```

## False positive 주의
- 정적 XPath 문자열(`xpath.select('//root/item', doc)`)은 결합 연산자가 없어 매칭되지 않습니다.
- `xpath.parse(...).select({variables: {...}})` 형태(인자화된 쿼리)는 변수 바인딩으로 안전하며 패턴에서 제외됩니다.
