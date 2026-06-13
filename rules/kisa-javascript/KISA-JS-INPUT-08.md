---
id: KISA-JS-INPUT-08
title_ko: Node.js 부적절한 XML 외부개체(XXE) 참조 - libxmljs noent:true / sax-parser 외부엔티티 활성
title_en: XML External Entity (XXE) in Node.js (libxmljs noent:true)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Javascript 시큐어코딩 가이드(2023년 개정본)
    item: 제1절 8. 부적절한 XML 외부개체 참조
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-08
cwe: [CWE-611, CWE-776]
severity: high
decision_default: block
domains: [kisa-secure-coding]
languages: [javascript, typescript]
scenarios: [backend-node, web-app]
related_baseline: [MOIS-49-INPUT-08]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    - "libxmljs\\.parseXml(?:String)?\\s*\\([^)]*noent\\s*:\\s*true"
    - "(?:new\\s+)?DOMParser\\s*\\(\\s*\\)\\s*\\.parseFromString\\s*\\([^)]*(?:req|request)\\."
    - "sax\\.parser\\s*\\([^)]*resolveExternals\\s*:\\s*true"
    - "xml2js\\.[Pp]arser\\s*\\(\\s*\\{[^}]*explicitCharkey"
    - "expat\\.Parser\\s*\\([^)]*\\)\\s*[\\s\\S]*?\\.parse\\s*\\(\\s*(?:req|request)\\."
  category: kisa-secure-coding
  why_it_matters: >-
    Node.js는 기본 XML 파서를 제공하지 않아 libxmljs, xml2js, sax, expat 같은
    외부 파서를 사용합니다. `noent: true`처럼 외부 엔티티 파싱을 명시적으로
    활성화하거나, 사용자 XML을 검증 없이 파싱하면 `/etc/passwd` 등 서버 파일
    노출·SSRF·DoS로 직결됩니다. 공공 EDI/전자세금계산서/문서연계 API에서
    가장 빈번한 취약점 중 하나입니다.
  public_sector_impact:
    - 서버 파일(/etc/passwd, .env) 노출
    - 내부망 SSRF 진입점
    - 파서 자원 고갈로 인한 서비스 거부
  safe_fix: |
    외부 엔티티 파싱을 명시적으로 비활성화하세요.
    const products = libxmljs.parseXmlString(xml, { noent: false, noblanks: true });
    // sax: const parser = sax.parser(true, { resolveExternals: false });
    // 가능하면 입력 XML 스키마 검증(XSD) 적용 후 처리.
  references:
    - KISA JavaScript 가이드 제1절 8
    - MOIS-49-INPUT-08
    - CWE-611
    - OWASP XML External Entity Prevention Cheat Sheet
  can_auto_fix: false
examples:
  language: javascript
  positive:
    - "const products = libxmljs.parseXmlString(data, { noent: true });"
    - "const doc = new DOMParser().parseFromString(req.body.xml, 'text/xml');"
    - "const parser = sax.parser(true, { resolveExternals: true });"
  negative:
    - "const products = libxmljs.parseXmlString(data, { noent: false });"
    - "const doc = new DOMParser().parseFromString(safeStaticXml, 'text/xml');"
    - "const parser = sax.parser(true, { resolveExternals: false });"
---

## 무엇이 위험한가
취약한 XML 파서가 `<!ENTITY xxe SYSTEM "file:///etc/passwd">` 같은 외부 엔티티를 해석하면 서버 파일이 응답에 포함됩니다. libxmljs의 `noent: true`, sax의 `resolveExternals: true`가 위험 스위치입니다. 가이드 §제1절 8은 *명시적으로 비활성화* 할 것을 권고합니다.

## 안전한 패턴 (가이드 원문 인용)
```javascript
const express = require('express');
const libxmljs = require("libxmljs");

router.post("/patched", (req, res) => {
  if (req.files.products && req.files.products.mimetype === "application/xml") {
    const products = libxmljs.parseXmlString(
      req.files.products.data.toString("utf8"),
      // 외부 엔티티 파싱 비활성화 (기본값이지만 명시 권장)
      { noent: false }
    );
    return res.send(products.get("//foo").text());
  }
  return res.send("fail");
});
```

## False positive 주의
- 정적 XML 문자열을 파싱하는 경우(사용자 입력 미포함)는 매칭되지 않습니다. `req.`/`request.`가 포함된 호출만 잡습니다.
- `noent: false`로 명시적으로 비활성화한 호출은 매칭에서 제외됩니다.
- 신뢰된 내부 XML 처리(예: 정적 설정 파일)는 `gvskb: ignore` 주석으로 예외 처리할 수 있습니다.
