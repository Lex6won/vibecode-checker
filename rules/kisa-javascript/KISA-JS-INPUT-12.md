---
id: KISA-JS-INPUT-12
title_ko: Node.js 서버사이드 요청 위조 (SSRF) - 사용자 입력 URL을 검증 없이 fetch/axios/request
title_en: Server-Side Request Forgery (SSRF) in Node.js (fetch/axios/request with user URL)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Javascript 시큐어코딩 가이드(2023년 개정본)
    item: 제1절 12. 서버사이드 요청 위조
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-31
cwe: [CWE-918]
severity: high
decision_default: block
domains: [kisa-secure-coding]
languages: [javascript, typescript]
scenarios: [backend-node, web-app, agent, llm-integration]
related_baseline: [MOIS-49-INPUT-12]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    - "(?<![A-Za-z0-9_$.])(?:fetch|request|got|undici\\.request|node-fetch)\\s*\\(\\s*(?:req|request)\\.(?:query|params|body)\\."
    - "axios(?:\\.(?:get|post|put|delete|patch|head|options|request))?\\s*\\(\\s*(?:req|request)\\.(?:query|params|body)\\."
    - "https?\\.(?:get|request)\\s*\\(\\s*(?:req|request)\\.(?:query|params|body)\\."
    - "(?:fetch|axios|got|request)\\s*\\(\\s*`[^`]*\\$\\{(?:req|request)\\."
    - "axios\\.(?:get|post|put|delete|patch)\\s*\\(\\s*`[^`]*\\$\\{(?:req|request)\\."
  category: kisa-secure-coding
  why_it_matters: >-
    사용자가 제공한 URL을 검증 없이 `fetch`, `axios`, `request`, `http.get`에
    넘기면 공격자가 `http://169.254.169.254/`(클라우드 메타데이터),
    `http://192.168.0.1/admin`(내부망), `file:///etc/passwd` 등을 호출하도록
    조작할 수 있습니다. 공공 클라우드(G-Cloud) 환경에서 IAM 토큰 탈취 및
    내부 행정 시스템 침투의 핵심 경로입니다.
  public_sector_impact:
    - 클라우드 메타데이터 서비스 토큰 탈취
    - 내부망 행정 시스템 침투
    - 접근통제 우회로 인한 정보 조회
  safe_fix: |
    호출 가능한 외부 도메인을 화이트리스트로 관리하세요.
    const WHITELIST = ['www.example.gov.kr', 'api.partner.go.kr'];
    const { hostname, protocol } = new URL(userUrl);
    if (!['https:'].includes(protocol) || !WHITELIST.includes(hostname)) {
      return res.status(400).send('invalid url');
    }
    await fetch(userUrl);
  references:
    - KISA JavaScript 가이드 제1절 12
    - MOIS-49-INPUT-12
    - CWE-918
    - OWASP SSRF Prevention Cheat Sheet
  can_auto_fix: false
examples:
  language: javascript
  positive:
    - "await fetch(req.query.url);"
    - "const r = await axios.get(req.body.target);"
    - "request(`${req.query.host}/api`, (err, response) => res.send(response.body));"
  negative:
    - "const WHITELIST = ['www.example.com']; if (WHITELIST.includes(url)) { await fetch(url); }"
    - "await fetch('https://api.example.gov.kr/health');"
    - "const r = await axios.get(internalConfig.statusUrl);"
---

## 무엇이 위험한가
SSRF는 클라우드 메타데이터(`169.254.169.254`), 내부 관리 페이지(`192.168.x`), `file://` 스킴 등을 서버 권한으로 호출하게 만듭니다. 가이드 §제1절 12는 *식별 가능한 범위 내에서 화이트리스트로 필터링*하고, 부득이한 경우 내부 IP 대역을 블랙리스트로 차단하라고 권고합니다.

## 안전한 패턴 (가이드 원문 인용)
```javascript
const request = require('request');
const express = require('express');

router.get("/patched", async (req, res) => {
  const url = req.query.url;
  const whiteList = ['www.example.com', 'www.safe.com'];
  if (whiteList.includes(url)) {
    await request(url, (err, response) => res.send(response.body));
  } else {
    return res.send('잘못된 요청입니다');
  }
});
```

## False positive 주의
- 정적 URL 호출(`fetch('https://api.example.gov.kr/...')`)은 변수 결합이 없어 매칭되지 않습니다.
- 내부 설정 객체(`internalConfig.statusUrl`)는 사용자 입력이 아니므로 매칭에서 제외됩니다.
- 매칭은 `req.`/`request.` 변수가 직접 인자로 들어간 경우에 한정됩니다. 별도 변수에 담아 검증한 후 호출하는 안전 패턴은 잡지 않습니다.
