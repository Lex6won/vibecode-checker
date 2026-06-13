---
id: KISA-JS-SEC-11
title_ko: Node.js 부적절한 인증서 유효성 검증 - rejectUnauthorized:false / NODE_TLS_REJECT_UNAUTHORIZED=0
title_en: Improper TLS certificate validation in Node.js (rejectUnauthorized:false, NODE_TLS_REJECT_UNAUTHORIZED=0)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Javascript 시큐어코딩 가이드(2023년 개정본)
    item: 제2절 11. 부적절한 인증서 유효성 검증
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-42
cwe: [CWE-295, CWE-297]
severity: high
decision_default: block
domains: [kisa-secure-coding]
languages: [javascript, typescript]
scenarios: [backend-node, web-app, agent, llm-integration]
related_baseline: [MOIS-49-SEC-11]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    - "rejectUnauthorized\\s*:\\s*false"
    - "process\\.env\\.NODE_TLS_REJECT_UNAUTHORIZED\\s*=\\s*['\"]?0['\"]?"
    - "(?:NODE_TLS_REJECT_UNAUTHORIZED)\\s*=\\s*['\"]?0['\"]?"
    - "new\\s+https\\.Agent\\s*\\(\\s*\\{[^}]*rejectUnauthorized\\s*:\\s*false"
    - "(?:axios|got|node-fetch|undici)[^;]{0,200}rejectUnauthorized\\s*:\\s*false"
  category: kisa-secure-coding
  why_it_matters: >-
    `rejectUnauthorized: false` 또는 `process.env.NODE_TLS_REJECT_UNAUTHORIZED='0'`을
    설정하면 만료·자가서명·호스트명 불일치 등 *모든 TLS 인증서 오류를 무시*합니다.
    이 경우 같은 네트워크 구간의 공격자가 *중간자 공격(MITM)*으로 트래픽을 가로채
    응답 데이터를 위·변조하거나 자격증명을 탈취할 수 있습니다. 가이드 §제2절 11은
    https.request의 `rejectUnauthorized` 옵션을 *항상 true*로 두라고 명시합니다.
    공공 백엔드가 외부 API를 호출할 때 이 옵션 한 줄로 G-Cloud 내부망 MITM이
    가능해지므로 운영 배포에서는 반드시 차단해야 합니다.
  public_sector_impact:
    - 공공기관 API 호출 시 MITM 공격으로 인증 토큰·민원 데이터 탈취
    - 외부 결제·전자서명 게이트웨이 응답 위변조
    - 사설 인증서 사용 회피로 인한 시스템 전반 신뢰체계 붕괴
  safe_fix: |
    1) 검증을 끄지 마세요. 기본값(true)을 유지합니다.
       const options = { hostname: 'api.partner.go.kr', port: 443, rejectUnauthorized: true };
       https.request(options, ...);
    2) 사설(내부) CA를 써야 한다면 *해당 CA만* 신뢰 목록에 추가하세요.
       const ca = fs.readFileSync('/etc/ssl/internal-ca.pem');
       https.request({ ..., ca, rejectUnauthorized: true });
    3) 개발 중에도 NODE_TLS_REJECT_UNAUTHORIZED=0 사용 금지.
       대신 mkcert 등으로 로컬 신뢰 CA를 발급해 사용하세요.
  references:
    - KISA JavaScript 가이드 제2절 11
    - MOIS-49-SEC-11
    - CWE-295
    - OWASP TLS Cheat Sheet
    - Node.js https.request docs
  can_auto_fix: false
examples:
  language: javascript
  positive:
    - "const options = { hostname: 'api.example.com', port: 443, rejectUnauthorized: false }; https.request(options);"
    - "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';"
    - "const agent = new https.Agent({ rejectUnauthorized: false }); axios.get(url, { httpsAgent: agent });"
  negative:
    - "const options = { hostname: 'api.partner.go.kr', port: 443, rejectUnauthorized: true }; https.request(options);"
    - "const ca = fs.readFileSync('/etc/ssl/internal-ca.pem'); https.request({ hostname: 'internal', ca, rejectUnauthorized: true });"
    - "axios.get('https://api.example.gov.kr/health');"
---

## 무엇이 위험한가
TLS 인증서 검증은 *통신 상대가 진짜 그 서버인지* 확인하는 마지막 방어선입니다. `rejectUnauthorized: false`로 검증을 끄면 (1) 자가서명 인증서로 위장한 *MITM 프록시*가 트래픽을 들여다볼 수 있고, (2) DNS 스푸핑·라우팅 변조와 결합해 공격자 서버로 요청이 흘러가도 클라이언트는 알아차리지 못합니다. `process.env.NODE_TLS_REJECT_UNAUTHORIZED='0'`은 *프로세스 전역*으로 동일한 효과를 내므로 더욱 위험합니다. 가이드 §제2절 11의 안전 예시는 옵션을 `true`로 두고 잘못된 인증서를 만나면 *예외를 발생시켜 연결을 중단*하는 흐름을 권장합니다.

## 안전한 패턴 (가이드 원문 인용)
```javascript
const express = require('express');
const https = require('https');

const getServer = () => {
  const options = {
    hostname: "dangerous.website",
    port: 443,
    method: "GET",
    path: "/",
    // 유효하지 않은 인증서 발견 시 예외 발생
    rejectUnauthorized: true
  };
  const hreq = https.request(options, (response) => {
    console.log('response - ', response.statusCode);
  });
  hreq.on('error', (e) => {
    console.error(' 에러발생 - ', e);
  });
};
```

## False positive 주의
- 정상적으로 `rejectUnauthorized: true`를 명시한 코드는 첫 번째 패턴(false 전용)과 매칭되지 않습니다.
- 환경변수 `NODE_TLS_REJECT_UNAUTHORIZED`를 *`'1'`로 명시*하는 코드(검증 강화) 역시 패턴 `=0` 부분이 일치하지 않아 매칭되지 않습니다.
- 테스트 코드에서 일시적으로 검증을 끄는 경우라도 운영 빌드에 포함되면 동일한 위험이 발생합니다. 환경별 설정 분기(`process.env.NODE_ENV !== 'production'`)와 별개로 *운영 코드에는 절대 들어가지 않도록* 빌드 검증 단계에 본 룰을 포함시키세요.
- axios·got·undici 등 HTTP 클라이언트에 `rejectUnauthorized: false`를 옵션으로 넘기는 경우도 동일한 위험으로 매칭됩니다.
