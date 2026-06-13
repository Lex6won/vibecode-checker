---
id: KISA-JS-API-01
title_ko: Node.js DNS lookup에 의존한 보안결정 - 호스트명 비교로 인가/접근통제 판단
title_en: Reliance on DNS lookup for security decision in Node.js (hostname comparison for auth)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Javascript 시큐어코딩 가이드(2023년 개정본)
    item: 제7절 1. DNS lookup에 의존한 보안결정
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-46
cwe: [CWE-350, CWE-247, CWE-807]
severity: high
decision_default: block
domains: [kisa-secure-coding]
languages: [javascript, typescript]
scenarios: [auth, backend-node, web-app]
related_baseline: [MOIS-49-API-01]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    - "dns\\.(?:lookup|reverse|resolve(?:4|6|Ptr)?)\\s*\\([^)]*\\)[\\s\\S]{0,400}?(?:if|return|===|!==)\\s*[\\s\\S]{0,100}?(?:trusted|allowed|isAdmin|authorize|role|whitelist)"
    - "if\\s*\\(\\s*(?:req\\.(?:hostname|headers\\.host)|hostname|host)\\s*===\\s*['\"][^'\"]*\\.(?:com|net|org|gov|kr|go\\.kr|or\\.kr)['\"]"
    - "(?:req\\.headers\\.host|req\\.hostname)\\s*===\\s*(?:trustedHost|allowedHost|whitelist|allowList)"
    - "if\\s*\\(\\s*(?:hostName|hostname|host)\\s*===\\s*trustedHost\\s*\\)\\s*\\{[\\s\\S]{0,200}?trusted\\s*=\\s*true"
  category: kisa-secure-coding
  why_it_matters: >-
    `dns.lookup()` 결과나 `req.headers.host` 같은 호스트명을 그대로 보안 결정
    (인증/인가/접근통제)에 사용하면, 공격자가 DNS 캐시 포이즈닝, Host 헤더
    주입, 또는 hosts 파일 조작으로 신뢰 도메인을 위장할 수 있습니다. 가이드
    §제7절 1은 *도메인명에 의존해서 보안결정을 하지 않아야 한다*고 명시하며,
    IP 주소를 직접 비교하거나 mTLS·서명 토큰 같은 암호학적 신원 확인을
    사용하라고 요구합니다. 공공 G-Cloud 내부 API 호출에서 흔히 발견됩니다.
  public_sector_impact:
    - DNS 스푸핑으로 신뢰 서버 위장, 행정 데이터 탈취
    - Host 헤더 주입으로 관리자 페이지 접근 우회
    - 내부망 IP 변경 시 트러스트 경계 잘못 설정
  safe_fix: |
    호스트명 대신 *IP 주소 직접 비교* 또는 *암호학적 신원 확인*을 사용하세요.
    1) IP 비교: const trustedIp = '142.250.207.100'; if (req.socket.remoteAddress === trustedIp) ...
    2) mTLS 클라이언트 인증서 검증.
    3) JWT/HMAC 서명 토큰.
    Host 헤더는 신뢰할 수 없는 사용자 입력으로 취급하세요(Express의 trust proxy
    설정 점검 포함).
  references:
    - KISA JavaScript 가이드 제7절 1
    - MOIS-49-API-01
    - CWE-350
    - OWASP Host Header Injection
  can_auto_fix: false
examples:
  language: javascript
  positive:
    - "const trustedHost = 'www.google.com'; const hostName = req.query.host; if (hostName === trustedHost) { trusted = true; }"
    - "dns.lookup(req.query.host, (err, addr) => { if (addr === '8.8.8.8') { allowed = true; res.send('ok'); } });"
    - "if (req.headers.host === 'admin.example.go.kr') { return next(); } return res.status(403).send('no');"
  negative:
    - "const trustedIp = '142.250.207.100'; if (req.socket.remoteAddress === trustedIp) { trusted = true; }"
    - "const ok = jwt.verify(req.headers.authorization, PUBLIC_KEY); if (ok) return next();"
    - "if (req.client.authorized && req.client.getPeerCertificate().subject.CN === 'partner.gov.kr') { return next(); }"
---

## 무엇이 위험한가
DNS 응답은 *인증된 채널이 아닙니다*. 공격자는 (1) 재귀 리졸버 캐시 오염, (2) ARP/라우팅 조작, (3) 호스트 파일 수정, (4) HTTP Host 헤더 주입을 통해 호스트명 기반 비교를 우회할 수 있습니다. 가이드 §제7절 1은 *공격자가 DNS 엔트리를 속일 수 있으므로 도메인명에 의존해서 보안결정을 하지 않아야 한다*고 명시합니다. 특히 공공 G-Cloud 내부 API 게이트웨이가 `req.headers.host` 또는 `dns.reverse(remoteAddress)`로 신뢰 판단을 한다면, 단일 Host 헤더 조작으로 관리자 API에 접근할 수 있습니다.

## 안전한 패턴 (가이드 원문 인용)
```javascript
router.get("/patched", async (req, res) => {
  let trusted = false;
  const trustedHost = "142.250.207.100";
  // 실제 서버의 IP 주소를 비교하여 DNS 변조에 대응
  async function dnsLookup() {
    return new Promise((resolve, reject) => {
      dns.lookup(req.query.host, 4, (err, address, family) => {
        if (err) reject(err);
        resolve(address);
      });
    });
  }
  const hostName = await dnsLookup();
  if (hostName === trustedHost) {
    trusted = true;
  }
  return res.send({ trusted });
});
```

## False positive 주의
- `req.socket.remoteAddress` 또는 `req.client.getPeerCertificate()` 기반 비교는 네트워크/TLS 계층 식별이므로 매칭하지 않습니다.
- JWT/HMAC/세션 토큰 검증을 통한 신뢰 판단은 암호학적 신원 확인이므로 매칭하지 않습니다.
- 단순 로깅·라우팅 용도로 `req.hostname`을 참조하는 코드는 보안 결정이 아니므로 매칭에서 제외됩니다. 패턴은 `trusted`, `allowed`, `authorize`, `role`, `whitelist`, `isAdmin` 같은 *보안 변수* 키워드가 동반될 때만 매칭합니다.
- IP 비교 자체도 SNAT/프록시 환경에서는 우회 가능하므로, 가능하면 mTLS를 함께 적용하세요.
