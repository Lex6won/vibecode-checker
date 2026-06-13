---
id: KISA-JS-ENCAP-01
title_ko: Node.js 잘못된 세션에 의한 데이터 정보 노출 - 싱글톤/모듈 전역 상태에 요청 데이터 저장
title_en: Exposure of data element to wrong session in Node.js (singleton/module-scoped state holding request data)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Javascript 시큐어코딩 가이드(2023년 개정본)
    item: 제6절 1. 잘못된 세션에 의한 데이터 정보 노출
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-39
cwe: [CWE-488, CWE-543]
severity: high
decision_default: block
domains: [kisa-secure-coding]
languages: [javascript, typescript]
scenarios: [backend-node, web-app, api]
related_baseline: [MOIS-49-ENCAP-01]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    - "class\\s+\\w*Singleton\\w*\\s*\\{[\\s\\S]{0,800}?if\\s*\\(\\s*instance\\s*\\)\\s*\\{[\\s\\S]{0,200}?return\\s+instance\\s*;[\\s\\S]{0,200}?\\}[\\s\\S]{0,200}?instance\\s*=\\s*this"
    - "(?:^|\\n)\\s*let\\s+instance\\s*;[\\s\\S]{0,400}?class\\s+\\w+\\s*\\{[\\s\\S]{0,600}?instance\\s*=\\s*this"
    - "(?:router|app)\\.(?:get|post|put|delete|patch|use)\\s*\\(\\s*['\"][^'\"]+['\"]\\s*,\\s*(?:async\\s*)?\\([^)]*req[^)]*\\)\\s*=>\\s*\\{[\\s\\S]{0,400}?(?:globalThis|global)\\.\\w+\\s*=\\s*req\\.(?:body|query|params|session)"
  category: kisa-secure-coding
  why_it_matters: >-
    Node.js의 모듈 스코프 변수와 싱글톤 인스턴스 필드는 *모든 요청이 공유*합니다.
    싱글톤 클래스의 인스턴스 필드에 요청별 데이터(`this.userName = req.body.user`)를
    저장하거나 `globalThis.currentUser` 같은 전역 변수에 세션 데이터를 담으면,
    동시에 들어온 다른 사용자의 요청이 직전 요청자의 데이터를 그대로 받아갑니다.
    가이드 §제6절 1은 *서로 다른 세션에서 데이터를 공유하지 않도록* 일반 클래스로
    인스턴스화하라고 명시합니다. 공공 민원/결제 시스템에서 발생하면 *세션 혼선*으로
    민원인 A가 시민 B의 주민등록번호를 보게 되는 *치명적 개인정보 노출*이 됩니다.
  public_sector_impact:
    - 동시 요청 시 타인의 주민등록번호/민원 내용 노출(세션 혼선)
    - 결제·신청 시스템에서 사용자 식별 정보 교차 오류
    - 감사 로그가 잘못된 시민에게 귀속되어 책임 추적 실패
  safe_fix: |
    공유가 금지된 사용자 데이터는 싱글톤/모듈 전역이 아니라 *요청 스코프*에서
    인스턴스화하세요. Express는 요청마다 핸들러가 새로 호출되므로 핸들러 내부에서
    `const user = new User(req.body)` 형태로 *지역 변수*로 만드세요. 진짜 싱글톤이
    필요한 객체(DB 풀, 로거)는 *요청 데이터를 필드로 들고 있지 않도록* 메소드 인자로만
    받아 처리합니다.
    router.get('/profile', (req, res) => {
      const user = new User(req.session.userId);  // 요청별 인스턴스
      return res.send(user.getProfile());
    });
  references:
    - KISA JavaScript 가이드 제6절 1
    - MOIS-49-ENCAP-01
    - CWE-488
    - CWE-543
    - OWASP Sensitive Data Exposure
  can_auto_fix: false
examples:
  language: javascript
  positive:
    - "let instance; class UserSingleton { constructor() { this.userName = 'testUser'; if (instance) { return instance; } instance = this; } getUserProfile() { return this.userName; } }"
    - "class SessionSingleton { constructor(user) { this.user = user; if (instance) { return instance; } instance = this; } }"
    - "app.post('/login', (req, res) => { globalThis.currentUser = req.body.user; return res.send('ok'); });"
  negative:
    - "class User { constructor() { this.userName = 'testUser'; } getUserProfile() { return this.userName; } } router.get('/patched', (req, res) => { const user = new User(); return res.send(user.getUserProfile()); });"
    - "router.get('/profile', (req, res) => { const profile = { user: req.session.userId, ts: Date.now() }; return res.send(profile); });"
    - "const pool = mysql.createPool(config); router.get('/data', async (req, res) => { const [rows] = await pool.query('SELECT 1'); res.json(rows); });"
---

## 무엇이 위험한가
Node.js는 단일 프로세스에서 이벤트 루프로 다수 요청을 처리합니다. 모듈 최상위에서 `let instance`로 선언한 변수나 `class Singleton`의 인스턴스 필드는 *전체 요청이 같은 메모리를 공유*합니다. 가이드 §제6절 1의 안전하지 않은 예제는 `UserSingleton`이 `this.userName`을 인스턴스에 저장한 뒤 두 번째 요청에서도 같은 객체를 재사용해 *직전 요청자의 이름*을 그대로 응답합니다. 동시성이 높은 공공 포털에서는 시민 A의 민원 데이터가 시민 B의 화면에 표시되는 *세션 혼선* 결함이 됩니다.

## 안전한 패턴 (가이드 원문 인용)
```javascript
class User {
  constructor() {
    this.userName = 'testUser';
  }
  getUserProfile() {
    return this.userName;
  }
};
router.get("/patched", (req, res) => {
  const user = new User();
  const profile = user.getUserProfile();
  // 서로 다른 세션에서 공유되지 않는 클래스 정의를 사용해 안전함
  return res.send(profile);
});
```

## False positive 주의
- *상태가 없는* 진짜 싱글톤(DB 커넥션 풀, 로거, 설정 객체)은 요청 데이터를 필드로 들고 있지 않으므로 안전합니다. 첫 번째/두 번째 패턴은 `instance = this` + `if (instance) return instance` 구조에 한해서만 매칭합니다.
- 클래스명에 `Singleton`이 들어가지 않더라도 모듈 최상위에 `let instance;`가 있고 클래스 안에서 `instance = this`로 캐싱하는 패턴은 두 번째 패턴이 잡습니다.
- 세 번째 패턴은 핸들러 본문에서 `globalThis.X = req.body...` 또는 `global.X = req.session...`처럼 *명시적으로 전역에 요청 데이터를 쓰는* 코드만 매칭합니다. 일반 지역변수(`const user = req.body.user`)는 매칭하지 않습니다.
- React/Redux의 store처럼 *클라이언트 측* 싱글톤은 브라우저 인스턴스당 하나이므로 다중 세션 혼선이 없습니다. 본 룰은 서버사이드(Express/Koa/NestJS) 핸들러에서의 모듈 전역 공유를 대상으로 합니다.
