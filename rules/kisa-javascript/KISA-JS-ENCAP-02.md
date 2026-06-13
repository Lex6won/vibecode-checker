---
id: KISA-JS-ENCAP-02
title_ko: JavaScript 제거되지 않고 남은 디버그 코드 - 운영 배포본의 console.log/debugger/source map 노출
title_en: Active debug code left in production JavaScript (console.log/debugger/source map exposure)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Javascript 시큐어코딩 가이드(2023년 개정본)
    item: 제6절 2. 제거되지 않고 남은 디버그 코드
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-40
cwe: [CWE-489, CWE-215]
severity: medium
decision_default: warn
domains: [kisa-secure-coding]
languages: [javascript, typescript]
scenarios: [frontend, backend-node, web-app]
related_baseline: [MOIS-49-ENCAP-02]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    - "(?:^|[\\s;{}])debugger\\s*;"
    - "console\\.(?:log|debug|info|trace|dir)\\s*\\(\\s*(?:'|\"|`)?(?:DEBUG|TODO|FIXME|XXX|HACK|TEST|password|token|secret|apiKey|api_key|jwt|session)"
    - "console\\.(?:log|debug|info)\\s*\\(\\s*(?:req\\.body|req\\.headers|req\\.session|process\\.env|user\\.password|jwt|token|apiKey|api_key|secret)"
    - "alert\\s*\\(\\s*(?:'|\"|`)?(?:DEBUG|TEST|TODO|XXX)"
  category: kisa-secure-coding
  why_it_matters: >-
    배포 빌드에 남은 `console.log(req.body)`, `console.log(process.env)`,
    `debugger;`, 또는 `console.log('DEBUG token=' + token)`은 *민감 정보 누출*과
    *공격자 정찰 보조*로 직결됩니다. 프런트엔드 번들에 남은 로그는 브라우저 콘솔
    누구나 볼 수 있고, 서버 측 로그는 컨테이너 stdout을 통해 비인가 운영자에게
    노출됩니다. 가이드 §제6절 2는 *배포 전 반드시 디버그 코드를 확인 및 삭제*하고
    `if (process.env.NODE_ENV === 'production') console.log = () => {}` 처럼 운영
    환경에서는 *완전히 비활성화*하라고 명시합니다.
  public_sector_impact:
    - JWT/세션 토큰이 프런트엔드 콘솔에 평문 출력되어 계정 탈취
    - process.env 출력으로 DB 비밀번호·KMS 키 ID 노출
    - debugger 구문이 운영 배포되어 DevTools만 열면 실행 중단/단계 실행 가능
  safe_fix: |
    1) 운영 빌드에서 console을 무력화하세요(가이드 권장):
       if (process.env.NODE_ENV === 'production') {
         console.log = console.debug = console.info = () => {};
       }
    2) 빌드 도구로 일괄 제거: webpack `terser-webpack-plugin`의 `drop_console: true`,
       Vite의 `esbuild.drop: ['console', 'debugger']`, Babel `babel-plugin-transform-remove-console`.
    3) 민감 정보 로깅 자체를 금지하고, 서버 로그는 pino/winston처럼 *구조화 로거 +
       redaction*을 사용하세요(`{ redact: ['req.headers.authorization', '*.password'] }`).
  references:
    - KISA JavaScript 가이드 제6절 2
    - MOIS-49-ENCAP-02
    - CWE-489
    - OWASP Information Leakage
  can_auto_fix: true
examples:
  language: javascript
  positive:
    - "function login(user) { debugger; return api.post('/login', user); }"
    - "console.log('DEBUG token=' + jwt); res.send('ok');"
    - "app.post('/login', (req, res) => { console.log(req.body); res.send('ok'); });"
  negative:
    - "if (process.env.NODE_ENV === 'production') { console.log = () => {}; } logger.info({ event: 'login', userId: user.id }, 'login ok');"
    - "logger.info({ userId: user.id }, 'login complete');"
    - "console.error(err.message);"
---

## 무엇이 위험한가
디버그 코드는 *원래 개발자만 볼 의도였던 정보*를 광범위하게 노출합니다. (1) `debugger;`는 브라우저 DevTools가 열려 있으면 실행을 멈추고 공격자가 변수 상태를 단계 실행할 수 있게 합니다. (2) `console.log(req.body)`는 입력 페이로드(비밀번호 포함)를 그대로 stdout으로 보내 컨테이너 로그 수집기에 남깁니다. (3) `console.log(process.env)`는 DB 비밀번호, JWT 시크릿, KMS 키 ID를 한 줄로 유출합니다. 가이드 §제6절 2의 안전 예시는 운영 환경에서 `console.log = () => {}`로 *함수 자체를 무력화*하는 패턴을 권장합니다.

## 안전한 패턴 (가이드 원문 인용)
```javascript
// 애플리케이션 진입 코드인 Index.js에 다음 코드를 추가하면
// 코드 내에 삭제되지 않은 모든 console.log 코드로 인해 아무런 내용도 출력되지 않음
if (process.env.NODE_ENV === 'production' && typeof window !== 'undefined') {
  console.log = () => {};
}

// 서버 진입 코드인 index.js 내의 서버 구동 부분
app.listen(80, () => {
  if (!process.env.DEBUG) {
    console.log = function(){};
  }
});
```

## False positive 주의
- 구조화 로거(`logger.info`, `logger.error`, `winston`, `pino`)는 매칭하지 않습니다. 운영 환경에서도 정상적으로 사용해야 하며, redaction을 함께 적용하세요.
- `console.error(err.message)` 처럼 *일반 에러 메시지*만 출력하는 구문은 매칭하지 않습니다. 단, `err.stack` 직접 출력은 정보노출 관점에서 별도 점검이 필요합니다.
- 첫 번째 패턴(`debugger;`)은 어떤 위치든 매칭됩니다. 단위 테스트 안의 의도적 디버그도 잡힐 수 있으니, 테스트 파일은 스캔 대상에서 제외하거나 주석으로 명시하세요.
- 두 번째/세 번째 패턴은 *민감 키워드*(password, token, secret, req.body, process.env 등)가 console 인자에 나타날 때만 매칭하므로 일반 디버그 로그 전체를 막지는 않습니다. 빌드 시점의 일괄 제거(`drop_console`)와 병행하세요.
