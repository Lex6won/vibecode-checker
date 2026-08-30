---
id: KISA-JS-INPUT-02
title_ko: JavaScript 코드 삽입 위험 - eval, new Function, setTimeout/setInterval(문자열)
title_en: JavaScript code injection (eval, new Function, setTimeout(string))
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Javascript 시큐어코딩 가이드(2023년 개정본)
    item: 제2절 2. 코드 삽입
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-21
cwe: [CWE-94, CWE-95]
severity: critical
decision_default: block
domains: [kisa-secure-coding]
languages: [javascript, typescript]
scenarios: [web-app, llm-integration, agent, backend-node]
related_baseline: [MOIS-49-INPUT-02]
verified_at: 2026-05-31
review_due: 2026-11-30
detection:
  patterns:
    - '(?<![A-Za-z0-9_$.])eval\s*\('
    - 'new\s+Function\s*\('
    - "setTimeout\\s*\\(\\s*[\"'`]"
    - "setInterval\\s*\\(\\s*[\"'`]"
    - 'vm\.runInNewContext\s*\('
    - 'vm\.runInThisContext\s*\('
  # 같은 코드를 다른 각도로 보는 룰과 한 묶음(KISA-JS-API-02). 같은 줄에 함께 걸리면
  # 가장 확실한 엔진의 발견 하나만 남고 나머지는 also_matched 로 합쳐진다(개선요청 #34 C).
  dedup_group: js-code-exec
  category: kisa-secure-coding
  why_it_matters: >-
    JavaScript에서 eval / new Function / 문자열을 받은 setTimeout·setInterval /
    vm.runIn*는 *문자열을 코드로 실행*합니다. 사용자 입력이나 LLM 출력이
    이 경로에 들어가면 즉시 XSS·RCE로 발전합니다. 챗봇·민원 시스템·자동화
    에이전트에서 가장 위험한 패턴 중 하나입니다.
  public_sector_impact:
    - 브라우저 XSS로 세션·CSRF 토큰 탈취
    - Node.js 서버 RCE
    - LLM 출력 처리로 인한 RCE
  safe_fix: |
    문자열을 코드로 실행해야 할 정당한 사유가 거의 없습니다.
    수식: 별도 파서 사용(mathjs.evaluate 안전 모드 등).
    동적 데이터: JSON.parse 사용.
    setTimeout/setInterval은 *함수 콜백*만 전달하세요: setTimeout(() => doX(), 1000)
  references:
    - KISA JavaScript 가이드 제2절 2
    - MOIS-49-INPUT-02
    - CWE-94
    - OWASP LLM05 Improper Output Handling
  can_auto_fix: false
examples:
  language: javascript
  positive:
    - "eval(userInput);"
    - "new Function('return ' + x);"
    - 'setTimeout("doX()", 1000);'
  negative:
    - "engine.eval(expr);"
    - "let f = (x) => x * 2;"
    - "setTimeout(() => doX(), 1000);"
---

## 무엇이 위험한가
`eval`은 모든 보안 가이드에서 사용 금지 1순위입니다. 그러나 `new Function("return " + x)`, `setTimeout("doX()", 1000)`, `vm.runInThisContext(code)` 같은 *간접 eval*도 동일하게 위험합니다. AI 코딩 도우미가 자주 제안하는 패턴이라 가드레일이 꼭 필요합니다.

## 안전한 패턴 (가이드 원문 인용)
```javascript
// 수식
import { evaluate } from "mathjs";
const r = evaluate(userExpr, { scope });           // limited scope

// JSON
const obj = JSON.parse(rawText);

// 콜백
setTimeout(() => handleX(), 1000);
```

## False positive 주의
- `obj.eval()` 같은 메소드는 lookbehind로 제외합니다.
- 라이브러리가 내부적으로 사용하는 eval은 검사 대상에 포함되지 않게 `_test.js`, `node_modules/` 등은 스캐너가 자동 제외합니다.
