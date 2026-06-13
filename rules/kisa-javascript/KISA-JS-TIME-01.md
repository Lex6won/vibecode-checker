---
id: KISA-JS-TIME-01
title_ko: Node.js 종료되지 않는 반복문 또는 재귀 함수 - 기본 케이스 누락으로 스택 오버플로
title_en: Uncontrolled recursion or infinite loop in Node.js (missing base case)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Javascript 시큐어코딩 가이드(2023년 개정본)
    item: 제3절 1. 종료되지 않는 반복문 또는 재귀 함수
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-34
cwe: [CWE-674, CWE-835]
severity: medium
decision_default: warn
domains: [kisa-secure-coding]
languages: [javascript, typescript]
scenarios: [backend-node, web-app, agent]
related_baseline: [MOIS-49-TIME-01]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    - "function\\s+([A-Za-z_$][\\w$]*)\\s*\\([^)]*\\)\\s*\\{(?:(?!\\breturn\\b[^;]*;|\\bif\\s*\\(|\\bthrow\\b|\\?\\s*[^:]+:)[\\s\\S]){0,200}?\\breturn\\b[^;{}]*\\b\\1\\s*\\("
    - "const\\s+([A-Za-z_$][\\w$]*)\\s*=\\s*(?:function\\s*\\([^)]*\\)|\\([^)]*\\)\\s*=>)\\s*\\{(?:(?!\\bif\\s*\\(|\\?\\s*[^:]+:|\\bthrow\\b)[\\s\\S]){0,200}?\\breturn\\b[^;{}]*\\b\\1\\s*\\("
    - "while\\s*\\(\\s*(?:true|1)\\s*\\)\\s*\\{(?:(?!\\bbreak\\b|\\breturn\\b|\\bthrow\\b)[\\s\\S]){0,400}\\}"
    - "for\\s*\\(\\s*;\\s*;\\s*\\)\\s*\\{(?:(?!\\bbreak\\b|\\breturn\\b|\\bthrow\\b)[\\s\\S]){0,400}\\}"
  category: kisa-secure-coding
  why_it_matters: >-
    재귀 함수에 기본 케이스(Base Case)가 없거나 `while(true)` 루프에 종료 조건이
    없으면 *Maximum call stack size exceeded* 예외 또는 CPU 100% 점유로 Node.js
    프로세스가 비정상 종료됩니다. 가이드 §제3절 1은 재귀 호출 횟수를 제한하거나
    종료 조건을 명확히 정의하라고 명시합니다. 공공 민원 API에서 입력값을 그대로
    재귀 호출에 넘기는 경우 DoS 벡터가 됩니다.
  public_sector_impact:
    - 사용자 입력으로 트리거되는 스택 오버플로 DoS
    - 이벤트 루프 블로킹으로 인한 행정 서비스 응답 지연
    - 단일 PID 점유로 인한 클러스터 워커 사망
  safe_fix: |
    재귀 함수는 *기본 케이스*를 가장 위에 두고, 입력값 범위를 미리 검증하세요.
    function factorial(x) {
      if (typeof x !== 'number' || x < 0 || x > 1000) throw new Error('out of range');
      if (x === 0) return 1;
      return x * factorial(x - 1);
    }
    무한 루프는 반드시 `break` 또는 시간/횟수 가드(`if (++i > LIMIT) break;`)를 두세요.
  references:
    - KISA JavaScript 가이드 제3절 1
    - MOIS-49-TIME-01
    - CWE-674
    - CWE-835
  can_auto_fix: false
examples:
  language: javascript
  positive:
    - "function factorial(x) { return x * factorial(x - 1); }"
    - "const sum = (n) => { return n + sum(n - 1); };"
    - "while (true) { processQueue(); doWork(); }"
  negative:
    - "function factorial(x) { if (x === 0) return 1; return x * factorial(x - 1); }"
    - "const sum = (n) => { if (n <= 0) return 0; return n + sum(n - 1); };"
    - "while (true) { const job = queue.pop(); if (!job) break; handle(job); }"
---

## 무엇이 위험한가
종료 조건 없는 재귀 함수는 콜스택을 가득 채워 `Maximum call stack size exceeded` 예외로 프로세스를 죽이며, `while(true)` 무한 루프는 이벤트 루프를 점유해 같은 워커의 모든 요청을 응답 불가 상태로 만듭니다. 사용자 입력값이 재귀 깊이나 루프 조건에 결합되면 외부 공격자가 *원격으로 DoS*를 트리거할 수 있습니다. 가이드 §제3절 1은 *모든 재귀 호출 시 호출 횟수를 제한하거나 재귀 함수 종료 조건을 명확히 정의*하라고 요구합니다.

## 안전한 패턴 (가이드 원문 인용)
```javascript
function factorial(x) {
  // 재귀함수 사용 시에는 탈출 조건을 명시해야 한다
  if (x === 0) {
    return;
  } else {
    return x * factorial(x - 1);
  }
}
```

## False positive 주의
- 재귀 함수 본문에 `if (...)`, `?:` 삼항, `throw`가 보이면 기본 케이스가 있는 것으로 보고 매칭하지 않습니다.
- `while(true)` / `for(;;)` 루프 안에 `break`, `return`, `throw`가 있으면 종료 경로가 있는 것으로 보고 제외합니다.
- 상호 재귀(`a → b → a`) 패턴은 같은 함수명 매칭으로는 잡지 못하므로 코드 리뷰로 보완하세요.
- 명시적 `setImmediate`/`process.nextTick`을 통한 비차단 재귀(이벤트 루프에 양보)는 false positive가 될 수 있으니, 그런 경우 리뷰 시 무시 처리하세요.
