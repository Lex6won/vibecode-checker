---
id: KISA-JS-ENCAP-04
title_ko: JavaScript Private 배열에 Public 데이터 할당 - 사용자 입력을 검증 없이 #private 필드에 대입
title_en: Public data assigned to private array in JavaScript (storing untrusted input in #private fields)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Javascript 시큐어코딩 가이드(2023년 개정본)
    item: 제6절 4. Private 배열에 Public 데이터 할당
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-42
cwe: [CWE-496]
severity: medium
decision_default: warn
domains: [kisa-secure-coding]
languages: [javascript, typescript]
scenarios: [backend-node, web-app, frontend]
related_baseline: [MOIS-49-ENCAP-04]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    - "class\\s+\\w+\\s*\\{[\\s\\S]{0,1200}?#(\\w+)\\s*=\\s*\\[[\\s\\S]{0,200}?\\][\\s\\S]{0,800}?(?:\\w+)\\s*=\\s*\\(\\s*(\\w+)\\s*\\)\\s*=>\\s*\\{[\\s\\S]{0,200}?this\\.#\\1\\s*=\\s*\\2\\s*;"
    - "class\\s+\\w+\\s*\\{[\\s\\S]{0,1200}?#(\\w+)\\s*=\\s*\\[[\\s\\S]{0,200}?\\][\\s\\S]{0,800}?(?:set\\s+\\w+\\s*\\(\\s*(\\w+)\\s*\\)|\\w+\\s*\\(\\s*(\\w+)\\s*\\))\\s*\\{[\\s\\S]{0,200}?this\\.#\\1\\s*=\\s*(?:\\2|\\3)\\s*;"
    - "class\\s+\\w+\\s*\\{[\\s\\S]{0,1200}?_(\\w+)\\s*=\\s*\\[[\\s\\S]{0,200}?\\][\\s\\S]{0,800}?(?:\\w+)\\s*\\(\\s*(\\w+)\\s*\\)\\s*\\{[\\s\\S]{0,200}?this\\._\\1\\s*=\\s*\\2\\s*;"
  category: kisa-secure-coding
  why_it_matters: >-
    `set_private_member = (input_list) => { this.#privArray = input_list }`처럼
    *사용자 입력 참조를 그대로 private 필드에 대입*하면, 호출자가 여전히
    `input_list`의 참조를 들고 있어 *클래스 외부에서 내부 private 상태를 자유롭게
    변조*할 수 있습니다. 캡슐화가 무력화되고 검증되지 않은 입력이 내부 신뢰
    경계 안으로 그대로 침투합니다. 가이드 §제6절 4는 *사용자가 전달한 값으로
    클래스 외부에서 private 값을 변경해서는 안 되며, 별도 인스턴스 변수로
    정의하거나 전달된 값의 정상 여부를 검증한 후 적용*하라고 명시합니다.
  public_sector_impact:
    - 권한/역할 배열을 외부 참조로 변조해 관리자 권한 획득
    - 결재선/승인자 배열을 호출자가 사후 변조해 결재 우회
    - 캐시·세션 객체에 검증 없는 원본 참조 저장으로 데이터 무결성 손상
  safe_fix: |
    1) *복사 + 검증* 후 대입(가이드 권장):
       set_private_member = (input_list) => {
         if (!Array.isArray(input_list)) throw new TypeError('expected array');
         // 정상성 검증 + 복사
         this.#privArray = input_list.map(item => sanitize(item));
       }
    2) 또는 private가 아닌 의도된 public 필드에 저장(가이드의 두 번째 안전 예시):
       set_private_member = (input_list) => { this.userInput = input_list; }
    3) JSON Schema/zod 같은 스키마 검증을 거친 *복사된* 값만 내부에 보관하세요.
  references:
    - KISA JavaScript 가이드 제6절 4
    - MOIS-49-ENCAP-04
    - CWE-496
    - MDN Object.assign
    - MDN Private class fields
  can_auto_fix: false
examples:
  language: javascript
  positive:
    - "class UserObj { #privArray = []; set_private_member = (input_list) => { this.#privArray = input_list; } }"
    - "class Cart { #items = []; setItems(items) { this.#items = items; } }"
    - "class Acl { _roles = []; setRoles(roles) { this._roles = roles; } }"
  negative:
    - "class UserObj2 { #privArray = []; set_private_member = (input_list) => { this.userInput = input_list; } }"
    - "class Cart { #items = []; setItems(items) { if (!Array.isArray(items)) throw new TypeError('arr'); this.#items = items.map(x => ({ ...x })); } }"
    - "class Acl { #roles = []; setRoles(roles) { this.#roles = [...roles].filter(r => ALLOWED.includes(r)); } }"
---

## 무엇이 위험한가
`this.#privArray = input_list`는 *대입이 아니라 참조 공유*입니다. 호출자가 같은 `input_list` 변수를 들고 `input_list.push('admin')` 하면, 클래스 내부의 `#privArray`도 같이 바뀝니다. 가이드 §제6절 4의 안전하지 않은 예제는 `set_private_member`가 외부 인자를 그대로 `#privArray`에 대입해, 캡슐화로 보호되어야 할 private 배열을 *클래스 외부 코드가 사후에 자유롭게 변조*할 수 있게 만듭니다. 이는 권한 목록·결재선·세션 같은 보안 데이터에서 *권한 상승*과 *데이터 변조* 취약점이 됩니다.

## 안전한 패턴 (가이드 원문 인용)
```javascript
class UserObj2 {
  #privArray = [];

  // 사용자가 전달한 값을 private가 아닌 public 배열로 저장
  set_private_member = (input_list) => {
    this.userInput = input_list;
  }
}
```
또는 private을 유지하면서 *검증 + 복사* 후 저장:
```javascript
set_private_member = (input_list) => {
  if (!Array.isArray(input_list)) throw new TypeError('expected array');
  this.#privArray = input_list.map(item => sanitize(item));
}
```

## False positive 주의
- *복사 후 대입*은 매칭에서 제외됩니다: `this.#x = [...input]`, `this.#x = Array.from(input)`, `this.#x = input.map(...)`, `this.#x = structuredClone(input)`.
- 원시값 대입(`this.#count = n`)은 mutable 참조가 아니므로 매칭하지 않습니다. 패턴은 `#field = [...]` 초기화 + 인자 직접 대입에 한정합니다.
- 검증을 별도 함수에 위임한 경우(`this.#x = validate(input)`)도 일반적으로 매칭에서 제외됩니다(인자명과 다른 식별자 대입).
- 언더스코어 컨벤션(`_roles`)도 세 번째 패턴에서 검사합니다. ES2022 이전 코드 마이그레이션 시 확인하세요.
- TypeScript `private` 키워드는 런타임에 보장되지 않으므로 본 룰의 직접 대상이 아니지만, 같은 위험을 갖습니다. 별도 리뷰가 필요합니다.
