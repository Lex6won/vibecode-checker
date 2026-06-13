---
id: KISA-JS-ENCAP-03
title_ko: JavaScript Public 메소드로부터 반환된 Private 배열 - 내부 mutable 객체 참조 직접 반환
title_en: Private array returned from public method in JavaScript (returning internal mutable reference)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Javascript 시큐어코딩 가이드(2023년 개정본)
    item: 제6절 3. Public 메소드로부터 반환된 Private 배열
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-41
cwe: [CWE-495]
severity: medium
decision_default: warn
domains: [kisa-secure-coding]
languages: [javascript, typescript]
scenarios: [backend-node, web-app, frontend]
related_baseline: [MOIS-49-ENCAP-03]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    - "class\\s+\\w+\\s*\\{[\\s\\S]{0,1200}?#(\\w+)\\s*=\\s*\\[[\\s\\S]{0,200}?\\][\\s\\S]{0,800}?(?:get\\s+\\w+\\s*\\(\\s*\\)|\\w+\\s*=\\s*\\([^)]*\\)\\s*=>|\\w+\\s*\\([^)]*\\))\\s*\\{[\\s\\S]{0,200}?return\\s+this\\.#\\1\\s*;"
    - "class\\s+\\w+\\s*\\{[\\s\\S]{0,1200}?_(\\w+)\\s*=\\s*\\[[\\s\\S]{0,200}?\\][\\s\\S]{0,800}?(?:get\\s+\\w+\\s*\\(\\s*\\)|\\w+\\s*\\([^)]*\\))\\s*\\{[\\s\\S]{0,200}?return\\s+this\\._\\1\\s*;"
    - "class\\s+\\w+\\s*\\{[\\s\\S]{0,1200}?#(\\w+)\\s*=\\s*\\{[\\s\\S]{0,200}?\\}[\\s\\S]{0,800}?(?:get\\s+\\w+\\s*\\(\\s*\\)|\\w+\\s*\\([^)]*\\))\\s*\\{[\\s\\S]{0,200}?return\\s+this\\.#\\1\\s*;"
  category: kisa-secure-coding
  why_it_matters: >-
    JavaScript의 `#privateField`는 *외부에서 직접 접근*은 막지만, 그 안에 든
    *배열/객체 참조를 그대로 return* 하면 호출자가 받은 참조로 내부 상태를 마음대로
    변조할 수 있습니다. `obj.get_private_member().push(...)`로 외부에서 클래스
    내부 데이터를 *추가/삭제/수정*할 수 있어 캡슐화가 무력화됩니다. 가이드 §제6절 3은
    *복사본을 반환하도록 하고 배열의 원소에 대해서는 Object.assign()을 통해 복사된
    원소를 저장*하라고 명시합니다. 행정 시스템의 권한 목록·세션 데이터·결재선
    배열이 이렇게 반환되면 권한 우회와 데이터 변조로 이어집니다.
  public_sector_impact:
    - 권한 목록/결재선 배열을 외부에서 변조해 권한 상승
    - 세션 사용자 객체 필드 변조로 ID 가로채기
    - 캐시된 민감 정보 객체가 외부 변조로 손상되어 무결성 위반
  safe_fix: |
    내부 mutable 객체는 *얕은/깊은 복사본*을 반환하세요(가이드 권장 패턴).
    class UserObj {
      #privArray = [];
      get_private_member = () => {
        // 새로운 객체를 생성하여 값을 반환 — 외부와 내부 배열이 서로 참조되지 않도록
        const copied = Object.assign([], this.#privArray);
        return copied;
      }
    }
    객체 배열이라면 원소까지 복사: `this.#privArray.map(o => ({ ...o }))`.
    더 강한 보장이 필요하면 `structuredClone(this.#privArray)` 또는 `Object.freeze`.
  references:
    - KISA JavaScript 가이드 제6절 3
    - MOIS-49-ENCAP-03
    - CWE-495
    - CERT OBJ05-J
    - MDN Private class fields
  can_auto_fix: false
examples:
  language: javascript
  positive:
    - "class UserObj { #privArray = []; get_private_member = () => { return this.#privArray; } }"
    - "class Cache { #items = []; getItems() { return this.#items; } }"
    - "class Config { #settings = { theme: 'dark' }; getSettings() { return this.#settings; } }"
  negative:
    - "class UserObj { #privArray = []; get_private_member = () => { const copied = Object.assign([], this.#privArray); return copied; } }"
    - "class Cache { #items = []; getItems() { return [...this.#items]; } }"
    - "class Config { #settings = { theme: 'dark' }; getSettings() { return structuredClone(this.#settings); } }"
---

## 무엇이 위험한가
JavaScript는 객체와 배열을 *참조로 전달*합니다. 따라서 클래스 내부의 `#privArray`를 `return this.#privArray`로 반환하면 호출자는 *원본 배열의 참조*를 받게 되고, `.push()`, `.splice()`, `obj.someField = ...`로 내부 상태를 자유롭게 바꿀 수 있습니다. `#` 접근 제한자는 이름 접근만 막을 뿐 *참조 유출은 막아주지 않습니다*. 가이드 §제6절 3의 안전하지 않은 예제는 `get_private_member`가 `return this.#privArray`로 참조를 그대로 흘려보내, 외부에서 클래스 내부 배열을 자유롭게 변조할 수 있는 문제를 보입니다.

## 안전한 패턴 (가이드 원문 인용)
```javascript
class UserObj {
  #privArray = [];
  // private 배열을 반환하는 경우 복사본을 사용해 외부와 내부의
  // 배열이 서로 참조되지 않도록 해야 함
  get_private_member = () => {
    const copied = Object.assign([], this.#privArray);
    return copied;
  }
}
```

## False positive 주의
- 복사본 반환 패턴은 매칭하지 않습니다: `[...this.#x]`, `Object.assign([], this.#x)`, `Array.from(this.#x)`, `structuredClone(this.#x)`, `this.#x.slice()`.
- 원시값 반환(`return this.#count`, `return this.#name`)은 mutable 참조가 아니므로 매칭하지 않습니다. 패턴은 `#name = [...]` 또는 `#name = {...}` 초기화에 한해 매칭합니다.
- 언더스코어 컨벤션(`_privArray`)도 두 번째 패턴이 검사합니다. ES2022 미만 코드베이스에서 흔히 발견됩니다.
- TypeScript의 `private` 키워드는 컴파일 타임 검사만 제공하므로(런타임에는 public) 별도 검토가 필요합니다. 본 룰은 런타임 강제력이 있는 `#`/`_` 접두 필드에 한정합니다.
- 의도적으로 *내부 상태를 외부에서 수정해야 하는 API*(예: observable store의 raw mutation)는 false positive입니다. 그 경우 README에 의도를 명시하거나 별도 리뷰 처리하세요.
