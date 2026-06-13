---
id: KISA-PY-ENCAP-03
title_ko: Python Public 메소드에서 Private 멤버를 그대로 반환 (return self.__x without copy)
title_en: Public method returning private mutable member directly in Python
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Python 시큐어코딩 가이드(2023년 개정본)
    item: 제6절 3. Public 메소드로부터 반환된 Private 배열
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-40
cwe: [CWE-374, CWE-375, CWE-495]
severity: medium
decision_default: warn
domains: [kisa-secure-coding]
languages: [python]
scenarios: [web-app, data-pipeline]
related_baseline: [MOIS-49-ENCAP-03]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    # name mangling private(__x)의 mutable 참조를 그대로 반환하는 경우만.
    # 단일 underscore(self._x)는 파이썬 관례상 흔한 정상 getter라 제외(과탐 방지).
    - "return\\s+self\\.__[A-Za-z_][A-Za-z0-9_]*\\s*(?:#.*)?$"
    - "return\\s+(?:cls|self)\\.__dict__\\s*(?:#.*)?$"
  category: kisa-secure-coding
  why_it_matters: >-
    파이썬은 명시적 private 키워드가 없어 `__name`/`_name` 접두사 규약을
    씁니다. `return self.__items`처럼 *내부 mutable 객체의 참조*를 그대로
    반환하면 호출자가 `obj.get_items().append(...)`만 해도 클래스 내부 상태가
    변경됩니다. 캐시·세션·권한 목록 같은 *민감 상태*를 보유한 객체가 이런
    식으로 노출되면 외부에서 권한 목록에 항목을 추가하는 등의 무결성 침해가
    가능합니다. KISA 가이드는 *얕은 복사([:])*를 권장합니다.
  public_sector_impact:
    - 권한·역할 목록의 외부 변조
    - 캐시 상태 일관성 깨짐
    - 내부 정책 객체가 의도치 않게 수정됨
  safe_fix: |
    가이드 안전 예시: *얕은 복사*로 새로운 객체를 반환하세요.
        def get_private_member(self):
            return self.__private_variable[:]    # 리스트 얕은 복사
    또는 *불변 타입*으로 변환:
        return tuple(self.__items)
        return MappingProxyType(self.__state)    # dict의 읽기 전용 뷰
    중첩 구조라면 `copy.deepcopy()` 또는 *immutable 자료구조*(예: pyrsistent)
    사용을 고려하세요. `__dict__` 자체를 반환하는 것은 *클래스 내부 전체*를
    노출하므로 절대 금지입니다.
  references:
    - KISA Python 가이드 제7절 3
    - MOIS-49-ENCAP-03
    - CWE-374, CWE-375, CWE-495
    - https://docs.python.org/3/library/copy.html
    - https://docs.python.org/3/tutorial/classes.html#private-variables
  can_auto_fix: false
examples:
  language: python
  positive:
    - "def get_private_member(self):\n    return self.__private_variable"
    - "def roles(self):\n    return self.__role_list"
    - "def dump(self):\n    return self.__dict__"
  negative:
    - "def get_private_member(self):\n    return self.__private_variable[:]"
    - "def roles(self):\n    return tuple(self.__role_list)"
    - "def dump(self):\n    return MappingProxyType(self.__state)"
---

## 무엇이 위험한가
파이썬의 *private*는 약속일 뿐 *언어가 막아주지 않습니다*. 예제:

```python
class UserObj:
    __private_variable = []

    def get_private_member(self):
        return self.__private_variable   # 참조 그대로 노출 — 취약
```

호출자는:

```python
u = UserObj()
u.get_private_member().append("evil")    # 내부 상태 변경 성공
```

권한 목록·세션 토큰 집합·정책 dict 같은 *내부 mutable 상태*가 이렇게 새 나가면, 외부 코드에서 한 줄로 *권한을 추가*하거나 *정책 dict의 key를 덮어쓸* 수 있습니다.

`return self.__dict__`는 더 심각한 케이스로, *클래스의 모든 비공개 속성을 통째로 외부에 넘겨주는* 행위입니다.

## 안전한 패턴 (가이드 원문 인용)
```python
class UserObj:
    __private_variable = []

    def __init__(self):
        pass

    def get_private_member(self):
        # private 배열을 반환하는 경우 [:]를 사용하여 외부와 내부의
        # 배열이 서로 참조되지 않도록 해야 한다
        return self.__private_variable[:]
```

추가 옵션:
```python
from types import MappingProxyType
import copy

class Policy:
    def __init__(self):
        self.__state = {"role": "viewer"}
        self.__items = []

    def state(self):
        # dict의 읽기 전용 뷰 — 새 객체 할당이 아니므로 빠름
        return MappingProxyType(self.__state)

    def items(self):
        # 중첩이 있으면 deepcopy
        return copy.deepcopy(self.__items)
```

## False positive 주의
- *불변 객체*(int, str, frozenset, tuple)를 담은 private 속성도 패턴은 매칭됩니다. 호출자가 변경할 수 없으므로 보안 영향은 작지만, 일관성을 위해 *복사 또는 명시*가 권장됩니다. 의도가 분명하면 `# gvskb: ignore KISA-PY-ENCAP-03`로 억제하세요.
- 데이터클래스의 `__post_init__` 등에서 *내부 보조 메서드가 자신의 private 멤버를 반환*해 같은 클래스 내부에서만 쓰이는 경우는 무해합니다. 그래도 외부에 노출되지 않도록 메서드 이름을 `_load_internal()`처럼 *non-public*으로 표기하세요.
- 본 룰은 *함수 정의의 마지막 단순 return 라인*만 잡습니다. `return self.__items.copy()`, `return list(self.__items)`, `return tuple(self.__items)`, `return self.__items[:]`처럼 *복사 표현이 함께 있는* 라인은 매칭되지 않습니다(패턴 끝 `$` 또는 `#` 주석만 허용).
