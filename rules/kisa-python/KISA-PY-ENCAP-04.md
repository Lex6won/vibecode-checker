---
id: KISA-PY-ENCAP-04
title_ko: Python Private 배열에 Public 데이터 직접 대입 - self.__x = input without copy
title_en: Public data assigned to private array-typed field in Python (without copy)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Python 시큐어코딩 가이드(2023년 개정본)
    item: 제6절 4. Private 배열에 Public 데이터 할당
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-41
cwe: [CWE-496]
severity: medium
decision_default: warn
domains: [kisa-secure-coding]
languages: [python]
scenarios: [web-app, data-pipeline]
related_baseline: [MOIS-49-ENCAP-04]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    # name mangling private(__x)에 외부 인자를 복사 없이 직접 대입한 경우만.
    # 단일 underscore(self._x)는 파이썬 관례상 정상 초기화·protected 속성이라
    # 과탐을 유발해 제외한다. KISA 가이드의 대상도 __ (name mangling)이다.
    # 1) self.__x = <bare_param_name> (라인 끝 — 복사 표현이 없는 직접 대입)
    - "^\\s*self\\.__[A-Za-z_][A-Za-z0-9_]*\\s*=\\s*[A-Za-z_][A-Za-z0-9_]*\\s*(?:#.*)?$"
    # 2) 클래스 속성에 mutable 인자 직접 대입 (cls.__items = input_list)
    - "^\\s*cls\\.__[A-Za-z_][A-Za-z0-9_]*\\s*=\\s*[A-Za-z_][A-Za-z0-9_]*\\s*(?:#.*)?$"
  category: kisa-secure-coding
  why_it_matters: >-
    파이썬은 `self.__name` 같은 이름맹글링(name mangling)이 있지만 *참조 의미는
    바뀌지 않습니다*. `def set_private_member(self, input_list):
    self.__private_variable = input_list` 처럼 외부 인자를 *복사 없이* 그대로
    대입하면, 호출자가 보유한 `input_list` 의 참조와 내부 `__private_variable`
    이 **같은 객체**가 됩니다. 호출자가 이후 `input_list.append("admin")`
    한 줄만 실행해도 클래스 내부 상태가 *외부에서* 변경됩니다. KISA 가이드는
    `[:]` 얕은 복사를 명시적 안전 패턴으로 권장합니다.
  public_sector_impact:
    - 권한 목록·정책 dict 가 호출자 코드에서 사후 변조
    - 캐시·세션 데이터의 외부 변경 가능
    - 불변 객체로 보였던 내부 상태가 *공유 mutable* 로 새 나감
  safe_fix: |
    *얕은 복사*([:], list(), dict()) 또는 *깊은 복사*(copy.deepcopy)로 새 객체를
    만들어 저장하세요. KISA 가이드 안전 예시:
        class UserObj:
            def __init__(self):
                self.__privateVariable = []

            def set_private_member(self, input_list):
                # [:] 로 새 객체 생성 -> 외부·내부 배열이 서로 참조되지 않음
                self.__privateVariable = input_list[:]

    추가 패턴:
        self.__items = list(input_list)        # 리스트
        self.__state = dict(input_dict)        # 얕은 dict 복사
        self.__items = copy.deepcopy(input)    # 중첩 mutable
        self.__items = tuple(input_list)       # 불변 변환 (가장 안전)

    값 검증이 필요한 경우 *복사 + 검증 + 저장* 순서를 지키세요. 검증 전 대입은
    *공유 참조 상태에서 검사하는 셈* 이라 의미가 약합니다.
  references:
    - KISA Python 가이드 제6절 4
    - MOIS-49-ENCAP-04
    - CWE-496
    - https://docs.python.org/3/library/copy.html
    - https://docs.python.org/3/tutorial/classes.html#private-variables
  can_auto_fix: false
examples:
  language: python
  positive:
    - "def set_private_member(self, input_list):\n    self.__private_variable = input_list"
    - "def set_roles(self, roles):\n    self.__role_list = roles"
    - "def load(self, items):\n    self.__items = items"
  negative:
    - "def set_private_member(self, input_list):\n    self.__private_variable = input_list[:]"
    - "def set_roles(self, roles):\n    self.__role_list = list(roles)"
    - "def load(self, items):\n    self.__items = tuple(items)"
---

## 무엇이 위험한가
파이썬의 `__name` 접두사는 *이름맹글링* 일 뿐 객체 참조 의미를 바꾸지 않습니다. 다음 코드는 *외부에서 내부 상태를 변조* 할 수 있는 길을 열어 둡니다.

```python
class UserObj:
    __private_variable = []

    def __init__(self):
        pass

    # private 배열에 외부 값을 바로 대입하는 public 메소드를 사용하는
    # 경우 취약하다
    def set_private_member(self, input_list):
        self.__private_variable = input_list   # 참조 공유
```

호출 측:
```python
data = ["viewer"]
u = UserObj()
u.set_private_member(data)

# 호출자가 자기 변수에 append
data.append("admin")

# 내부 __private_variable 도 ["viewer", "admin"] 으로 바뀜
# -> 권한 목록 변조
```

권한·역할 리스트, 정책 dict, 캐시 등 *내부 mutable 상태*가 이런 경로로 새 나가면 *읽기 시점*에는 정상이지만 *나중에* 외부에서 무결성이 깨집니다. KISA 가이드는 CWE-496(Public Data Assigned to Private Array-Typed Field) 로 분류합니다.

본 룰은 `KISA-PY-ENCAP-03`(*private 멤버를 그대로 *반환* 하는 패턴*) 과 쌍을 이룹니다. ENCAP-03 은 *나가는 방향*, ENCAP-04 는 *들어오는 방향* 의 참조 누수입니다.

## 안전한 패턴 (가이드 원문 인용)
```python
class UserObj:

    def __init__(self):
        self.__privateVariable = []

    # private 배열에 외부 값을 바로 대입하는 경우 [:]를 사용하여
    # 외부와 내부의 배열이 서로 참조되지 않도록 해야 한다
    def set_private_member(self, input_list):
        self.__privateVariable = input_list[:]
```

선택 가능한 안전 패턴:
```python
import copy

class Policy:
    def __init__(self):
        self.__items = []
        self.__state = {}

    # 1) 얕은 복사
    def set_items(self, items):
        self.__items = list(items)

    # 2) 불변 변환 (이후 변경 자체를 차단)
    def set_items_immutable(self, items):
        self.__items = tuple(items)

    # 3) 중첩 구조 — 깊은 복사
    def set_state(self, state):
        self.__state = copy.deepcopy(state)

    # 4) 검증 후 저장 (검증은 반드시 *복사본* 위에서)
    def set_items_validated(self, items):
        copied = list(items)
        if any(not isinstance(x, str) for x in copied):
            raise ValueError("문자열만 허용")
        self.__items = copied
```

## False positive 주의
- 본 룰은 *함수 본문의 한 라인에서 `self.__x = <식별자>` 가 그대로 끝나는* 패턴만 잡습니다. `self.__x = input_list[:]`, `self.__x = list(input_list)`, `self.__x = copy.deepcopy(x)` 처럼 *복사 표현*이 우변에 있으면 매칭되지 않습니다(negative 예시).
- 우변이 *리터럴*(`self.__x = []`, `self.__x = 0`, `self.__x = ""`)인 경우는 `[A-Za-z_]` 식별자 패턴에 걸리지 않아 안전하게 제외됩니다.
- 우변이 *함수 호출* (`self.__x = fetch_default()`)인 경우도 패턴에 잡히지 않습니다. 다만 그 함수가 *호출자가 보유한 mutable 컨테이너의 별칭*을 반환한다면 같은 위험이 존재합니다 — 라인 단위 regex 로 추적 불가.
- *불변 타입* (`tuple`, `frozenset`, `str`, `int`)을 담은 인자라면 별칭 공유가 실제 위험으로 이어지진 않습니다. 의도가 분명하면 `# gvskb: ignore KISA-PY-ENCAP-04` 로 억제하세요.
- 데이터클래스 / Pydantic 모델은 자체 복사 의미를 가지므로 본 룰의 *주 타깃이 아닙니다*.
