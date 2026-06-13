---
id: KISA-PY-INPUT-14
title_ko: Python 정수형 오버플로우 - numpy 고정 비트(int8/16/32/64) dtype 연산 시 입력 범위 미검사
title_en: Integer overflow in Python (fixed-width numpy dtype without range validation)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Python 시큐어코딩 가이드(2023년 개정본)
    item: 제1절 14. 정수형 오버플로우
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-14
cwe: [CWE-190, CWE-191]
severity: medium
decision_default: warn
domains: [kisa-secure-coding]
languages: [python]
scenarios: [data-pipeline, batch-job, llm-integration]
related_baseline: [MOIS-49-INPUT-14]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    # 1) np.power / np.multiply / np.add 가 고정 비트 dtype(int8/16/32/64, uint8/16/32/64) 으로 호출 — 범위 검사 신호 없음
    - "np\\.(?:power|multiply|add|subtract|sum|prod)\\s*\\([^)]*dtype\\s*=\\s*np\\.(?:int|uint)(?:8|16|32|64)"
    # 2) numpy 배열 산술 캐스팅 astype(np.int8/16/32/64) — 큰 값 잘림 위험
    - "\\.astype\\s*\\(\\s*np\\.(?:int|uint)(?:8|16|32|64)\\s*\\)"
    # 3) struct.pack/unpack 의 고정폭 포맷('b','h','i','l','B','H','I','L','q','Q') — 범위 미검사
    - "struct\\.(?:pack|unpack)\\s*\\(\\s*['\"][<>!=@]?[bhilqBHILQ]+['\"]"
    # 4) request 입력을 int() 로 받아 numpy 고정 비트 연산에 같은 라인에서 사용
    - "np\\.(?:int|uint)(?:8|16|32|64)\\s*\\(\\s*int\\s*\\(\\s*request\\."
  category: kisa-secure-coding
  why_it_matters: >-
    파이썬 3.x의 기본 int 는 임의 정밀도라서 자체 오버플로우는 발생하지 않지만,
    `numpy`·`struct`·C 확장 패키지는 *고정 비트 폭* 정수를 사용합니다.
    KISA 가이드 안전하지 않은 예시 `np.power(number, pow, dtype=np.int64)` 는
    입력이 64비트 한계를 넘어가면 결과가 0이나 음수로 *조용히 래핑*되어
    이후 메모리 할당·반복문 제어·결제 금액 계산에 사용되면 비즈니스 로직이
    무너집니다. 가이드 안전 예시처럼 파이썬 기본 int 로 먼저 계산한 뒤
    `np.iinfo(np.int64).max/min` 범위를 검사해야 합니다.
  public_sector_impact:
    - 행정 통계·세입 집계 금액이 음수로 래핑되어 결산 오류
    - 민원 처리 건수 카운터가 0으로 되돌아가 KPI 왜곡
    - struct.pack 으로 만든 외부 시스템 연계 메시지 길이 필드가 잘려 인터페이스 실패
  safe_fix: |
    파이썬 기본 int 로 계산 → 범위 검사 → numpy dtype 변환 순서로 작성하세요.
        import numpy as np
        MAX_NUMBER = np.iinfo(np.int64).max
        MIN_NUMBER = np.iinfo(np.int64).min
        def handle_data(number, pow):
            calculated = number ** pow            # 파이썬 기본 int (임의 정밀도)
            if calculated > MAX_NUMBER or calculated < MIN_NUMBER:
                return -1                          # 오버플로우 탐지 시 비정상 종료
            return np.power(number, pow, dtype=np.int64)
    struct 사용 시에는 pack 직전에 명시적으로 입력 범위를 검증하세요.
        if not (-2**31 <= n < 2**31):
            raise ValueError("int32 range exceeded")
        struct.pack('<i', n)
  references:
    - KISA Python 가이드 제1절 14
    - MOIS-49-INPUT-14
    - CWE-190
    - PEP 237 (Unifying Long Integers and Integers)
    - https://numpy.org/doc/stable/user/basics.types.html
  can_auto_fix: false
examples:
  language: python
  positive:
    - "res = np.power(number, pow, dtype=np.int64)"
    - "arr2 = arr.astype(np.int32)"
    - "buf = struct.pack('<i', user_input)"
    - "value = np.int32(int(request.GET['n']))"
  negative:
    - "calculated = number ** pow\nif calculated > MAX_NUMBER or calculated < MIN_NUMBER:\n    return -1"
    - "total = sum(values)  # 파이썬 기본 int, 임의 정밀도"
    - "arr2 = arr.astype(float)  # 부동소수점 — 정수 오버플로우 무관"
---

## 무엇이 위험한가
Python 3.x의 기본 `int` 는 임의 정밀도(arbitrary-precision)이므로 *언어 차원에서는* 정수 오버플로우가 발생하지 않습니다. 그러나 `numpy`, `struct`, `ctypes`, Pandas의 일부 dtype, 그리고 C/C++ 로 작성된 머신러닝 백엔드는 *고정 비트 폭* 정수(int8/16/32/64, uint8/16/32/64)를 사용합니다. 이때 입력값이 비트 폭을 넘어가면 결과는 예외 없이 *조용히 래핑* 됩니다.

가이드의 안전하지 않은 예시 `np.power(number, pow, dtype=np.int64)` 는 입력 검증 없이 64비트로 캐스팅합니다. `number=10, pow=20` 만 되어도 결과가 음수로 뒤집힙니다. 이 값을 그대로 반복 횟수, 메모리 크기, 결제 금액에 사용하면 비즈니스 로직 전체가 망가집니다.

공공기관 사례:
- 행정 결산·통계 집계가 numpy 로 벡터화되어 *총합이 음수* 로 표시
- IoT 게이트웨이가 `struct.pack('<i', counter)` 로 메시지를 만들 때 카운터가 2^31 을 넘어 음수 메시지가 외부로 전송
- 민원 처리량 KPI 가 32비트 카운터로 누적되다 갑자기 0으로 초기화

KISA 가이드 안전 예시는 *파이썬 기본 int 로 계산 → 범위 검사 → numpy dtype 변환* 순서를 강제합니다.

## 안전한 패턴 (가이드 원문 인용)
```python
import numpy as np

MAX_NUMBER = np.iinfo(np.int64).max
MIN_NUMBER = np.iinfo(np.int64).min

def handle_data(number, pow):
    # 파이썬 기본 자료형(임의 정밀도)으로 먼저 계산
    calculated = number ** pow
    # 오버플로우 탐지: 64비트 범위를 벗어나면 비정상 종료(-1) 반환
    if calculated > MAX_NUMBER or calculated < MIN_NUMBER:
        return -1
    res = np.power(number, pow, dtype=np.int64)
    return res
```

struct/ctypes 사용 시 명시적 범위 검사:
```python
import struct

def encode_int32(n: int) -> bytes:
    if not (-2**31 <= n < 2**31):
        raise ValueError(f"int32 range exceeded: {n}")
    return struct.pack('<i', n)
```

## False positive 주의
- 본 룰은 `np.power/multiply/add/subtract/sum/prod` 가 *고정 비트 dtype* 으로 호출되는 경우만 잡습니다. dtype 지정이 없는 일반 numpy 연산(`np.power(a, b)`)은 매칭되지 않습니다.
- 정상적으로 범위 검사가 *앞 라인* 에 분리되어 있어도 본 룰은 호출 라인 자체를 잡습니다 — 의도된 보수적 detection입니다. 검증이 명시되어 있다면 `# gvskb: ignore KISA-PY-INPUT-14` 로 억제하세요.
- `np.float32/64` 등 부동소수점 dtype 은 정수 오버플로우와 무관하므로 본 룰에서 제외했습니다.
- `struct.pack('s', s)` 등 문자열 포맷은 정수 오버플로우와 무관하므로 패턴이 정수형 포맷(`bhilqBHILQ`)만 잡습니다.
