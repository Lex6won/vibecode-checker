"""SQL 식별자 조립 — 스코프 안만 봐서는 알 수 없는 것, 그리고 모르는 것을 안다고 말하지 않기.

실사용 저장소(`koica-reg-mcp`)를 검사하다 나왔다.

```python
def _bump(conn, table, key_col, key, now):
    conn.execute(
        f"INSERT INTO {table}({key_col}, count, first_seen, last_seen)"
        " VALUES(?, 1, ?, ?)" ...,
        (key, now, now),
    )
...
_bump(conn, "tool_usage", "tool", tool, now)      # 호출부 넷 전부 리터럴
```

값(`key`·`now`)은 전부 `?` 바인딩이고, f-string 이 끼워 넣는 것은 **테이블·컬럼
이름뿐**이다. SQL 식별자는 파라미터로 넘길 수 없으므로 f-string 조립 자체는
정당하다. 그런데 **치명·차단** 두 건이 떴다.

결함이 둘이었다.

1. **오탐** — 스코프 안만 보는 상수 판정은 매개변수의 출처를 알 수 없다.
   모듈 안 모든 호출부가 리터럴을 넘긴다는 것은 **증명할 수 있는데** 안 했다.
2. **거짓 확신** — 판정 근거가 `confirmed`("확인됨 · 데이터 흐름 추적")였다.
   매개변수의 값이 어디서 오는지는 **추적한 적이 없다.** 오탐보다 이쪽이 무겁다.
   틀린 판정은 검토로 걸러지지만, 틀린 확신은 검토를 건너뛰게 만든다.
"""

from __future__ import annotations

import ast

import pytest

from gvskb.scanner import scan_code
from gvskb.scanners.py_const import literal_only_parameters

_SQLI = "GOV-SQL-INJECTION-001"


def _sql(code: str):
    return [f for f in scan_code(code, filename="a.py").findings if f.rule_id == _SQLI]


# ---------------------------------------------------------------------------
# ① 증명된 것은 잡지 않는다
# ---------------------------------------------------------------------------

_KOICA = '''
def _bump(conn, table, key_col, key, now):
    conn.execute(
        f"INSERT INTO {table}({key_col}, count) VALUES(?, ?)",
        (key, now),
    )

def _bump_daily(conn, table, key_col, day, key):
    conn.execute(
        f"INSERT INTO {table}(day, {key_col}, count) VALUES(?, ?, 1)",
        (day, key),
    )

def record(conn, tool, day, now):
    _bump(conn, "tool_usage", "tool", tool, now)
    _bump_daily(conn, "daily_tool", "tool", day, tool)
'''


def test_literal_only_parameters_are_proven() -> None:
    proven = literal_only_parameters(ast.parse(_KOICA))
    assert proven == {
        "_bump": {"table", "key_col"},
        "_bump_daily": {"table", "key_col"},
    }, "리터럴만 오는 매개변수만 골라야 한다 — 값 매개변수까지 상수로 보면 진짜를 놓친다"


def test_koica_shape_is_not_flagged() -> None:
    """실사용 저장소에서 '치명·차단' 두 건으로 뜨던 모양."""
    assert not _sql(_KOICA)


# ---------------------------------------------------------------------------
# ② 증명하지 못한 것은 그대로 잡는다 — 증명 실패를 안전으로 바꾸지 않는다
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("code, why", [
    ('''
def _bump(conn, table, key):
    conn.execute(f"INSERT INTO {table}(k) VALUES(?)", (key,))
def run(conn, t, k):
    _bump(conn, t, k)
''', "호출부가 변수를 넘긴다"),
    ('''
def bump(conn, table, key):
    conn.execute(f"INSERT INTO {table}(k) VALUES(?)", (key,))
bump(c, "t", k)
''', "공개 함수 — 다른 모듈에서 부를 수 있어 이 모듈만 봐서는 증명이 안 된다"),
    ('''
def _bump(conn, table, key):
    conn.execute(f"INSERT INTO {table}(k) VALUES(?)", (key,))
handler = _bump
_bump(c, "t", k)
''', "함수가 값으로 새어 나가면 간접 호출을 놓친다"),
    ('''
def _bump(conn, table, key):
    conn.execute(f"INSERT INTO {table}(k) VALUES(?)", (key,))
_bump(*args)
''', "*args 호출 — 무엇이 어디로 가는지 모른다"),
    ('''
def _bump(conn, table, key):
    conn.execute(f"INSERT INTO {table}(k) VALUES(?)", (key,))
def a(c, k):
    _bump(c, "t", k)
def b(c, k, t):
    _bump(c, t, k)
''', "호출부 하나라도 변수면 증명 실패"),
    ('''
def _bump(conn, table, key):
    conn.execute(f"INSERT INTO {table}(k) VALUES(?)", (key,))
def _bump(conn, table, key):
    conn.execute(f"DELETE FROM {table}")
_bump(c, "t", k)
''', "같은 이름 정의가 둘 — 어느 쪽이 불리는지 모른다"),
])
def test_unproven_parameters_are_still_flagged(code: str, why: str) -> None:
    """**증명하지 못한 것을 안전하다고 말하지 않는다.**"""
    assert _sql(code), why


def test_value_parameters_are_never_promoted() -> None:
    """식별자가 아니라 **값**이 f-string 으로 들어가면 그건 진짜 삽입이다."""
    code = '''
def _q(conn, uid):
    conn.execute(f"SELECT * FROM users WHERE id = {uid}")
def run(conn):
    _q(conn, "42")
'''
    # 호출부가 리터럴이라 증명은 되지만, 그렇다고 미래의 호출까지 안전한 것은
    # 아니다 — 다만 지금 이 모듈 안에서는 사용자 입력이 닿지 않는다.
    # 이 테스트는 증명 로직이 **자리를 가리지 않고 일관되게** 동작함을 고정한다.
    assert literal_only_parameters(ast.parse(code))["_q"] == {"uid"}


# ---------------------------------------------------------------------------
# ③ 추적하지 않은 것을 "추적했다"고 말하지 않는다
# ---------------------------------------------------------------------------

def test_parameter_sourced_sql_is_likely_not_confirmed() -> None:
    """매개변수의 출처는 이 스코프 밖이다 — 따라간 흐름이 없다.

    보고서에서 `confirmed` 는 "확인됨(데이터 흐름 추적)"으로 읽힌다. 흐름을
    따라가지 않고 그렇게 쓰면, 담당자는 검토 없이 그대로 믿는다.
    """
    code = '''
def _bump(conn, table, key):
    conn.execute(f"INSERT INTO {table}(k) VALUES(?)", (key,))
def run(conn, t, k):
    _bump(conn, t, k)
'''
    fs = _sql(code)
    assert fs and all(f.confidence == "likely" for f in fs)


def test_traced_assignment_is_still_confirmed() -> None:
    """같은 스코프에서 대입을 따라간 것은 실제로 추적한 것이다.

    DDL 룰이 `likely`("조립 사실만 확인")인 것과 짝을 이루는 구분이다 —
    기준은 '공격자 통제 증명'이 아니라 **'흐름을 따라갔는가'** 다.
    """
    code = '''
def q(conn, req):
    uid = req.args.get("id")
    sql = "SELECT * FROM users WHERE id = " + uid
    conn.execute(sql)
'''
    fs = _sql(code)
    assert fs and all(f.confidence == "confirmed" for f in fs)


def test_parameter_bound_query_is_never_flagged() -> None:
    """회귀 방지 — 파라미터 바인딩은 예나 지금이나 깨끗하다."""
    assert not _sql('''
def q(conn, uid):
    conn.execute("SELECT * FROM users WHERE id = ?", (uid,))
''')


# ---------------------------------------------------------------------------
# ④ 증명 조건 하나하나가 실제로 무언가를 막고 있는가
#
# 변이 검사에서 세 가드가 **빠져나갔다** — 가드가 죽어 있어서가 아니라
# 그 자리를 짚는 테스트가 없어서였다. 검사하지 않는 조건은 다음 사람에게
# '검증된 것'처럼 보인다.
# ---------------------------------------------------------------------------

def test_starred_call_shifts_positions_so_nothing_is_proven() -> None:
    """`_bump(*pre, "t")` 에서 `"t"` 가 어느 매개변수로 갈지는 알 수 없다.

    자리 번호로만 보면 두 번째 인자가 `table` 이지만, 앞의 `*pre` 가 몇 개를
    풀어 놓느냐에 따라 실제로는 `key` 로 갈 수도 있다. 언팩이 하나라도 있으면
    그 호출부는 통째로 포기한다.
    """
    code = '''
def _bump(conn, table, key):
    conn.execute(f"INSERT INTO {table}(k) VALUES(?)", (key,))
_bump(*pre, "t")
'''
    assert literal_only_parameters(ast.parse(code)) == {}
    assert _sql(code), "자리 밀림을 무시하면 엉뚱한 값을 상수로 증명한다"


def test_a_function_with_no_call_sites_proves_nothing() -> None:
    """호출부가 없으면 증거가 없는 것이지 '전부 리터럴'인 것이 아니다.

    '모든 호출부가 리터럴'을 순진하게 구현하면 **공집합에 대해 참**이 되어,
    한 번도 불리지 않는 함수의 매개변수가 전부 상수로 승격된다.
    """
    code = '''
def _bump(conn, table, key):
    conn.execute(f"INSERT INTO {table}(k) VALUES(?)", (key,))
'''
    assert literal_only_parameters(ast.parse(code)) == {}
    assert _sql(code), "증거 없음을 안전으로 바꾸면 안 된다"


def test_module_level_dynamic_sql_stays_confirmed() -> None:
    """매개변수가 없는 스코프(모듈 최상위)에서는 흐름을 끝까지 따라간 것이다."""
    code = '''
uid = request.args["id"]
sql = "SELECT * FROM t WHERE id = " + uid
conn.execute(sql)
'''
    fs = _sql(code)
    assert fs and all(f.confidence == "confirmed" for f in fs)


# ---------------------------------------------------------------------------
# ⑤ 자원을 넘겨주는 자리에는 `with` 를 요구할 수 없다
#
# 같은 실사용 저장소에서 나온 세 번째 발견. `_connect()` 가 연결을 만들어
# **반환**하고, 호출부 둘 다 `try/finally: conn.close()` 로 닫고 있었다.
# 룰이 걱정하는 상황("예외가 나면 안 닫힌다")이 아니었다.
# ---------------------------------------------------------------------------

_RESOURCE = "KISA-PY-CODE-02"


def _resource(code: str):
    return [f for f in scan_code(code, filename="a.py").findings if f.rule_id == _RESOURCE]


@pytest.mark.parametrize("code, want, why", [
    ('''
def _connect(path):
    conn = sqlite3.connect(path, timeout=5.0)
    return conn
''', "low", "생성 함수 — 호출자에게 넘긴다(실측 모양)"),
    ('''
def _open(p):
    f = open(p)
    return f
''', "low", "파일도 같다"),
    ('''
def work(path):
    conn = sqlite3.connect(path)
    conn.execute("SELECT 1")
''', "medium", "자기가 열고 안 닫는다 — 진짜 지적"),
    ('''
def leak(p):
    f = open(p)
    data = f.read()
    return data
''', "medium", "자원이 아니라 **값**을 반환 — 자원은 여기 남는다"),
])
def test_factory_functions_cannot_be_required_to_use_with(
    code: str, want: str, why: str,
) -> None:
    """생성 함수는 `with` 를 쓸 수 없다 — 블록을 벗어나면 닫혀서 반환값이 죽는다.

    **해제 책임이 있는 곳에 요구해야 할 규칙을 책임이 없는 곳에 요구**하고
    있었다. 다만 호출자가 정말 닫는지는 이 자리에서 알 수 없으므로 지우지 않고
    낮춘다.
    """
    fs = _resource(code)
    assert fs, "발견 자체를 지우지는 않는다"
    assert fs[0].severity.value == want, why


def test_factory_attenuation_says_where_to_look() -> None:
    """낮춘 이유에 **어디를 봐야 하는지**가 있어야 한다."""
    fs = _resource('''
def _connect(path):
    conn = sqlite3.connect(path)
    return conn
''')
    assert fs[0].severity_adjusted and "호출부" in fs[0].severity_adjusted


def test_with_block_is_never_flagged() -> None:
    assert not _resource('''
def work(path):
    with sqlite3.connect(path) as conn:
        conn.execute("SELECT 1")
''')
