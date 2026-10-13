"""29차 — Python 미탐 묶음(전면 점검 docs/40 §3-2 재현 목록). 각 미탐은 재현 테스트 + 같은 모양의
안전 코드가 조용한 적대 테스트를 쌍으로 둔다.

- `.format(name=request…)` 키워드 인자 · 상수 템플릿 `TMPL.format(…)`
- sink 인자 한 겹: `text(f"…")`·`.strip()`·키워드 `sql=` · 출처 그대로 `execute(request.form['q'])`
- 루트 식 밖 sink: `for row in cur.execute(…)`·`if cur.execute(…).fetchone()`·`with conn.execute(…) as r`
- sink 추가: `pd.read_sql`·`exec_driver_sql`·`Model.objects.raw`
- 분기 합집합 · `seen[key] = True` 가 출처를 지우지 않음
- 명령 삽입 여러 줄 출처 → 확인됨
- 목록 조립 `parts.append(… + n)` → `" ".join(parts)`
- 상수 환경: `conds += [dyn]` · `COLS[0] = request…`
- 변수명 `input` 은 출처가 아님(오탐)
"""
from __future__ import annotations

from gvskb.scanner import scan_code


def _hits(code: str, rule_prefix: str = "GOV-SQL") -> list:
    r = scan_code("from flask import request\nimport os\nimport subprocess\n" + code, filename="app.py")
    return [f for f in r.findings if f.rule_id.startswith(rule_prefix)]


def _conf(code: str, rule_prefix: str = "GOV-SQL") -> list[str]:
    return [f.confidence for f in _hits(code, rule_prefix)]


# ---------------------------------------------------------------------------
# .format 키워드 인자
# ---------------------------------------------------------------------------

def test_format_keyword_with_request_is_confirmed() -> None:
    code = '''
def q(cur):
    sql = "SELECT * FROM t WHERE name = '{name}'".format(name=request.args["n"])
    cur.execute(sql)
'''
    assert _conf(code) == ["confirmed"]


def test_format_keyword_with_constants_is_quiet() -> None:
    code = '''
TABLE = "users"
def q(cur):
    sql = "SELECT * FROM {t} WHERE id = ?".format(t=TABLE)
    cur.execute(sql, (1,))
'''
    assert _hits(code) == []


def test_constant_template_format_with_request_is_confirmed() -> None:
    code = '''
TMPL = "SELECT * FROM t WHERE name = '{}'"
def q(cur):
    cur.execute(TMPL.format(request.args["n"]))
'''
    assert _conf(code) == ["confirmed"]


# ---------------------------------------------------------------------------
# sink 인자 한 겹 · 키워드 · 출처 그대로
# ---------------------------------------------------------------------------

def test_sqlalchemy_text_fstring_is_confirmed() -> None:
    code = '''
from sqlalchemy import text
def q(conn):
    conn.execute(text(f"SELECT * FROM t WHERE a = '{request.args['a']}'"))
'''
    assert _conf(code) == ["confirmed"]


def test_sqlalchemy_text_constant_with_params_is_quiet() -> None:
    code = '''
from sqlalchemy import text
def q(conn):
    conn.execute(text("SELECT * FROM t WHERE a = :a"), {"a": request.args["a"]})
'''
    assert _hits(code) == []


def test_strip_wrapper_and_sql_keyword() -> None:
    code = '''
def q(cur):
    sql = "SELECT * FROM t WHERE a = '" + request.args["a"] + "'"
    cur.execute(sql.strip())
    cur.execute(sql=sql)
'''
    assert _conf(code) == ["confirmed", "confirmed"]


def test_raw_request_value_as_query_is_confirmed() -> None:
    code = '''
def q(cur):
    cur.execute(request.form["q"])
'''
    assert _conf(code) == ["confirmed"]


def test_request_through_helper_call_is_only_likely() -> None:
    """조립을 보지 못했으면 차단 근거가 아니다 — 유력(검토)까지만."""
    code = '''
def q(cur):
    cur.execute(build_query(request.args["x"]))
'''
    assert _conf(code) == ["likely"]


# ---------------------------------------------------------------------------
# 루트 식 밖 sink
# ---------------------------------------------------------------------------

def test_sink_inside_for_if_with_is_found() -> None:
    code = '''
def q(cur, conn):
    n = request.args["n"]
    sql = "SELECT * FROM t WHERE n = '" + n + "'"
    for row in cur.execute(sql):
        pass
    if cur.execute(sql).fetchone():
        pass
    with conn.execute(sql) as r:
        pass
'''
    assert _conf(code) == ["confirmed", "confirmed", "confirmed"]


def test_sink_inside_for_with_constant_is_quiet() -> None:
    code = '''
def q(cur):
    for row in cur.execute("SELECT * FROM t WHERE n = ?", (request.args["n"],)):
        pass
'''
    assert _hits(code) == []


# ---------------------------------------------------------------------------
# sink 추가
# ---------------------------------------------------------------------------

def test_pandas_read_sql_and_exec_driver_sql_and_django_raw() -> None:
    code = '''
import pandas as pd
def q(con, conn):
    t = request.args["t"]
    df = pd.read_sql(f"SELECT * FROM {t}", con)
    conn.exec_driver_sql("DELETE FROM t WHERE id = " + request.args["id"])
    rows = User.objects.raw("SELECT * FROM u WHERE n = '%s'" % request.args["n"])
'''
    assert _conf(code) == ["confirmed", "confirmed", "confirmed"]


def test_pandas_read_sql_parameterised_is_quiet() -> None:
    code = '''
import pandas as pd
def q(con):
    df = pd.read_sql("SELECT * FROM t WHERE a = %s", con, params=[request.args["a"]])
'''
    assert _hits(code) == []


# ---------------------------------------------------------------------------
# 분기 합집합 · 첨자 저장
# ---------------------------------------------------------------------------

def test_branch_union_keeps_source_from_either_path() -> None:
    code = '''
def q(cur, c):
    if c:
        n = request.args["n"]
    else:
        n = "default"
    cur.execute("SELECT * FROM t WHERE n = '" + n + "'")
'''
    assert _conf(code) == ["confirmed"]


def test_try_default_keeps_source() -> None:
    code = '''
def q(cur):
    try:
        n = request.args["n"]
    except KeyError:
        n = ""
    cur.execute(f"SELECT * FROM t WHERE n = '{n}'")
'''
    assert _conf(code) == ["confirmed"]


def test_subscript_store_does_not_erase_source_of_key() -> None:
    code = '''
def q(cur):
    key = request.args["k"]
    seen = {}
    seen[key] = True
    cur.execute("SELECT * FROM t WHERE k = '" + key + "'")
'''
    assert _conf(code) == ["confirmed"]


def test_overwrite_in_straight_line_still_cuts_source() -> None:
    """직선 흐름의 덮어쓰기는 출처를 끊는다 — 확인됨(차단)이 아니어야 한다.
    (상수 환경은 흐름 무관이라 `n` 이 두 번 대입되면 상수로 못 봐 '유력'은 남을 수 있다.)"""
    code = '''
def q(cur):
    n = request.args["n"]
    n = "fixed"
    cur.execute("SELECT * FROM t WHERE n = '" + n + "'")
'''
    assert "confirmed" not in _conf(code)


# ---------------------------------------------------------------------------
# 명령 삽입 — 여러 줄 출처
# ---------------------------------------------------------------------------

def test_command_injection_multiline_source_is_confirmed() -> None:
    code = '''
def ping():
    host = request.args["h"]
    os.system("ping " + host)
    subprocess.run("nslookup " + host, shell=True)
'''
    confs = _conf(code, "KISA-PY-INPUT-05")
    assert confs == ["confirmed", "confirmed"], confs


def test_command_without_source_stays_likely_and_single() -> None:
    code = '''
def ping(host):
    os.system("ping " + host)
'''
    assert _conf(code, "KISA-PY-INPUT-05") == ["likely"]


# ---------------------------------------------------------------------------
# 목록 조립 · 상수 환경 구멍
# ---------------------------------------------------------------------------

def test_list_append_then_join_is_found() -> None:
    code = '''
def q(cur):
    parts = ["SELECT * FROM t"]
    parts.append("WHERE n = '" + request.args["n"] + "'")
    cur.execute(" ".join(parts))
'''
    assert _conf(code) == ["confirmed"]


def test_list_append_of_literals_then_join_is_quiet() -> None:
    code = '''
def q(cur, flag):
    parts = ["SELECT * FROM t"]
    if flag:
        parts.append("WHERE active = 1")
    cur.execute(" ".join(parts))
'''
    assert _hits(code) == []


def test_augassign_list_and_subscript_store_disqualify_constant() -> None:
    code = '''
def q(cur):
    conds = ["active = 1"]
    conds += ["n = '" + request.args["n"] + "'"]
    cur.execute("SELECT * FROM t WHERE " + " AND ".join(conds))
'''
    assert _hits(code), "conds += [동적] 은 컨테이너를 실격시켜야 한다"
    code2 = '''
def q(cur):
    cols = ["id", "name"]
    cols[0] = request.args["c"]
    cur.execute(f"SELECT {', '.join(cols)} FROM t")
'''
    assert _hits(code2), "cols[0] = 출처 는 컨테이너를 실격시켜야 한다"


def test_variable_named_input_is_not_a_source() -> None:
    code = '''
def q(cur, fh):
    input = fh.read()
    cur.execute("SELECT * FROM t WHERE a = '" + input + "'")
'''
    assert _conf(code) == ["likely"]


def test_input_call_is_a_source() -> None:
    code = '''
def q(cur):
    n = input("name? ")
    cur.execute("SELECT * FROM t WHERE a = '" + n + "'")
'''
    assert _conf(code) == ["confirmed"]
