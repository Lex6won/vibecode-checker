"""33차 — 호출자→매개변수 전파(Python). 함수 경계를 넘는 미탐(docs/40 §3-2 "중첩 함수·모듈 변수").

`find(cur, request.args['n'])` 처럼 호출자가 외부 값을 넘기면 `def find(cur, name)` 안의 sink 는
'확인됨'(차단)이다. 호출자가 전부 리터럴이면 그대로 '유력'(검토). 두 홉(f → g → h)까지.
"""
from __future__ import annotations

from gvskb.scanner import scan_code
from gvskb.schema import Decision

_HDR = "from flask import request\nimport os\n"


def _conf(code: str, prefix: str = "GOV-SQL") -> list[tuple[str, str]]:
    r = scan_code(_HDR + code, filename="app.py")
    return [(f.confidence, f.decision.value) for f in r.findings if f.rule_id.startswith(prefix)]


def test_request_passed_to_helper_confirms_sink_in_helper() -> None:
    code = '''
def find(cur, name):
    return cur.execute("SELECT * FROM t WHERE name = '" + name + "'").fetchall()

def view(cur):
    return find(cur, request.args["n"])
'''
    assert _conf(code) == [("confirmed", "block")]


def test_helper_without_external_caller_stays_review() -> None:
    code = '''
def find(cur, name):
    return cur.execute("SELECT * FROM t WHERE name = '" + name + "'").fetchall()

def view(cur):
    return find(cur, "fixed")
'''
    assert _conf(code) == [("likely", "warn")]


def test_two_hop_chain_is_followed() -> None:
    code = '''
def lookup(cur, key):
    return cur.execute(f"SELECT * FROM t WHERE k = '{key}'").fetchone()

def handle(cur, value):
    return lookup(cur, value)

def view(cur):
    n = request.args["n"]
    return handle(cur, n)
'''
    assert _conf(code) == [("confirmed", "block")]


def test_keyword_argument_is_mapped_to_parameter() -> None:
    code = '''
def find(cur, limit, name):
    return cur.execute("SELECT * FROM t WHERE name = '" + name + "'").fetchall()

def view(cur):
    return find(cur, name=request.form["n"], limit=10)
'''
    assert _conf(code) == [("confirmed", "block")]


def test_source_in_a_different_argument_does_not_taint_other_param() -> None:
    code = '''
def find(cur, limit, name):
    return cur.execute("SELECT * FROM t WHERE name = '" + name + "'").fetchall()

def view(cur):
    return find(cur, request.args["limit"], "fixed")
'''
    assert _conf(code) == [("likely", "warn")]


def test_command_injection_through_helper_is_confirmed() -> None:
    code = '''
def ping(host):
    os.system("ping " + host)

def view():
    ping(request.args["h"])
'''
    assert _conf(code, "KISA-PY-INPUT-05") == [("confirmed", "block")]


def test_parameterised_helper_stays_quiet_even_with_external_caller() -> None:
    code = '''
def find(cur, name):
    return cur.execute("SELECT * FROM t WHERE name = ?", (name,)).fetchall()

def view(cur):
    return find(cur, request.args["n"])
'''
    assert _conf(code) == []


def test_duplicate_function_names_are_not_propagated() -> None:
    code = '''
def find(cur, name):
    return cur.execute("SELECT * FROM t WHERE name = '" + name + "'").fetchall()

def find(cur, other):
    return None

def view(cur):
    return find(cur, request.args["n"])
'''
    confs = _conf(code)
    assert confs and all(c != "confirmed" for c, _ in confs), confs


def test_connection_parameter_is_never_a_source() -> None:
    code = '''
def run(conn, sql):
    return conn.execute(sql).fetchall()

def view(conn):
    return run(conn, "SELECT 1")
'''
    r = scan_code(_HDR + code, filename="app.py")
    assert all(f.decision != Decision.block for f in r.findings)


def test_tool_parameter_sql_reaching_helper_with_strip_chain_is_confirmed() -> None:
    """실측(safe_check soosiro_mcp_server.py:465): MCP 도구 `run_sql(sql)` 이 `_db_run_sql(sql)` 을 부르고
    그 안에서 `conn.execute(sql.strip().rstrip(";"), params)` — 도구가 넘긴 SQL 전체가 실행된다."""
    code = '''
def _db_run_sql(sql, params=None):
    conn = get_conn()
    cur = conn.execute(sql.strip().rstrip(";"), params or [])
    return cur.fetchall()

@mcp.tool()
def run_sql(sql: str):
    return _db_run_sql(sql)
'''
    assert _conf(code) == [("confirmed", "block")]
