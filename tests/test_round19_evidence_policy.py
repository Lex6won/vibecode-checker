"""근거 수준 × 판정 정책(1층, 2026-10-13) — 회귀·적대적 검증.

스패로우 비교(safe_check)에서 체커의 차단 71건 중 실제 위험은 16~20건이었다. 원인은 룰이 아니라
두 가지 구조였다: ① 근거가 '패턴 일치만'·'유력'인 발견도 룰 기본값대로 차단했다, ② Python AST 가
"동적으로 조립됐다"를 "외부 입력이 닿았다(확인됨)"로 적었다. 이 파일은 그 두 가지를 고정한다.

  ① 내려가야 하는 것: 정규식만의 경로 조작·XPath·LLM 출력, 자리표시자 확장·모듈 상수·헬퍼로 만든 SQL,
     경고 억제(disable_warnings), lockfile 의 루트 프로젝트
  ② 그대로 차단이어야 하는 것: 요청·argv·라우트 매개변수가 닿은 SQL/명령/프롬프트, 구문 자체가
     약점인 룰(verify=False·eval·디버그), 비밀값·개인정보, 가짜 정화 함수를 거친 요청값
"""

from __future__ import annotations

from pathlib import Path

from gvskb.scanner import scan_code, scan_path
from gvskb.schema import Decision, Severity
from gvskb.tools.lockfiles import parse_lockfile


def _one(code: str, rule: str, filename: str = "app.py"):
    fs = [f for f in scan_code(code, filename=filename).findings if rule in (f.rule_id, *f.also_matched)]
    assert fs, f"{rule} 가 발화해야 한다: {code!r}"
    return fs[0]


def _none(code: str, rule: str, filename: str = "app.py") -> None:
    assert not [f for f in scan_code(code, filename=filename).findings if rule in (f.rule_id, *f.also_matched)], \
        f"{rule} 가 발화하면 안 된다: {code!r}"


# ---------------------------------------------------------------------------
# ② 먼저 — 그대로 차단이어야 하는 것 (적대적)
# ---------------------------------------------------------------------------


def test_request_reaching_sql_is_confirmed_and_blocked() -> None:
    code = 'from flask import request\nname = request.args.get("n")\ncur.execute(f"SELECT * FROM t WHERE n = \'{name}\'")\n'
    f = _one(code, "GOV-SQL-INJECTION-001")
    assert f.decision == Decision.block and f.confidence == "confirmed"


def test_route_parameter_reaching_sql_is_confirmed() -> None:
    code = (
        "@app.route('/u/<name>')\n"
        "def show(name):\n"
        "    sql = f\"SELECT * FROM users WHERE name = '{name}'\"\n"
        "    return con.execute(sql).fetchall()\n"
    )
    f = _one(code, "GOV-SQL-INJECTION-001")
    assert f.decision == Decision.block and f.confidence == "confirmed"


def test_source_propagates_through_assignment_and_loop() -> None:
    code = (
        "ids = request.form.getlist('id')\n"
        "for i in ids:\n"
        "    q = 'DELETE FROM t WHERE id = ' + i\n"
        "    cur.execute(q)\n"
    )
    f = _one(code, "GOV-SQL-INJECTION-001")
    assert f.decision == Decision.block and f.confidence == "confirmed"


def test_argv_in_os_command_is_confirmed_and_blocked() -> None:
    f = _one('import os, sys\nos.system("cp /data/" + sys.argv[1])\n', "KISA-PY-INPUT-05")
    assert f.decision == Decision.block and f.confidence == "confirmed"


def test_construct_rules_still_block_without_a_source() -> None:
    for code, rule in (
        ("requests.get(url, verify=False)\n", "KISA-PY-SEC-11"),
        ("ctx.verify_mode = ssl.CERT_NONE\n", "KISA-PY-SEC-11"),
        ("eval(expr)\n", "KISA-PY-INPUT-02"),
        ('app.run(debug=True)\n', "GOV-FLASK-DEBUG-001"),
    ):
        f = _one(code, rule)
        assert f.decision == Decision.block, (code, f.decision, f.severity_adjusted)


def test_value_based_rules_still_block() -> None:
    f = _one('API_KEY = "sk-proj-Ab3xK9mQ2pR7sT1uV5wY8zC4dE6fG0hJ"\n', "GOV-SECRET-APIKEY-001")
    assert f.decision == Decision.block


def test_fake_placeholder_helper_is_not_trusted() -> None:
    """join 의 인자가 자리표시자 리터럴이 아니면 헬퍼라도 자리표시자가 아니다."""
    code = (
        "def _ph(xs):\n    return \",\".join(xs)\n"
        "@app.get('/q')\n"
        "def q(codes):\n"
        "    conn.execute(f\"SELECT * FROM t WHERE c IN ({_ph(codes)})\")\n"
    )
    f = _one(code, "GOV-SQL-INJECTION-001")
    assert f.decision == Decision.block and f.confidence == "confirmed"


def test_shadowed_module_constant_is_not_inherited() -> None:
    code = (
        'VIEW = "v_x"\n'
        "@app.get('/v')\n"
        "def q(con, user):\n"
        "    VIEW = user\n"
        "    con.execute(f\"SELECT * FROM {VIEW}\")\n"
    )
    f = _one(code, "GOV-SQL-INJECTION-001")
    assert f.decision == Decision.block and f.confidence == "confirmed"


# ---------------------------------------------------------------------------
# ① 내려가야 하는 것 — 지워지지 않고, 차단만 아니다
# ---------------------------------------------------------------------------


def test_pattern_only_block_rule_becomes_high_review() -> None:
    f = _one('tag = month.replace("-", "_")\nwith open(os.path.join(LABEL_DIR, f"refit_{tag}.json"), "w") as fh:\n    pass\n', "KISA-PY-INPUT-03")
    assert f.decision == Decision.warn and f.severity == Severity.high and f.confidence == "pattern-only"
    assert "패턴 일치만" in (f.severity_adjusted or "") and f.requires_approval_to_bypass is False


def test_dynamic_sql_without_a_source_is_likely_and_reviewed() -> None:
    code = "def q(con, table):\n    con.execute(f\"DELETE FROM {table}\")\n"
    f = _one(code, "GOV-SQL-INJECTION-001")
    assert f.decision == Decision.warn and f.confidence == "likely" and f.severity == Severity.critical


def test_placeholder_expansion_is_not_dynamic_sql() -> None:
    _none(
        "def q(conn, codes):\n"
        "    ph = ','.join('?' * len(codes))\n"
        "    clause = f\"AND c IN ({ph})\"\n"
        "    sql = f\"SELECT * FROM t WHERE 1=1 {clause}\"\n"
        "    return conn.execute(sql, list(codes)).fetchall()\n",
        "GOV-SQL-INJECTION-001",
    )
    _none("def q(con, regions):\n    ph = ', '.join('?' for _ in regions)\n    con.execute(f\"SELECT x FROM f WHERE r IN ({ph})\", regions)\n", "GOV-SQL-INJECTION-001")


def test_placeholder_helper_function_is_recognised() -> None:
    _none(
        "def _ph(xs):\n    return \",\".join(\"?\" * len(xs))\n"
        "def q(conn, codes):\n"
        "    sql = f\"SELECT * FROM t WHERE c IN ({_ph(codes)})\"\n"
        "    return conn.execute(sql, list(codes)).fetchall()\n",
        "GOV-SQL-INJECTION-001",
    )


def test_module_constants_are_visible_inside_functions() -> None:
    _none(
        'COLS = ["a", "b"]\nVIEW = "v_x"\n'
        "def q(con):\n"
        "    sql = f\"SELECT {', '.join(COLS)} FROM {VIEW}\"\n"
        "    con.cursor().execute(sql)\n",
        "GOV-SQL-INJECTION-001",
    )


def test_disable_warnings_alone_is_not_cert_validation_off() -> None:
    _none("import urllib3\nurllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)\n", "KISA-PY-SEC-11")


def test_uv_lock_root_project_is_not_a_component(tmp_path: Path) -> None:
    lock = tmp_path / "uv.lock"
    lock.write_text(
        'version = 1\nrequires-python = ">=3.12"\n\n'
        '[[package]]\nname = "wtms-reverse"\nversion = "0.1.0"\nsource = { virtual = "." }\n'
        'dependencies = [\n    { name = "requests" },\n]\n\n'
        '[[package]]\nname = "requests"\nversion = "2.32.5"\nsource = { registry = "https://pypi.org/simple" }\n',
        encoding="utf-8",
    )
    parsed = parse_lockfile(lock.read_text(encoding="utf-8"), "uv.lock")
    assert parsed and parsed["format"] == "uv.lock"
    names = {p["name"] for p in parsed["packages"]}
    assert "requests" in names and "wtms-reverse" not in names
    assert {"from": None, "to": "requests"} in parsed["edges"]


def test_policy_does_not_touch_severity_or_remove_findings(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text('ds = root.find(f".//Dataset[@id=\'{ds_id}\']")\n', encoding="utf-8")
    report = scan_path(tmp_path)
    xp = [f for f in report.findings if f.rule_id == "KISA-PY-INPUT-09"]
    assert xp and xp[0].decision == Decision.warn and xp[0].severity == Severity.high
    assert report.summary.blocked is False and report.summary.finding_count >= 1
