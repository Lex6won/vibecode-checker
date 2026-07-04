"""JS/TS 다줄 taint 스캐너 — "조립은 윗줄, 실행은 아랫줄" 탐지 + FP 가드."""
from __future__ import annotations

from gvskb.scanner import scan_code


def _taint_hits(code: str, filename: str = "app.js") -> dict[str, list[int]]:
    r = scan_code(code, filename=filename)
    out: dict[str, list[int]] = {}
    for f in r.findings:
        if f.engine == "js-taint":
            out.setdefault(f.rule_id, []).append(f.location.line)
    return out


# ---------------------------------------------------------------------------
# Positive — 다줄 조립 후 sink 도달은 반드시 발화
# ---------------------------------------------------------------------------


def test_multiline_sql_concat_query() -> None:
    code = (
        "const q = \"SELECT * FROM users WHERE name = '\" + name + \"'\";\n"
        "db.query(q);\n"
    )
    hits = _taint_hits(code)
    assert "KISA-JS-INPUT-01" in hits
    assert hits["KISA-JS-INPUT-01"] == [2]  # sink 줄에서 발화


def test_multiline_sql_template_literal() -> None:
    code = "let q = `SELECT * FROM t WHERE id = ${req.query.id}`;\nconn.execute(q);\n"
    assert "KISA-JS-INPUT-01" in _taint_hits(code)


def test_multiline_eval_of_built_string() -> None:
    code = 'var cmd = "run(" + userInput + ")";\neval(cmd);\n'
    assert "KISA-JS-INPUT-02" in _taint_hits(code)


def test_multiline_innerhtml_assignment() -> None:
    code = (
        'const htmlStr = "<p>" + comment + "</p>";\n'
        "document.getElementById('box').innerHTML = htmlStr;\n"
    )
    assert "KISA-JS-INPUT-04" in _taint_hits(code)


def test_taint_propagates_through_simple_copy() -> None:
    code = (
        "const part = `WHERE n = ${name}`;\n"
        'const q = "SELECT * FROM t " + part;\n'
        "db.query(q);\n"
    )
    assert "KISA-JS-INPUT-01" in _taint_hits(code)


def test_typescript_file_also_scanned() -> None:
    code = "const q = `DELETE FROM t WHERE id = ${id}`;\ndb.query(q);\n"
    assert "KISA-JS-INPUT-01" in _taint_hits(code, filename="api.ts")


# ---------------------------------------------------------------------------
# Negative — 안전한 형태는 절대 발화 금지 (FP=0 원칙)
# ---------------------------------------------------------------------------


def test_constant_query_not_flagged() -> None:
    code = 'const q = "SELECT * FROM t WHERE id = ?";\ndb.query(q, [id]);\n'
    assert _taint_hits(code) == {}


def test_reassignment_to_constant_clears_taint() -> None:
    code = (
        'let q = "SELECT " + col;\n'
        'q = "SELECT 1";\n'
        "db.query(q);\n"
    )
    assert _taint_hits(code) == {}


def test_dompurify_sanitized_not_flagged() -> None:
    code = (
        "const clean = DOMPurify.sanitize(rawHtml);\n"
        "el.innerHTML = clean;\n"
    )
    assert _taint_hits(code) == {}


def test_template_without_interpolation_not_tainted() -> None:
    code = "const q = `SELECT * FROM t WHERE id = 1`;\ndb.query(q);\n"
    assert _taint_hits(code) == {}


def test_comment_lines_ignored() -> None:
    code = (
        "// const q = \"SELECT \" + name;\n"
        'const q = "SELECT 1";\n'
        "db.query(q);\n"
    )
    assert _taint_hits(code) == {}


def test_python_file_not_scanned_by_js_taint() -> None:
    code = 'q = "SELECT " + name\ncur.execute(q)\n'
    assert _taint_hits(code, filename="a.py") == {}


def test_gvskb_ignore_suppresses_finding() -> None:
    code = (
        "const q = `SELECT ${x}`;\n"
        "db.query(q); // gvskb: ignore KISA-JS-INPUT-01\n"
    )
    assert _taint_hits(code) == {}


def test_untracked_variable_at_sink_not_flagged() -> None:
    # 오염 근거가 없는 변수는 sink에 들어가도 발화하지 않는다(보수적).
    code = "const q = buildQuery();\ndb.query(q);\n"
    assert _taint_hits(code) == {}
