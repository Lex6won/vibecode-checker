"""KISA Python + JavaScript 시범 룰 10개의 detection 정확성 테스트.

위험 코드 → 매칭, 안전 코드 → 미매칭(false positive 가드) 양쪽을 모두 검증합니다.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from gvskb.loader import load_all_rules
from gvskb.scanner import scan_code

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


@pytest.fixture(scope="module")
def kisa_rule_ids() -> set[str]:
    return {r.id for r in load_all_rules(RULES_DIR) if r.id.startswith("KISA-")}


def test_kisa_rules_load_with_detection_patterns(kisa_rule_ids: set[str]) -> None:
    rules = [r for r in load_all_rules(RULES_DIR) if r.id.startswith("KISA-")]
    assert len(rules) >= 25, f"expected at least 25 KISA rules (pilot 10 + extended 15), got {len(rules)}"
    for r in rules:
        assert r.detection is not None, f"{r.id} missing detection"
        assert r.detection.patterns, f"{r.id} has no detection patterns"
        assert r.sources, f"{r.id} has no sources"
        assert r.related_baseline, f"{r.id} should reference MOIS-49 baseline"


# ---------------------------------------------------------------------------
# Python — positive matches
# ---------------------------------------------------------------------------

def test_kisa_py_input_01_sql_raw_concat() -> None:
    report = scan_code(
        'cursor.execute("UPDATE board SET name=%s WHERE id=%s" % (name, id))\n',
        filename="bad.py", language="python",
    )
    assert any(f.rule_id == "KISA-PY-INPUT-01" for f in report.findings)


def test_kisa_py_input_02_eval_exec() -> None:
    report = scan_code("eval(user_input)\nexec(code)\n", filename="bad.py", language="python")
    hits = {f.rule_id for f in report.findings}
    assert "KISA-PY-INPUT-02" in hits


def test_kisa_py_input_05_os_command() -> None:
    report = scan_code(
        'os.system(cmd)\nsubprocess.run(cmd_str, shell=True)\n',
        filename="bad.py", language="python",
    )
    assert any(f.rule_id == "KISA-PY-INPUT-05" for f in report.findings)


def test_kisa_py_sec_04_weak_crypto() -> None:
    report = scan_code(
        'import hashlib\nhashlib.md5(password.encode()).hexdigest()\n',
        filename="bad.py", language="python",
    )
    assert any(f.rule_id == "KISA-PY-SEC-04" for f in report.findings)


def test_kisa_py_code_03_pickle_loads() -> None:
    report = scan_code(
        'import pickle\npickle.loads(open(f, "rb").read())\n',
        filename="bad.py", language="python",
    )
    assert any(f.rule_id == "KISA-PY-CODE-03" for f in report.findings)


# ---------------------------------------------------------------------------
# JavaScript — positive matches
# ---------------------------------------------------------------------------

def test_kisa_js_input_01_sql_template_literal() -> None:
    report = scan_code(
        'db.query(`SELECT * FROM u WHERE id=${userId}`);\n',
        filename="bad.js", language="javascript",
    )
    assert any(f.rule_id == "KISA-JS-INPUT-01" for f in report.findings)


def test_kisa_js_input_02_eval_and_new_function() -> None:
    report = scan_code(
        'eval(userText);\nnew Function("return " + code);\nsetTimeout("alert(1)", 100);\n',
        filename="bad.js", language="javascript",
    )
    hits = {f.rule_id for f in report.findings}
    assert "KISA-JS-INPUT-02" in hits


def test_kisa_js_input_04_xss_inner_html_and_document_write() -> None:
    report = scan_code(
        "el.innerHTML = userText;\ndocument.write(input);\n",
        filename="bad.js", language="javascript",
    )
    assert any(f.rule_id == "KISA-JS-INPUT-04" for f in report.findings)


def test_kisa_js_input_05_child_process_exec() -> None:
    # 직접 호출
    report = scan_code(
        'const cp = require("child_process");\ncp.exec("ls " + dir);\n',
        filename="bad.js", language="javascript",
    )
    assert any(f.rule_id == "KISA-JS-INPUT-05" for f in report.findings)


def test_kisa_js_sec_04_weak_crypto() -> None:
    report = scan_code(
        'crypto.createHash("md5").update(p).digest();\n',
        filename="bad.js", language="javascript",
    )
    assert any(f.rule_id == "KISA-JS-SEC-04" for f in report.findings)


# ---------------------------------------------------------------------------
# Negative tests — safe patterns must NOT match (false-positive guard)
# ---------------------------------------------------------------------------

def test_safe_python_does_not_trigger_kisa_py(kisa_rule_ids: set[str]) -> None:
    safe = (
        'cursor.execute("UPDATE board SET name=%s WHERE id=%s", (name, content_id))\n'
        "data = ast.literal_eval(text)\n"
        'subprocess.run(["convert", "--", filename], shell=False, check=True)\n'
        "import hashlib\n"
        "digest = hashlib.sha256(data).hexdigest()\n"
        "obj = json.loads(raw)\n"
    )
    report = scan_code(safe, filename="safe.py", language="python")
    py_hits = [f.rule_id for f in report.findings if f.rule_id.startswith("KISA-PY")]
    assert py_hits == [], f"safe Python should not trigger KISA-PY rules, got {py_hits}"


def test_safe_javascript_does_not_trigger_kisa_js() -> None:
    safe = (
        'const [rows] = await db.execute("SELECT * FROM u WHERE id = ?", [userId]);\n'
        "setTimeout(() => doX(), 100);\n"
        "el.textContent = userInput;\n"
        'const digest = crypto.createHash("sha256").update(data).digest("hex");\n'
        'const child = spawn("convert", ["--", filename], { shell: false });\n'
    )
    report = scan_code(safe, filename="safe.js", language="javascript")
    js_hits = [f.rule_id for f in report.findings if f.rule_id.startswith("KISA-JS")]
    assert js_hits == [], f"safe JS should not trigger KISA-JS rules, got {js_hits}"


def test_kisa_py_input_02_skips_method_eval_calls() -> None:
    """obj.eval() is a method call - must not match KISA-PY-INPUT-02."""
    report = scan_code(
        "result = engine.eval(expression)\nm = re.compile(pat)\n",
        filename="safe.py", language="python",
    )
    py_input02 = [f for f in report.findings if f.rule_id == "KISA-PY-INPUT-02"]
    assert py_input02 == []


def test_kisa_js_input_05_static_command_does_not_match() -> None:
    """Static commands without variable concat are too noisy if they all match."""
    report = scan_code('cp.exec("npm test");\n', filename="safe.js", language="javascript")
    js_input05 = [f for f in report.findings if f.rule_id == "KISA-JS-INPUT-05"]
    assert js_input05 == []
