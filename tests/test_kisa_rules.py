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


# ---------------------------------------------------------------------------
# 실측 오탐 좁히기 (2026-08-08, kordoc·lexdiff·noti.kpetro 전수 스캔 기준)
#
# 셋 다 "규제 추가 = 매치 집합의 진부분집합" 이라 새 오탐은 구조적으로 생길 수
# 없다. 따라서 테스트의 일은 **새 미탐이 없는지** 지키는 쪽에 있다 —
# 오탐 케이스와 진탐 케이스를 반드시 짝으로 둔다.
# ---------------------------------------------------------------------------

def _rule_hit(code: str, rule_id: str, filename: str = "app.js") -> bool:
    report = scan_code(code, filename=filename)
    return any(f.rule_id == rule_id for f in report.findings)


# --- KISA-JS-INPUT-05: 정규식의 .exec() 은 명령 실행이 아니다 ---

def test_js_input05_ignores_regex_exec_receivers() -> None:
    for code, why in [
        ("const match = /^[A-Za-z]+/.exec(input.slice(idx + 1))", "정규식 리터럴(실측)"),
        ("while ((dm = lineRegex.exec(sections[i + 1])) !== null) {", "Regex 변수(실측)"),
        ("const m = new RegExp(p).exec(s + t)", "new RegExp(...).exec"),
        # 아래 두 개는 '변수명' 가드의 고유 효과다. new RegExp(...) 형태는 앞의
        # `)` 가드가 이미 막아 주므로, 이것들이 없으면 RegExp/regexp 가드를
        # 통째로 지워도 테스트가 통과한다(실제로 변이검사에서 통과했다).
        ("myRegExp.exec(a + b)", "RegExp 변수명"),
        ("const r = urlRegexp.exec(path + q)", "regexp 변수명"),
        ("myPattern.exec(a + b)", "Pattern 변수"),
    ]:
        assert not _rule_hit(code, "KISA-JS-INPUT-05"), why


def test_js_input05_still_catches_real_command_exec() -> None:
    for code, why in [
        ("cp.exec('ls ' + dir)", "문자열 조립 명령"),
        ("childProcess.exec(`rm ${path}`)", "템플릿 명령"),
        ("child_process.execSync('cat ' + f)", "execSync"),
        ("shell.exec(cmd + args)", "shell 래퍼 — 정규식이 아니다"),
    ]:
        assert _rule_hit(code, "KISA-JS-INPUT-05"), why


# --- KISA-JS-INPUT-04: 인자 없는 .html() 은 getter(읽기) ---

def test_js_input04_ignores_html_getter() -> None:
    for code, why in [
        ('let bodyHtml = $("body").html() || $.root().html() || html', "cheerio 읽기(실측)"),
        ('return $("body").html() || $.root().html() || fragmentHtml', "cheerio 읽기(실측)"),
        ('$("#out").html( )', "공백만 — 여전히 읽기"),
    ]:
        assert not _rule_hit(code, "KISA-JS-INPUT-04"), why


def test_js_input04_still_catches_html_setter() -> None:
    for code, why in [
        ('$("#out").html(userInput)', "변수 주입"),
        ('$("#out").html("<b>" + name + "</b>")', "문자열 조립 주입"),
        ('$(sel).html(', "줄바꿈으로 인자를 넘긴 경우 — 보수적으로 잡는다"),
    ]:
        assert _rule_hit(code, "KISA-JS-INPUT-04"), why


# --- KISA-JS-SEC-01: 역할 기반 인가가 붙은 관리자 초기화는 제외 ---

_ADMIN_RESET = (
    'app.post("/api/users/:id/reset-password", requireAuth([\'admin\']), '
    'async (req: Request, res: Response) => {\n  await db.reset(req.params.id)\n}'
)
_SELF_CHANGE = (
    'app.post("/api/change-password", async (req, res) => {\n'
    '  await db.setPassword(req.body.pw)\n}'
)
_LOGIN_ONLY = (
    'router.post("/withdraw", requireAuth(), async (req, res) => {\n'
    '  await close(req.user)\n}'
)


_ROLE_GUARDS = [
    ('app.post("/api/users/:id/reset-password", requireAuth([\'admin\']), '
     'async (req, res) => {\n  await db.reset(req.params.id)\n}', "requireAuth 역할배열"),
    ('router.patch("/reset-password", requireRole("admin"), '
     'async (req, res) => {\n  x()\n}', "requireRole"),
    ('router.post("/withdraw", requireAdmin, async (req, res) => {\n  x()\n}', "requireAdmin"),
    ('app.put("/change-password", adminOnly, async (req, res) => {\n  x()\n}', "adminOnly"),
    ('app.post("/delete-account", isAdmin(req), async (req, res) => {\n  x()\n}', "isAdmin"),
]


def test_js_sec01_ignores_role_guarded_admin_reset() -> None:
    """관리자가 **남의** 비밀번호를 초기화하는 경로에 그 사람의 옛 비밀번호를
    요구할 수는 없다 — 재인증 부재가 결함이 아니다.

    가드 이름을 **하나씩** 시험한다. 대표 하나만 두면 나머지를 목록에서
    지워도 통과한다(실제로 변이검사에서 통과했다)."""
    assert not _rule_hit(_ADMIN_RESET, "KISA-JS-SEC-01", "routes.ts")
    for code, why in _ROLE_GUARDS:
        assert not _rule_hit(code, "KISA-JS-SEC-01", "routes.ts"), why


def test_js_sec01_still_catches_self_change_without_reauth() -> None:
    assert _rule_hit(_SELF_CHANGE, "KISA-JS-SEC-01", "routes.ts")


def test_js_sec01_login_only_guard_is_not_enough() -> None:
    """역할 없는 requireAuth() 는 '그냥 로그인'이다 — 본인 비밀번호 변경에
    재인증을 생략할 근거가 되지 않으므로 계속 잡아야 한다.
    이 테스트가 없으면 가드 목록을 넓히다 룰을 통째로 무력화할 수 있다."""
    assert _rule_hit(_LOGIN_ONLY, "KISA-JS-SEC-01", "routes.ts")
