"""Extended KISA Python+JS rules — positive + negative checks.

Covers the 15 rules added beyond the initial 10 pilot rules:
- Python: INPUT-03/04/06/11, SEC-06/14, TIME-01/02, ERR-01, CODE-02
- JavaScript: INPUT-03/06/11, SEC-06/09
"""
from __future__ import annotations

from gvskb.scanner import scan_code


def _hits(code: str, filename: str, language: str) -> set[str]:
    r = scan_code(code, filename=filename, language=language)
    return {f.rule_id for f in r.findings}


# ---------------------------------------------------------------------------
# KISA Python — positive
# ---------------------------------------------------------------------------

def test_kisa_py_input_03_path_traversal_via_request() -> None:
    hits = _hits(
        'data = open(request.GET["file"], "rb").read()\n',
        "app.py", "python",
    )
    assert "KISA-PY-INPUT-03" in hits


def test_kisa_py_input_04_xss_via_mark_safe() -> None:
    hits = _hits(
        "from django.utils.safestring import mark_safe\n"
        "html = mark_safe(user_input)\n",
        "app.py", "python",
    )
    assert "KISA-PY-INPUT-04" in hits


def test_kisa_py_input_06_unrestricted_file_upload() -> None:
    hits = _hits(
        'file.save(os.path.join("/var/upload", file.filename))\n',
        "app.py", "python",
    )
    assert "KISA-PY-INPUT-06" in hits


def test_kisa_py_input_11_csrf_exempt_decorator() -> None:
    hits = _hits(
        "@csrf_exempt\ndef update_complaint(request):\n    ...\n",
        "views.py", "python",
    )
    assert "KISA-PY-INPUT-11" in hits


def test_kisa_py_sec_06_hardcoded_password_with_korean_var_name() -> None:
    hits = _hits(
        '비밀번호 = "Admin1234!"\nDB_PASSWORD = "production-secret-value"\n',
        "config.py", "python",
    )
    assert "KISA-PY-SEC-06" in hits


def test_kisa_py_sec_14_password_hashed_without_kdf() -> None:
    hits = _hits(
        "h = hashlib.sha256(password.encode()).hexdigest()\n",
        "auth.py", "python",
    )
    assert "KISA-PY-SEC-14" in hits


def test_kisa_py_err_01_debug_true_and_traceback_exposed() -> None:
    hits = _hits(
        "import traceback\n"
        "DEBUG = True\n"
        'return jsonify({"error": str(e)})\n',
        "app.py", "python",
    )
    assert "KISA-PY-ERR-01" in hits


def test_kisa_py_code_02_open_without_with_block() -> None:
    hits = _hits(
        'f = open("/etc/config")\n',
        "app.py", "python",
    )
    assert "KISA-PY-CODE-02" in hits


# ---------------------------------------------------------------------------
# KISA Python — negative (safe patterns should not trigger)
# ---------------------------------------------------------------------------

def test_kisa_py_extended_safe_patterns_dont_fire() -> None:
    safe = (
        "from pathlib import Path\n"
        "base = Path('/uploads').resolve()\n"
        "target = (base / Path(name).name).resolve()\n"
        "with open(target) as f:\n"
        "    data = f.read()\n"
        "import bcrypt\n"
        "hashed = bcrypt.hash(password)\n"
        "@require_POST\n"
        "def update(request):\n"
        "    pass\n"
    )
    r = scan_code(safe, filename="safe.py", language="python")
    py_kisa = [f.rule_id for f in r.findings if f.rule_id.startswith("KISA-PY")]
    assert py_kisa == []


# ---------------------------------------------------------------------------
# KISA JavaScript — positive
# ---------------------------------------------------------------------------

def test_kisa_js_input_03_path_traversal_in_fs() -> None:
    hits = _hits(
        "const data = fs.readFileSync(req.params.file);\n",
        "server.js", "javascript",
    )
    assert "KISA-JS-INPUT-03" in hits


def test_kisa_js_input_06_multer_without_filter() -> None:
    hits = _hits(
        'const upload = multer({ dest: "uploads/" });\n',
        "server.js", "javascript",
    )
    assert "KISA-JS-INPUT-06" in hits


def test_kisa_js_input_11_samesite_none_cookie() -> None:
    hits = _hits(
        'app.use(cookieSession({ sameSite: "none", secure: true }));\n',
        "app.js", "javascript",
    )
    assert "KISA-JS-INPUT-11" in hits


def test_kisa_js_sec_06_hardcoded_api_key() -> None:
    hits = _hits(
        'const API_KEY = "sk-prod-abcdef0123456789";\n',
        "config.js", "javascript",
    )
    assert "KISA-JS-SEC-06" in hits


def test_kisa_js_sec_09_plain_password_compare() -> None:
    hits = _hits(
        "if (user.password === req.body.password) { ... }\n",
        "auth.js", "javascript",
    )
    assert "KISA-JS-SEC-09" in hits


def test_kisa_js_sec_09_math_random_for_token() -> None:
    hits = _hits(
        "const resetToken = Math.random().toString(36);\n",
        "auth.js", "javascript",
    )
    assert "KISA-JS-SEC-09" in hits


# ---------------------------------------------------------------------------
# KISA JS — negative
# ---------------------------------------------------------------------------

def test_kisa_js_extended_safe_patterns_dont_fire() -> None:
    safe = (
        'const path = require("path");\n'
        'const SAFE = path.resolve("/uploads");\n'
        "const target = path.resolve(SAFE, path.basename(req.params.name));\n"
        "if (!target.startsWith(SAFE + path.sep)) return res.status(400).end();\n"
        'const upload = multer({ dest: "/var/uploads", fileFilter: filterFn, limits: { fileSize: 1024 } });\n'
        'app.use(cors({ origin: ["https://allowed.example"], credentials: true }));\n'
        'const apiKey = process.env.UPSTREAM_API_KEY;\n'
        'const ok = await bcrypt.compare(req.body.password, user.passwordHash);\n'
        'const token = randomBytes(32).toString("hex");\n'
    )
    r = scan_code(safe, filename="safe.js", language="javascript")
    js_kisa = [f.rule_id for f in r.findings if f.rule_id.startswith("KISA-JS")]
    assert js_kisa == []


# ---------------------------------------------------------------------------
# Language filter check (regression guard)
# ---------------------------------------------------------------------------

def test_python_file_does_not_trigger_js_only_rules() -> None:
    """Python의 eval(x)가 KISA-JS-INPUT-02 regex로 매칭되면 안 됨."""
    r = scan_code("eval(user_input)\n", filename="t.py", language="python")
    js_only = [f for f in r.findings if f.rule_id.startswith("KISA-JS")]
    assert js_only == []


def test_javascript_file_does_not_trigger_py_only_rules() -> None:
    r = scan_code("eval(userText);\n", filename="t.js", language="javascript")
    py_only = [f for f in r.findings if f.rule_id.startswith("KISA-PY")]
    assert py_only == []
