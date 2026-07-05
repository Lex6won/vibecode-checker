"""Python AST scanner — precision tests.

The AST adapter must:
- Detect bare ``eval`` / ``exec`` / risky ``compile`` modes
- Detect ``os.system`` / ``os.popen`` / ``subprocess.* shell=True``
- Detect weak hashes (``hashlib.md5/sha1``, ``hashlib.new('md5')``)
- Detect untrusted deserialization (pickle, marshal, joblib, torch.load without weights_only)
- NOT match on safe equivalents (method calls like ``obj.eval()``, ``shell=False``, ``torch.load(weights_only=True)``)
- Tag findings with ``engine="python-ast"``
"""
from __future__ import annotations

from gvskb.scanner import scan_code


def _ast_hits(code: str) -> set[str]:
    r = scan_code(code, filename="t.py", language="python")
    return {f.rule_id for f in r.findings if f.engine == "python-ast"}


# ---------------------------------------------------------------------------
# Positive — AST must catch
# ---------------------------------------------------------------------------

def test_ast_detects_bare_eval_and_exec() -> None:
    hits = _ast_hits("eval(user_input)\nexec(code)\n")
    assert "KISA-PY-INPUT-02" in hits


def test_ast_detects_compile_in_exec_mode() -> None:
    hits = _ast_hits('co = compile(src, "<s>", "exec")\n')
    assert "KISA-PY-INPUT-02" in hits


def test_ast_detects_os_system_and_popen() -> None:
    hits = _ast_hits("import os\nos.system(cmd)\nos.popen('ls')\n")
    assert "KISA-PY-INPUT-05" in hits


def test_ast_detects_subprocess_shell_true() -> None:
    hits = _ast_hits(
        "import subprocess\n"
        "subprocess.run(cmd, shell=True)\n"
        "subprocess.Popen(['sh', '-c', x], shell=True)\n"
    )
    assert "KISA-PY-INPUT-05" in hits


def test_ast_detects_weak_hashlib_calls() -> None:
    hits = _ast_hits(
        "import hashlib\n"
        "hashlib.md5(b'x').hexdigest()\n"
        "hashlib.sha1(b'y').hexdigest()\n"
        "hashlib.new('md5')\n"
    )
    assert "KISA-PY-SEC-04" in hits


def test_ast_detects_pickle_loads_and_torch_load_unsafe() -> None:
    hits = _ast_hits(
        "import pickle, torch, joblib\n"
        "pickle.loads(data)\n"
        "torch.load('model.pt')\n"
        "joblib.load(p)\n"
    )
    assert "KISA-PY-CODE-03" in hits


# ---------------------------------------------------------------------------
# Negative — AST must NOT match these safe forms
# ---------------------------------------------------------------------------

def test_ast_skips_method_eval_call() -> None:
    """obj.eval() is a method, not the builtin — must not match KISA-PY-INPUT-02 from AST."""
    r = scan_code("engine.eval(expression)\npattern.exec(text)\n", filename="t.py", language="python")
    ast_input02 = [f for f in r.findings if f.rule_id == "KISA-PY-INPUT-02" and f.engine == "python-ast"]
    assert ast_input02 == []


def test_ast_skips_subprocess_shell_false() -> None:
    code = (
        "import subprocess\n"
        "subprocess.run(['ls', '--', path], shell=False, check=True)\n"
        "subprocess.run(['cat', filename])\n"  # default shell=False
    )
    r = scan_code(code, filename="t.py", language="python")
    ast_input05 = [f for f in r.findings if f.rule_id == "KISA-PY-INPUT-05" and f.engine == "python-ast"]
    assert ast_input05 == []


def test_ast_skips_torch_load_with_weights_only_true() -> None:
    code = "import torch\nmodel = torch.load('m.pt', weights_only=True)\n"
    r = scan_code(code, filename="t.py", language="python")
    assert r.findings == []  # regex no longer matches either


def test_ast_skips_hashlib_sha256() -> None:
    hits = _ast_hits("import hashlib\nhashlib.sha256(b'x').hexdigest()\n")
    assert "KISA-PY-SEC-04" not in hits


def test_ast_skips_compile_to_regex_or_non_exec() -> None:
    """compile() with non-exec mode (e.g. for pattern code objects) is fine."""
    r = scan_code('import re\npat = re.compile("a.*b")\n', filename="t.py", language="python")
    ast_input02 = [f for f in r.findings if f.rule_id == "KISA-PY-INPUT-02" and f.engine == "python-ast"]
    assert ast_input02 == []


# ---------------------------------------------------------------------------
# Multi-line SQL injection — variable taint (assemble on one line, run on next)
# ---------------------------------------------------------------------------

def _sql_findings(code: str) -> list:
    r = scan_code(code, filename="t.py", language="python")
    return [f for f in r.findings if f.rule_id == "GOV-SQL-INJECTION-001"]


def test_taint_detects_concat_query_run_next_line() -> None:
    code = (
        "query = \"SELECT * FROM citizens WHERE name = '\" + name + \"'\"\n"
        "cur.execute(query)\n"
    )
    hits = _sql_findings(code)
    assert hits, "multi-line concat SQL must be flagged"
    assert hits[0].engine == "python-ast"
    assert hits[0].location.line == 2  # flagged at the execute() sink


def test_taint_detects_fstring_query_run_next_line() -> None:
    code = 'q = f"SELECT * FROM u WHERE n = {name}"\ncursor.execute(q)\n'
    assert _sql_findings(code)


def test_taint_detects_format_query_run_next_line() -> None:
    code = 'q = "SELECT * FROM u WHERE n = {}".format(name)\ndb.execute(q)\n'
    assert _sql_findings(code)


def test_taint_detects_query_used_inside_if_block() -> None:
    code = 'q = "SELECT " + col + " FROM t"\nif ok:\n    cur.execute(q)\n'
    assert _sql_findings(code)


def test_taint_detects_executemany_and_executescript() -> None:
    code = 'q = "INSERT INTO t VALUES (" + v + ")"\ncur.executemany(q, rows)\n'
    assert _sql_findings(code)


# Negative — safe / parameterised forms must never be flagged (keeps FP=0)

def test_taint_skips_parameter_binding() -> None:
    assert _sql_findings('cur.execute("SELECT * FROM t WHERE n = %s", (name,))\n') == []


def test_taint_skips_qmark_binding() -> None:
    assert _sql_findings('cur.execute("SELECT * FROM t WHERE id = ?", (uid,))\n') == []


def test_taint_skips_constant_query_variable() -> None:
    assert _sql_findings('q = "SELECT 1"\ncur.execute(q)\n') == []


def test_taint_clears_on_reassignment_to_safe_value() -> None:
    code = 'q = "..." + name\nq = "SELECT 1"\ncur.execute(q)\n'
    assert _sql_findings(code) == []


def test_taint_skips_non_string_concat() -> None:
    """a + b with no string literal is not a SQL string build."""
    assert _sql_findings('x = a + b\ncur.execute(x)\n') == []


def test_taint_scope_isolation_between_functions() -> None:
    """A tainted var in one function must not leak into another's execute()."""
    code = (
        "def build():\n"
        "    q = \"SELECT \" + col\n"
        "    return q\n"
        "def run(q):\n"           # different scope, param q is untainted here
        "    cur.execute(q)\n"
    )
    hits = _sql_findings(code)
    assert all(f.location.line != 5 for f in hits)


# ---------------------------------------------------------------------------
# LLM prompt injection — a dynamically-built prompt reaching an LLM SDK call
# ---------------------------------------------------------------------------

def _llm_findings(code: str) -> list:
    r = scan_code(code, filename="t.py", language="python")
    return [f for f in r.findings if f.rule_id == "GOV-LLM-PROMPT-INJECTION-001"]


def test_llm_taint_detects_concat_prompt_into_openai_call() -> None:
    code = (
        "prompt = SYSTEM_PROMPT + \"\\n사용자: \" + user_input\n"
        "resp = openai.chat.completions.create(model='gpt-4o', "
        "messages=[{'role':'user','content': prompt}])\n"
    )
    hits = _llm_findings(code)
    assert hits, "concat prompt reaching an LLM call must be flagged (OWASP LLM01)"
    assert hits[0].engine == "python-ast"
    assert hits[0].location.line == 2  # flagged at the LLM SDK sink


def test_llm_taint_detects_fstring_prompt() -> None:
    code = (
        "prompt = f\"질문에 답하세요: {user_input}\"\n"
        "client.responses.create(model='gpt-4o', input=prompt)\n"
    )
    assert _llm_findings(code)


def test_llm_taint_detects_anthropic_messages_create() -> None:
    code = (
        "text = \"요약: \" + doc\n"
        "client.messages.create(model='claude', messages=[{'role':'user','content': text}])\n"
    )
    assert _llm_findings(code)


def test_llm_taint_detects_gemini_generate_content() -> None:
    code = (
        "prompt = \"다음을 분석: \" + payload\n"
        "model.generate_content(prompt)\n"
    )
    assert _llm_findings(code)


def test_llm_taint_detects_inline_concat_in_call() -> None:
    """The narrow regex catches an inline concat inside the LLM call itself."""
    code = "openai.chat.completions.create(messages=[{'content': 'Q: ' + q}])\n"
    assert _llm_findings(code)


# Negative — the recommended patterns and non-LLM calls must never fire (FP=0)

def test_llm_taint_skips_raw_input_as_data() -> None:
    """Passing untrusted input as its own message field (not concatenated into
    instructions) is the recommended pattern — must not be flagged."""
    code = (
        "openai.chat.completions.create(messages=[{'role':'user','content': user_input}])\n"
    )
    assert _llm_findings(code) == []


def test_llm_taint_skips_role_separated_messages() -> None:
    code = (
        "messages = [{'role':'system','content': SYSTEM_PROMPT},\n"
        "            {'role':'user','content': user_input}]\n"
        "openai.chat.completions.create(model='gpt-4o', messages=messages)\n"
    )
    assert _llm_findings(code) == []


def test_llm_taint_skips_constant_prompt() -> None:
    code = (
        "prompt = '오늘 날씨를 알려주세요'\n"
        "model.generate_content(prompt)\n"
    )
    assert _llm_findings(code) == []


def test_llm_taint_skips_non_llm_create_with_concat() -> None:
    """A dynamic string reaching a non-LLM ``.create()`` (ORM) is not an LLM sink."""
    code = (
        "name = 'user-' + suffix\n"
        "User.objects.create(username=name)\n"
    )
    assert _llm_findings(code) == []


def test_llm_taint_scope_isolation_between_functions() -> None:
    code = (
        "def build():\n"
        "    p = 'Q: ' + col\n"
        "    return p\n"
        "def run(p):\n"                       # different scope, param p untainted
        "    model.generate_content(p)\n"
    )
    hits = _llm_findings(code)
    assert all(f.location.line != 5 for f in hits)


# ---------------------------------------------------------------------------
# Adapter behaviour
# ---------------------------------------------------------------------------

def test_ast_does_not_run_on_non_python_files() -> None:
    code = "eval(x)\n"
    r = scan_code(code, filename="t.js", language="javascript")
    assert all(f.engine != "python-ast" for f in r.findings)


def test_ast_engine_field_is_set_on_findings() -> None:
    r = scan_code("eval(x)\n", filename="t.py", language="python")
    ast_findings = [f for f in r.findings if f.rule_id == "KISA-PY-INPUT-02" and f.engine == "python-ast"]
    assert ast_findings, "AST should produce KISA-PY-INPUT-02 finding with engine=python-ast"
    assert ast_findings[0].evidence  # should have line content


def test_ast_dedupes_with_regex_on_same_line() -> None:
    """When AST + regex both match the same (rule_id, line), only one wins."""
    r = scan_code("eval(user_input)\n", filename="t.py", language="python")
    # 정확히 1개의 KISA-PY-INPUT-02 finding이어야 함
    same = [f for f in r.findings if f.rule_id == "KISA-PY-INPUT-02"]
    assert len(same) == 1
    # 더 정밀한 엔진(AST)이 이김
    assert same[0].engine == "python-ast"


def test_ast_handles_syntax_error_gracefully() -> None:
    """Malformed Python must not crash the scan — regex still runs."""
    code = "def broken(:\n    eval(x)\n"
    r = scan_code(code, filename="t.py", language="python")
    # AST는 실패해도 regex는 작동
    assert all(f.engine != "python-ast" for f in r.findings)
