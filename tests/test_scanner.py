from gvskb.scanner import detect_secrets_and_pii, parse_manifest_packages, scan_code, suggest_fix


def test_scan_code_blocks_sql_injection():
    report = scan_code(
        "name = input('name')\n"
        "cursor.execute(f\"SELECT * FROM complaints WHERE name = '{name}'\")\n",
        filename="app.py",
        language="python",
    )

    assert report.summary.blocked is True
    assert any(f.rule_id == "GOV-SQL-INJECTION-001" for f in report.findings)
    finding = next(f for f in report.findings if f.rule_id == "GOV-SQL-INJECTION-001")
    assert finding.requires_approval_to_bypass is True
    assert "파라미터" in (finding.safe_fix or "")


def test_detect_secrets_and_pii_redacts_evidence():
    report = detect_secrets_and_pii(
        'OPENAI_API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz"\n'
        'citizen_id = "900101-1234567"\n',
        filename="settings.py",
    )

    assert report.summary.finding_count == 2
    joined = "\n".join(f.evidence for f in report.findings)
    assert "abcdefghijklmnopqrstuvwxyz" not in joined
    assert "1234567" not in joined
    assert "***REDACTED***" in joined or "******" in joined


def test_scan_code_detects_llm_output_handling():
    report = scan_code(
        "model_output = llm.invoke(prompt)\n"
        "document.body.innerHTML = model_output\n",
        filename="chat.js",
        language="javascript",
    )

    assert any(f.rule_id == "GOV-LLM-OUTPUT-HANDLING-001" for f in report.findings)


def test_parse_manifest_packages_for_pypi_and_npm():
    pypi = parse_manifest_packages("fastapi==0.111.0\n# comment\nuvicorn>=0.30\n", "pypi")
    assert pypi == [
        {"name": "fastapi", "version": "0.111.0"},
        {"name": "uvicorn", "version": "0.30"},
    ]

    npm = parse_manifest_packages('{"dependencies": {"react": "^19.0.0"}}', "npm")
    assert npm == [{"name": "react", "version": "19.0.0"}]


def test_suggest_fix_for_known_rule():
    fix = suggest_fix("GOV-CMD-INJECTION-001", "os.system(user_input)")

    assert fix["can_suggest"] is True
    assert "subprocess.run" in fix["safe_fix"]


# ---------------------------------------------------------------------------
# Negative tests — safe code must not trigger specific rules (false positive guard).
# ---------------------------------------------------------------------------

def test_safe_parameterized_sql_does_not_trigger_sql_rule():
    """Parameter binding is the recommended fix; it must not match SQL-INJECTION-001."""
    report = scan_code(
        'def get_citizen(name):\n'
        '    cursor.execute("SELECT * FROM complaints WHERE name = %s", (name,))\n',
        filename="safe_sql.py",
        language="python",
    )
    sql_findings = [f for f in report.findings if f.rule_id == "GOV-SQL-INJECTION-001"]
    assert sql_findings == [], f"safe parameterized SQL must not trigger, got {sql_findings}"


def test_safe_subprocess_run_does_not_trigger_cmd_rule():
    """subprocess.run with shell=False and a list of args is the safe pattern."""
    report = scan_code(
        'import subprocess\n'
        'subprocess.run(["cat", "--", filename], shell=False, check=True)\n',
        filename="safe_cmd.py",
        language="python",
    )
    cmd_findings = [f for f in report.findings if f.rule_id == "GOV-CMD-INJECTION-001"]
    assert cmd_findings == [], f"safe subprocess.run must not trigger, got {cmd_findings}"


def test_env_var_secret_loading_does_not_trigger_secret_rule():
    """Loading a key from env var (no literal) is the recommended pattern."""
    report = scan_code(
        'import os\n'
        'api_key = os.environ["OPENAI_API_KEY"]\n'
        'token = os.getenv("SLACK_TOKEN")\n',
        filename="safe_secret.py",
        language="python",
    )
    secret_findings = [f for f in report.findings if f.rule_id == "GOV-SECRET-APIKEY-001"]
    assert secret_findings == [], f"env-var secret loading must not trigger, got {secret_findings}"


def test_python_docstring_examples_do_not_trigger_code_execution_rules():
    report = scan_code(
        '"""Examples:\n'
        'eval(user_input)\n'
        'subprocess.run(cmd, shell=True)\n'
        'hashlib.md5(b"x").hexdigest()\n'
        '"""\n',
        filename="docs_as_code.py",
        language="python",
    )
    risky = {
        "KISA-PY-INPUT-02",
        "GOV-CODE-EXEC-001",
        "KISA-PY-INPUT-05",
        "GOV-CMD-INJECTION-001",
        "KISA-PY-SEC-04",
    }
    assert [f for f in report.findings if f.rule_id in risky] == []


def test_python_comment_examples_do_not_trigger_code_execution_but_secrets_still_do():
    report = scan_code(
        "# eval(user_input)\n"
        "# subprocess.run(cmd, shell=True)\n"
        "# hashlib.sha1(b'x').hexdigest()\n"
        '# OPENAI_API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz"\n',
        filename="comment_examples.py",
        language="python",
    )
    suppressed = {
        "KISA-PY-INPUT-02",
        "GOV-CODE-EXEC-001",
        "KISA-PY-INPUT-05",
        "GOV-CMD-INJECTION-001",
        "KISA-PY-SEC-04",
    }
    assert [f for f in report.findings if f.rule_id in suppressed] == []
    assert any(f.rule_id == "GOV-SECRET-APIKEY-001" for f in report.findings)


def test_gvskb_ignore_specific_rule_only_suppresses_that_rule():
    report = scan_code(
        "eval(user_input)  # gvskb: ignore KISA-PY-INPUT-02\n",
        filename="ignore_one.py",
        language="python",
    )
    assert not any(f.rule_id == "KISA-PY-INPUT-02" for f in report.findings)
    assert any(f.rule_id == "GOV-CODE-EXEC-001" for f in report.findings)
