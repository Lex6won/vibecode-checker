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


# ── sk_ 계열 키(언더스코어) ──────────────────────────────────────────────
# 실측 구멍: 패턴이 `sk-`(하이픈)만 보고 있어 `sk_ggtrust_…`·`sk_live_…` 형식
# 키를 탐지도 마스킹도 하지 못했다. 특히 마스킹 누락은 토큰이 보고서·오류
# 메시지에 그대로 찍힌다는 뜻이라 탐지 누락보다 직접적인 유출이다.
_SK_UNDERSCORE_KEY = "sk_ggtrust_Ab3xK9mQ2pR7sT1uV5wY8zC4dE6fG0hJ"


def test_underscore_sk_key_is_masked_even_without_a_variable_name():
    """값만 인자로 넘겨도 마스킹돼야 한다 — 변수명 기반 규칙이 놓치는 자리."""
    from gvskb.scanners.regex_scanner import redact_evidence

    out = redact_evidence(f'client = RegistryClient(base_url, "{_SK_UNDERSCORE_KEY}")')
    assert _SK_UNDERSCORE_KEY not in out
    assert "REDACTED" in out


def test_underscore_sk_key_is_masked_in_free_text():
    """오류 메시지처럼 따옴표 밖에 있는 토큰도 가려야 한다."""
    from gvskb.scanners.regex_scanner import redact_evidence

    out = redact_evidence(f"error: token {_SK_UNDERSCORE_KEY} rejected by registry")
    assert _SK_UNDERSCORE_KEY not in out


def test_underscore_sk_key_is_detected_as_a_finding():
    report = detect_secrets_and_pii(
        f'client = RegistryClient(base_url, "{_SK_UNDERSCORE_KEY}")\n',
        filename="registry_client.py",
    )
    assert report.summary.finding_count >= 1
    assert _SK_UNDERSCORE_KEY not in "\n".join(f.evidence for f in report.findings)


def test_snake_case_identifier_is_not_mistaken_for_a_key():
    """`sk_` 는 하이픈과 달리 식별자에 흔하다 — 전부 소문자면 키로 보지 않는다."""
    report = detect_secrets_and_pii(
        "sk_model_pipeline_transformer = build()\n",
        filename="model.py",
    )
    assert report.summary.finding_count == 0


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
        {"name": "fastapi", "version": "0.111.0", "version_exact": True},
        # `>=0.30` 은 "0.30 이상"이지 "0.30"이 아니다 — 경계값임을 함께 싣는다.
        {"name": "uvicorn", "version": "0.30", "version_exact": False},
    ]

    npm = parse_manifest_packages('{"dependencies": {"react": "^19.0.0"}}', "npm")
    assert npm == [{"name": "react", "version": "19.0.0", "version_exact": False}]


def test_manifest_constraints_are_not_mistaken_for_installed_versions():
    """제약 연산자를 버리면 하한이 '쓰는 버전'으로 둔갑한다.

    `requests>=2.28` 인 프로젝트에 실제로는 2.31.0 이 깔려 있을 수 있다. 예전에는
    연산자를 버려 2.28 로 판정했고, 2.28 의 취약점이 2.30 에서 고쳐졌다면 그대로
    오탐이 됐다. 더 나쁜 것은 그 오탐이 레지스트리에 "2.28 에 대한 관측 사실"로
    저장된다는 점이다 — 우리가 보지 않은 것을 사실로 넘기게 된다.
    """
    exact = {"==2.31.0"}
    for spec in ("==2.31.0", ">=2.28", "<=3.0", "~=2.31", ">2.0", "<3.0", "==2.*"):
        pkg = parse_manifest_packages(f"requests{spec}\n", "pypi")[0]
        assert pkg["version_exact"] is (spec in exact), f"{spec} 판단이 틀렸다"

    # npm: 접두사가 없어야 고정이다.
    for spec, want in (("4.17.0", True), ("^4.17.0", False), ("~4.17.0", False),
                       ("4.17.0-beta.1", True), ("*", False), ("latest", False)):
        pkg = parse_manifest_packages(
            '{"dependencies": {"express": "%s"}}' % spec, "npm",
        )[0]
        assert pkg["version_exact"] is want, f"{spec} 판단이 틀렸다"


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
