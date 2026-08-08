"""Semgrep adapter — unit tests with subprocess mocked.

These tests do not require Semgrep to be installed. They pin:
- graceful skip when the binary is missing
- language gating (Python files never trigger Semgrep)
- correct mapping of Semgrep JSON output → Finding(engine="semgrep")
- categories filter passthrough
- malformed output never crashes the scan
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from gvskb.scanners import semgrep_scanner as sg


@pytest.fixture
def fake_rules_dir(tmp_path: Path) -> Path:
    """A rules dir that *exists and is non-empty*, so is_available() can pass
    the dir check; binary availability is forced via monkeypatch in each test."""
    d = tmp_path / "semgrep_rules"
    d.mkdir()
    (d / "stub.yaml").write_text("rules: []\n", encoding="utf-8")
    return d


def _fake_semgrep_output(rule_id: str = "KISA-JS-INPUT-02", line: int = 3,
                        lines: str = "eval(userInput)") -> str:
    return json.dumps({
        "results": [{
            "check_id": "rules.js-code-injection.gvskb-js-code-injection",
            "path": "input.js",
            "start": {"line": line, "col": 1},
            "end": {"line": line, "col": 20},
            "extra": {
                "message": "JS code injection",
                "severity": "ERROR",
                "lines": lines,
                "metadata": {"gvskb_rule_id": rule_id, "category": "kisa-secure-coding"},
            },
        }],
        "errors": [],
    })


# ---------------------------------------------------------------------------
# Graceful skip
# ---------------------------------------------------------------------------

def test_skips_when_binary_missing(monkeypatch: pytest.MonkeyPatch,
                                   fake_rules_dir: Path) -> None:
    monkeypatch.setattr(sg.shutil, "which", lambda name: None)
    scanner = sg.SemgrepScanner(rules_dir=fake_rules_dir)
    assert scanner.is_available() is False
    assert scanner.scan("eval(x)\n", filename="t.js", language="javascript") == []


def test_skips_when_rules_dir_missing(monkeypatch: pytest.MonkeyPatch,
                                      tmp_path: Path) -> None:
    monkeypatch.setattr(sg.shutil, "which", lambda name: "/fake/semgrep")
    scanner = sg.SemgrepScanner(rules_dir=tmp_path / "does_not_exist", binary="/fake/semgrep")
    assert scanner.is_available() is False
    assert scanner.scan("eval(x)\n", filename="t.js") == []


def test_skips_when_rules_dir_empty(monkeypatch: pytest.MonkeyPatch,
                                    tmp_path: Path) -> None:
    monkeypatch.setattr(sg.shutil, "which", lambda name: "/fake/semgrep")
    empty = tmp_path / "empty"
    empty.mkdir()
    scanner = sg.SemgrepScanner(rules_dir=empty, binary="/fake/semgrep")
    assert scanner.is_available() is False


# ---------------------------------------------------------------------------
# Language gating
# ---------------------------------------------------------------------------

def test_skips_python_input_even_when_available(
    monkeypatch: pytest.MonkeyPatch, fake_rules_dir: Path
) -> None:
    """Semgrep should never be invoked for Python files — that's python-ast's job."""
    calls: list[list[str]] = []

    def _fake_run(cmd, **_kw):
        calls.append(cmd)
        return SimpleNamespace(stdout=_fake_semgrep_output(), stderr="", returncode=0)

    monkeypatch.setattr(sg.subprocess, "run", _fake_run)
    scanner = sg.SemgrepScanner(rules_dir=fake_rules_dir, binary="/fake/semgrep")
    out = scanner.scan("eval(x)\n", filename="t.py", language="python")
    assert out == []
    assert calls == []


# ---------------------------------------------------------------------------
# Successful run → Finding mapping
# ---------------------------------------------------------------------------

def test_maps_semgrep_result_to_finding_via_gvskb_rule_id(
    monkeypatch: pytest.MonkeyPatch, fake_rules_dir: Path
) -> None:
    monkeypatch.setattr(
        sg.subprocess, "run",
        lambda cmd, **kw: SimpleNamespace(
            stdout=_fake_semgrep_output("KISA-JS-INPUT-02", line=7, lines="eval(req.body.x)"),
            stderr="", returncode=0,
        ),
    )
    scanner = sg.SemgrepScanner(rules_dir=fake_rules_dir, binary="/fake/semgrep")
    findings = scanner.scan(
        "function f(req) { return eval(req.body.x); }\n",
        filename="app.js",
        language="javascript",
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "KISA-JS-INPUT-02"
    assert f.engine == "semgrep"
    assert f.location.file == "app.js"
    assert f.location.line == 7
    assert "eval" in f.evidence


def test_unknown_rule_id_is_dropped(monkeypatch: pytest.MonkeyPatch,
                                    fake_rules_dir: Path) -> None:
    monkeypatch.setattr(
        sg.subprocess, "run",
        lambda cmd, **kw: SimpleNamespace(
            stdout=_fake_semgrep_output("UNKNOWN-RULE-9999", line=1, lines="x"),
            stderr="", returncode=0,
        ),
    )
    scanner = sg.SemgrepScanner(rules_dir=fake_rules_dir, binary="/fake/semgrep")
    out = scanner.scan("x\n", filename="t.js", language="javascript")
    assert out == []


def test_categories_filter_passes_through(monkeypatch: pytest.MonkeyPatch,
                                          fake_rules_dir: Path) -> None:
    monkeypatch.setattr(
        sg.subprocess, "run",
        lambda cmd, **kw: SimpleNamespace(
            stdout=_fake_semgrep_output(), stderr="", returncode=0,
        ),
    )
    scanner = sg.SemgrepScanner(rules_dir=fake_rules_dir, binary="/fake/semgrep")
    # Restrict to a category the KISA JS rule is NOT in
    out = scanner.scan("eval(x)\n", filename="t.js", language="javascript",
                       categories={"secret-scanning"})
    assert out == []


# ---------------------------------------------------------------------------
# Failure / malformed output never crashes the scan
# ---------------------------------------------------------------------------

def test_timeout_returns_empty(monkeypatch: pytest.MonkeyPatch, fake_rules_dir: Path) -> None:
    def _raise(cmd, **_kw):
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=1.0)
    monkeypatch.setattr(sg.subprocess, "run", _raise)
    scanner = sg.SemgrepScanner(rules_dir=fake_rules_dir, binary="/fake/semgrep", timeout=1.0)
    assert scanner.scan("eval(x)\n", filename="t.js", language="javascript") == []


def test_malformed_json_returns_empty(monkeypatch: pytest.MonkeyPatch, fake_rules_dir: Path) -> None:
    monkeypatch.setattr(
        sg.subprocess, "run",
        lambda cmd, **kw: SimpleNamespace(stdout="not json", stderr="", returncode=0),
    )
    scanner = sg.SemgrepScanner(rules_dir=fake_rules_dir, binary="/fake/semgrep")
    assert scanner.scan("eval(x)\n", filename="t.js", language="javascript") == []


def test_empty_stdout_returns_empty(monkeypatch: pytest.MonkeyPatch, fake_rules_dir: Path) -> None:
    monkeypatch.setattr(
        sg.subprocess, "run",
        lambda cmd, **kw: SimpleNamespace(stdout="", stderr="", returncode=0),
    )
    scanner = sg.SemgrepScanner(rules_dir=fake_rules_dir, binary="/fake/semgrep")
    assert scanner.scan("eval(x)\n", filename="t.js", language="javascript") == []


def test_invocation_command_includes_required_flags(
    monkeypatch: pytest.MonkeyPatch, fake_rules_dir: Path
) -> None:
    seen: dict = {}

    def _capture(cmd, **_kw):
        seen["cmd"] = cmd
        return SimpleNamespace(stdout=_fake_semgrep_output(), stderr="", returncode=0)

    monkeypatch.setattr(sg.subprocess, "run", _capture)
    sg.SemgrepScanner(rules_dir=fake_rules_dir, binary="/fake/semgrep").scan(
        "eval(x)\n", filename="t.js", language="javascript"
    )
    cmd = seen["cmd"]
    assert cmd[0] == "/fake/semgrep"
    assert "--json" in cmd
    assert "--quiet" in cmd
    assert "--no-rewrite-rule-ids" in cmd
    # The rules dir comes right after --config
    idx = cmd.index("--config")
    assert Path(cmd[idx + 1]).resolve() == fake_rules_dir.resolve()


def test_looks_relevant_covers_mts_and_cts() -> None:
    """scan_path 는 language=None 으로 넘기므로 확장자 목록이 유일한 관문이다.
    `.mts`/`.cts` 가 빠지면 Semgrep 층만 조용히 이 파일들을 건너뛴다."""
    assert sg._looks_relevant("mod.mts", None)
    assert sg._looks_relevant("mod.cts", None)
    assert not sg._looks_relevant("notes.md", None)
