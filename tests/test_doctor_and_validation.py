"""diagnostics + validation + CLI doctor/validate-rules 동작 확인."""
from __future__ import annotations

import json
import tomllib
from pathlib import Path

import pytest

from gvskb import cli, diagnostics, validation


def test_diagnostics_offline_runs_without_network() -> None:
    report = diagnostics.run_diagnostics(network=False, expected_minimum=20)
    assert "overall" in report
    assert report["overall"] in {"ok", "warn", "error"}
    names = {c["name"] for c in report["checks"]}
    assert {"Python", "Total rules", "MCP server import"} <= names


def test_diagnostics_runtime_status_for_mcp() -> None:
    status = diagnostics.runtime_status_for_mcp()
    assert status["rules_loaded_ok"] is True
    assert status["total_rules"] >= 20
    assert status["runtime_detection_rules"] >= 1
    assert "disclaimer" in status


def test_doctor_cli_offline_text(capsys: pytest.CaptureFixture[str]) -> None:
    rc = cli.main(["doctor", "--offline"])
    out = capsys.readouterr().out
    assert "gvskb doctor" in out
    assert "Total rules" in out
    assert rc in (cli.EXIT_OK, cli.EXIT_FINDINGS_WARN)


def test_doctor_cli_offline_json(capsys: pytest.CaptureFixture[str]) -> None:
    rc = cli.main(["doctor", "--offline", "--json"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["overall"] in {"ok", "warn", "error"}
    assert isinstance(payload["checks"], list)
    assert len(payload["checks"]) >= 5
    assert rc in (cli.EXIT_OK, cli.EXIT_FINDINGS_WARN)


def test_doctor_respects_gvskb_rules_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An empty rules dir should yield ERROR (total rules under expected minimum)."""
    empty = tmp_path / "empty_rules"
    empty.mkdir()
    monkeypatch.setenv("GVSKB_RULES_DIR", str(empty))
    report = diagnostics.run_diagnostics(network=False, expected_minimum=20)
    statuses = {c["name"]: c["status"] for c in report["checks"]}
    assert statuses.get("Total rules") == "error"
    assert report["overall"] == "error"


def test_doctor_reports_malformed_rule_as_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bad_rules = tmp_path / "bad_rules"
    bad_rules.mkdir()
    (bad_rules / "BROKEN.md").write_text("missing frontmatter\n", encoding="utf-8")
    monkeypatch.setenv("GVSKB_RULES_DIR", str(bad_rules))
    report = diagnostics.run_diagnostics(network=False, expected_minimum=1)
    statuses = {c["name"]: c["status"] for c in report["checks"]}
    assert statuses.get("Rule loader") == "error"
    assert report["overall"] == "error"


def test_validate_rules_current_repo_passes() -> None:
    """The repository's own rules/ must validate cleanly (no ERROR)."""
    rules_dir = Path(__file__).resolve().parent.parent / "rules"
    report = validation.validate_rules_dir(rules_dir)
    error_issues = [i for i in report["issues"] if i["status"] == "error"]
    assert error_issues == [], f"existing rules should not produce errors: {error_issues[:3]}"


def test_validate_rules_detects_regex_compile_failure(tmp_path: Path) -> None:
    bad = tmp_path / "BAD-REGEX-01.md"
    bad.write_text(
        "---\n"
        "id: BAD-REGEX-01\n"
        "title_ko: 잘못된 정규식\n"
        "sources: [{publisher: test, document: t}]\n"
        "severity: high\n"
        "verified_at: 2026-01-01\n"
        "detection:\n"
        "  patterns: ['[invalid(regex']\n"
        "  category: test\n"
        "---\n\n"
        "body\n",
        encoding="utf-8",
    )
    report = validation.validate_rules_dir(tmp_path)
    codes = [i["code"] for i in report["issues"]]
    assert "regex-compile-fail" in codes
    assert report["overall"] == "error"


def test_validate_rules_detects_duplicate_id(tmp_path: Path) -> None:
    common = (
        "title_ko: duplicate test\n"
        "sources: [{publisher: test, document: t}]\n"
        "severity: low\n"
        "verified_at: 2026-01-01\n"
    )
    (tmp_path / "a.md").write_text(f"---\nid: DUP-01\n{common}---\n\nbody\n", encoding="utf-8")
    (tmp_path / "b.md").write_text(f"---\nid: DUP-01\n{common}---\n\nbody\n", encoding="utf-8")
    report = validation.validate_rules_dir(tmp_path)
    codes = {i["code"] for i in report["issues"]}
    assert "duplicate-rule-id" in codes


def test_validate_rules_cli_json(capsys: pytest.CaptureFixture[str]) -> None:
    rc = cli.main(["validate-rules", "--json"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["overall"] in {"ok", "warn"}  # current repo should not be error
    assert rc in (cli.EXIT_OK, cli.EXIT_FINDINGS_WARN)


def test_mcp_server_status_does_not_call_network() -> None:
    """server_status must be MCP-safe: no network, no exceptions."""
    status = diagnostics.runtime_status_for_mcp()
    assert "OSV" not in status  # no network-dependent fields
    assert status["total_rules"] >= 20


def test_wheel_includes_runtime_policy_and_config_data() -> None:
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    force_include = data["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"]
    assert force_include["rules"] == "gvskb/rules"
    assert force_include["policies"] == "gvskb/policies"
    assert force_include["config"] == "gvskb/config"


# ---------------------------------------------------------------------------
# 인텔 캐시 진단 — 오프라인 운영의 1차 건강신호
# ---------------------------------------------------------------------------


def test_doctor_intel_cache_warns_when_offline_and_missing(monkeypatch, tmp_path):
    """망분리 + 캐시 없음 = check-package 전건 판정불가 상황 — doctor가 WARN으로 알린다."""
    monkeypatch.setenv("GVSKB_MODE", "offline")
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path / "none"))
    from gvskb.diagnostics import check_intel_cache

    results = check_intel_cache()
    cache_checks = [r for r in results if r["name"].startswith("Intel cache:")]
    assert len(cache_checks) == 2  # osv-malicious · cisa-kev
    assert all(r["status"] == "warn" for r in cache_checks)
    assert any("update-intel" in r.get("note", "") for r in cache_checks)
    # 자동 당김 진단도 함께 나온다 — 오프라인인데 배포 폴더가 없으면 경고.
    autopull = [r for r in results if r["name"] == "Intel auto-update"]
    assert len(autopull) == 1
    assert autopull[0]["status"] == "warn"
    assert "GVSKB_INTEL_DIR" in autopull[0].get("note", "")


def test_doctor_intel_cache_ok_when_fresh(monkeypatch, tmp_path):
    monkeypatch.delenv("GVSKB_MODE", raising=False)
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path))
    from gvskb.intel.cache import IntelCache

    cache = IntelCache()
    cache.save("osv-malicious", "https://example/x", [], ecosystems=["PyPI"])
    cache.save("cisa-kev", "https://example/x", [])
    from gvskb.diagnostics import check_intel_cache

    results = check_intel_cache()
    assert all(r["status"] == "ok" for r in results)


def test_server_status_exposes_intel_cache(monkeypatch, tmp_path):
    """에이전트가 scan_dependencies 전에 캐시 존재·신선도를 알 수 있어야 한다."""
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path))
    from gvskb.intel.cache import IntelCache

    IntelCache().save("osv-malicious", "https://example/x", [], ecosystems=["PyPI"])
    from gvskb.diagnostics import runtime_status_for_mcp

    info = runtime_status_for_mcp()
    assert "intel_cache" in info
    osv = info["intel_cache"]["osv-malicious"]
    assert osv["present"] is True
    assert osv["stale"] is False
    assert osv["ecosystems"] == ["PyPI"]
    assert info["intel_cache"]["cisa-kev"]["present"] is False
