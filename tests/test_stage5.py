"""Stage 5 — schema_version + GVSKB_MODE=offline gating + case-book quote."""
from __future__ import annotations

from pathlib import Path

import pytest

from gvskb import diagnostics
from gvskb.loader import load_all_rules
from gvskb.schema import CURRENT_RULE_SCHEMA_VERSION
from gvskb.tools.check_package import check_package_impl


RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


# ---------------------------------------------------------------------------
# schema_version
# ---------------------------------------------------------------------------

def test_rule_schema_version_default_is_current() -> None:
    """A rule loaded without schema_version field must default to CURRENT."""
    rules = load_all_rules(RULES_DIR)
    sample = rules[0]
    assert sample.schema_version == CURRENT_RULE_SCHEMA_VERSION


def test_all_repo_rules_use_current_schema_version() -> None:
    """Existing rules either omit schema_version (defaults to 1) or match current."""
    for r in load_all_rules(RULES_DIR):
        assert r.schema_version <= CURRENT_RULE_SCHEMA_VERSION, (
            f"{r.id}: schema_version={r.schema_version} > current={CURRENT_RULE_SCHEMA_VERSION}"
        )


def test_rule_with_future_schema_version_triggers_validation_warn(tmp_path: Path) -> None:
    """validate-rules surfaces a WARN if a rule declares an unknown future version."""
    from gvskb.validation import validate_rules_dir
    f = tmp_path / "FUTURE-01.md"
    f.write_text(
        "---\n"
        "id: FUTURE-01\n"
        "schema_version: 999\n"
        "title_ko: 미래 버전 룰\n"
        "sources: [{publisher: test, document: t}]\n"
        "severity: low\n"
        "verified_at: 2026-01-01\n"
        "---\n\n"
        "body\n",
        encoding="utf-8",
    )
    report = validate_rules_dir(tmp_path)
    codes = [i["code"] for i in report["issues"]]
    assert "schema-version-future" in codes


# ---------------------------------------------------------------------------
# GVSKB_MODE=offline gating
# ---------------------------------------------------------------------------

def test_offline_mode_skips_osv_in_doctor(monkeypatch: pytest.MonkeyPatch) -> None:
    """doctor with network=True still skips OSV if env says offline."""
    monkeypatch.setenv("GVSKB_MODE", "offline")
    report = diagnostics.run_diagnostics(network=True)
    osv_check = next(c for c in report["checks"] if c["name"] == "OSV.dev reachability")
    assert "skipped" in str(osv_check["value"]).lower()


def test_doctor_reports_gvskb_mode_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GVSKB_MODE", "offline")
    report = diagnostics.run_diagnostics(network=False)
    mode_check = next(c for c in report["checks"] if c["name"] == "GVSKB_MODE")
    assert mode_check["value"] == "offline"


def test_doctor_unknown_mode_warns(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GVSKB_MODE", "potato")
    report = diagnostics.run_diagnostics(network=False)
    mode_check = next(c for c in report["checks"] if c["name"] == "GVSKB_MODE")
    assert mode_check["status"] == "warn"


def test_check_package_returns_offline_marker_without_network(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """check_package must not reach OSV when GVSKB_MODE=offline.

    캐시 디렉터리를 빈 tmp_path 로 격리한다 — 개발 PC 의 실제 캐시
    (``gvskb intel-sync`` 로 채워짐)가 있으면 결과가 달라져 테스트가
    환경에 의존하게 된다.
    """
    monkeypatch.setenv("GVSKB_MODE", "offline")
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path))

    import asyncio
    result = asyncio.run(check_package_impl(name="anything", ecosystem="pypi"))
    assert result["offline"] is True
    assert result["checked"] is False       # 캐시 없음 → 판정 불가('안전' 아님)
    assert result["verdict"] == "unknown"
    assert "heuristics" in result


# ---------------------------------------------------------------------------
# Case-book quote presence in NIS-AI rules
# ---------------------------------------------------------------------------

def test_nis_ai_threat_rules_include_case_book_quotes() -> None:
    """Five NIS-AI threat rules carry an explicit case-book citation block."""
    targets = ["T01_data_poisoning.md", "T03_ai_backdoor_insertion.md",
               "T07_sensitive_data_input_and_leakage.md",
               "T08_prompt_injection.md", "T14_supply_chain_attack.md"]
    for name in targets:
        text = (RULES_DIR / "nis-ai" / name).read_text(encoding="utf-8")
        assert "인공지능 위험 사례집" in text, f"{name} missing 사례집 quote"
        assert "사례 #" in text, f"{name} should cite an explicit case number"
