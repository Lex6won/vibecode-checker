"""기본 스모크 테스트."""
from pathlib import Path

import pytest

from gvskb.loader import RuleLoadError, load_all_rules
from gvskb.schema import Rule, Severity, SourceLayer
from gvskb.search import simple_search

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


@pytest.fixture(scope="module")
def rules() -> list[Rule]:
    return load_all_rules(RULES_DIR)


def test_reference_seed_rules_present(rules):
    """The 5 original reference rules must always be loadable."""
    ids = {r.id for r in rules}
    seed_ids = {
        "OWASP-LLM-2025-01",
        "OWASP-LLM-2025-02",
        "NIS-AI-M01",
        "MOIS-49-SW-17",
        "INTEL-2026-SLOPSQUATTING",
    }
    missing = seed_ids - ids
    assert not missing, f"missing seed rules: {missing}"


def test_scanner_builtin_rules_present_and_have_detection(rules):
    """All scanner-builtin GOV-* rules must carry a detection block (single source of truth)."""
    builtin = [r for r in rules if r.id.startswith("GOV-")]
    assert len(builtin) >= 11, f"expected at least 11 GOV-* rules, got {len(builtin)}"
    for r in builtin:
        assert r.detection is not None, f"{r.id} missing detection block"
        assert r.detection.patterns, f"{r.id} has no detection patterns"


def test_all_rules_have_required_metadata(rules):
    for r in rules:
        assert r.title_ko
        assert r.sources, f"{r.id} has no sources"
        assert r.severity in Severity
        assert r.source_layer in SourceLayer
        assert r.verified_at is not None
        assert r.body, f"{r.id} has empty body"


def test_search_finds_prompt_injection(rules):
    hits = simple_search(rules, "프롬프트 인젝션", limit=5)
    assert any(r.id == "OWASP-LLM-2025-01" for r in hits)


def test_search_filters_by_scenario(rules):
    hits = simple_search(rules, "데이터", scenario="data-pipeline", limit=5)
    for r in hits:
        assert "data-pipeline" in r.scenarios


def test_realtime_rule_present(rules):
    rt = [r for r in rules if r.source_layer == SourceLayer.realtime]
    assert len(rt) >= 1
    assert any(r.id == "INTEL-2026-SLOPSQUATTING" for r in rt)


def test_load_all_rules_strict_raises_on_bad_rule(tmp_path: Path):
    (tmp_path / "BAD.md").write_text("no frontmatter\n", encoding="utf-8")
    with pytest.raises(RuleLoadError) as excinfo:
        load_all_rules(tmp_path, strict=True)
    assert "frontmatter not found" in str(excinfo.value)


def test_load_all_rules_non_strict_skips_bad_rule(tmp_path: Path):
    (tmp_path / "BAD.md").write_text("no frontmatter\n", encoding="utf-8")
    assert load_all_rules(tmp_path, strict=False) == []
