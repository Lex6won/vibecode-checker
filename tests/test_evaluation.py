"""Evaluation metrics derived from rule examples — unit + integration tests."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from gvskb import cli, evaluation
from gvskb.loader import load_rule


REPO_RULES = Path(__file__).resolve().parent.parent / "rules"


# ---------------------------------------------------------------------------
# Unit — per-rule metric calculation
# ---------------------------------------------------------------------------

def test_evaluate_rule_returns_perfect_metrics_for_known_good_rule() -> None:
    """KISA-PY-INPUT-02 has high-quality positive/negative examples — all hit."""
    rule = load_rule(REPO_RULES / "kisa-python" / "KISA-PY-INPUT-02.md")
    metrics = evaluation.evaluate_rule(rule)
    assert metrics is not None
    assert metrics.rule_id == "KISA-PY-INPUT-02"
    assert metrics.positives >= 2
    assert metrics.negatives >= 2
    assert metrics.true_positives == metrics.positives
    assert metrics.true_negatives == metrics.negatives
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert metrics.f1 == 1.0


def test_evaluate_rule_returns_none_when_no_examples(tmp_path: Path) -> None:
    rule_md = tmp_path / "stub.md"
    rule_md.write_text(
        "---\n"
        "id: STUB-001\n"
        "title_ko: stub\n"
        "sources:\n"
        "  - publisher: x\n"
        "    document: y\n"
        "severity: low\n"
        "verified_at: 2026-01-01\n"
        "detection:\n"
        "  patterns: ['stub_pattern_unused']\n"
        "  category: gov-secure-coding\n"
        "---\n"
        "body",
        encoding="utf-8",
    )
    rule = load_rule(rule_md)
    assert evaluation.evaluate_rule(rule) is None


# ---------------------------------------------------------------------------
# Integration — evaluate_all on the real repo
# ---------------------------------------------------------------------------

def test_evaluate_all_on_repo_rules_returns_coverage_and_macro_metrics() -> None:
    report = evaluation.evaluate_all(REPO_RULES)
    assert report.total_rules > 0
    assert report.rules_with_examples >= 10  # A-2 set 10 rules
    assert 0.0 <= report.coverage_pct <= 100.0
    assert report.macro_precision is not None
    assert report.macro_recall is not None
    assert report.macro_f1 is not None
    assert report.total_tp + report.total_fn == sum(m.positives for m in report.per_rule)
    assert report.total_tn + report.total_fp == sum(m.negatives for m in report.per_rule)


def test_format_text_contains_summary_block() -> None:
    report = evaluation.evaluate_all(REPO_RULES)
    text = evaluation.format_text(report)
    assert "runnable rules" in text
    assert "macro" in text
    assert "precision" in text


def test_format_markdown_emits_table_and_disclaimer() -> None:
    report = evaluation.evaluate_all(REPO_RULES)
    md = evaluation.format_markdown(report)
    assert "| rule_id |" in md
    assert "자체 검증" in md
    assert "precision" in md


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------

def test_cli_evaluate_json_output(capsys: pytest.CaptureFixture[str]) -> None:
    rc = cli.main(["evaluate", "--format", "json", "--rules-dir", str(REPO_RULES)])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert "per_rule" in payload
    assert payload["rules_with_examples"] >= 10
    # All current example sets are clean -> exit OK
    assert rc == cli.EXIT_OK


def test_cli_evaluate_writes_file(tmp_path: Path,
                                  capsys: pytest.CaptureFixture[str]) -> None:
    out_path = tmp_path / "metrics.md"
    rc = cli.main([
        "evaluate", "--format", "markdown",
        "--rules-dir", str(REPO_RULES),
        "--output", str(out_path),
    ])
    assert rc == cli.EXIT_OK
    assert out_path.exists()
    body = out_path.read_text(encoding="utf-8")
    assert "| rule_id |" in body
