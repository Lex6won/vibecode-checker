"""Rule-attached examples meta-tests.

Every rule with an ``examples`` block is exercised against the scanner so the
positive snippets stay detected and the negative snippets never regress into
false positives. Authors add examples in the MD frontmatter; this file makes
them executable spec rather than documentation.

A coverage observer also runs (non-failing) so we can see how many runnable
rules have examples wired up. The floor assertion grows over time — bump it
when a sprint pushes coverage higher so we never drift backwards.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from gvskb.loader import load_all_rules
from gvskb.scanner import scan_code
from gvskb.schema import Rule

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
_RULES: list[Rule] = load_all_rules(RULES_DIR)
_RULES_WITH_EXAMPLES: list[Rule] = [
    r for r in _RULES
    if r.examples and (r.examples.positive or r.examples.negative)
]

# Runnable = patterns are present so the scanner can actually detect this rule.
_RUNNABLE_RULES: list[Rule] = [
    r for r in _RULES if r.detection and r.detection.patterns
]

# Soft coverage floor for runnable rules. Bump as more rules get examples.
# At the introduction of this infrastructure we set it conservatively.
_COVERAGE_FLOOR_PCT: float = 25.0


def _language_for(rule: Rule) -> str | None:
    if rule.examples and rule.examples.language:
        return rule.examples.language
    return rule.languages[0] if rule.languages else None


# ---------------------------------------------------------------------------
# Per-rule positive / negative checks (parametrized by rule ID)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "rule",
    _RULES_WITH_EXAMPLES,
    ids=lambda r: r.id,
)
def test_rule_positive_examples_are_detected(rule: Rule) -> None:
    assert rule.examples is not None
    if not rule.examples.positive:
        pytest.skip(f"{rule.id} has no positive examples")
    lang = _language_for(rule)
    for i, snippet in enumerate(rule.examples.positive):
        report = scan_code(snippet, filename=f"{rule.id}.pos.{i}", language=lang)
        ids = {f.rule_id for f in report.findings}
        assert rule.id in ids, (
            f"{rule.id} positive example #{i} was not detected.\n"
            f"  snippet: {snippet!r}\n"
            f"  found rule_ids: {sorted(ids)}"
        )


@pytest.mark.parametrize(
    "rule",
    _RULES_WITH_EXAMPLES,
    ids=lambda r: r.id,
)
def test_rule_negative_examples_are_not_detected(rule: Rule) -> None:
    assert rule.examples is not None
    if not rule.examples.negative:
        pytest.skip(f"{rule.id} has no negative examples")
    lang = _language_for(rule)
    for i, snippet in enumerate(rule.examples.negative):
        report = scan_code(snippet, filename=f"{rule.id}.neg.{i}", language=lang)
        ids = {f.rule_id for f in report.findings}
        assert rule.id not in ids, (
            f"{rule.id} negative example #{i} produced a false positive.\n"
            f"  snippet: {snippet!r}\n"
            f"  matched rule_ids: {sorted(ids)}"
        )


# ---------------------------------------------------------------------------
# Coverage floor — guard against silent regression
# ---------------------------------------------------------------------------

def test_examples_coverage_floor(capsys: pytest.CaptureFixture[str]) -> None:
    if not _RUNNABLE_RULES:
        pytest.skip("no runnable rules loaded")
    with_ex = [
        r for r in _RUNNABLE_RULES
        if r.examples and (r.examples.positive or r.examples.negative)
    ]
    pct = (len(with_ex) / len(_RUNNABLE_RULES)) * 100.0
    # Always print for visibility in CI logs.
    print(
        f"\n[examples coverage] {len(with_ex)}/{len(_RUNNABLE_RULES)} "
        f"runnable rules carry examples ({pct:.1f}%)"
    )
    capsys.readouterr()  # discard for non-strict environments
    assert pct >= _COVERAGE_FLOOR_PCT, (
        f"examples coverage {pct:.1f}% dropped below floor {_COVERAGE_FLOOR_PCT}%. "
        f"Either restore examples on the missing rules or, if intentional, lower the floor in this file."
    )
