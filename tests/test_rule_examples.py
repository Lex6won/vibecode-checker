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

# 실행형 룰은 전부 examples 를 가져야 한다. 25%로 두었을 때 실제로 22개 룰이
# 예시 없이 굴러갔고, 그중 GOV-PII-RRN-001 은 임의 13자리 정수의 40%를 주민번호로
# 보고하고 있었다 — examples 가 없으니 evaluate 표에 아예 나타나지 않아 아무도
# 몰랐다. validate-rules 도 같은 규칙을 ERROR 로 집행한다.
_COVERAGE_FLOOR_PCT: float = 100.0


def _language_for(rule: Rule) -> str | None:
    if rule.examples and rule.examples.language:
        return rule.examples.language
    return rule.languages[0] if rule.languages else None


# 파일명 + 내용을 함께 봐야 판정되는 룰 — scan_code(코드 조각)로는 재현 불가.
# 실제 파일을 만들어 검증하는 테스트가 따로 있다(test_round2_fixes.py).
_FILE_CONTEXT_RULE_IDS = {"GOV-SECRET-KEYFILE-001"}


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
    if rule.id in _FILE_CONTEXT_RULE_IDS:
        # 파일명과 내용을 함께 봐야 판정되는 룰은 코드 조각(scan_code)으로
        # 재현할 수 없다 — 실제 파일을 만들어 확인하는 별도 테스트가 있다.
        pytest.skip(f"{rule.id} needs file context (see test_round2_fixes/test_secret_keyfile)")
    lang = _language_for(rule)
    for i, snippet in enumerate(rule.examples.positive):
        # dedup_group 으로 묶인 룰은 서로를 가릴 수 있다 — 룰별 예시 검증은
        # "이 룰이 잡았는가"를 묻는 것이므로 묶기를 끈다.
        report = scan_code(snippet, filename=f"{rule.id}.pos.{i}", language=lang,
                           collapse_duplicates=False)
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
        report = scan_code(snippet, filename=f"{rule.id}.neg.{i}", language=lang,
                           collapse_duplicates=False)
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
