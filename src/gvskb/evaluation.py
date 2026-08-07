"""Precision / recall metrics derived from rule-attached examples.

The same snippets that pin per-rule regression also act as a tiny evaluation
set: every ``examples.positive`` snippet is a labeled positive, every
``examples.negative`` snippet is a labeled negative. Running them through the
scanner gives TP / FN / TN / FP per rule, which is the most honest answer we
can give to "how accurate is this MCP?" — because the labels live next to the
rule they prove.

This is intentionally NOT a substitute for a third-party benchmark: it
measures the rules against their authors' own examples. A wider eval corpus
can be added later by pointing this module at ``evaluation/positive/`` /
``evaluation/negative/`` directories.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

from .loader import load_all_rules
from .scanner import scan_code
from .schema import Rule


@dataclass(frozen=True)
class RuleMetrics:
    rule_id: str
    positives: int          # number of labeled positives examined
    negatives: int          # number of labeled negatives examined
    true_positives: int
    false_negatives: int
    true_negatives: int
    false_positives: int
    precision: float | None
    recall: float | None
    f1: float | None

    def to_dict(self) -> dict:
        return asdict(self)


def _f1(precision: float | None, recall: float | None) -> float | None:
    if precision is None or recall is None:
        return None
    if precision + recall == 0:
        return 0.0
    return 2 * precision * recall / (precision + recall)


def _language_for(rule: Rule) -> str | None:
    if rule.examples and rule.examples.language:
        return rule.examples.language
    return rule.languages[0] if rule.languages else None


def evaluate_rule(rule: Rule) -> RuleMetrics | None:
    """Return metrics for a single rule, or None if it has no examples."""
    if not rule.examples or (not rule.examples.positive and not rule.examples.negative):
        return None
    lang = _language_for(rule)
    tp = fn = tn = fp = 0
    for snippet in rule.examples.positive:
        # dedup_group 으로 묶인 룰이 서로를 가리면 재현율이 0으로 보인다 —
        # 룰별 평가에서는 묶기를 끈다.
        report = scan_code(snippet, filename=f"{rule.id}.pos", language=lang,
                           collapse_duplicates=False)
        hit = any(f.rule_id == rule.id for f in report.findings)
        if hit:
            tp += 1
        else:
            fn += 1
    for snippet in rule.examples.negative:
        report = scan_code(snippet, filename=f"{rule.id}.neg", language=lang,
                           collapse_duplicates=False)
        hit = any(f.rule_id == rule.id for f in report.findings)
        if hit:
            fp += 1
        else:
            tn += 1
    precision = (tp / (tp + fp)) if (tp + fp) > 0 else None
    recall = (tp / (tp + fn)) if (tp + fn) > 0 else None
    return RuleMetrics(
        rule_id=rule.id,
        positives=tp + fn,
        negatives=tn + fp,
        true_positives=tp,
        false_negatives=fn,
        true_negatives=tn,
        false_positives=fp,
        precision=precision,
        recall=recall,
        f1=_f1(precision, recall),
    )


@dataclass(frozen=True)
class EvaluationReport:
    total_rules: int                 # runnable rules in repo
    rules_with_examples: int
    coverage_pct: float              # rules_with_examples / total_rules * 100
    per_rule: list[RuleMetrics]
    macro_precision: float | None
    macro_recall: float | None
    macro_f1: float | None
    total_tp: int
    total_fn: int
    total_tn: int
    total_fp: int

    def to_dict(self) -> dict:
        d = asdict(self)
        d["per_rule"] = [m.to_dict() for m in self.per_rule]
        return d


def _macro_avg(values: Iterable[float | None]) -> float | None:
    vs = [v for v in values if v is not None]
    if not vs:
        return None
    return sum(vs) / len(vs)


def evaluate_all(rules_dir: Path) -> EvaluationReport:
    rules = load_all_rules(rules_dir)
    runnable = [r for r in rules if r.detection and r.detection.patterns]
    per_rule: list[RuleMetrics] = []
    for rule in runnable:
        metrics = evaluate_rule(rule)
        if metrics is not None:
            per_rule.append(metrics)
    total_tp = sum(m.true_positives for m in per_rule)
    total_fn = sum(m.false_negatives for m in per_rule)
    total_tn = sum(m.true_negatives for m in per_rule)
    total_fp = sum(m.false_positives for m in per_rule)
    coverage = (len(per_rule) / len(runnable) * 100.0) if runnable else 0.0
    return EvaluationReport(
        total_rules=len(runnable),
        rules_with_examples=len(per_rule),
        coverage_pct=coverage,
        per_rule=per_rule,
        macro_precision=_macro_avg(m.precision for m in per_rule),
        macro_recall=_macro_avg(m.recall for m in per_rule),
        macro_f1=_macro_avg(m.f1 for m in per_rule),
        total_tp=total_tp,
        total_fn=total_fn,
        total_tn=total_tn,
        total_fp=total_fp,
    )


# ---------------------------------------------------------------------------
# Formatters
# ---------------------------------------------------------------------------


def _pct(value: float | None) -> str:
    return f"{value * 100:5.1f}%" if value is not None else "  n/a "


def format_text(report: EvaluationReport) -> str:
    lines: list[str] = []
    lines.append("vibecode-checker — rule examples evaluation")
    lines.append("")
    lines.append(
        f"runnable rules: {report.total_rules}   "
        f"with examples: {report.rules_with_examples} ({report.coverage_pct:.1f}%)"
    )
    lines.append(
        f"totals: TP={report.total_tp}  FN={report.total_fn}  "
        f"TN={report.total_tn}  FP={report.total_fp}"
    )
    lines.append(
        f"macro: precision={_pct(report.macro_precision).strip()}  "
        f"recall={_pct(report.macro_recall).strip()}  "
        f"f1={_pct(report.macro_f1).strip()}"
    )
    lines.append("")
    lines.append(f"{'rule_id':28s}  {'P/N':>5}  {'TP':>3}  {'FN':>3}  {'FP':>3}  "
                 f"{'prec':>6}  {'rec':>6}  {'F1':>6}")
    lines.append("-" * 86)
    for m in sorted(report.per_rule, key=lambda x: x.rule_id):
        lines.append(
            f"{m.rule_id:28s}  {m.positives:>2}/{m.negatives:<2}  "
            f"{m.true_positives:>3}  {m.false_negatives:>3}  {m.false_positives:>3}  "
            f"{_pct(m.precision)}  {_pct(m.recall)}  {_pct(m.f1)}"
        )
    return "\n".join(lines)


def format_markdown(report: EvaluationReport) -> str:
    lines: list[str] = []
    lines.append("# vibecode-checker — 룰 평가 결과")
    lines.append("")
    lines.append(
        f"- 검사 가능 룰: **{report.total_rules}** · "
        f"examples 보유: **{report.rules_with_examples}** "
        f"({report.coverage_pct:.1f}%)"
    )
    lines.append(
        f"- 합계: TP={report.total_tp} · FN={report.total_fn} · "
        f"TN={report.total_tn} · FP={report.total_fp}"
    )
    macro_p = f"{report.macro_precision * 100:.1f}%" if report.macro_precision is not None else "n/a"
    macro_r = f"{report.macro_recall * 100:.1f}%" if report.macro_recall is not None else "n/a"
    macro_f = f"{report.macro_f1 * 100:.1f}%" if report.macro_f1 is not None else "n/a"
    lines.append(f"- 매크로 평균: precision **{macro_p}** · recall **{macro_r}** · F1 **{macro_f}**")
    lines.append("")
    lines.append("| rule_id | P / N | TP | FN | FP | precision | recall | F1 |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|")
    for m in sorted(report.per_rule, key=lambda x: x.rule_id):
        p = f"{m.precision * 100:.1f}%" if m.precision is not None else "n/a"
        r = f"{m.recall * 100:.1f}%" if m.recall is not None else "n/a"
        f = f"{m.f1 * 100:.1f}%" if m.f1 is not None else "n/a"
        lines.append(
            f"| `{m.rule_id}` | {m.positives}/{m.negatives} | "
            f"{m.true_positives} | {m.false_negatives} | {m.false_positives} | "
            f"{p} | {r} | {f} |"
        )
    lines.append("")
    lines.append("> 본 평가는 각 룰에 첨부된 positive/negative 예시 코드를 스캐너에 다시 던져 산출한 자체 검증입니다.")
    lines.append("> 가이드라인 원문 또는 외부 벤치마크의 정확도와 일치한다고 보장하지 않습니다.")
    return "\n".join(lines)
