"""룰 품질 검증 — gvskb validate-rules 백엔드.

룰을 추가·수정하는 기여자가 자기 PR이 합리적인지 머지 전에 확인하고,
운영자가 정기적으로 룰 베이스의 위생을 점검할 수 있도록 합니다.

검증 항목:
- frontmatter 필수 필드 존재
- rule id 중복 여부
- detection.patterns의 정규식 compile 가능 여부
- review_due 만료 여부 (지난 룰은 stale)
- severity와 decision_default의 합리적 조합
"""
from __future__ import annotations

import re
from collections import Counter
from datetime import date
from pathlib import Path
from typing import Literal, TypedDict

from .schema import CURRENT_RULE_SCHEMA_VERSION, Decision, Rule, Severity
from .schema import Status as RuleStatus

Status = Literal["ok", "warn", "error"]


class RuleIssue(TypedDict):
    rule_id: str
    file: str
    status: Status
    code: str
    detail: str


def _issue(rule_id: str, file: str, status: Status, code: str, detail: str) -> RuleIssue:
    return {"rule_id": rule_id, "file": file, "status": status, "code": code, "detail": detail}


def _check_regex(rule: Rule, rel_path: str) -> list[RuleIssue]:
    out: list[RuleIssue] = []
    if rule.detection is None:
        return out
    for i, pattern in enumerate(rule.detection.patterns):
        try:
            re.compile(pattern)
        except re.error as exc:
            out.append(_issue(rule.id, rel_path, "error", "regex-compile-fail",
                              f"pattern[{i}]: {exc!s}"))
    return out


def _check_severity_decision(rule: Rule, rel_path: str) -> list[RuleIssue]:
    out: list[RuleIssue] = []
    if rule.decision_default is None:
        return out
    sev = rule.severity
    dec = rule.decision_default
    # block on low/medium is suspicious — too aggressive
    if dec == Decision.block and sev in (Severity.low, Severity.medium):
        out.append(_issue(rule.id, rel_path, "warn", "severity-decision-mismatch",
                          f"decision=block but severity={sev.value} (block은 high/critical 권장)"))
    # allow on critical is suspicious — too permissive
    if dec == Decision.allow and sev in (Severity.high, Severity.critical):
        out.append(_issue(rule.id, rel_path, "warn", "severity-decision-mismatch",
                          f"decision=allow but severity={sev.value}"))
    return out


def _check_schema_version(rule: Rule, rel_path: str) -> list[RuleIssue]:
    if rule.schema_version > CURRENT_RULE_SCHEMA_VERSION:
        return [_issue(rule.id, rel_path, "warn", "schema-version-future",
                       f"schema_version={rule.schema_version} > current={CURRENT_RULE_SCHEMA_VERSION} "
                       "— 로더 마이그레이션 코드 확인 필요")]
    return []


def _check_examples(rule: Rule, rel_path: str) -> list[RuleIssue]:
    """실제로 집행되는 룰은 positive·negative 예시를 반드시 가져야 한다.

    이게 없으면 ``gvskb evaluate`` 가 그 룰을 **평가 대상에서 통째로 건너뛴다**.
    실측에서 GOV-PII-RRN-001 은 임의 13자리 정수의 40%를 주민등록번호로
    보고하고 있었는데, examples 가 없어 평가표에는 아예 나타나지 않았고 나머지
    75개 룰이 전부 100% 라 품질 게이트는 초록불이었다. 룰의 정확도를 아무도
    모르는 상태를 만드는 것이 이 검사가 막으려는 대상이다.

    negative 를 함께 요구하는 이유: positive 만 있으면 재현율만 고정되고,
    정작 사용자를 괴롭히는 *오탐*은 그대로 통과한다.
    """
    if rule.detection is None or not rule.detection.patterns:
        return []                      # 전용 엔진용·참고용 룰은 대상 아님
    if rule.status not in (RuleStatus.approved, RuleStatus.stale):
        return []                      # proposed/deprecated 는 집행되지 않음
    ex = rule.examples
    if ex is None or (not ex.positive and not ex.negative):
        return [_issue(rule.id, rel_path, "error", "examples-missing",
                       "실행형 룰에 examples 가 없어 evaluate 가 이 룰을 건너뜁니다 "
                       "— positive/negative 를 추가하세요")]
    out: list[RuleIssue] = []
    if not ex.positive:
        out.append(_issue(rule.id, rel_path, "error", "examples-missing-positive",
                          "positive 예시가 없어 재현율이 고정되지 않습니다"))
    if not ex.negative:
        out.append(_issue(rule.id, rel_path, "error", "examples-missing-negative",
                          "negative 예시가 없어 오탐이 고정되지 않습니다"))
    return out


def _check_review_due(rule: Rule, rel_path: str, today: date) -> list[RuleIssue]:
    if rule.review_due is None:
        return []
    if rule.review_due < today:
        return [_issue(rule.id, rel_path, "warn", "review-due-expired",
                       f"review_due={rule.review_due.isoformat()} 이미 지남 — 갱신 필요")]
    return []


def validate_rules_dir(rules_dir: Path, *, today: date | None = None) -> dict:
    today = today or date.today()
    issues: list[RuleIssue] = []
    rules: list[Rule] = []
    load_errors: list[str] = []

    # Custom walk so we can report frontmatter parse errors as issues
    from .loader import load_rule
    DOC = {"README.MD", "CHANGELOG.MD", "INDEX.MD", "NOTICE.MD"}
    for md in sorted(rules_dir.rglob("*.md")):
        if md.name.upper() in DOC:
            continue
        rel = str(md.relative_to(rules_dir))
        try:
            rule = load_rule(md)
            rules.append(rule)
        except Exception as exc:
            issues.append(_issue("<unparsed>", rel, "error", "frontmatter-parse-fail",
                                 str(exc)))
            load_errors.append(f"{rel}: {exc!s}")
            continue

    # Duplicate IDs
    ids = Counter(r.id for r in rules)
    for rid, count in ids.items():
        if count > 1:
            for r in [x for x in rules if x.id == rid]:
                issues.append(_issue(rid, "<multiple>", "error", "duplicate-rule-id",
                                     f"{count}개 파일에 동일 id 존재"))
            break

    # Per-rule checks
    for r in rules:
        rel = next(
            (str(p.relative_to(rules_dir)) for p in rules_dir.rglob(f"{r.id}*.md") if p.is_file()),
            "<unknown>",
        )
        issues.extend(_check_regex(r, rel))
        issues.extend(_check_severity_decision(r, rel))
        issues.extend(_check_review_due(r, rel, today))
        issues.extend(_check_schema_version(r, rel))
        issues.extend(_check_examples(r, rel))

    summary = {
        "rules_dir": str(rules_dir),
        "rules_loaded": len(rules),
        "load_errors": len(load_errors),
        "issues": {
            "error": sum(1 for i in issues if i["status"] == "error"),
            "warn": sum(1 for i in issues if i["status"] == "warn"),
        },
    }
    overall: Status = "error" if summary["issues"]["error"] > 0 else (
        "warn" if summary["issues"]["warn"] > 0 else "ok"
    )
    return {
        "overall": overall,
        "summary": summary,
        "issues": issues,
    }


def format_text_report(report: dict) -> str:
    lines = [f"gvskb validate-rules — {report['summary']['rules_dir']}",
             f"로드된 룰: {report['summary']['rules_loaded']}건", ""]
    if not report["issues"]:
        lines.append("문제 없음.")
    else:
        for issue in report["issues"]:
            marker = {"error": "[ERR ]", "warn": "[WARN]"}.get(issue["status"], "[ ?? ]")
            lines.append(f"{marker}  {issue['rule_id']:32s}  {issue['code']}")
            lines.append(f"        파일: {issue['file']}")
            lines.append(f"        상세: {issue['detail']}")
    s = report["summary"]["issues"]
    lines.extend([
        "",
        f"요약: ERROR {s['error']} · WARN {s['warn']}",
        f"종합 상태: {report['overall'].upper()}",
    ])
    return "\n".join(lines)
