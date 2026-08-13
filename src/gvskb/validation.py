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


# ---------------------------------------------------------------------------
# 오탐 archetype 린터 — 실측에서 실제로 뚫린 모양만 검사한다
#
# 라운드 10·13·14에서 나온 오탐을 하나씩 세지 않고 분해하니 소수의 **모양**으로
# 모였다. 그 모양을 룰 작성 시점에 잡으면 같은 오탐이 다시 태어나지 않는다.
#
# 원칙: **실측으로 증명된 모양만** 넣는다. 시끄러운 린터는 꺼지고, 꺼진 린터는
# 없는 것과 같다. 후보였다가 뺀 것도 아래에 이유와 함께 남긴다.
# ---------------------------------------------------------------------------

#: 짧고 흔한 **실행 sink** 이름. 이것들이 경계 없이 대안 목록에 들어가면
#: `evaluate`·`execution` 같은 더 긴 단어 안에서 걸린다(실측 오탐 14건).
_SINK_TOKENS = frozenset({
    "eval", "exec", "execute", "system", "innerhtml", "unserialize", "deserialize",
})

#: 정화로 인정하는 이름들. **호출 형태**(`sanitize(`)여야 하고, 맨 단어면
#: `sanitizeMaybe(h){return h.trim()}` 같은 가짜에 뚫린다(적대적 검증 2026-08-08).
_SANITIZER_WORD_RE = re.compile(
    r"(?i)\b(DOMPurify|sanitiz[a-z]*|escapeHtml[a-z]*|escapeHTML|purify[a-z]*|encodeHtml[a-z]*)")

_GROUP_RE = re.compile(r"\((?:\?:)?([^()]*)\)")
_LOOKAHEAD_RE = re.compile(r"\(\?!")


def _has_boundary_guard(src: str, start: int, end: int) -> bool:
    """그룹 좌우에 경계 장치가 있는가.

    인정하는 것: 후방/전방탐색 · `\\b` · 호출 앵커 `\\s*\\(` · **따옴표 구분자**.
    따옴표를 빼먹었더니 `["'](exec|eval|single)["']`(파이썬 `compile()` 의 모드
    인자)가 걸렸다 — 따옴표 사이의 리터럴이라 더 긴 단어에 섞일 수 없는데도
    경고가 났다. 린터의 오탐은 린터를 끄게 만든다.
    """
    left, right = src[max(0, start - 8):start], src[end:end + 10]
    if "(?<" in left or left.endswith("\\b"):
        return True
    if right.startswith(("\\b", "(?!", "(?=")):
        return True
    if bool(re.match(r"\\+s\*\\+\(", right)):          # `\s*\(` 호출 앵커
        return True
    # 따옴표로 둘러싸인 리터럴: `["']( … )["']` · `'( … )'`
    return bool(re.search(r"""(?:\["'\]|['"])\s*$""", left)) and \
        bool(re.match(r"""\s*(?:\["'\]|['"])""", right))


def _check_sink_token_boundaries(rule: Rule, rel_path: str) -> list[RuleIssue]:
    """실행 sink 이름이 경계 없이 대안 목록에 있는가.

    실측: `(execute|exec|eval|...)` 에 경계가 없어 `evaluate`·`evaluator` 안의
    `eval` 이 걸렸다 — 한 룰의 차단 오탐 14건이 전부 이 하나였다.
    """
    out: list[RuleIssue] = []
    if rule.detection is None:
        return out
    for i, src in enumerate(rule.detection.patterns):
        for m in _GROUP_RE.finditer(src):
            alts = {a.strip().lower() for a in m.group(1).split("|")}
            hot = sorted(alts & _SINK_TOKENS)
            if not hot or _has_boundary_guard(src, m.start(), m.end()):
                continue
            out.append(_issue(
                rule.id, rel_path, "error", "sink-token-without-boundary",
                f"patterns[{i}]: 실행 sink {hot} 가 경계 없이 대안 목록에 있습니다 — "
                "`evaluate` 속 `eval` 처럼 더 긴 단어 안에서 걸립니다. "
                r"좌측 `(?<![A-Za-z0-9])` · 우측 `(?!(?-i:[a-z]))` 또는 "
                r"호출 앵커 `\s*\(` 를 붙이세요.",
            ))
            break                                   # 룰당 한 번만 말한다
    return out


def _check_sanitizer_allowlist_is_a_call(rule: Rule, rel_path: str) -> list[RuleIssue]:
    """정화 화이트리스트가 **부분문자열**로 판정하는가.

    실측(적대적 검증): `(?!.{0,120}(?:DOMPurify|sanitize|escapeHtml))` 은
    `sanitizeMaybe(h){ return h.trim() }` 를 정화로 인정해 **발견을 통째로
    삭제**했다. 이름은 아무것도 보장하지 않는다 — 최소한 호출 형태를 요구해야
    하고, 더 나아가 함수 본문 판단은 엔진(html_sink_context)의 일이다.
    """
    out: list[RuleIssue] = []
    if rule.detection is None:
        return out
    for i, src in enumerate(rule.detection.patterns):
        for la in _LOOKAHEAD_RE.finditer(src):
            body = src[la.start():_group_end(src, la.start())]
            bare = [w.group(1) for w in _SANITIZER_WORD_RE.finditer(body)
                    if not _followed_by_call(body, w.end())]
            if not bare:
                continue
            out.append(_issue(
                rule.id, rel_path, "error", "sanitizer-allowlist-substring",
                f"patterns[{i}]: 정화 화이트리스트 {sorted(set(bare))} 가 "
                "부분문자열로 판정합니다 — `sanitizeMaybe` 같은 **이름만 정화**인 "
                "함수가 통과합니다(그리고 통과는 곧 발견 삭제입니다). "
                r"호출 형태(`sanitiz\w*\s*\(`)를 요구하거나, 판단을 엔진으로 옮기세요.",
            ))
            break
    return out


def _check_ignorecase_lowercase_class(rule: Rule, rel_path: str) -> list[RuleIssue]:
    """`(?i)` 아래의 `[a-z]` — 대문자까지 잡아 **진탐을 죽인다**.

    실측: `(?i)…(?![a-z])` 로 쓰면 `executeTool(llmResponse)`(에이전트 도구
    실행, OWASP ASI05)가 함께 죽는다. `(?-i:[a-z])` 로 대소문자 구분을 되살려야
    한다. 오탐이 아니라 **미탐**을 만드는 모양이라 더 조용하다.
    """
    out: list[RuleIssue] = []
    if rule.detection is None:
        return out
    ci_flag = "IGNORECASE" in (rule.detection.flags or [])
    for i, src in enumerate(rule.detection.patterns):
        if not (ci_flag or "(?i)" in src or "(?i:" in src):
            continue
        if re.search(r"\[a-z\]", re.sub(r"\(\?-i:[^)]*\)", "", src)):
            out.append(_issue(
                rule.id, rel_path, "error", "lowercase-class-under-ignorecase",
                f"patterns[{i}]: `(?i)` 아래의 `[a-z]` 는 대문자도 잡습니다 — "
                "`executeTool` 같은 camelCase 진짜 위험까지 함께 걸러집니다. "
                "`(?-i:[a-z])` 로 대소문자 구분을 되살리세요.",
            ))
    return out


def _group_end(src: str, start: int) -> int:
    """`start` 위치의 `(` 에 대응하는 닫는 괄호 다음 위치(못 찾으면 문자열 끝)."""
    depth = 0
    i = start
    while i < len(src):
        c = src[i]
        if c == "\\":
            i += 2
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return len(src)


def _followed_by_call(body: str, pos: int) -> bool:
    """이 이름 뒤에 (같은 대안 안에서) 여는 괄호가 오는가 = 호출 형태인가."""
    i = pos
    while i < len(body):
        c = body[i]
        if c == "(":
            return True
        if c in "|)":                     # 대안이 끝났다 — 호출이 아니다
            return False
        if c == "\\" and i + 1 < len(body):
            if body[i + 1] == "(":
                return True
            i += 2
            continue
        i += 1
    return False


# 후보였다가 **뺀** 검사: "그룹 사이의 무제한 `.*`".
# GOV-LLM 이 산문 JSON 에서 181자 떨어진 토큰을 잡은 실제 모양이라 넣으려 했으나,
# 324개 룰에 돌려 보니 유일한 적중이 `GOV-LLM-PII-PROMPT-001` 의 **정당한**
# 줄 전체 전방탐색(`(?!.*(?:...))(?=.*(?:...))`)이었다. 적중 1건이 전부 오탐이면
# 그 검사는 경고 피로만 만든다 — 진짜 경고까지 무시되게 한다. 거리 제한은
# 개별 룰의 주석으로 남기고, 자동 검사는 하지 않는다.


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


# ---------------------------------------------------------------------------
# 중복 커버리지 — 같은 일을 하는 룰이 둘이면 담당자는 한 줄을 두 번 고친다
# ---------------------------------------------------------------------------

def _fires_on(compiled: dict, text: str) -> bool:
    """컴파일된 룰이 이 한 줄에 걸리는가.

    **스캐너의 판정 순서를 그대로 따른다** — 패턴 매치 → 값 검증기 → 맥락 제외.
    린터가 자기만의 매칭을 따로 구현하면 언젠가 스캐너와 어긋나고, 그때
    린터는 조용히 틀린 답을 낸다. 그래서 컴파일도 ``_compile_rule`` 을 그대로
    빌려 쓴다.

    주석 판정·언어 필터·억제 주석은 일부러 보지 않는다. 여기서 묻는 것은
    "이 룰이 저 예시를 자기 것으로 보는가"이지 "실제 파일에서 발행되는가"가
    아니다. 언어 필터를 존중하면 이번에 실제로 벌어진 일 — 언어 목록에 구멍이
    있어 겹침이 가려진 것 — 을 그대로 놓친다.
    """
    validators = compiled.get("validators") or ()
    hit = None
    for pat in compiled["patterns"]:
        candidate = pat.search(text)
        if candidate is None:
            continue
        if validators and not all(v(candidate.group(0)) for v in validators):
            continue
        hit = candidate
        break
    if hit is None:
        return False
    return not any(ex.search(text) for ex in compiled.get("excludes") or ())


def _check_duplicate_coverage(rules: list[Rule], rel_of) -> list[RuleIssue]:
    """같은 카테고리의 두 룰이 **서로의 positive 예시를 전부** 잡으면 중복이다.

    실제로 벌어진 일이라 만들었다. ``GOV-PII-PHONE-001`` 이 있는 줄 모르고
    ``GOV-PII-CONTACT-001`` 을 새로 만들었고, 같은 전화번호 한 줄에 두 건이
    발행됐다. 회귀 코퍼스가 못 잡은 이유는 기존 룰의 ``languages`` 에
    typescript 가 없어 ``.ts`` 코퍼스에서는 애초에 겹치지 않았기 때문이다.

    판정 기준을 **양방향 전부**로 좁힌 이유:

    - 한쪽만 덮는 것은 정상이다. 넓은 룰과 좁은 룰이 공존하는 편이 낫다
      (예: 일반 하드코딩 시크릿 룰 vs. 특정 벤더 토큰 룰).
    - 서로가 서로의 예시를 **남김없이** 잡는다는 것은 두 룰이 같은 것을 본다는
      뜻이다. 이건 우연으로 잘 생기지 않는다.

    ``dedup_group`` 을 선언한 쌍은 건너뛴다 — 겹침을 이미 **알고 있고**
    보고 단계에서 하나로 묶고 있다는 선언이기 때문이다. 예시가 2개 미만인
    룰도 건너뛴다. 한 줄만 보고 "같다"고 말할 수는 없다.
    """
    from .scanners.regex_scanner import _compile_rule

    candidates: list[tuple[Rule, dict, list[str]]] = []
    for r in rules:
        det = r.detection
        if det is None or not det.patterns or not r.examples or len(r.examples.positive) < 2:
            continue
        compiled = _compile_rule(r)
        if compiled is None or not compiled.get("patterns"):
            continue
        candidates.append((r, compiled, list(r.examples.positive)))

    out: list[RuleIssue] = []
    for i, (ra, ca, pa) in enumerate(candidates):
        for rb, cb, pb in candidates[i + 1:]:
            if (ra.detection.category or "") != (rb.detection.category or ""):
                continue
            group_a = getattr(ra.detection, "dedup_group", None)
            if group_a and group_a == getattr(rb.detection, "dedup_group", None):
                continue
            if not all(_fires_on(cb, x) for x in pa):
                continue
            if not all(_fires_on(ca, x) for x in pb):
                continue
            detail = (
                f"{ra.id} 와 {rb.id} 가 서로의 positive 예시를 전부 잡습니다 "
                f"(카테고리 {ra.detection.category}). 같은 줄에 두 건이 발행돼 "
                "담당자가 한 번 고칠 것을 두 번 봅니다. 하나로 합치거나, "
                "의도된 겹침이면 양쪽에 같은 dedup_group 을 선언하세요."
            )
            out.append(_issue(ra.id, rel_of(ra), "error", "duplicate-coverage", detail))
            out.append(_issue(rb.id, rel_of(rb), "error", "duplicate-coverage", detail))
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
    _rel_cache: dict[str, str] = {}

    def _rel_of(rule: Rule) -> str:
        if rule.id not in _rel_cache:
            _rel_cache[rule.id] = next(
                (str(p.relative_to(rules_dir))
                 for p in rules_dir.rglob(f"{rule.id}*.md") if p.is_file()),
                "<unknown>",
            )
        return _rel_cache[rule.id]

    for r in rules:
        rel = _rel_of(r)
        issues.extend(_check_regex(r, rel))
        issues.extend(_check_severity_decision(r, rel))
        issues.extend(_check_review_due(r, rel, today))
        issues.extend(_check_schema_version(r, rel))
        issues.extend(_check_examples(r, rel))
        # 오탐 archetype — 룰 작성 시점에 잡아 같은 오탐이 다시 태어나지 않게.
        issues.extend(_check_sink_token_boundaries(r, rel))
        issues.extend(_check_sanitizer_allowlist_is_a_call(r, rel))
        issues.extend(_check_ignorecase_lowercase_class(r, rel))

    # 룰 사이의 검사 — 룰 하나만 봐서는 절대 보이지 않는 결함.
    issues.extend(_check_duplicate_coverage(rules, _rel_of))

    # 룰셋 잠금 — "룰을 고쳤는데 버전은 그대로"를 여기서 막는다.
    # 별도 명령으로만 두면 아무도 안 돌린다. CI 가 이미 부르는 자리에 붙여야
    # '버전을 안 올리고 룰만 고치는' 경로가 실제로 닫힌다.
    from . import ruleset as _ruleset
    lock_verdict = _ruleset.verify_lock(rules, rules_dir)
    if lock_verdict["status"] == "drift":
        issues.append(_issue("<ruleset>", _ruleset.LOCK_FILENAME, "error",
                             "ruleset-digest-drift", lock_verdict["message"]))
    elif lock_verdict["status"] == "missing":
        issues.append(_issue("<ruleset>", _ruleset.LOCK_FILENAME, "warn",
                             "ruleset-lock-missing", lock_verdict["message"]))

    summary = {
        "rules_dir": str(rules_dir),
        "rules_loaded": len(rules),
        "load_errors": len(load_errors),
        "ruleset": {
            "status": lock_verdict["status"],
            "version": lock_verdict["version"],
            "digest": lock_verdict["actual"],
        },
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
             f"로드된 룰: {report['summary']['rules_loaded']}건"]
    rs = report["summary"].get("ruleset") or {}
    if rs:
        ver = rs.get("version") or "(선언 없음)"
        lines.append(f"룰셋: {ver} · 지문 {(rs.get('digest') or '?')[:12]}… [{rs.get('status')}]")
    lines.append("")
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
