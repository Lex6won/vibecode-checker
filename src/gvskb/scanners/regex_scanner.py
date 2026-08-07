"""Regex scanner — the original engine.

Compiles ``detection.patterns`` from every MD rule once at import time and
matches them against each line of input. The compiled rule cache is exposed
as ``RULES`` so the AST adapter can look up rule metadata without re-parsing.
"""
from __future__ import annotations

import ast
import hashlib
import os
import re
import sys
from collections.abc import Callable
from importlib import resources
from pathlib import Path

from ..loader import load_all_rules
from ..schema import CodeLocation, Decision, Finding, Rule, Severity, Status
from .base import ScannerAdapter

_FLAG_NAMES = {
    "IGNORECASE": re.IGNORECASE,
    "MULTILINE": re.MULTILINE,
    "DOTALL": re.DOTALL,
}

# Filename suffix → language identifier, for rule.languages filtering.
_EXT_TO_LANG = {
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".java": "java", ".kt": "kotlin", ".scala": "scala",
    ".go": "go", ".rs": "rust",
    ".rb": "ruby", ".php": "php",
    ".cs": "csharp", ".vb": "vbnet",
    ".swift": "swift", ".m": "objc",
    ".c": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".h": "c", ".hpp": "cpp",
    ".sql": "sql",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell", ".ps1": "powershell",
    ".html": "html", ".htm": "html", ".xml": "xml",
    ".vue": "javascript", ".svelte": "javascript",
}

# A comment line cannot host a live vulnerability, so comment/docstring lines
# are skipped for *all* rules — EXCEPT these categories, whose whole purpose is
# to find secrets/credentials written *inside* comments (e.g. KISA-PY-SEC-13
# "주석문 안에 포함된 시스템 주요정보", hardcoded keys). Those keep matching.
_COMMENT_SKIP_EXEMPT_CATEGORIES = {
    "secret-scanning",
}

_IGNORE_RE = re.compile(r"gvskb:\s*ignore(?:\s+([A-Za-z0-9_.:-]+))?", re.IGNORECASE)

# ── 값 검증기 ──────────────────────────────────────────────────────────────
# 정규식은 *형태*만 본다. 형태가 같은 남(13자리 정수, 16자리 카드 모양 숫자)을
# 걸러내려면 값 자체를 계산해 봐야 한다. 룰이 detection.validators 로 이름을
# 지정하면 매치된 문자열에 대해 여기 등록된 함수가 돌고, 하나라도 실패하면
# 그 매치는 발견으로 올리지 않는다.

_RRN_WEIGHTS = (2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5)


def _rrn_checksum_ok(matched: str) -> bool:
    """주민등록번호 검증식(mod 11) — **하이픈 없는 값에만** 적용한다.

    앞 12자리에 가중치를 곱해 더한 뒤 ``(11 - 합%11) % 10`` 이 마지막 자리와
    같아야 한다. 날짜 유효성까지 통과한 13자리 난수가 이 식까지 맞을 확률은
    약 1/11 이라, 하이픈 없는 형태의 오탐이 크게 준다(실측: 임의 13자리 정수
    기준 1.51% → 0.15%).

    **하이픈이 있으면 검증식을 적용하지 않고 통과시킨다.** 두 가지 이유다:
    ① ``YYMMDD-#######`` 형태 자체가 "주민번호로 쓰려 했다"는 강한 의도 신호라
       검증식까지 요구할 이유가 없다.
    ② 2020.10. 뒷자리 개편으로 지역번호가 임의값으로 바뀌었고, 이 검증식이
       모든 신규 번호에 성립한다고 단정할 근거를 확인하지 못했다. 확실하지
       않은 규칙을 *탐지 취소*(미탐) 쪽에 쓰면 놓친 사실이 아무 데도 남지
       않으므로, 형태가 명확한 쪽에는 적용하지 않는다.
    """
    if "-" in matched:
        return True
    digits = [int(ch) for ch in matched if ch.isdigit()]
    if len(digits) != 13:
        return False
    total = sum(d * w for d, w in zip(digits[:12], _RRN_WEIGHTS))
    return (11 - total % 11) % 10 == digits[12]


_VALIDATORS: dict[str, "Callable[[str], bool]"] = {
    "rrn_checksum": _rrn_checksum_ok,
}

# 증거 문자열 — 매치 구간을 중심으로 잘라 낸다. 줄 전체를 넣으면 200자가 넘는
# 요즘 TS/JS 한 줄에서 *매치와 무관한 앞부분만* 보여, 정탐인데도 사용자가
# 오탐으로 판단한다(실측: VoiceWhisper.tsx 의 빈 catch 가 줄 끝에 있어
# 증거에는 useEffect(fetch(...)) 만 찍혔다).
_EVIDENCE_CONTEXT = 60
_EVIDENCE_WHOLE_LINE_MAX = 200


def _infer_language(filename: str, language: str | None) -> str | None:
    if language:
        return language.lower()
    suffix = ""
    for sep in ("/", "\\"):
        if sep in filename:
            filename = filename.rsplit(sep, 1)[-1]
    dot = filename.rfind(".")
    if dot >= 0:
        suffix = filename[dot:].lower()
    return _EXT_TO_LANG.get(suffix)


def _is_python(eff_lang: str | None, filename: str) -> bool:
    return eff_lang == "python" or filename.endswith((".py", ".pyw"))


def _python_docstring_lines(code: str) -> set[int]:
    """Return line numbers occupied by Python module/class/function docstrings."""
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError):
        return set()

    lines: set[int] = set()
    nodes: list[ast.AST] = [tree]
    nodes.extend(n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)))
    for node in nodes:
        body = getattr(node, "body", [])
        if not body:
            continue
        first = body[0]
        if (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        ):
            start = getattr(first, "lineno", 0)
            end = getattr(first, "end_lineno", start)
            if start:
                lines.update(range(start, end + 1))
    return lines


_JS_LANGS = {"javascript", "typescript"}


def _comment_lines(code: str, eff_lang: str | None, filename: str) -> set[int]:
    """Line numbers that are *entirely* comments, for JS/TS and HTML.

    Conservative and line-based: a JS line is treated as a comment when its
    stripped form starts with ``//`` or it falls inside a ``/* ... */`` block;
    an HTML line when it falls inside ``<!-- ... -->``. We never strip inline
    trailing comments — under-skipping is safer than hiding a real finding that
    shares a line with code. Mirrors the Python docstring/``#`` handling.
    """
    is_js = eff_lang in _JS_LANGS or filename.endswith(
        (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".vue", ".svelte"))
    is_html = eff_lang in {"html", "xml"} or filename.endswith((".html", ".htm", ".xml"))
    if not (is_js or is_html):
        return set()

    lines: set[int] = set()
    in_block = False          # JS /* */ block
    in_html_comment = False   # HTML <!-- --> block
    for line_no, raw in enumerate(code.splitlines(), start=1):
        stripped = raw.strip()
        if is_html:
            if in_html_comment:
                lines.add(line_no)
                if "-->" in raw:
                    in_html_comment = False
                continue
            if stripped.startswith("<!--"):
                lines.add(line_no)
                if "-->" not in stripped[4:]:
                    in_html_comment = True
                continue
        if is_js:
            if in_block:
                lines.add(line_no)
                if "*/" in raw:
                    in_block = False
                continue
            if stripped.startswith("//"):
                lines.add(line_no)
                continue
            if stripped.startswith("/*"):
                lines.add(line_no)
                if "*/" not in stripped[2:]:
                    in_block = True
                continue
    return lines


def _ignored_rule_ids(line: str) -> set[str] | None:
    match = _IGNORE_RE.search(line)
    if not match:
        return set()
    rule_id = match.group(1)
    if not rule_id:
        return None
    return {rule_id}


def _suppresses_rule(
    *,
    line: str,
    line_no: int,
    rule: dict,
    docstring_lines: set[int],
    python_comments_enabled: bool,
) -> bool:
    ignored = _ignored_rule_ids(line)
    if ignored is None:
        return True
    if rule["rule_id"] in ignored:
        return True

    category = str(rule.get("category") or "")
    if category in _COMMENT_SKIP_EXEMPT_CATEGORIES:
        return False  # secret-scanning rules keep matching inside comments
    if line_no in docstring_lines:
        return True
    return python_comments_enabled and line.lstrip().startswith("#")


def _resolve_rules_dir() -> Path:
    """env override → repo checkout → packaged data."""
    override = os.environ.get("GVSKB_RULES_DIR")
    if override:
        return Path(override)
    pkg_root = Path(__file__).resolve().parent.parent
    project_root = pkg_root.parent.parent
    repo_rules = project_root / "rules"
    if repo_rules.exists():
        return repo_rules
    return Path(str(resources.files("gvskb").joinpath("rules")))


def _compile_rule(rule: Rule) -> dict | None:
    detection = rule.detection
    if detection is None:
        return None

    # patterns 를 의도적으로 비운 룰 = **전용 엔진(AST 등)이 발행하는 룰**.
    # 줄 단위 regex 로는 삽입 값의 출처를 알 수 없어 오탐이 불가피한 주제
    # (예: DDL 조립)를 AST 판단에만 맡기기 위한 장치다. 컴파일된 패턴이 0개라
    # regex 매칭에는 절대 걸리지 않지만, lookup_rule 로 조회는 가능해야
    # 엔진이 Finding 을 만들 수 있다.
    engine_only = not detection.patterns

    flags = 0
    for flag_name in detection.flags:
        flags |= _FLAG_NAMES.get(flag_name, 0)

    compiled: list[re.Pattern[str]] = []
    for pattern in detection.patterns:
        try:
            compiled.append(re.compile(pattern, flags))
        except re.error as exc:
            print(f"[regex_scanner] invalid regex in {rule.id}: {exc}", file=sys.stderr)
    if not compiled and not engine_only:
        return None

    # 맥락 제외 패턴 — 같은 줄에 매칭되면 발견을 취소한다(예: 안내문의 예시 IP).
    excludes: list[re.Pattern[str]] = []
    for pattern in detection.exclude_patterns:
        try:
            excludes.append(re.compile(pattern, flags))
        except re.error as exc:
            print(f"[regex_scanner] invalid exclude regex in {rule.id}: {exc}", file=sys.stderr)

    # 값 검증기 — 이름이 등록돼 있지 않으면 *조용히 통과시키지 않고* 경고한다.
    # 오타 난 검증기 이름이 무시되면 룰이 의도보다 느슨하게 동작하는데, 그
    # 사실이 아무 데도 드러나지 않는다.
    validators: list[Callable[[str], bool]] = []
    for name in detection.validators:
        fn = _VALIDATORS.get(name)
        if fn is None:
            print(f"[regex_scanner] unknown validator {name!r} in {rule.id}", file=sys.stderr)
            continue
        validators.append(fn)

    return {
        "rule_id": rule.id,
        "title": rule.title_en or rule.title_ko,
        "plain_title": rule.title_ko,
        "severity": rule.severity,
        "decision": rule.decision_default or Decision.warn,
        "category": detection.category or (rule.domains[0] if rule.domains else "uncategorized"),
        "patterns": compiled,
        "excludes": excludes,
        "validators": validators,
        "dedup_group": detection.dedup_group,
        "confidence": detection.confidence,
        "languages": {lang.lower() for lang in rule.languages},
        "why": detection.why_it_matters or rule.body[:200].strip(),
        "impact": detection.public_sector_impact,
        "fix": detection.safe_fix,
        "refs": detection.references,
        "auto": detection.can_auto_fix,
    }


def _load_runtime_rules() -> list[dict]:
    """Compile runnable rules, gated by rule status.

    실행(집행) 게이트 — 검색/설명(search_rules·get_rule)은 모든 status를 그대로
    보여주지만, *스캐너가 실제로 집행*하는 룰은 status로 거른다:
    - approved / stale: 집행 (stale은 재검토 기한 초과일 뿐 룰 자체는 유효 —
      조용히 꺼지면 recall이 보이지 않게 줄어든다. doctor가 별도로 경고)
    - proposed: 기본 미집행. 자동 생성 룰(intel promote)이 사람 검토 없이
      바로 발화하는 것을 막는다. GVSKB_ALLOW_PROPOSED=1 로 옵트인.
    - deprecated: 절대 미집행.
    """
    runtime: list[dict] = []
    strict = os.environ.get("GVSKB_STRICT_RULES", "").lower() in {"1", "true", "yes"}
    allow_proposed = os.environ.get("GVSKB_ALLOW_PROPOSED", "").lower() in {"1", "true", "yes"}
    for rule in load_all_rules(_resolve_rules_dir(), strict=strict):
        if rule.status == Status.deprecated:
            continue
        if rule.status == Status.proposed and not allow_proposed:
            continue
        compiled = _compile_rule(rule)
        if compiled is not None:
            runtime.append(compiled)
    return runtime


# Loaded once at import; refreshable via reload_rules().
RULES: list[dict] = _load_runtime_rules()


def reload_rules() -> int:
    """Reload rules from disk. Returns the new rule count."""
    global RULES
    RULES = _load_runtime_rules()
    return len(RULES)


def lookup_rule(rule_id: str) -> dict | None:
    """Return the compiled rule entry for a rule_id, or None."""
    for r in RULES:
        if r["rule_id"] == rule_id:
            return r
    return None


def _finding_id(rule_id: str, filename: str, line_no: int, evidence: str) -> str:
    digest = hashlib.sha256(
        f"{rule_id}:{filename}:{line_no}:{evidence}".encode("utf-8"),
    ).hexdigest()[:10]
    return f"{rule_id}:{digest}"


def redact_evidence(text: str) -> str:
    """Mask Korean PII, secrets, AWS/sk-* keys, and credential-shaped strings."""
    text = re.sub(r"\b(\d{6})-?([1-4])\d{6}\b", r"\1-\2******", text)
    text = re.sub(r"\b(01[016789])-?\d{3,4}-?(\d{4})\b", r"\1-****-\2", text)
    # 탐지 룰보다 **일부러 느슨하게** 잡는다. 여기서 못 가리면 토큰이 보고서·
    # 로그·오류 메시지에 그대로 찍히지만, 넓게 가려서 생기는 손해는 증거 문자열이
    # 조금 덜 읽히는 것뿐이다. 비대칭이 명백하므로 과잉 마스킹 쪽을 택한다.
    # (실측: sk- 만 가려서 sk_ggtrust_… 형식 기관 API 키가 무방비였다.)
    text = re.sub(r"sk([-_])[A-Za-z0-9_-]{8,}", r"sk\1***REDACTED***", text)
    text = re.sub(r"AKIA[0-9A-Z]{16}", "AKIA***REDACTED***", text)
    text = re.sub(
        r"(?i)((api[_-]?key|secret|password|passwd|token)\s*[:=]\s*[\"'])[^\"']+([\"'])",
        r"\1***REDACTED***\3",
        text,
    )
    return text.strip()[:240]


_SEVERITY_RANK = {
    Severity.critical: 4, Severity.high: 3, Severity.medium: 2, Severity.low: 1,
}
_DECISION_RANK = {Decision.block: 2, Decision.warn: 1, Decision.allow: 0}


def _dedup_rank(finding: Finding) -> tuple:
    # 심각도 → 결정 → rule_id 순. rule_id 를 마지막에 넣어 같은 무게일 때
    # 실행 순서와 무관하게 항상 같은 룰이 남게 한다(리포트 재현성).
    return (
        _SEVERITY_RANK.get(finding.severity, 0),
        _DECISION_RANK.get(finding.decision, 0),
        finding.rule_id,
    )


def dedupe_by_group(findings: list[Finding]) -> list[Finding]:
    """같은 ``dedup_group`` 룰이 같은 파일·같은 줄에 걸리면 하나만 남긴다.

    같은 코드를 다른 각도로 보는 룰(예: KISA-JS-ERR-02 '오류상황 대응 부재' 와
    -03 '부적절한 예외 처리' 는 둘 다 빈 catch 를 본다)이 각각 발행하면 검토자는
    같은 한 줄을 두 번 고쳐야 하는 줄 안다. 그룹을 선언한 룰끼리만 묶으므로,
    서로 다른 주제의 룰이 우연히 같은 줄에 걸린 것은 그대로 남는다.
    """
    kept: list[Finding] = []
    seen: dict[tuple[str, int | None, str], int] = {}
    for finding in findings:
        rule = lookup_rule(finding.rule_id)
        group = (rule or {}).get("dedup_group")
        if not group:
            kept.append(finding)
            continue
        key = (finding.location.file, finding.location.line, group)
        index = seen.get(key)
        if index is None:
            seen[key] = len(kept)
            kept.append(finding)
        elif _dedup_rank(finding) > _dedup_rank(kept[index]):
            kept[index] = finding
    return kept


def evidence_for_match(line: str, start: int, end: int) -> str:
    """매치 구간을 중심으로 증거를 잘라 낸다(짧은 줄은 그대로).

    잘라 낸 쪽에는 '…' 를 붙여 *줄의 일부*임을 드러낸다. 그래야 검토자가
    "왜 이 코드가 걸렸지?" 를 증거만 보고 판단할 수 있다.
    """
    if len(line.strip()) <= _EVIDENCE_WHOLE_LINE_MAX:
        return redact_evidence(line)
    left = max(0, start - _EVIDENCE_CONTEXT)
    right = min(len(line), end + _EVIDENCE_CONTEXT)
    snippet = line[left:right].strip()
    if left > 0:
        snippet = "… " + snippet
    if right < len(line):
        snippet = snippet + " …"
    return redact_evidence(snippet)


def build_finding(rule: dict, *, filename: str, line_no: int, evidence: str,
                  engine: str, confidence: str | None = None) -> Finding:
    # 근거 강도 기본값 — 엔진이 명시하지 않으면 방식으로 추정한다.
    # regex 는 값의 출처를 알 수 없으므로 항상 pattern-only 다(실측에서 이 구분이
    # 없어 상수 기반 SQL 조립이 '치명'으로 보고됐다).
    if confidence is None:
        # 룰이 스스로 선언한 값이 최우선 — 패턴 자체가 확증인 경우가 있다.
        confidence = rule.get("confidence") or ("pattern-only" if engine == "regex" else "likely")
    return Finding(
        id=_finding_id(rule["rule_id"], filename, line_no, evidence),
        rule_id=rule["rule_id"],
        title=rule["title"],
        plain_title=rule["plain_title"],
        severity=rule["severity"],
        decision=rule["decision"],
        category=rule["category"],
        location=CodeLocation(file=filename, line=line_no),
        evidence=evidence,
        why_it_matters=rule["why"],
        public_sector_impact=rule["impact"],
        safe_fix=rule.get("fix"),
        references=rule["refs"],
        can_auto_fix=bool(rule.get("auto", False)),
        requires_approval_to_bypass=rule["decision"] == Decision.block,
        confidence=confidence,
        engine=engine,
    )


class RegexScanner(ScannerAdapter):
    """Single-line regex matcher driven by MD ``detection.patterns``."""

    name = "regex"

    def scan(
        self,
        code: str,
        *,
        filename: str = "<memory>",
        language: str | None = None,
        scenario: str | None = None,
        profile: str = "public-default-strict",
        categories: set[str] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        eff_lang = _infer_language(filename, language)
        is_python = _is_python(eff_lang, filename)
        docstring_lines = _python_docstring_lines(code) if is_python else set()
        comment_lines = _comment_lines(code, eff_lang, filename) if not is_python else set()
        for line_no, line in enumerate(code.splitlines(), start=1):
            is_comment = line_no in comment_lines
            for rule in RULES:
                if categories and rule["category"] not in categories:
                    continue
                # JS/TS/HTML comment-only line: skip every rule except the
                # secret-scanning ones (which look for keys inside comments).
                if is_comment and rule["category"] not in _COMMENT_SKIP_EXEMPT_CATEGORIES:
                    continue
                if is_python and _suppresses_rule(
                    line=line,
                    line_no=line_no,
                    rule=rule,
                    docstring_lines=docstring_lines,
                    python_comments_enabled=True,
                ):
                    continue
                # Language filter: a rule with a non-empty `languages` set only
                # applies when input language matches (or input language is unknown).
                rule_langs = rule.get("languages") or set()
                if rule_langs and eff_lang and eff_lang not in rule_langs:
                    continue
                # 매치 객체를 들고 있어야 ① 값 검증기를 돌리고 ② 증거를 매치
                # 구간으로 자를 수 있다. 검증기가 떨어뜨린 매치는 다음 패턴으로
                # 계속 시도한다 — 한 룰의 여러 패턴 중 하나만 통과하면 된다.
                validators = rule.get("validators") or ()
                match = None
                for pat in rule["patterns"]:
                    candidate = pat.search(line)
                    if candidate is None:
                        continue
                    if validators and not all(v(candidate.group(0)) for v in validators):
                        continue
                    match = candidate
                    break
                if match is None:
                    continue
                # 맥락 제외 — 예시·플레이스홀더 문구가 같은 줄에 있으면 취소.
                if any(ex.search(line) for ex in rule.get("excludes") or ()):
                    continue
                evidence = evidence_for_match(line, match.start(), match.end())
                findings.append(build_finding(
                    rule, filename=filename, line_no=line_no,
                    evidence=evidence, engine=self.name,
                ))
        # 중복 묶기는 여기서 하지 않는다 — 룰별 정확도 평가(evaluate)는 "이 룰이
        # 잡았는가"를 물으므로, 묶어 버리면 가려진 룰의 재현율이 0으로 보인다.
        # 묶기는 scan_code 가 결과를 합칠 때 한다.
        return findings
