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
from importlib import resources
from pathlib import Path

from ..loader import load_all_rules
from ..schema import CodeLocation, Decision, Finding, Rule
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
    if detection is None or not detection.patterns:
        return None

    flags = 0
    for flag_name in detection.flags:
        flags |= _FLAG_NAMES.get(flag_name, 0)

    compiled: list[re.Pattern[str]] = []
    for pattern in detection.patterns:
        try:
            compiled.append(re.compile(pattern, flags))
        except re.error as exc:
            print(f"[regex_scanner] invalid regex in {rule.id}: {exc}", file=sys.stderr)
    if not compiled:
        return None

    return {
        "rule_id": rule.id,
        "title": rule.title_en or rule.title_ko,
        "plain_title": rule.title_ko,
        "severity": rule.severity,
        "decision": rule.decision_default or Decision.warn,
        "category": detection.category or (rule.domains[0] if rule.domains else "uncategorized"),
        "patterns": compiled,
        "languages": {lang.lower() for lang in rule.languages},
        "why": detection.why_it_matters or rule.body[:200].strip(),
        "impact": detection.public_sector_impact,
        "fix": detection.safe_fix,
        "refs": detection.references,
        "auto": detection.can_auto_fix,
    }


def _load_runtime_rules() -> list[dict]:
    runtime: list[dict] = []
    strict = os.environ.get("GVSKB_STRICT_RULES", "").lower() in {"1", "true", "yes"}
    for rule in load_all_rules(_resolve_rules_dir(), strict=strict):
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
    text = re.sub(r"sk-[A-Za-z0-9_-]{8,}", "sk-***REDACTED***", text)
    text = re.sub(r"AKIA[0-9A-Z]{16}", "AKIA***REDACTED***", text)
    text = re.sub(
        r"(?i)((api[_-]?key|secret|password|passwd|token)\s*[:=]\s*[\"'])[^\"']+([\"'])",
        r"\1***REDACTED***\3",
        text,
    )
    return text.strip()[:240]


def build_finding(rule: dict, *, filename: str, line_no: int, evidence: str,
                  engine: str) -> Finding:
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
                if not any(pat.search(line) for pat in rule["patterns"]):
                    continue
                evidence = redact_evidence(line)
                findings.append(build_finding(
                    rule, filename=filename, line_no=line_no,
                    evidence=evidence, engine=self.name,
                ))
        return findings
