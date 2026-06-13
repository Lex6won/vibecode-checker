"""Public scanner facade.

Runs every registered ``ScannerAdapter`` and combines their findings into a
single ``ScanReport``. When two adapters report the same ``(rule_id, file,
line)`` the more precise engine wins (currently: python-ast > regex).

External callers should continue to use ``scan_code`` / ``scan_file`` /
``scan_path`` here; the per-engine adapters live in ``gvskb.scanners``.

Rules are still loaded once at import via the regex adapter. ``RULES`` and
``reload_rules`` are re-exported for backwards compatibility.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Iterable

from .profiles import apply_profile, load_profile
from .scanners.ast_scanner import PythonAstScanner
from .scanners.regex_scanner import (
    RULES as RULES,
    RegexScanner,
    lookup_rule,
    redact_evidence as _redact_evidence,
    reload_rules as _reload_runtime_rules,
)
from .scanners.semgrep_scanner import SemgrepScanner
from .schema import Decision, Finding, ScanReport, ScanSummary, Severity, SkippedFile

# Adapter run order. Earlier adapters establish baseline findings; later
# adapters (more precise) can supersede them via dedup_findings. SemgrepScanner
# self-disables when the binary or rules dir is missing, so safe to include.
_ADAPTERS = [RegexScanner(), PythonAstScanner(), SemgrepScanner()]

# Engine precision ranking — higher number wins on collisions.
_ENGINE_PRECISION = {"regex": 0, "python-ast": 1, "semgrep": 2}

SEVERITY_RANK = {
    Severity.low: 0,
    Severity.medium: 1,
    Severity.high: 2,
    Severity.critical: 3,
}


def reload_rules() -> int:
    """Reload the regex rule cache from disk. AST adapter follows along."""
    return _reload_runtime_rules()


def _highest(findings: Iterable[Finding]) -> Severity | None:
    highest: Severity | None = None
    for finding in findings:
        if highest is None or SEVERITY_RANK[finding.severity] > SEVERITY_RANK[highest]:
            highest = finding.severity
    return highest


def _summary(findings: list[Finding]) -> ScanSummary:
    by_severity = {s.value: 0 for s in Severity}
    by_decision = {d.value: 0 for d in Decision}
    for finding in findings:
        by_severity[finding.severity.value] += 1
        by_decision[finding.decision.value] += 1
    return ScanSummary(
        finding_count=len(findings),
        by_severity=by_severity,
        by_decision=by_decision,
        highest_severity=_highest(findings),
        blocked=any(f.decision == Decision.block for f in findings),
    )


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """Keep the most precise engine's finding for each (rule_id, file, line)."""
    best: dict[tuple[str, str, int], Finding] = {}
    for f in findings:
        key = (f.rule_id, f.location.file, f.location.line)
        prev = best.get(key)
        if prev is None:
            best[key] = f
        elif _ENGINE_PRECISION.get(f.engine, 0) > _ENGINE_PRECISION.get(prev.engine, 0):
            best[key] = f
    return list(best.values())


def scan_code(
    code: str,
    *,
    filename: str = "<memory>",
    language: str | None = None,
    scenario: str | None = None,
    profile: str = "public-default-strict",
    categories: set[str] | None = None,
) -> ScanReport:
    raw: list[Finding] = []
    for adapter in _ADAPTERS:
        raw.extend(adapter.scan(
            code,
            filename=filename,
            language=language,
            scenario=scenario,
            profile=profile,
            categories=categories,
        ))
    findings = _dedupe(raw)

    # Apply scenario-bound policy: decision overrides + severity_min filter.
    profile_spec = load_profile(profile)
    findings = apply_profile(findings, profile_spec)

    return ScanReport(
        target=filename,
        language=language,
        scenario=scenario,
        profile=profile,
        summary=_summary(findings),
        findings=findings,
        # 인메모리 조각도 "이 파일을 검사함"으로 기록 — 발견 0이 "검사 안 됨"이
        # 아니라 "위험 없음"으로 올바르게 결론나게 한다.
        scanned_files=[filename],
    )


def scan_file(path: str | Path, *, language: str | None = None, scenario: str | None = None) -> ScanReport:
    p = Path(path)
    return scan_code(p.read_text(encoding="utf-8"), filename=str(p), language=language, scenario=scenario)


# ---------------------------------------------------------------------------
# Directory / path scanning — unchanged from the pre-adapter version
# ---------------------------------------------------------------------------

DEFAULT_INCLUDE_EXTS: frozenset[str] = frozenset({
    ".py", ".pyw",
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".java", ".kt", ".scala",
    ".go", ".rs",
    ".rb", ".php",
    ".cs", ".vb",
    ".swift", ".m",
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp",
    ".sql",
    ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd",
    ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf",
    ".env", ".properties",
    ".html", ".htm", ".xml",
    ".vue", ".svelte",
    ".tf", ".tfvars",
    ".dockerfile",
})

# 의존성 매니페스트/락파일 — regex 스캔으로는 취약 버전이 잡히지 않으므로
# SCA(check-package / scan_dependencies)로 보내야 한다. 디렉터리 스캔 중
# 만나면 스킵하되 그 사실을 안내로 남긴다. (package.json은 .json으로 이미 스캔됨)
_DEP_MANIFEST_NAMES: frozenset[str] = frozenset({
    "requirements.txt", "poetry.lock", "pipfile.lock",
    "yarn.lock", "package-lock.json", "pnpm-lock.yaml",
})

DEFAULT_EXCLUDE_DIRS: frozenset[str] = frozenset({
    ".git", ".hg", ".svn",
    "node_modules", "bower_components",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    ".venv", "venv", "env", ".env",
    "dist", "build", "out", "target",
    ".tox", ".nox",
    ".idea", ".vscode",
    "coverage", ".coverage", "htmlcov",
    "vendor", "third_party", "thirdparty",
    ".next", ".nuxt", ".cache",
})

DEFAULT_MAX_FILES = 500
DEFAULT_MAX_FILE_BYTES = 1_000_000


def _looks_binary(sample: bytes) -> bool:
    return b"\x00" in sample


def _rel(p: Path, root: Path, is_dir: bool) -> str:
    if not is_dir:
        return p.name
    try:
        return str(p.relative_to(root))
    except ValueError:
        return str(p)


def scan_path(
    path: str | Path,
    *,
    include_exts: set[str] | frozenset[str] | None = None,
    exclude_dirs: set[str] | frozenset[str] | None = None,
    scenario: str | None = None,
    profile: str = "public-default-strict",
    max_files: int = DEFAULT_MAX_FILES,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> ScanReport:
    """Scan a file or directory tree on disk."""
    root = Path(path)
    inc = frozenset(e.lower() for e in (include_exts or DEFAULT_INCLUDE_EXTS))
    exc = frozenset(exclude_dirs or DEFAULT_EXCLUDE_DIRS)
    skipped: list[SkippedFile] = []

    if not root.exists():
        return ScanReport(
            target=str(root),
            scenario=scenario,
            profile=profile,
            summary=_summary([]),
            findings=[],
            scanned_files=[],
            skipped_files=[SkippedFile(path=str(root), reason="path does not exist")],
        )

    files_to_scan: list[Path] = []
    is_dir = root.is_dir()

    if root.is_file():
        files_to_scan = [root]
    else:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in exc]
            for name in filenames:
                if len(files_to_scan) >= max_files:
                    break
                p = Path(dirpath) / name
                if name.lower() in _DEP_MANIFEST_NAMES:
                    skipped.append(SkippedFile(
                        path=_rel(p, root, is_dir),
                        reason="의존성 매니페스트 — 취약점은 `gvskb check-package` 또는 MCP `scan_dependencies`로 검사하세요",
                    ))
                    continue
                if p.suffix.lower() not in inc and name.lower() not in {"dockerfile", "makefile"}:
                    continue
                try:
                    size = p.stat().st_size
                except OSError as exc_io:
                    skipped.append(SkippedFile(path=_rel(p, root, is_dir), reason=f"stat error: {exc_io!s}"))
                    continue
                if size > max_file_bytes:
                    skipped.append(SkippedFile(path=_rel(p, root, is_dir), reason=f"too large ({size} bytes)"))
                    continue
                if size == 0:
                    continue
                files_to_scan.append(p)
            if len(files_to_scan) >= max_files:
                skipped.append(SkippedFile(path=str(root), reason=f"max_files={max_files} reached"))
                break

    all_findings: list[Finding] = []
    scanned: list[str] = []

    for f in files_to_scan:
        rel = _rel(f, root, is_dir)
        try:
            head = f.read_bytes()[:4096]
        except OSError as exc_io:
            skipped.append(SkippedFile(path=rel, reason=f"read error: {exc_io!s}"))
            continue
        if _looks_binary(head):
            skipped.append(SkippedFile(path=rel, reason="binary content (NUL detected)"))
            continue
        try:
            text = f.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            try:
                text = f.read_text(encoding="cp949")
            except UnicodeDecodeError:
                skipped.append(SkippedFile(path=rel, reason="encoding: not utf-8 or cp949"))
                continue
        report = scan_code(text, filename=rel, scenario=scenario, profile=profile)
        all_findings.extend(report.findings)
        scanned.append(rel)

    return ScanReport(
        target=str(root),
        scenario=scenario,
        profile=profile,
        summary=_summary(all_findings),
        findings=all_findings,
        scanned_files=scanned,
        skipped_files=skipped,
    )


def detect_secrets_and_pii(code: str, *, filename: str = "<memory>") -> ScanReport:
    return scan_code(
        code,
        filename=filename,
        categories={"privacy-public-sector", "secret-scanning", "public-sector-internal"},
    )


def parse_manifest_packages(manifest_text: str, ecosystem: str) -> list[dict[str, str | None]]:
    """Parse common dependency manifests without executing package managers."""
    packages: list[dict[str, str | None]] = []
    eco = ecosystem.lower()
    if eco == "pypi":
        for raw in manifest_text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            m = re.match(r"([A-Za-z0-9_.-]+)\s*(==|>=|<=|~=|>|<)?\s*([A-Za-z0-9_.!*+-]+)?", line)
            if m:
                packages.append({"name": m.group(1), "version": m.group(3)})
    elif eco == "npm":
        try:
            data = json.loads(manifest_text)
        except json.JSONDecodeError:
            return packages
        deps = {}
        for key in ("dependencies", "devDependencies", "optionalDependencies"):
            deps.update(data.get(key, {}) or {})
        for name, version in deps.items():
            packages.append({"name": name, "version": str(version).lstrip("^~") if version else None})
    return packages


def suggest_fix(rule_id: str, unsafe_code: str | None = None) -> dict:
    matched = lookup_rule(rule_id)
    if not matched:
        return {
            "rule_id": rule_id,
            "can_suggest": False,
            "message": "알 수 없는 룰입니다. finding의 rule_id를 확인하세요.",
        }
    return {
        "rule_id": rule_id,
        "can_suggest": True,
        "plain_title": matched["plain_title"],
        "safe_fix": matched.get("fix"),
        "can_auto_fix": bool(matched.get("auto", False)),
        "unsafe_code_preview": _redact_evidence(unsafe_code or ""),
        "note": "자동 수정은 diff 미리보기 후 적용해야 하며, 업무 로직 변경은 담당자 확인이 필요합니다.",
    }
