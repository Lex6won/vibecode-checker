"""Semgrep adapter — AST-precise detection for JavaScript / TypeScript (and more).

This adapter shells out to the ``semgrep`` CLI rather than embedding a JS
parser. Rationale: Semgrep CE covers JS/TS/Java/Go/Ruby/etc. via a single
binary with stable rule semantics, and the OSS rule store is huge. We
deliberately do not add ``semgrep`` as a hard dependency:

- On Linux / macOS / WSL / CI it is one ``pip install semgrep`` away.
- On native Windows Semgrep is not officially supported; the adapter
  degrades gracefully (returns no findings) instead of crashing the scan.

Findings are bridged back to our MD rule catalog by ``metadata.gvskb_rule_id``
in each Semgrep YAML rule, so policy decisions, severity, and references
remain single-sourced in ``rules/``.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from importlib import resources
from pathlib import Path
from typing import Iterable

from ..schema import Finding
from .base import ScannerAdapter


_JS_EXTS: tuple[str, ...] = (
    ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".vue", ".svelte",
)
_JS_LANGS: frozenset[str] = frozenset({"javascript", "typescript", "js", "ts"})


def _default_rules_dir() -> Path:
    """env override → repo checkout → packaged data."""
    override = os.environ.get("GVSKB_SEMGREP_RULES_DIR")
    if override:
        return Path(override)
    pkg_root = Path(__file__).resolve().parent.parent
    project_root = pkg_root.parent.parent
    repo_rules = project_root / "rules" / "semgrep"
    if repo_rules.exists():
        return repo_rules
    try:
        return Path(str(resources.files("gvskb").joinpath("rules/semgrep")))
    except (ModuleNotFoundError, FileNotFoundError):
        return repo_rules  # last resort


def _looks_relevant(filename: str, language: str | None) -> bool:
    if language and language.lower() in _JS_LANGS:
        return True
    lower = filename.lower()
    return any(lower.endswith(ext) for ext in _JS_EXTS)


class SemgrepScanner(ScannerAdapter):
    """Run Semgrep CE on JS/TS sources and bridge results to MD rule metadata."""

    name = "semgrep"

    def __init__(
        self,
        rules_dir: Path | None = None,
        binary: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        self._rules_dir = rules_dir or _default_rules_dir()
        self._binary_override = binary
        self._timeout = timeout
        self._available_cache: bool | None = None
        self._resolved_binary: str | None = binary

    # ------------------------------------------------------------------
    # Availability / introspection
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """True only when both the binary and a rules dir are present.

        Cached after the first call. Tests reset by constructing a new adapter.
        """
        if self._available_cache is not None:
            return self._available_cache
        binary = self._binary_override or shutil.which("semgrep")
        self._resolved_binary = binary
        ok = bool(binary) and self._rules_dir.exists() and any(self._rules_dir.iterdir())
        self._available_cache = ok
        return ok

    @property
    def rules_dir(self) -> Path:
        return self._rules_dir

    @property
    def binary(self) -> str | None:
        if self._resolved_binary is None and self._available_cache is None:
            self.is_available()
        return self._resolved_binary

    # ------------------------------------------------------------------
    # Scan
    # ------------------------------------------------------------------

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
        if not _looks_relevant(filename, language):
            return []
        if not self.is_available():
            return []

        with tempfile.TemporaryDirectory(prefix="gvskb-sg-") as td:
            # Preserve the suffix so Semgrep picks the right language by extension.
            suffix = Path(filename).suffix or ".js"
            tmp = Path(td) / f"input{suffix}"
            tmp.write_text(code, encoding="utf-8")
            try:
                completed = subprocess.run(
                    [
                        str(self._resolved_binary),
                        "--config", str(self._rules_dir),
                        "--json", "--quiet",
                        "--no-rewrite-rule-ids",
                        "--metrics=off",
                        str(tmp),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=self._timeout,
                    encoding="utf-8",
                )
            except (OSError, subprocess.TimeoutExpired):
                return []

        if not completed.stdout:
            return []
        try:
            data = json.loads(completed.stdout)
        except json.JSONDecodeError:
            return []

        return self._results_to_findings(data, filename=filename, categories=categories)

    # ------------------------------------------------------------------
    # Bridge Semgrep JSON → our Finding model
    # ------------------------------------------------------------------

    @staticmethod
    def _results_to_findings(
        data: dict,
        *,
        filename: str,
        categories: set[str] | None,
    ) -> list[Finding]:
        # Local import to avoid a top-level cycle (regex_scanner pulls loader).
        from .regex_scanner import build_finding, lookup_rule, redact_evidence

        findings: list[Finding] = []
        for r in data.get("results", []) or []:
            extra = r.get("extra") or {}
            metadata = extra.get("metadata") or {}
            rule_id = metadata.get("gvskb_rule_id")
            if not rule_id:
                # Tolerate "<file>.<id>" check_id by taking the trailing segment.
                check_id = str(r.get("check_id") or "")
                rule_id = check_id.rsplit(".", 1)[-1] if check_id else None
            if not rule_id:
                continue
            rule = lookup_rule(rule_id)
            if rule is None:
                continue
            if categories and rule["category"] not in categories:
                continue
            line_no = int(((r.get("start") or {}).get("line")) or 1)
            evidence = redact_evidence(str(extra.get("lines") or ""))
            findings.append(
                build_finding(
                    rule,
                    filename=filename,
                    line_no=line_no,
                    evidence=evidence,
                    engine="semgrep",
                )
            )
        return findings


def supported_rule_ids() -> Iterable[str]:
    """Rule IDs the bundled Semgrep YAML files declare via gvskb_rule_id.

    This is best-effort: we parse YAML lazily so doctor/status doesn't have to
    import PyYAML if semgrep itself is missing.
    """
    rules_dir = _default_rules_dir()
    if not rules_dir.exists():
        return ()
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        return ()
    ids: list[str] = []
    for path in rules_dir.glob("*.yaml"):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError:
            continue
        for rule in data.get("rules", []) or []:
            md = (rule.get("metadata") or {})
            rid = md.get("gvskb_rule_id")
            if rid:
                ids.append(rid)
    return tuple(ids)
