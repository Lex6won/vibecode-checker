"""Load Markdown security rules with YAML frontmatter."""
from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

from .schema import Rule

_FRONTMATTER_RE = re.compile(r"^---\n(?P<meta>.*?)\n---\n(?P<body>.*)$", re.DOTALL)


class RuleLoadError(RuntimeError):
    """Raised when strict rule loading encounters malformed rule files."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        super().__init__("\n".join(errors))


def load_rule(path: Path) -> Rule:
    text = path.read_text(encoding="utf-8")
    match = _FRONTMATTER_RE.match(text)
    if not match:
        raise ValueError(f"frontmatter not found: {path}")
    meta = yaml.safe_load(match.group("meta")) or {}
    body = match.group("body").strip()
    return Rule(body=body, **meta)


_DOC_FILENAMES = {"README.MD", "CHANGELOG.MD", "INDEX.MD", "NOTICE.MD"}


def load_all_rules(rules_dir: Path, *, strict: bool = False) -> list[Rule]:
    rules: list[Rule] = []
    errors: list[str] = []
    for md in sorted(rules_dir.rglob("*.md")):
        if md.name.upper() in _DOC_FILENAMES:
            continue
        try:
            rules.append(load_rule(md))
        except Exception as exc:
            errors.append(f"{md.relative_to(rules_dir)}: {exc}")
    if errors and strict:
        raise RuleLoadError(errors)
    for err in errors:
        print(f"[loader] WARN {err}", file=sys.stderr)
    return rules
