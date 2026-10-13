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


# 같은 프로세스에서 룰을 여러 번 읽는다(집행용 정규식 컴파일 · 룰셋 지문 대조). 실측(2026-10-13
# safe_check 프로파일): 한 번 검사에 두 번 읽어 5.1초/50초. 파일 목록·수정시각·크기가 같으면
# 결과를 재사용한다 — 디스크가 바뀌면 키가 달라져 다시 읽으므로 룰 편집·테스트에 안전하다.
_LOAD_CACHE: dict[tuple, list[Rule]] = {}


def _rules_fingerprint(rules_dir: Path) -> tuple:
    entries = []
    for md in sorted(rules_dir.rglob("*.md")):
        try:
            st = md.stat()
        except OSError:
            continue
        entries.append((str(md), st.st_mtime_ns, st.st_size))
    return tuple(entries)


def load_all_rules(rules_dir: Path, *, strict: bool = False) -> list[Rule]:
    key = (str(Path(rules_dir).resolve()), strict, _rules_fingerprint(Path(rules_dir)))
    cached = _LOAD_CACHE.get(key)
    if cached is not None:
        return list(cached)
    rules = _load_all_rules_uncached(rules_dir, strict=strict)
    _LOAD_CACHE.clear()          # 최신 하나만 — 메모리를 키우지 않는다
    _LOAD_CACHE[key] = rules
    return list(rules)


def _load_all_rules_uncached(rules_dir: Path, *, strict: bool = False) -> list[Rule]:
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
