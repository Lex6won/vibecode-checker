"""Rule search — substring scoring + Korean synonym expansion.

The synonym layer is intentionally tiny: a YAML file maps each query term to
a bag of equivalent terms (English ↔ 한국어 ↔ 도메인 키워드). When a query
matches a synonym, the original score is preserved and the synonym terms add
a small bonus, so the user sees the rule even when they type the *Korean*
phrase but the rule's body uses English (or vice versa).

Full-text search (FTS5 / BM25) is a follow-up; this module keeps the surface
small until we have real beta-tester queries to optimize against.
"""
from __future__ import annotations

import os
from functools import lru_cache
from importlib import resources
from pathlib import Path

import yaml

from .schema import Rule


# ---------------------------------------------------------------------------
# Synonym index
# ---------------------------------------------------------------------------


@lru_cache(maxsize=1)
def _load_synonyms() -> dict[str, frozenset[str]]:
    """term (lowercased) → frozenset of equivalent terms (lowercased)."""
    p = _resolve_synonyms_path()
    if not p.exists():
        return {}
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    out: dict[str, frozenset[str]] = {}
    for group in data.get("groups", []) or []:
        normalized = frozenset(str(t).lower() for t in group if t)
        for term in normalized:
            existing = out.get(term, frozenset())
            out[term] = frozenset(existing | normalized)
    return out


def _resolve_synonyms_path() -> Path:
    override = os.environ.get("GVSKB_SYNONYMS")
    if override:
        return Path(override)
    pkg_root = Path(__file__).resolve().parent
    project_root = pkg_root.parent.parent
    repo = project_root / "config" / "korean_synonyms.yaml"
    if repo.exists():
        return repo
    return Path(str(resources.files("gvskb").joinpath("config", "korean_synonyms.yaml")))


def expand_query(query: str) -> list[str]:
    """Return the lowercased query token plus its synonyms (deduped, order stable)."""
    q = query.strip().lower()
    if not q:
        return []
    syn = _load_synonyms()
    bag = syn.get(q, frozenset({q}))
    # original first, then synonyms (excluding original) sorted for stability
    others = sorted(t for t in bag if t != q)
    return [q, *others]


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def _score_for_term(rule: Rule, term: str, *, weight: float = 1.0) -> float:
    score = 0.0
    t = term.lower()
    if t in rule.title_ko.lower():
        score += 10
    if rule.title_en and t in rule.title_en.lower():
        score += 7
    if t in rule.id.lower():
        score += 6
    for tag in rule.scenarios + rule.languages + rule.cwe + rule.domains:
        if t in tag.lower():
            score += 3
    body = rule.body.lower()
    if t in body:
        score += min(body.count(t), 5)
    return score * weight


def _score(rule: Rule, query: str) -> float:
    """Original-term match with full weight; synonyms add a small bonus."""
    terms = expand_query(query)
    if not terms:
        return 0.0
    primary = _score_for_term(rule, terms[0], weight=1.0)
    bonus = sum(_score_for_term(rule, t, weight=0.4) for t in terms[1:])
    return primary + bonus


def simple_search(
    rules: list[Rule],
    query: str,
    scenario: str | None = None,
    language: str | None = None,
    severity_min: str | None = None,
    limit: int = 5,
    *,
    status: str | None = None,
    approved_only: bool = False,
) -> list[Rule]:
    severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    min_rank = severity_order.get(severity_min or "", -1)

    scored: list[tuple[float, Rule]] = []
    for rule in rules:
        if approved_only and rule.status.value != "approved":
            continue
        if status and rule.status.value != status:
            continue
        if scenario and scenario not in rule.scenarios:
            continue
        if language and language not in rule.languages:
            continue
        if severity_order[rule.severity.value] < min_rank:
            continue
        score = _score(rule, query)
        if score > 0:
            scored.append((score, rule))
    scored.sort(key=lambda item: -item[0])
    return [rule for _, rule in scored[:limit]]
