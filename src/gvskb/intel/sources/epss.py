"""FIRST EPSS — recent exploit prediction scores.

EPSS publishes daily scores for every public CVE. A full snapshot is ~250k
rows, which is too much for a local cache by default; we query the recent
days window instead. Operators wanting full coverage can override via the
``EPSS_DAYS`` environment variable or by passing ``days=N`` at the API level.
"""
from __future__ import annotations

import os

from .base import HttpFetcher, SourceAdapter, register_source

EPSS_API_URL = "https://api.first.org/data/v1/epss"
DEFAULT_DAYS = 1


def _normalize(entry: dict) -> dict:
    return {
        "cve": entry.get("cve"),
        "epss": float(entry.get("epss", 0.0)) if entry.get("epss") else 0.0,
        "percentile": float(entry.get("percentile", 0.0)) if entry.get("percentile") else 0.0,
        "date": entry.get("date"),
    }


def fetch_epss_recent(client: HttpFetcher) -> tuple[str, list[dict]]:
    days = int(os.environ.get("EPSS_DAYS", DEFAULT_DAYS))
    params = {"days": days, "limit": 5000}
    resp = client.get(EPSS_API_URL, params=params)
    resp.raise_for_status()
    data = resp.json() or {}
    if data.get("status") != "OK":
        return EPSS_API_URL, []
    items = [_normalize(d) for d in data.get("data", []) if d.get("cve")]
    return EPSS_API_URL, items


#: 누적 캐시 상한(항목 수). 항목이 100B 미만으로 작아 전체 CVE(~30만)를 담아도
#: 수십 MB 를 넘지 않지만, 무제한은 두지 않는다. GVSKB_EPSS_CACHE_MAX 로 조정.
DEFAULT_CACHE_MAX = 300_000


def _cache_max() -> int:
    raw = os.environ.get("GVSKB_EPSS_CACHE_MAX", "")
    try:
        return max(1000, int(raw)) if raw else DEFAULT_CACHE_MAX
    except ValueError:
        return DEFAULT_CACHE_MAX


def merge_epss(prev_items: list[dict], new_items: list[dict]) -> list[dict]:
    """CVE 기준 병합 — 점수 날짜(date)가 더 최신인 쪽을 남긴다.

    예전에는 매일 "최근 1일" 창으로 **덮어써서** 캐시에 늘 수천 건만 남았다.
    누적하면 오래전 CVE 의 악용확률도 오프라인에서 계속 조회된다.
    """
    by_cve: dict[str, dict] = {str(i.get("cve")): i for i in prev_items if i.get("cve")}
    for i in new_items:
        cve = str(i.get("cve") or "")
        if not cve:
            continue
        old = by_cve.get(cve)
        if old is None or str(i.get("date") or "") >= str(old.get("date") or ""):
            by_cve[cve] = i
    merged = sorted(by_cve.values(), key=lambda i: str(i.get("date") or ""), reverse=True)
    return merged[:_cache_max()]


register_source(SourceAdapter(
    id="epss-recent",
    description=(
        f"FIRST EPSS — exploit prediction scores from the last {DEFAULT_DAYS} day(s), "
        "merged cumulatively into the local cache (newest score per CVE kept)"
    ),
    fetch=fetch_epss_recent,
    merge=merge_epss,
))
