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


register_source(SourceAdapter(
    id="epss-recent",
    description=f"FIRST EPSS — exploit prediction scores from the last {DEFAULT_DAYS} day(s)",
    fetch=fetch_epss_recent,
))
