"""update-intel orchestrator.

Coordinates fetching one or more sources, writing their normalized items to
the on-disk cache, and reporting per-source success/failure. Network failures
are reported as WARN so air-gapped environments can keep using the existing cache.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .cache import CacheEntry, IntelCache
from .sources.base import SOURCES, SourceAdapter


class IntelUpdateError(Exception):
    """Raised when a specific source cannot be updated AND no cache exists."""


@dataclass
class IntelUpdateResult:
    source_id: str
    status: str  # "ok" | "warn" | "error"
    item_count: int = 0
    delta: int = 0  # vs. previous cache
    cache_path: str = ""
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    def to_dict(self) -> dict:
        return {
            "source_id": self.source_id,
            "status": self.status,
            "item_count": self.item_count,
            "delta": self.delta,
            "cache_path": self.cache_path,
            "error": self.error,
        }


def _client_factory(timeout: float = 30.0):
    import httpx
    return httpx.Client(timeout=timeout, headers={"User-Agent": "gvskb-intel/0.1"})


def update_source(
    source_id: str,
    *,
    cache: IntelCache | None = None,
    client=None,
    timeout: float = 30.0,
) -> IntelUpdateResult:
    adapter: SourceAdapter | None = SOURCES.get(source_id)
    if adapter is None:
        return IntelUpdateResult(source_id=source_id, status="error",
                                 error=f"unknown source id: {source_id}")

    cache = cache or IntelCache()
    prev = cache.load(source_id)
    prev_count = prev.item_count if prev else 0

    owns_client = client is None
    if owns_client:
        client = _client_factory(timeout=timeout)
    try:
        try:
            url, items = adapter.fetch(client)
        except Exception as exc:
            return IntelUpdateResult(
                source_id=source_id,
                status="warn" if prev else "error",
                item_count=prev_count,
                cache_path=str(cache.path_for(source_id)) if prev else "",
                error=f"fetch failed: {exc!s}",
            )
        ecosystems = adapter.ecosystems() if adapter.ecosystems else None
        entry: CacheEntry = cache.save(source_id, url, items, ecosystems=ecosystems)
        return IntelUpdateResult(
            source_id=source_id,
            status="ok",
            item_count=entry.item_count,
            delta=entry.item_count - prev_count,
            cache_path=str(cache.path_for(source_id)),
        )
    finally:
        if owns_client:
            client.close()


def update_sources(
    source_ids: Iterable[str] | None = None,
    *,
    cache: IntelCache | None = None,
    timeout: float = 30.0,
) -> list[IntelUpdateResult]:
    cache = cache or IntelCache()
    ids = list(source_ids) if source_ids else list(SOURCES.keys())
    results: list[IntelUpdateResult] = []
    client = _client_factory(timeout=timeout)
    try:
        for sid in ids:
            results.append(update_source(sid, cache=cache, client=client))
    finally:
        client.close()
    return results
