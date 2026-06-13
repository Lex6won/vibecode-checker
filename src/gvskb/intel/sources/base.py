"""Shared source-adapter abstractions and registry."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Protocol


class HttpFetcher(Protocol):
    """Minimal subset of httpx.Client the adapters depend on (eases mocking)."""

    def get(self, url: str, *args, **kwargs): ...  # pragma: no cover

    def post(self, url: str, *args, **kwargs): ...  # pragma: no cover


FetchFn = Callable[[HttpFetcher], tuple[str, list[dict]]]


@dataclass(frozen=True)
class SourceAdapter:
    """A registered intel source adapter."""

    id: str
    description: str
    fetch: FetchFn


SOURCES: dict[str, SourceAdapter] = {}


def register_source(adapter: SourceAdapter) -> SourceAdapter:
    """Register an adapter so the update orchestrator can find it by id."""
    if adapter.id in SOURCES:
        raise ValueError(f"duplicate intel source id: {adapter.id}")
    SOURCES[adapter.id] = adapter
    return adapter
