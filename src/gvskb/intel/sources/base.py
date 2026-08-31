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
    # 이번 수집이 커버하는 생태계 목록(예: ["PyPI", "npm"]). 캐시 envelope에
    # 기록돼, 오프라인 조회 시 미포함 생태계를 '깨끗함'으로 오판하지 않게 한다.
    ecosystems: Callable[[], list[str]] | None = None
    # 이전 캐시와 새 수집분의 병합 함수 ``merge(prev_items, new_items) -> items``.
    # None 이면 새 수집분이 캐시를 **덮어쓴다**(전체 스냅샷 소스: OSV·KEV).
    # NVD("최근 7일")·EPSS("최근 1일")처럼 **창(window) 조회** 소스는 덮어쓰면
    # 창 밖으로 밀려난 항목이 매일 사라진다 — 시간이 지나도 데이터가 쌓이지 않고
    # 오히려 잊는다(실측 지적 2026-08-31). 그런 소스는 병합 함수로 누적한다.
    merge: Callable[[list[dict], list[dict]], list[dict]] | None = None


SOURCES: dict[str, SourceAdapter] = {}


def register_source(adapter: SourceAdapter) -> SourceAdapter:
    """Register an adapter so the update orchestrator can find it by id."""
    if adapter.id in SOURCES:
        raise ValueError(f"duplicate intel source id: {adapter.id}")
    SOURCES[adapter.id] = adapter
    return adapter
