"""On-disk JSON cache for intel sources.

Each source is stored as a single JSON file with a fixed metadata envelope so
that air-gapped operators can verify the data origin and freshness without
needing the network back.

Layout::

    ~/.gvskb/cache/
      cisa-kev.json
      osv-mal-pypi.json
      ...

The envelope:

    {
      "schema_version": 1,
      "source_id": "cisa-kev",
      "fetched_at": "2026-05-31T19:45:00+09:00",
      "url": "https://...",
      "sha256": "abc...",
      "item_count": 1234,
      "items": [ ... source-specific normalized records ... ]
    }
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# v2: envelope에 ecosystems 기록 — 어떤 생태계를 담았는지 모르면 PyPI-only
# 캐시에 npm을 조회했을 때 "깨끗함"이라는 거짓 판정이 나온다.
CACHE_VERSION = 2

# 캐시 신선도 기준(일). 망분리 반입 캐시가 몇 달 묵어도 "깨끗함"으로 판정되지
# 않도록, 초과 시 소비자(check_package·doctor)가 stale로 승격한다.
DEFAULT_INTEL_MAX_AGE_DAYS = 30


def intel_max_age_days() -> int:
    """신선도 임계(일). GVSKB_INTEL_MAX_AGE_DAYS 로 기관 정책에 맞게 조정."""
    raw = os.environ.get("GVSKB_INTEL_MAX_AGE_DAYS", "")
    try:
        return max(1, int(raw)) if raw else DEFAULT_INTEL_MAX_AGE_DAYS
    except ValueError:
        return DEFAULT_INTEL_MAX_AGE_DAYS


def default_cache_dir() -> Path:
    """Return the directory where intel caches are stored.

    Honors ``GVSKB_CACHE_DIR`` if set, otherwise uses ``~/.gvskb/cache``.
    """
    override = os.environ.get("GVSKB_CACHE_DIR")
    if override:
        return Path(override)
    return Path.home() / ".gvskb" / "cache"


@dataclass(frozen=True)
class CacheEntry:
    """A single intel-source cache file in normalized form."""

    schema_version: int
    source_id: str
    fetched_at: str
    url: str
    sha256: str
    item_count: int
    items: list[dict]
    # 이 캐시가 커버하는 생태계(osv-malicious 전용, 예: ["PyPI", "npm"]).
    # None = 미기록(v1 캐시) — 소비자가 보수적으로 해석해야 한다.
    ecosystems: list[str] | None = field(default=None)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def age_days(self) -> int | None:
        """fetched_at 기준 경과 일수. 파싱 불가 시 None(신선도 확인 불가)."""
        try:
            fetched = datetime.fromisoformat(self.fetched_at)
        except (ValueError, TypeError):
            return None
        if fetched.tzinfo is None:
            fetched = fetched.replace(tzinfo=timezone.utc)
        return max(0, (datetime.now(timezone.utc) - fetched).days)

    def is_stale(self, max_age_days: int | None = None) -> bool:
        """신선도 초과 여부. 확인 불가(None)도 stale로 본다(보수적)."""
        age = self.age_days()
        limit = max_age_days if max_age_days is not None else intel_max_age_days()
        return age is None or age > limit


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _sha256(items: list[dict]) -> str:
    blob = json.dumps(items, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


class IntelCache:
    """Filesystem-backed cache for intel source results."""

    def __init__(self, cache_dir: Path | None = None) -> None:
        self.cache_dir = cache_dir or default_cache_dir()

    def path_for(self, source_id: str) -> Path:
        # source_id is constrained by the adapter registry, so no traversal risk.
        return self.cache_dir / f"{source_id}.json"

    def save(
        self,
        source_id: str,
        url: str,
        items: list[dict],
        *,
        ecosystems: list[str] | None = None,
    ) -> CacheEntry:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        entry = CacheEntry(
            schema_version=CACHE_VERSION,
            source_id=source_id,
            fetched_at=_now_iso(),
            url=url,
            sha256=_sha256(items),
            item_count=len(items),
            items=items,
            ecosystems=ecosystems,
        )
        self.path_for(source_id).write_text(
            json.dumps(entry.to_dict(), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return entry

    def load(self, source_id: str) -> CacheEntry | None:
        p = self.path_for(source_id)
        if not p.exists():
            return None
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return None
        items = data.get("items", [])
        # 무결성 재검증 — USB 반입 등 이동 경로에서 변조·손상된 캐시가 판정에
        # 쓰이지 않도록, 기록된 sha256이 있으면 items 해시를 다시 계산해 비교한다.
        # sha256 이 비어 있으면 **통과시키지 않는다** — 예전에는 "검증 불가 — 그대로
        # 통과"였다. 캐시 폴더에 쓸 수 있는 누구나 서명 없는 항목을 넣어 판정
        # (악성 패키지 목록)을 바꿀 수 있었다(재점검 2026-08-29). 구버전 캐시는
        # `gvskb update-intel` 로 다시 받으면 된다.
        recorded = data.get("sha256", "")
        if not recorded:
            print(
                f"[gvskb] ⚠ intel cache without integrity hash: {p.name} — "
                "sha256 이 없는 캐시는 쓰지 않습니다. `gvskb update-intel`로 다시 받으세요.",
                file=sys.stderr,
            )
            return None
        if _sha256(items) != recorded:
            print(
                f"[gvskb] ⚠ intel cache integrity check failed: {p.name} — "
                "sha256 불일치(변조·손상 가능). 이 캐시는 무시합니다. "
                "`gvskb update-intel`로 다시 받으세요.",
                file=sys.stderr,
            )
            return None
        return CacheEntry(
            schema_version=data.get("schema_version", 0),
            source_id=data.get("source_id", source_id),
            fetched_at=data.get("fetched_at", ""),
            url=data.get("url", ""),
            sha256=recorded,
            item_count=data.get("item_count", 0),
            items=items,
            ecosystems=data.get("ecosystems"),
        )

    def list_sources(self) -> list[str]:
        if not self.cache_dir.exists():
            return []
        return sorted(p.stem for p in self.cache_dir.glob("*.json"))
