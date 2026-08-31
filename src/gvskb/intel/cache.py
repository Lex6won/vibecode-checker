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


# ---------------------------------------------------------------------------
# 로드 메모 — 같은 파일을 프로세스 안에서 반복 파싱하지 않는다.
#
# check_package 는 **패키지마다** IntelCache() 를 만들어 load() 를 부른다. 예전
# 캐시(악성 목록 2.7MB)에서는 낭비 수준이었지만, osv-vulns(수십 MB)가 생기면
# 락파일 900개 검사가 "30MB JSON 파싱 + sha256 재검증"을 900번 하게 된다 —
# 검사가 분 단위로 느려진다. 파일의 (경로, mtime_ns, size) 가 같으면 파싱 결과를
# 재사용한다. 파일이 바뀌면 서명이 달라져 자연히 다시 읽는다. 무결성 검증 실패
# (None)도 메모한다 — 손상된 대용량 파일을 900번 재파싱하며 경고를 900줄 찍지
# 않기 위해서다.
# ---------------------------------------------------------------------------
_LOAD_MEMO: dict[str, tuple[tuple[int, int], "CacheEntry | None"]] = {}
_LOAD_MEMO_MAX = 8

#: 이 항목 수를 넘는 캐시는 indent 없이 저장한다 — 사람이 읽을 크기가 아니고,
#: indent=2 는 파일을 1.5배 안팎으로 키운다(osv 계열 수십 MB).
_COMPACT_THRESHOLD_ITEMS = 10_000


def _memo_put(key: str, sig: tuple[int, int], entry: "CacheEntry | None") -> None:
    if len(_LOAD_MEMO) >= _LOAD_MEMO_MAX and key not in _LOAD_MEMO:
        _LOAD_MEMO.pop(next(iter(_LOAD_MEMO)), None)
    _LOAD_MEMO[key] = (sig, entry)


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
        indent = None if len(items) > _COMPACT_THRESHOLD_ITEMS else 2
        p = self.path_for(source_id)
        p.write_text(
            json.dumps(entry.to_dict(), ensure_ascii=False, indent=indent),
            encoding="utf-8",
        )
        try:
            st = p.stat()
            _memo_put(str(p.resolve()), (st.st_mtime_ns, st.st_size), entry)
        except OSError:
            pass
        return entry

    def load(self, source_id: str) -> CacheEntry | None:
        p = self.path_for(source_id)
        if not p.exists():
            return None
        sig: tuple[int, int] | None = None
        key = ""
        try:
            st = p.stat()
            sig = (st.st_mtime_ns, st.st_size)
            key = str(p.resolve())
        except OSError:
            pass
        if sig is not None and key in _LOAD_MEMO and _LOAD_MEMO[key][0] == sig:
            return _LOAD_MEMO[key][1]
        entry = self._load_uncached(source_id, p)
        if sig is not None:
            _memo_put(key, sig, entry)
        return entry

    def _load_uncached(self, source_id: str, p: Path) -> CacheEntry | None:
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
        # `.autopull-state.json` 같은 상태 파일은 캐시 항목이 아니다 — 무결성 검사에
        # 걸려 매 검사마다 경고를 냈다(S-8 재측정 2026-08-30).
        return sorted(p.stem for p in self.cache_dir.glob("*.json") if not p.name.startswith("."))
