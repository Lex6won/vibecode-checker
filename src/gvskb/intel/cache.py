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
import re
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
# 2일: KEV·OSV 악성 목록은 매일 바뀐다. 30일이던 때 서버 캐시가 한 달 묵은 채 판정을 냈다
# (실측 2026-10-13, KEV 30건 누락). 온라인 PC 는 기본 패키지 검사가 하루 1회 자동 갱신하므로
# 짧아도 부담이 없고, 망분리 PC 는 보고서가 "N일 경과"를 정직하게 적는다.
DEFAULT_INTEL_MAX_AGE_DAYS = 2


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


# ---------------------------------------------------------------------------
# 검증 스탬프 — 프로세스가 바뀌어도 sha256 재계산을 반복하지 않는다(46차 검증 지적 HIGH-3).
#
# 패키지 검사가 기본이 되면서 CLI·pre-commit·VS Code 태스크 같은 **단명 프로세스**가 매번
# osv-vulns(수십 MB)의 items 를 다시 직렬화해 해시했다(실측 2.6s/프로세스). 한 번 검증한
# 파일은 (mtime_ns, size, 기록된 sha256) 을 사이드카 `<이름>.verified` 에 남기고, 다음 로드에서
# 세 값이 같으면 해시 계산만 건너뛴다(JSON 파싱은 그대로 한다).
#
# 위협 모델: 이 envelope sha256 은 **손상** 감지용이다. 캐시 폴더에 쓸 수 있는 사람은 sha256
# 필드도 함께 고칠 수 있으므로 스탬프가 보안 수준을 낮추지 않는다. 위조 방어는 번들 서명
# (intel/signing.py)이 맡는다. 파일이 바뀌면 mtime·size 가 달라져 자연히 다시 해시한다.
# ---------------------------------------------------------------------------
def _safe_int(value: Any) -> int:
    """손상된 ``item_count``(비정수)가 적재를 **크래시**시키지 않게 한다(리뷰 L-3) — 0 으로 둔다."""
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _stamp_path(p: Path) -> Path:
    return p.with_name(p.name + ".verified")


def _stamp_matches(p: Path, st: "os.stat_result | None", recorded: str) -> bool:
    if st is None:
        return False
    try:
        d = json.loads(_stamp_path(p).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return False
    return (d.get("mtime_ns") == st.st_mtime_ns and d.get("size") == st.st_size
            and d.get("sha256") == recorded)


def _write_stamp(
    p: Path,
    st: "os.stat_result | None",
    recorded: str,
    *,
    fetched_at: str = "",
    item_count: int | None = None,
) -> None:
    if st is None:
        return
    # 47차 — 수집 시각·항목 수도 스탬프에 적는다. `peek()` 가 수십 MB JSON 을 열지 않고
    # 신선도를 답할 수 있게 하기 위한 것(포털 /health · 하네스 doctor 가 매번 묻는다).
    target = _stamp_path(p)
    tmp = target.with_name(target.name + f".{os.getpid()}.tmp")
    try:
        # 임시파일 + 교체 — 폴링 중인 다른 프로세스가 반쯤 쓰인 스탬프를 읽지 않게 한다(리뷰 M-2c).
        tmp.write_text(
            json.dumps({
                "mtime_ns": st.st_mtime_ns, "size": st.st_size, "sha256": recorded,
                "fetched_at": fetched_at, "item_count": item_count,
            }),
            encoding="utf-8",
        )
        os.replace(tmp, target)
    except OSError:
        # 스탬프는 편의 장치 — 못 써도 검증은 된다. 다만 **매 프로세스가 재해시**하게 되므로
        # 한 번은 알린다(읽기 전용 공유 폴더·다른 계정 소유 캐시에서 실제로 일어난다).
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        _warn_stamp_unwritable_once(target)


_STAMP_WARNED: set[str] = set()


def _warn_stamp_unwritable_once(target: Path) -> None:
    key = str(target.parent)
    if key in _STAMP_WARNED:
        return
    _STAMP_WARNED.add(key)
    print(
        f"[gvskb] 참고: 위협정보 캐시 폴더에 검증 스탬프를 쓸 수 없습니다({target.parent}) — 판정은 그대로지만 "
        "매 실행마다 캐시 무결성을 다시 계산해 느립니다. 폴더 쓰기 권한 또는 GVSKB_CACHE_DIR 을 확인하세요.",
        file=sys.stderr,
    )


_HEADER_BYTES = 1024
_HEADER_FETCHED_RE = re.compile(r'"fetched_at"\s*:\s*"([^"]*)"')
_HEADER_COUNT_RE = re.compile(r'"item_count"\s*:\s*(\d+)')


def _read_header(p: Path) -> tuple[str | None, int | None]:
    """캐시 파일 **앞 1KB** 에서 수집 시각·항목 수만 뽑는다 — 본문(items, 수십 MB)은 열지 않는다.

    envelope 은 ``asdict`` 순서(schema_version, source_id, fetched_at, url, sha256, item_count, items…)로
    직렬화되므로 두 값은 항상 머리에 있다. 무결성은 보장하지 않는다(표시용).
    """
    try:
        with p.open("rb") as fh:
            head = fh.read(_HEADER_BYTES).decode("utf-8", errors="replace")
    except OSError:
        return None, None
    m1 = _HEADER_FETCHED_RE.search(head)
    m2 = _HEADER_COUNT_RE.search(head)
    return (m1.group(1) if m1 else None), (int(m2.group(1)) if m2 else None)


def _read_stamp(p: Path, st: "os.stat_result | None") -> dict | None:
    """(mtime, size) 가 지금 파일과 같은 스탬프 dict. 없거나 어긋나면 None."""
    if st is None:
        return None
    try:
        d = json.loads(_stamp_path(p).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return None
    if d.get("mtime_ns") != st.st_mtime_ns or d.get("size") != st.st_size:
        return None
    return d


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
            # 방금 쓴 본문은 검증할 것이 없다 — 스탬프를 바로 남겨 다음 프로세스의 peek·load 가 빠르다.
            _write_stamp(p, st, entry.sha256, fetched_at=entry.fetched_at, item_count=entry.item_count)
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
            st: os.stat_result | None = p.stat()
        except OSError:
            st = None
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
        stamp = _read_stamp(p, st)
        # 스탬프의 (mtime, size) 는 _read_stamp 가 이미 대조했다 — 남은 조건은 기록된 sha256 일치(리뷰 L-1).
        if not (stamp and stamp.get("sha256") == recorded):
            if _sha256(items) != recorded:
                print(
                    f"[gvskb] ⚠ intel cache integrity check failed: {p.name} — "
                    "sha256 불일치(변조·손상 가능). 이 캐시는 무시합니다. "
                    "`gvskb update-intel`로 다시 받으세요.",
                    file=sys.stderr,
                )
                return None
            stamp = None
        if stamp is None or "fetched_at" not in stamp:
            # 새 스탬프이거나 46차 형식(수집 시각 없음) — peek 가 쓸 수 있게 다시 적는다.
            _write_stamp(p, st, recorded, fetched_at=str(data.get("fetched_at", "") or ""),
                         item_count=_safe_int(data.get("item_count")))
        return CacheEntry(
            schema_version=data.get("schema_version", 0),
            source_id=data.get("source_id", source_id),
            fetched_at=data.get("fetched_at", ""),
            url=data.get("url", ""),
            sha256=recorded,
            item_count=_safe_int(data.get("item_count")),
            items=items,
            ecosystems=data.get("ecosystems"),
        )

    def peek_info(self, source_id: str) -> dict | None:
        """상태 표시용 경량 조회 — **본문을 열지 않는다**(47차, 리뷰 M-1·M-2 반영).

        반환: ``{"present", "fetched_at", "item_count", "sha256", "basis", "stamp_mismatch"}``
        - ``basis="stamp"``: (mtime, size) 가 맞는 검증 스탬프에서 읽음. 파일 앞 1KB 의 수집 시각과도
          대조해 다르면 머리값을 쓰고 ``stamp_mismatch=True`` 로 알린다(스탬프만 고친 조작·복사 흔적).
        - ``basis="header"``: 스탬프가 없거나 구형 — 파일 앞 1KB 에서만 읽음(무결성 미검증).
        - ``basis="unknown"``: 둘 다 못 읽음 — 상태는 '알 수 없음'.
        어느 경우에도 수십 MB 본문을 파싱하거나 캐시 폴더에 **쓰지 않는다**. 판정은 ``load()`` 로만.
        """
        p = self.path_for(source_id)
        if not p.exists():
            return None
        try:
            st: os.stat_result | None = p.stat()
        except OSError:
            st = None
        stamp = _read_stamp(p, st) or {}
        head_fetched, head_count = _read_header(p)
        info: dict = {"present": True, "fetched_at": None, "item_count": None,
                      "sha256": stamp.get("sha256") or None, "basis": "unknown", "stamp_mismatch": False}
        if stamp.get("sha256") and "fetched_at" in stamp:
            info["fetched_at"] = str(stamp.get("fetched_at") or "") or None
            info["item_count"] = _safe_int(stamp.get("item_count")) if stamp.get("item_count") is not None else None
            info["basis"] = "stamp"
            if head_fetched is not None and head_fetched != info["fetched_at"]:
                info["stamp_mismatch"] = True
                info["fetched_at"] = head_fetched or None
                info["item_count"] = head_count
                info["basis"] = "header"
        elif head_fetched is not None:
            info["fetched_at"] = head_fetched or None
            info["item_count"] = head_count
            info["basis"] = "header"
        return info

    def peek(self, source_id: str) -> CacheEntry | None:
        """``peek_info`` 를 CacheEntry 모양으로 — ``items`` 는 비어 있고 수집 시각을 모르면 None.

        판정에 쓰지 말 것(무결성 미검증). ``fetched_at``·``age_days()``·``is_stale()``·``item_count`` 만 읽는다.
        """
        info = self.peek_info(source_id)
        if not info or not info.get("fetched_at"):
            return None
        return CacheEntry(
            schema_version=CACHE_VERSION,
            source_id=source_id,
            fetched_at=str(info["fetched_at"]),
            url="",
            sha256=str(info.get("sha256") or ""),
            item_count=int(info.get("item_count") or 0),
            items=[],
            ecosystems=None,
        )

    def list_sources(self) -> list[str]:
        if not self.cache_dir.exists():
            return []
        # `.autopull-state.json` 같은 상태 파일은 캐시 항목이 아니다 — 무결성 검사에
        # 걸려 매 검사마다 경고를 냈다(S-8 재측정 2026-08-30).
        return sorted(p.stem for p in self.cache_dir.glob("*.json") if not p.name.startswith("."))
