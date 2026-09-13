"""CVE 기준 조회 인덱스 — 캐시를 읽을 때 한 번만 만들고, 조회는 상수 시간.

무엇이 문제였나: ``_enrich_with_epss_nvd`` 가 호출될 때마다 NVD·EPSS 캐시 전체로
dict 를 새로 만들었다. NVD 캐시가 5만 건이면 락파일 900개 검사에서 5만 건 dict
생성을 수백 번 반복한다. KNVD 를 같은 방식으로 붙이면 패키지마다 공지 전체를
선형 순회하게 된다.

여기서는 ``CacheEntry`` 의 ``(source_id, sha256)`` 를 키로 인덱스를 메모한다.
캐시 파일이 바뀌면 sha256 이 달라져 자연히 다시 만든다. 로드 메모(cache.py)와
같은 원리이며, 메모 크기는 작게 제한한다.
"""
from __future__ import annotations

from collections.abc import Callable

from .cache import CacheEntry, IntelCache

_INDEX_MEMO: dict[tuple[str, str, str], dict] = {}
_INDEX_MEMO_MAX = 12


def _memo_put(key: tuple[str, str, str], value: dict) -> None:
    if len(_INDEX_MEMO) >= _INDEX_MEMO_MAX and key not in _INDEX_MEMO:
        _INDEX_MEMO.pop(next(iter(_INDEX_MEMO)), None)
    _INDEX_MEMO[key] = value


def _indexed(entry: CacheEntry | None, kind: str, build: Callable[[list[dict]], dict]) -> dict:
    if entry is None:
        return {}
    key = (kind, entry.source_id, entry.sha256)
    hit = _INDEX_MEMO.get(key)
    if hit is not None:
        return hit
    index = build(entry.items)
    _memo_put(key, index)
    return index


def _by_field(field: str) -> Callable[[list[dict]], dict]:
    def build(items: list[dict]) -> dict:
        return {str(i.get(field)): i for i in items if i.get(field)}
    return build


def _by_cve_list(items: list[dict]) -> dict:
    """KNVD 공지 → ``CVE-ID → [공지, …]``. 한 공지에 CVE 가 여럿이면 각각에 매단다."""
    index: dict[str, list[dict]] = {}
    for item in items:
        for cve in item.get("cve_ids") or []:
            index.setdefault(str(cve).upper(), []).append(item)
    return index


def nvd_by_cve(entry: CacheEntry | None) -> dict[str, dict]:
    return _indexed(entry, "nvd", _by_field("id"))


def epss_by_cve(entry: CacheEntry | None) -> dict[str, dict]:
    return _indexed(entry, "epss", _by_field("cve"))


def knvd_by_cve(entry: CacheEntry | None) -> dict[str, list[dict]]:
    return _indexed(entry, "knvd", _by_cve_list)


def cve_ids_of(vuln: dict) -> list[str]:
    """OSV 항목의 정확한 CVE ID 목록(id 자체 + aliases). 형태가 CVE- 인 것만."""
    out: list[str] = []
    for candidate in [vuln.get("id"), *(vuln.get("aliases") or [])]:
        cid = str(candidate or "").strip().upper()
        if cid.startswith("CVE-") and cid not in out:
            out.append(cid)
    return out


def knvd_notices_for(cve_ids: list[str], cache: IntelCache) -> tuple[list[dict], list[str]]:
    """정확한 CVE 일치로 KNVD 공지를 찾는다 → (증적 목록, 사용한 source_id 목록).

    증적 구조: source=KNVD · source_id · source_url · cve_id · title · published_at ·
    fetched_at · match_method=exact_cve. 판정 값은 하나도 만들지 않는다.
    """
    from .sources.knvd import FEEDS

    notices: list[dict] = []
    used: list[str] = []
    if not cve_ids:
        return notices, used
    for source_id in FEEDS:
        entry = cache.load(source_id)
        if entry is None:
            continue
        index = knvd_by_cve(entry)
        hit = False
        for cve in cve_ids:
            for item in index.get(cve, ()):
                hit = True
                notices.append({
                    "source": "KNVD",
                    "source_id": source_id,
                    "source_url": item.get("link"),
                    "cve_id": cve,
                    "title": item.get("title"),
                    "published_at": item.get("published_at"),
                    "fetched_at": entry.fetched_at,
                    "match_method": "exact_cve",
                })
        if hit:
            used.append(source_id)
    return notices, used
