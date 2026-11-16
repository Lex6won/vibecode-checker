"""위협정보 이름 색인 — 패키지 1건 검사가 수십 MB JSON 전체를 읽지 않게 한다 (A14, 2026-11-16).

무엇이 문제였나: ``check-package`` 1건이 악성 권고(60MB)·취약점 권고(35MB)를 통째로 파싱하고
23만 건짜리 이름 색인을 매번 만들어 6초가 걸렸다. 포털·하네스는 패키지마다 새 프로세스로 묻는다.

어떻게 하나: 캐시 파일을 쓰거나 검증한 뒤, 항목을 **패키지 이름**으로 묶어 256개 조각(gzip JSON)에 나눠 둔다.
검사는 이름이 들어 있는 조각 하나만 읽어 원래 캐시와 **모양이 같은** ``CacheEntry`` (항목만 그 이름 것)를 돌려준다.
판정 함수는 그대로다 — 같은 입력의 부분집합을 같은 순서로 받는다.

정확성 근거:
- 색인 키는 PEP 503 정규화 이름이다. 소비자의 이름 비교(PyPI 는 PEP 503, 그 밖은 소문자)가 같다고 보는 두 이름은
  항상 같은 키가 된다 — 색인이 돌려주는 항목은 실제 일치 항목의 **상위집합**이고, 소비자가 다시 정확히 거른다.
  생태계는 키에 넣지 않는다(생태계가 빈 항목을 모든 생태계와 맞추는 소비자가 있다).
- 항목 순서는 원래 캐시 순서 그대로다.

신뢰 근거(전체 로딩과 같은 수준):
- 매니페스트는 원본 캐시의 (크기, 수정시각, sha256)에 묶인다. 원본의 검증 스탬프가 지금 파일과 맞고
  스탬프 sha256 = 파일 머리의 sha256 = 매니페스트의 원본 sha256 일 때만 쓴다 — ``IntelCache.load`` 가
  재해시 없이 받아들이는 조건과 같다.
- 조각마다 sha256 을 매니페스트에 적고 읽을 때 대조한다(반쯤 쓰인 조각·손상).
- 어느 하나라도 어긋나면 ``None`` — 호출자는 기존 전체 로딩으로 돌아간다. 색인은 빨라지게만 하고 판정을 바꾸지 않는다.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import os
import re
import shutil
import time
from pathlib import Path

from .cache import CacheEntry, IntelCache, _read_stamp, replace_with_retry

#: 색인을 두는 소스 — 패키지 이름으로 찾는 큰 캐시만. KEV·NVD·EPSS 는 작거나 CVE 로 찾는다.
INDEXED_SOURCES: tuple[str, ...] = ("osv-malicious", "osv-vulns")
INDEX_FORMAT = 1
#: 키 정규화 방식이 바뀌면 올린다 — 옛 색인은 자동으로 무시된다.
KEY_SCHEME = "pep503-name-v1"
_INDEX_DIRNAME = ".index"
_SHARD_HEX = 2                      # 256 조각
#: 한 프로세스가 같은 소스를 이만큼 색인으로 찾으면 그다음부터는 전체를 한 번 읽어 메모한다
#: (락파일 수백 건 검사는 조각 수백 번보다 전체 한 번이 빠르다).
VIEW_LOOKUP_LIMIT = 24
_HEADER_BYTES = 1024
_HEADER_SHA_RE = re.compile(r'"sha256"\s*:\s*"([0-9a-f]{64})"')
_HEADER_SOURCE_RE = re.compile(r'"source_id"\s*:\s*"([^"]*)"')

_SHARD_MEMO: dict[tuple[str, str], dict] = {}
_SHARD_MEMO_MAX = 32
_VIEW_COUNTS: dict[str, int] = {}


def index_key(name: str) -> str:
    """색인 키 — PEP 503 정규화(소문자, ``-_.`` 연속을 ``-`` 하나로, 양끝 ``-`` 제거)."""
    return re.sub(r"[-_.]+", "-", str(name)).strip("-").lower()


def _shard_of(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:_SHARD_HEX]


def _names_of(item: dict) -> set[str]:
    """항목이 가리키는 패키지 이름들의 색인 키. OSV 원형(package 가 dict)과 평평한 형식(package 가 문자열) 모두."""
    keys: set[str] = set()
    for aff in item.get("affected") or []:
        if not isinstance(aff, dict):
            continue
        pkg = aff.get("package")
        name = pkg.get("name") if isinstance(pkg, dict) else pkg
        if name:
            key = index_key(str(name))
            if key:
                keys.add(key)
    return keys


def _source_root(cache: IntelCache, source_id: str) -> Path:
    return cache.cache_dir / _INDEX_DIRNAME / source_id


def _header_values(p: Path) -> tuple[str | None, str | None]:
    try:
        with p.open("rb") as fh:
            head = fh.read(_HEADER_BYTES).decode("utf-8", errors="replace")
    except OSError:
        return None, None
    m1, m2 = _HEADER_SHA_RE.search(head), _HEADER_SOURCE_RE.search(head)
    return (m1.group(1) if m1 else None), (m2.group(1) if m2 else None)


def _read_manifest(cache: IntelCache, source_id: str) -> dict | None:
    try:
        doc = json.loads((_source_root(cache, source_id) / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(doc, dict) or doc.get("format") != INDEX_FORMAT or doc.get("key_scheme") != KEY_SCHEME:
        return None
    if doc.get("source_id") != source_id or not isinstance(doc.get("shards"), dict):
        return None
    return doc


def _valid_manifest(cache: IntelCache, source_id: str) -> dict | None:
    """지금 캐시 파일에 묶인 매니페스트 — 아니면 None(전체 로딩으로)."""
    manifest = _read_manifest(cache, source_id)
    if manifest is None:
        return None
    p = cache.path_for(source_id)
    try:
        st = p.stat()
    except OSError:
        return None
    if manifest.get("file_size") != st.st_size or manifest.get("file_mtime_ns") != st.st_mtime_ns:
        return None
    stamp = _read_stamp(p, st)
    recorded, header_source = _header_values(p)
    want = manifest.get("source_sha256")
    if not stamp or not want or stamp.get("sha256") != want or recorded != want or header_source != source_id:
        return None
    return manifest


def _load_shard(cache: IntelCache, source_id: str, manifest: dict, shard: str) -> dict | None:
    expected = manifest["shards"].get(shard)
    folder = str(manifest.get("dir") or "")
    if not expected or not re.fullmatch(r"[0-9A-Za-z_-]{1,64}", folder):
        return None
    memo_key = (f"{cache.cache_dir}|{source_id}|{folder}", shard)
    hit = _SHARD_MEMO.get(memo_key)
    if hit is not None and hit.get("_sha") == expected:
        return hit["data"]
    try:
        raw = (_source_root(cache, source_id) / folder / f"{shard}.json.gz").read_bytes()
    except OSError:
        return None
    if hashlib.sha256(raw).hexdigest() != expected:
        return None
    try:
        data = json.loads(gzip.decompress(raw).decode("utf-8"))
    except (OSError, ValueError, EOFError):
        return None
    if not isinstance(data, dict):
        return None
    if len(_SHARD_MEMO) >= _SHARD_MEMO_MAX:
        _SHARD_MEMO.pop(next(iter(_SHARD_MEMO)), None)
    _SHARD_MEMO[memo_key] = {"_sha": expected, "data": data}
    return data


def lookup(cache: IntelCache, source_id: str, name: str) -> CacheEntry | None:
    """이 이름의 항목만 담은 ``CacheEntry`` — 색인을 믿을 수 없으면 None."""
    if source_id not in INDEXED_SOURCES:
        return None
    manifest = _valid_manifest(cache, source_id)
    if manifest is None:
        return None
    key = index_key(name)
    data = _load_shard(cache, source_id, manifest, _shard_of(key))
    if data is None:
        return None
    items = data.get(key, [])
    if not isinstance(items, list) or not all(isinstance(i, dict) for i in items):
        return None
    meta = manifest.get("meta") or {}
    ecosystems = meta.get("ecosystems")
    return CacheEntry(
        schema_version=int(meta.get("schema_version") or 0),
        source_id=source_id,
        fetched_at=str(meta.get("fetched_at") or ""),
        url=str(meta.get("url") or ""),
        # 부분 항목이다 — lookup.py 의 색인 메모가 전체 캐시 색인과 섞이지 않게 sha256 에 표식을 붙인다.
        sha256=f"{manifest['source_sha256']}#name={key}",
        item_count=int(meta.get("item_count") or 0),
        items=list(items),
        ecosystems=list(ecosystems) if isinstance(ecosystems, list) else None,
    )


def load_for_package(cache: IntelCache, source_id: str, name: str) -> CacheEntry | None:
    """패키지 1건 검사용 — 색인이 있으면 그 이름 항목만, 없거나 어긋나면 전체 캐시(``IntelCache.load``).

    같은 프로세스에서 많이 찾으면 전체를 한 번 읽는 쪽으로 넘어간다. 전체를 읽은 뒤 색인이 없으면 만들어 둔다.
    """
    full_key = f"{cache.cache_dir}|{source_id}"
    count = _VIEW_COUNTS.get(full_key, 0)
    if count < VIEW_LOOKUP_LIMIT:
        view = lookup(cache, source_id, name)
        if view is not None:
            _VIEW_COUNTS[full_key] = count + 1
            return view
    entry = cache.load(source_id)
    if entry is not None and source_id in INDEXED_SOURCES and count < VIEW_LOOKUP_LIMIT:
        # 색인이 없거나 낡았다 — 다음 검사부터 빨라지게 만든다. 실패해도 판정과 무관하다.
        _VIEW_COUNTS[full_key] = VIEW_LOOKUP_LIMIT   # 이 프로세스는 이제 전체 메모를 쓴다
        try:
            build(cache, source_id, entry)
        except Exception:  # noqa: BLE001 — 색인은 편의 장치다
            pass
    return entry


def build(cache: IntelCache, source_id: str, entry: CacheEntry | None = None) -> bool:
    """검증된 캐시로 색인을 만든다. 성공하면 True. 폴더에 쓸 수 없거나 도중에 캐시가 바뀌면 False(아무것도 남기지 않음)."""
    if source_id not in INDEXED_SOURCES:
        return False
    p = cache.path_for(source_id)
    try:
        st0 = p.stat()
    except OSError:
        return False
    if entry is None:
        entry = cache.load(source_id)
    if entry is None:
        return False
    # 색인은 검증 스탬프에 묶인다 — 스탬프가 지금 파일·이 내용과 맞지 않으면 만들지 않는다.
    stamp = _read_stamp(p, st0)
    if not stamp or stamp.get("sha256") != entry.sha256 or "#" in entry.sha256:
        return False
    recorded, header_source = _header_values(p)
    if recorded != entry.sha256 or header_source != source_id:
        return False

    root = _source_root(cache, source_id)
    folder = f"{entry.sha256[:16]}-{time.time_ns()}-{os.getpid()}"
    work = root / f".{folder}.tmp"
    try:
        work.mkdir(parents=True, exist_ok=False)
    except OSError:
        return False
    try:
        buckets: dict[str, dict[str, list[dict]]] = {}
        for item in entry.items:
            if not isinstance(item, dict):
                continue
            for key in sorted(_names_of(item)):
                buckets.setdefault(_shard_of(key), {}).setdefault(key, []).append(item)
        shards: dict[str, str] = {}
        for i in range(16 ** _SHARD_HEX):
            shard = f"{i:0{_SHARD_HEX}x}"
            raw = gzip.compress(json.dumps(buckets.get(shard, {}), ensure_ascii=False,
                                           separators=(",", ":")).encode("utf-8"), compresslevel=5, mtime=0)
            (work / f"{shard}.json.gz").write_bytes(raw)
            shards[shard] = hashlib.sha256(raw).hexdigest()
        del buckets
        final = root / folder
        os.replace(work, final)
    except OSError:
        shutil.rmtree(work, ignore_errors=True)
        return False

    try:
        st1 = p.stat()
    except OSError:
        st1 = None
    if st1 is None or (st1.st_size, st1.st_mtime_ns) != (st0.st_size, st0.st_mtime_ns):
        shutil.rmtree(final, ignore_errors=True)   # 만드는 동안 캐시가 바뀌었다 — 이 색인은 버린다
        return False
    manifest = {
        "format": INDEX_FORMAT, "key_scheme": KEY_SCHEME, "source_id": source_id,
        "source_sha256": entry.sha256, "file_size": st0.st_size, "file_mtime_ns": st0.st_mtime_ns,
        "dir": folder, "shards": shards,
        "meta": {"schema_version": entry.schema_version, "fetched_at": entry.fetched_at, "url": entry.url,
                 "item_count": entry.item_count, "ecosystems": entry.ecosystems},
    }
    tmp = root / f".manifest.{os.getpid()}.tmp"
    try:
        tmp.write_text(json.dumps(manifest, ensure_ascii=True), encoding="utf-8")
        replace_with_retry(tmp, root / "manifest.json")
    except OSError:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        shutil.rmtree(final, ignore_errors=True)
        return False
    _cleanup_old(root, keep=folder)
    return True


def _cleanup_old(root: Path, keep: str) -> None:
    """옛 색인 폴더를 지운다 — 다른 프로세스가 읽는 중이면 남겨 둔다(다음에 지운다)."""
    try:
        children = list(root.iterdir())
    except OSError:
        return
    now = time.time()
    for child in children:
        if not child.is_dir() or child.name == keep:
            continue
        if child.name.startswith("."):
            # 다른 프로세스가 지금 만드는 중일 수 있다 — 한 시간 넘게 남은 임시 폴더만 지운다.
            try:
                if now - child.stat().st_mtime < 3600:
                    continue
            except OSError:
                continue
        shutil.rmtree(child, ignore_errors=True)


def build_all(cache: IntelCache, sources: list[str] | None = None) -> list[str]:
    """반입·갱신 뒤 호출 — 색인을 만든 소스 이름들. 실패한 소스는 조용히 건너뛴다(검사는 전체 로딩으로 된다)."""
    built: list[str] = []
    for source_id in sources or list(INDEXED_SOURCES):
        if source_id not in INDEXED_SOURCES:
            continue
        try:
            if build(cache, source_id):
                built.append(source_id)
        except Exception:  # noqa: BLE001 — 색인은 편의 장치다
            continue
    return built
