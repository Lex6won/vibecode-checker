"""폐쇄망 패키지 레지스트리 정보 번들 (A13 · 결정 D16 ①, 2026-11-16).

무엇이 문제였나: 폐쇄망 서버의 로컬 검사는 공식 저장소에 물을 수 없어 **실재·발행일(쿨다운)·라이선스·설치 스크립트·
deprecated** 를 영영 모른다. 그래서 깨끗한 패키지도 늘 '확인 필요'였고(오탐성 검토 부담), 존재하지 않는 이름(AI 가 지어낸
패키지)은 '악성 피드에 없음'으로만 보였다(미탐 위험).

흐름(위협정보 번들과 같은 길):
1. 서버(포털)가 관측한 패키지 목록을 요청 파일로 내보낸다 — 생태계·이름·버전만(부서·프로젝트·경로 없음).
2. 외부망 PC 가 ``gvskb registry-meta collect`` 로 공식 저장소(pypi.org·registry.npmjs.org)에서 정보를 모아
   서명 번들을 만든다(기관 키 — ``gvskb intel-bundle keygen``, 공개키는 서버의 ``GVSKB_INTEL_TRUSTED_KEYS``).
3. 서버가 ``gvskb registry-meta import`` 로 검증·반입한다(서명 정책은 위협정보와 같다: 서명이 있으면 맞아야 하고,
   ``GVSKB_INTEL_REQUIRE_SIGNATURE=1`` 이면 서명 없는 번들은 거부).
4. 로컬 검사가 번들 정보로 온라인 검사와 같은 판정을 더한다. 번들에 없는 패키지는 「확인 필요(다음 반입)」로 남는다.

판정 원칙: 번들 정보는 **악성·취약점 판정을 지우지 못한다**(위협정보 판정 뒤에 덧붙이기만 한다). 바꿀 수 있는 것은
'확인 필요'를 확정으로 바꾸거나(실재·발행일 확인), 새 사유(미존재·쿨다운·버전 없음)를 더하는 것뿐이다.
"""
from __future__ import annotations

import asyncio
import hashlib
import io
import json
import os
import re
import zipfile
import zlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..intel.cache import IntelCache, default_cache_dir
from ..intel.signing import SIG_MEMBER, sign_manifest, signature_required, verify_manifest
from ..schema import PackageRegistryMetadata

REQUEST_SCHEMA = "gvskb-registry-meta-request/1"
BUNDLE_SCHEMA = "gvskb-registry-meta-bundle/1"
MANIFEST_NAME = "manifest.json"
DATA_NAME = "registry-meta.json"
SOURCE_ID = "registry-meta"
#: 캐시는 위협정보 폴더의 **하위 폴더**에 둔다 — 같은 폴더면 위협정보 소스 목록(신선도·상태 화면)에 섞인다.
CACHE_SUBDIR = "registry-meta"
SUPPORTED = ("npm", "pypi")
MAX_PACKAGES = 20000
MAX_VERSIONS_PER_PACKAGE = 50
MAX_NAME_LEN = 214                       # npm 이름 상한
MAX_VERSION_LEN = 128
MAX_DATA_BYTES = 200 * 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024
MAX_SIG_BYTES = 16 * 1024
ENV_MAX_AGE = "GVSKB_REGISTRY_META_MAX_AGE_DAYS"
DEFAULT_MAX_AGE_DAYS = 30
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")


class RegistryMetaError(ValueError):
    """요청·번들을 받을 수 없다. 사유는 사람이 읽을 문장이다."""


def max_age_days() -> int:
    raw = os.environ.get(ENV_MAX_AGE, "").strip()
    try:
        return max(1, int(raw)) if raw else DEFAULT_MAX_AGE_DAYS
    except ValueError:
        return DEFAULT_MAX_AGE_DAYS


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


def _parse_iso(value: object) -> datetime | None:
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def norm_name(ecosystem: str, name: str) -> str:
    """조회 키의 이름 — PyPI 는 PEP 503, npm 은 소문자(레지스트리가 대소문자를 구분하지 않게 받는다)."""
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", name).strip("-").lower()
    return name.lower()


def _key(ecosystem: str, name: str, version: str | None) -> str:
    return f"{ecosystem}\x00{norm_name(ecosystem, name)}\x00{version or ''}"


def _valid_name(name: object) -> bool:
    return isinstance(name, str) and 0 < len(name) <= MAX_NAME_LEN and not _CTRL_RE.search(name) and name.strip() == name


def _valid_version(version: object) -> bool:
    return isinstance(version, str) and 0 < len(version) <= MAX_VERSION_LEN and not _CTRL_RE.search(version) \
        and version.strip() == version


# ---------------------------------------------------------------- 1. 요청 파일

def parse_request(text: str) -> list[tuple[str, str, str | None]]:
    """요청 파일 → ``[(생태계, 이름, 버전|None)]``. 형식이 틀린 항목은 버리지 않고 오류로 알린다."""
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RegistryMetaError(f"요청 파일을 JSON 으로 읽지 못했습니다({exc.lineno}행): {exc.msg}") from exc
    if not isinstance(doc, dict) or doc.get("schema") != REQUEST_SCHEMA:
        raise RegistryMetaError(f"요청 파일 형식이 아닙니다 — schema 가 {REQUEST_SCHEMA!r} 이어야 합니다.")
    rows = doc.get("packages")
    if not isinstance(rows, list):
        raise RegistryMetaError("요청 파일에 packages 목록이 없습니다.")
    out: list[tuple[str, str, str | None]] = []
    seen: set[str] = set()
    bad: list[str] = []
    for i, row in enumerate(rows):
        if not isinstance(row, dict):
            bad.append(f"{i}번째 항목이 객체가 아닙니다")
            continue
        eco = str(row.get("ecosystem") or "").lower()
        name = row.get("name")
        if eco not in SUPPORTED or not _valid_name(name):
            bad.append(f"{i}번째 항목의 생태계·이름이 올바르지 않습니다")
            continue
        versions = row.get("versions") or []
        if not isinstance(versions, list):
            bad.append(f"{name}: versions 가 목록이 아닙니다")
            continue
        wanted: list[str | None] = [v for v in versions[:MAX_VERSIONS_PER_PACKAGE] if _valid_version(v)] or [None]
        for version in wanted:
            k = _key(eco, str(name), version)
            if k not in seen:
                seen.add(k)
                out.append((eco, str(name), version))
    if bad:
        raise RegistryMetaError("요청 파일에 올바르지 않은 항목이 있습니다: " + "; ".join(bad[:5])
                                + (f" 외 {len(bad) - 5}건" if len(bad) > 5 else ""))
    if len(out) > MAX_PACKAGES:
        raise RegistryMetaError(f"요청이 너무 큽니다({len(out):,}건, 상한 {MAX_PACKAGES:,}) — 나눠서 수집하세요.")
    return out


def build_request(packages: list[dict]) -> dict:
    """포털·시험용 — ``[{ecosystem, name, versions}]`` → 요청 문서. 생태계·이름·버전 외의 키는 싣지 않는다(허용목록)."""
    rows = []
    for p in packages:
        eco = str(p.get("ecosystem") or "").lower()
        name = p.get("name") or p.get("package_name")
        if eco in SUPPORTED and _valid_name(name):
            rows.append({"ecosystem": eco, "name": name,
                         "versions": [v for v in (p.get("versions") or []) if _valid_version(v)][:MAX_VERSIONS_PER_PACKAGE]})
    return {"schema": REQUEST_SCHEMA, "created_at": _iso(_now()), "packages": rows}


# ---------------------------------------------------------------- 2. 외부망 수집

async def collect(
    entries: list[tuple[str, str, str | None]], *, concurrency: int = 8, timeout: float = 15.0,
    fetch=None, progress=None,
) -> tuple[list[dict], list[dict]]:
    """공식 저장소에서 정보를 모은다 → (수집된 행, 실패한 행). 조회 실패(실재 미확인)는 번들에 넣지 않는다."""
    if fetch is None:
        from .package_metadata import fetch_registry_metadata as fetch
    sem = asyncio.Semaphore(max(1, concurrency))
    rows: list[dict] = []
    failed: list[dict] = []
    done = 0

    async def one(eco: str, name: str, version: str | None) -> None:
        nonlocal done
        async with sem:
            meta: PackageRegistryMetadata = await fetch(name, eco, version=version, timeout=timeout)
        done += 1
        if progress:
            progress(done, len(entries))
        if meta.exists is None:
            failed.append({"ecosystem": eco, "name": name, "version": version, "error": meta.error or "조회 실패"})
            return
        rows.append({"ecosystem": eco, "name": name, "version": version, "collected_at": meta.fetched_at or _iso(_now()),
                     "meta": meta.model_dump(mode="json")})

    await asyncio.gather(*(one(*e) for e in entries))
    rows.sort(key=lambda r: _key(r["ecosystem"], r["name"], r["version"]))
    failed.sort(key=lambda r: _key(r["ecosystem"], r["name"], r["version"]))
    return rows, failed


def export_bundle(rows: list[dict], out_path: str | Path, *, sign_seed: bytes | None = None,
                  key_id: str | None = None, failed: list[dict] | None = None) -> dict:
    """수집 결과 → 번들 zip(+ ``.sha256``). 서명 키가 있으면 manifest 에 서명한다."""
    data = json.dumps({"schema": BUNDLE_SCHEMA, "items": rows}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    manifest = {
        "schema": BUNDLE_SCHEMA,
        "created_at": _iso(_now()),
        "tool": "vibecode-checker registry-meta",
        "item_count": len(rows),
        "failed_count": len(failed or []),
        "files": {DATA_NAME: {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}},
    }
    manifest_bytes = json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    signed_key = None
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(MANIFEST_NAME, manifest_bytes)
        zf.writestr(DATA_NAME, data)
        if sign_seed is not None:
            sig = sign_manifest(manifest_bytes, sign_seed, key_id)
            zf.writestr(SIG_MEMBER, json.dumps(sig, ensure_ascii=False, indent=2))
            signed_key = sig["key_id"]
    digest = hashlib.sha256(out.read_bytes()).hexdigest()
    sidecar = out.with_name(out.name + ".sha256")
    sidecar.write_text(f"{digest}  {out.name}\n", encoding="utf-8")
    return {"ok": True, "bundle": str(out), "sha256": digest, "item_count": len(rows),
            "failed_count": len(failed or []), "signed": sign_seed is not None, "key_id": signed_key}


# ---------------------------------------------------------------- 3. 서버 반입

def _cache(cache_dir: Path | None = None) -> IntelCache:
    return IntelCache((cache_dir or default_cache_dir()) / CACHE_SUBDIR)


def _read_member(zf: zipfile.ZipFile, name: str, limit: int) -> bytes:
    info = zf.getinfo(name)
    if info.file_size > limit:
        raise RegistryMetaError(f"번들 안 '{name}' 가 너무 큽니다({info.file_size:,}B, 상한 {limit:,}B).")
    with zf.open(info) as fh:
        data = fh.read(limit + 1)
    if len(data) > limit:
        raise RegistryMetaError(f"번들 안 '{name}' 가 선언보다 큽니다 — 손상·조작 의심.")
    return data


def _validate_row(row: object, now: datetime) -> dict | None:
    if not isinstance(row, dict):
        return None
    eco = row.get("ecosystem")
    name = row.get("name")
    version = row.get("version")
    if eco not in SUPPORTED or not _valid_name(name) or not (version is None or _valid_version(version)):
        return None
    collected = _parse_iso(row.get("collected_at"))
    if collected is None:
        return None
    if collected > now + timedelta(days=1):
        collected = now                      # 미래 시각은 반입 시각으로 낮춘다(오래된 정보가 새것으로 보이지 않게)
    try:
        meta = PackageRegistryMetadata.model_validate(row.get("meta"))
    except Exception:  # noqa: BLE001 — 형식이 틀린 행은 받지 않는다
        return None
    if meta.exists is None:
        return None
    return {"ecosystem": eco, "name": name, "version": version, "collected_at": _iso(collected),
            "meta": meta.model_dump(mode="json")}


def import_bundle(zip_path: str | Path, *, cache_dir: Path | None = None, verify_only: bool = False) -> dict:
    """번들을 검증하고(서명·manifest 해시·행 형식) 서버 캐시에 합친다. 같은 패키지·버전은 더 최근 수집이 이긴다."""
    p = Path(zip_path)
    try:
        zf = zipfile.ZipFile(p)
    except (OSError, zipfile.BadZipFile) as exc:
        return {"ok": False, "error": f"번들을 열지 못했습니다: {exc}"}
    try:
        with zf:
            names = set(zf.namelist())
            allowed = {MANIFEST_NAME, DATA_NAME, SIG_MEMBER}
            extra = sorted(names - allowed)
            if extra or not {MANIFEST_NAME, DATA_NAME} <= names:
                return {"ok": False, "error": f"레지스트리 정보 번들 형식이 아닙니다(예상 밖 항목: {extra[:3]} / 필수 항목 누락)."}
            manifest_bytes = _read_member(zf, MANIFEST_NAME, MAX_MANIFEST_BYTES)
            signed, key_id = False, None
            if SIG_MEMBER in names:
                try:
                    sig_doc = json.loads(_read_member(zf, SIG_MEMBER, MAX_SIG_BYTES).decode("utf-8"))
                except (ValueError, UnicodeDecodeError):
                    return {"ok": False, "error": "서명 문서가 손상됐습니다 — 반입하지 않습니다."}
                ok, why = verify_manifest(manifest_bytes, sig_doc)
                if not ok:
                    return {"ok": False, "error": f"번들 서명 검증 실패 — {why}. 위조·변조 의심으로 반입하지 않습니다."}
                signed, key_id = True, why
            elif signature_required():
                return {"ok": False, "error": "서명 없는 번들 — GVSKB_INTEL_REQUIRE_SIGNATURE=1 정책에 따라 거부합니다. "
                                              "기관 키로 서명해(`--sign-key-env`) 다시 만드세요."}
            try:
                manifest = json.loads(manifest_bytes.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                return {"ok": False, "error": "manifest 를 읽지 못했습니다."}
            if not isinstance(manifest, dict) or manifest.get("schema") != BUNDLE_SCHEMA:
                return {"ok": False, "error": f"번들 형식이 다릅니다(schema {manifest.get('schema') if isinstance(manifest, dict) else '?'})."}
            expect = (manifest.get("files") or {}).get(DATA_NAME) or {}
            data = _read_member(zf, DATA_NAME, MAX_DATA_BYTES)
            if hashlib.sha256(data).hexdigest() != expect.get("sha256"):
                return {"ok": False, "error": "번들 내용이 manifest 해시와 다릅니다 — 손상·변조 의심으로 반입하지 않습니다."}
    except RegistryMetaError as exc:
        return {"ok": False, "error": str(exc)}
    except (zipfile.BadZipFile, zlib.error, EOFError, KeyError, OSError, RuntimeError) as exc:
        return {"ok": False, "error": f"번들을 읽다가 실패했습니다: {exc}"}

    try:
        doc = json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return {"ok": False, "error": "번들 내용을 JSON 으로 읽지 못했습니다."}
    if not isinstance(doc, dict) or doc.get("schema") != BUNDLE_SCHEMA or not isinstance(doc.get("items"), list):
        return {"ok": False, "error": "번들 내용 형식이 다릅니다."}
    now = _now()
    incoming: dict[str, dict] = {}
    rejected = 0
    for raw in doc["items"]:
        row = _validate_row(raw, now)
        if row is None:
            rejected += 1
            continue
        incoming[_key(row["ecosystem"], row["name"], row["version"])] = row
    if len(incoming) > MAX_PACKAGES * MAX_VERSIONS_PER_PACKAGE:
        return {"ok": False, "error": "번들 항목이 비정상적으로 많습니다 — 반입하지 않습니다."}
    result = {"ok": True, "signed": signed, "key_id": key_id, "item_count": len(incoming), "rejected_rows": rejected,
              "created_at": manifest.get("created_at"), "verify_only": verify_only}
    if not signed:
        result["warning"] = "서명 없는 번들을 받았습니다(정책 미설정). 운영 서버는 GVSKB_INTEL_REQUIRE_SIGNATURE=1 을 권장합니다."
    if verify_only:
        return result

    cache = _cache(cache_dir)
    existing = cache.load(SOURCE_ID)
    merged: dict[str, dict] = {}
    for row in (existing.items if existing else []):
        if isinstance(row, dict) and row.get("ecosystem") in SUPPORTED and row.get("name"):
            merged[_key(row["ecosystem"], row["name"], row.get("version"))] = row
    replaced = added = kept_newer = 0
    for k, row in incoming.items():
        old = merged.get(k)
        if old is None:
            added += 1
        elif (_parse_iso(old.get("collected_at")) or datetime.min.replace(tzinfo=timezone.utc)) > _parse_iso(row["collected_at"]):
            kept_newer += 1                  # 이미 더 최근 정보가 있다 — 옛 번들이 덮지 않게
            continue
        else:
            replaced += 1
        merged[k] = row
    items = [merged[k] for k in sorted(merged)]
    try:
        cache.save(SOURCE_ID, f"bundle:{p.name}", items)
    except OSError as exc:
        return {"ok": False, "error": f"서버 캐시에 쓰지 못했습니다: {exc}"}
    _INDEX_MEMO.clear()
    result.update(added=added, replaced=replaced, kept_newer=kept_newer, total=len(items),
                  cache_dir=str(cache.cache_dir))
    return result


# ---------------------------------------------------------------- 4. 로컬 검사에서 조회

_INDEX_MEMO: dict[str, dict] = {}


def _index(cache_dir: Path | None = None) -> tuple[dict | None, str | None]:
    cache = _cache(cache_dir)
    entry = cache.load(SOURCE_ID)
    if entry is None:
        return None, None
    hit = _INDEX_MEMO.get(entry.sha256)
    if hit is None:
        rows: dict[str, dict] = {}
        absent: dict[str, dict] = {}         # 이름 자체가 저장소에 없다는 행 — 버전과 무관하게 적용
        for row in entry.items:
            if isinstance(row, dict) and row.get("ecosystem") in SUPPORTED and row.get("name"):
                rows[_key(row["ecosystem"], row["name"], row.get("version"))] = row
                if (row.get("meta") or {}).get("exists") is False:
                    absent[_key(row["ecosystem"], row["name"], None)] = row
        hit = {"rows": rows, "absent": absent}
        _INDEX_MEMO.clear()
        _INDEX_MEMO[entry.sha256] = hit
    return hit, entry.fetched_at


def _age(iso: str | None, now: datetime) -> int | None:
    dt = _parse_iso(iso) if iso else None
    return None if dt is None else max(0, (now - dt).days)


def lookup(ecosystem: str, name: str, version: str | None, *, cache_dir: Path | None = None) -> tuple[PackageRegistryMetadata | None, dict]:
    """(정보, 상태). 상태 ``state``: absent(번들을 받은 적 없음) · missing(이 패키지·버전 없음) · stale(기준일 초과) · hit.

    - 버전이 있으면 그 버전의 행만 쓴다 — 다른 버전의 라이선스·발행일을 빌려 쓰지 않는다.
    - 패키지가 **없다**(exists=False)는 행은 버전과 무관하게 적용한다(이름 자체가 저장소에 없음).
    - 경과일(쿨다운·신생)은 수집 시점 값이 아니라 **지금** 기준으로 다시 계산한다.
    """
    eco = ecosystem.lower()
    index, imported_at = _index(cache_dir)
    if index is None:
        return None, {"state": "absent"}
    now = _now()
    row = index["rows"].get(_key(eco, name, version))
    if row is None:
        # 이름 자체가 없다는 수집 결과는 버전과 상관없다.
        row = index["absent"].get(_key(eco, name, None))
    if row is None:
        return None, {"state": "missing", "imported_at": imported_at}
    collected_age = _age(row.get("collected_at"), now)
    info = {"state": "hit", "collected_at": row.get("collected_at"), "imported_at": imported_at,
            "collected_age_days": collected_age, "max_age_days": max_age_days()}
    if collected_age is None or collected_age > max_age_days():
        info["state"] = "stale"
        return None, info
    meta = PackageRegistryMetadata.model_validate(row["meta"])
    if meta.version_published_at:
        meta.version_age_days = _age(meta.version_published_at, now)
    if meta.first_published_at:
        meta.package_age_days = _age(meta.first_published_at, now)
    meta.source = f"registry-meta bundle ({meta.source or 'registry'}, 수집 {str(row.get('collected_at'))[:10]})"
    return meta, info


def status(cache_dir: Path | None = None) -> dict:
    """상태 화면용 — 받은 적 있는지, 몇 건, 마지막 반입·가장 오래된 수집."""
    cache = _cache(cache_dir)
    entry = cache.load(SOURCE_ID)
    if entry is None:
        return {"state": "absent", "item_count": 0}
    collected = [_parse_iso(r.get("collected_at")) for r in entry.items if isinstance(r, dict)]
    collected = [c for c in collected if c]
    now = _now()
    limit = max_age_days()
    stale = sum(1 for c in collected if (now - c).days > limit)
    return {"state": "ok", "item_count": entry.item_count, "imported_at": entry.fetched_at,
            "oldest_collected_at": _iso(min(collected)) if collected else None,
            "newest_collected_at": _iso(max(collected)) if collected else None,
            "stale_count": stale, "max_age_days": limit}


def request_from_bytes(data: bytes) -> list[tuple[str, str, str | None]]:
    return parse_request(io.TextIOWrapper(io.BytesIO(data), encoding="utf-8-sig").read())
