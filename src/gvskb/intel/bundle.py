"""인텔 캐시 반입 번들 — 망분리 USB 이동을 검증 가능한 절차로.

기존 안내("캐시 폴더를 복사해 옮기세요")는 이동 중 변조·손상을 확인할 방법이
없었다. 번들은 단일 zip 안에 캐시 파일들과 ``manifest.json``(파일별 sha256)을
함께 담아, 반입(import) 시:

1. manifest의 파일별 sha256을 재계산해 **전수 검증**하고,
2. 하나라도 불일치·누락이면 **전체 거부**한다(부분 반입 금지 — 원자성),
3. 통과한 경우에만 캐시 디렉터리에 복사한다.

로드 계층의 envelope sha256 재검증(intel/cache.py)과 이중 방어를 이룬다.

절차::

    (외부망 PC)  gvskb update-intel --all
                 gvskb intel-bundle export 반입.zip
    (매체 이동)  반입.zip → USB → 망분리 PC
    (망분리 PC)  gvskb intel-bundle import 반입.zip
                 gvskb doctor --offline     # 캐시 존재·신선도 확인
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import zipfile
import zlib
from datetime import datetime, timezone
from pathlib import Path

from .cache import (
    IntelCache,
    cleanup_stale_temp_files,
    default_cache_dir,
    ecosystem_counts,
    entry_items_sha256,
    replace_with_retry,
    write_verified_stamp,
)
from .signing import SIG_MEMBER, sign_manifest, signature_required, verify_manifest

MANIFEST_NAME = "manifest.json"
#: 서명·manifest 는 작다. 읽기 **전에** 크기를 본다 — 공유 폴더 쓰기 권한자가 수 GB 로 부풀린
#: 멤버를 놓으면 서명 검증 이전에 각 PC 가 메모리로 전부 읽어 멈춘다(검증 지적 MEDIUM-6).
MAX_SIG_BYTES = 64 * 1024
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
_CACHES_PREFIX = "caches/"
BUNDLE_FORMAT_VERSION = 1


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


#: 캐시 파일 하나의 상한. OSV 악성 목록 전체가 수 MB 이므로 넉넉하되, 압축 폭탄으로
#: 메모리를 채우는 번들은 거절한다.
MAX_MEMBER_BYTES = 200 * 1024 * 1024

_SAFE_MEMBER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,200}$")

# ---------------------------------------------------------------------------
# 축소 방지 — 서명·해시가 맞아도 **내용이 비거나 크게 줄어든** 번들은 받지 않는다.
#
# 서명은 "누가 만들었나"만 말한다. 공개 파이프라인이 수집 중 잘린 목록(OSV 응답 일부, 빈 KEV)을
# 서명해 내보내면 모든 PC 가 그것을 받아 악성 판정이 '깨끗함'으로 뒤집힌다(2026-11-07 적대적 검증:
# 빈 번들 반입으로 chalk 5.6.1 악성 → 판정 없음). 아래 소스는 **누적 목록**이라 하루 사이에 크게
# 줄 이유가 없다 — 줄면 수집 사고로 보고 기존 캐시를 지킨다. 기관이 의도적으로 줄일 때는
# ``--allow-shrink`` 또는 ``GVSKB_INTEL_ALLOW_SHRINK=1``.
# ---------------------------------------------------------------------------
SHRINK_GUARDED_SOURCES = ("osv-malicious", "cisa-kev", "osv-vulns")
#: 새 항목 수가 기존의 이 비율 미만이면 거부한다.
MIN_KEEP_RATIO = 0.8
ENV_ALLOW_SHRINK = "GVSKB_INTEL_ALLOW_SHRINK"
#: 생태계별 비교는 기존 건수가 이 이상일 때만 — 몇 건짜리 생태계의 자연 변동으로 막지 않는다.
MIN_ECOSYSTEM_BASELINE = 500
#: 서명된 manifest 에만 효력이 있는 '의도한 축소' 표시(배포 파이프라인 수동 실행으로만 켠다).
MANIFEST_ALLOW_SHRINK = "allow_shrink"

# 기준선 신뢰 규칙(2026-11-08 적대적 검증 HIGH-1):
# 축소·'더 오래됨' 검사의 기준선이 **서명 없는** 반입이나 직접 수집에서 왔다면, 서명된 번들은 그 기준선에
# 묶이지 않고 덮어쓴다. 그러지 않으면 서명 없는 오염 번들 한 번(생태계를 부풀리거나 항목을 늘리거나 미래 시각)이
# 이후 모든 공식 번들을 거부하게 만들어 오염이 고정된다. 서명 없는 번들은 어떤 기준선에도 묶인다.
#: 기존 캐시의 수집 시각이 이보다 미래면(시계 오류·위조) 믿지 않는다 — 기준선으로 쓰지 않는다.
#: 공식 번들 시각은 GitHub 실행기 시계라 정확하다. 길게 두면 미래 시각을 적은 번들이 그만큼 공식 번들을 가린다.
_FUTURE_SKEW_SECONDS = 3600

# 정체 상한(2026-11-08 2차 적대적 검증): 축소 거부는 **그 소스만** 건너뛰고, 기준선이 신선할 때(intel_max_age_days
# 이내)만 적용한다. 그래야 '의도한 축소' 표시를 놓친 PC·스탬프를 위조당한 PC 도 최대 그 기간 뒤에는 새 서명
# 데이터를 받는다 — 그 사이 캐시는 '낡음'으로 정직하게 표시된다. 번들 전체를 영구히 거부하면 KEV·NVD 까지 멈췄다.


def _allow_shrink_env() -> bool:
    return os.environ.get(ENV_ALLOW_SHRINK, "").strip().lower() in {"1", "true", "yes", "on"}


def _parse_time(raw: object) -> datetime | None:
    try:
        ts = datetime.fromisoformat(str(raw))
    except (TypeError, ValueError):
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def _inspect_envelope(fname: str, data: bytes) -> tuple[dict | None, str]:
    """번들 안 캐시 파일이 **로드 계층이 받아들일 envelope** 인지 반입 전에 확인한다.

    예전에는 바이트를 그대로 썼다 — 해시가 틀린 envelope 은 로드 때 무시되어 '캐시 없음'이 됐고,
    빈 items 는 그대로 '깨끗함'이 됐다. 지금은 쓰기 전에 거른다.
    반환: (정보, 오류). 정보 = {source_id, item_count, fetched_at, ecosystems, sha256}.
    """
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, f"'{fname}' 이 JSON 캐시 형식이 아닙니다"
    if not isinstance(doc, dict) or not isinstance(doc.get("items"), list):
        return None, f"'{fname}' 에 항목 목록(items)이 없습니다"
    sid = fname[:-5] if fname.endswith(".json") else fname
    if str(doc.get("source_id", "")) != sid:
        return None, f"'{fname}' 의 source_id({doc.get('source_id')!r})가 파일명과 다릅니다"
    items = doc["items"]
    recorded = str(doc.get("sha256", "") or "")
    if not recorded or entry_items_sha256(items) != recorded:
        return None, f"'{fname}' 의 내용 해시(envelope sha256)가 맞지 않습니다"
    try:
        count = int(doc.get("item_count"))
    except (TypeError, ValueError):
        count = -1
    if count != len(items):
        return None, f"'{fname}' 의 item_count({doc.get('item_count')!r})가 실제 항목 수({len(items)})와 다릅니다"
    ecos = doc.get("ecosystems")
    return {
        "source_id": sid,
        "item_count": len(items),
        "fetched_at": str(doc.get("fetched_at", "") or ""),
        "ecosystems": [str(e) for e in ecos] if isinstance(ecos, list) else None,
        "sha256": recorded,
        "eco_counts": ecosystem_counts(items) if sid in SHRINK_GUARDED_SOURCES and sid.startswith("osv-") else None,
    }, ""


def _shrink_problem(new: dict, old: dict | None) -> str:
    """기존 캐시 대비 새 파일이 줄었으면 사유, 아니면 빈 문자열.

    ``old`` 는 ``IntelCache.guard_info`` — 수십 MB 본문을 다시 파싱하지 않고 머리·꼬리에서 읽은 값이다.
    캐시 폴더에 쓸 수 있는 사람은 어차피 캐시를 고칠 수 있으므로 이 값을 검증 없이 써도 방어 수준이 낮아지지 않는다.
    """
    sid = new["source_id"]
    if old is None or sid not in SHRINK_GUARDED_SOURCES:
        return ""
    old_ecos_raw = old.get("ecosystems")
    old_ecos = set(old_ecos_raw or [])
    new_ecos = set(new["ecosystems"] or [])
    if old_ecos_raw is not None and new["ecosystems"] is not None and not old_ecos <= new_ecos:
        lost = ", ".join(sorted(old_ecos - new_ecos))
        return f"'{sid}' 가 기존 캐시에 있던 생태계({lost})를 담고 있지 않습니다"
    old_count = int(old.get("item_count") or 0)
    if old_count > 0 and new["item_count"] == 0:
        return f"'{sid}' 가 비어 있습니다(기존 {old_count:,}건 → 0건)"
    if old_count > 0 and new["item_count"] < old_count * MIN_KEEP_RATIO:
        return (f"'{sid}' 항목이 크게 줄었습니다(기존 {old_count:,}건 → {new['item_count']:,}건, "
                f"{int(MIN_KEEP_RATIO * 100)}% 미만)")
    # 생태계별 — 전체 건수는 비슷한데 한 생태계만 잘린 경우(PyPI 악성 목록은 전체의 5% 남짓이라 전체 비율로는 안 잡힌다).
    # 비교는 **선언한 대조 생태계**(envelope 의 ecosystems, 예: PyPI·npm)만 — 취약점 목록에는 다른 생태계에
    # 함께 걸린 권고가 수십 건씩 딸려 오는데(실측 Packagist 50·crates.io 50), 그 자연 변동으로 번들 전체를 막으면
    # 모든 PC 의 위협정보가 낡는다.
    old_eco, new_eco = old.get("ecosystem_counts") or {}, new.get("eco_counts") or {}
    declared = set(old_ecos_raw or []) & set(new["ecosystems"] or [])
    if old_eco and new.get("eco_counts") is not None and declared:
        for eco, before in sorted(old_eco.items()):
            if eco not in declared:
                continue
            try:
                before = int(before)
            except (TypeError, ValueError):
                continue
            after = int(new_eco.get(eco, 0))
            if before >= MIN_ECOSYSTEM_BASELINE and after < before * MIN_KEEP_RATIO:
                return (f"'{sid}' 의 {eco} 항목이 크게 줄었습니다(기존 {before:,}건 → {after:,}건, "
                        f"{int(MIN_KEEP_RATIO * 100)}% 미만)")
    return ""


def _is_future(ts: datetime | None) -> bool:
    return ts is not None and (ts - datetime.now(timezone.utc)).total_seconds() > _FUTURE_SKEW_SECONDS


def _trusted_baseline_time(old: dict | None) -> datetime | None:
    """기준선 시각 — 수집 시각과 **이 PC 에 들어온 시각** 중 이른 쪽. 읽을 수 없거나 허용 오차 넘게 미래면 None.

    들어온 시각을 함께 보는 이유(3차 적대적 검증 HIGH-1): 서명 없는 번들이 수집 시각을 '조금 미래'로 적으면,
    그 뒤 들어오는 공식 서명 번들이 '더 오래됨'으로 건너뛰어져 오염이 가려졌다. 들어온 시각은 반입하는 PC 가
    기록하므로 번들이 꾸밀 수 없다.
    """
    if old is None:
        return None
    candidates = [ts for ts in (_parse_time(old.get("fetched_at")), _parse_time(old.get("imported_at")))
                  if ts is not None and not _is_future(ts)]
    # 수집 시각이 미래로 보이면(시계가 느린 PC 에 들어온 서명 번들) 반입 시각만 쓴다 — 기준선을 버리면 되돌리기 방어가 빠진다.
    return min(candidates) if candidates else None


def _strict_shrink() -> bool:
    """배포 파이프라인의 게시 전 재검증용 — 기준선이 낡아도 축소 검사를 한다(GVSKB_INTEL_STRICT_SHRINK=1).

    소비 PC 에서는 정체 상한 때문에 낡은 기준선으로는 막지 않지만, 게시하는 쪽까지 그러면 수집 사고가
    며칠 이어져 직전 번들이 낡는 순간 잘린 목록이 그대로 게시됐다(3차 적대적 검증 MEDIUM-3).
    """
    return os.environ.get("GVSKB_INTEL_STRICT_SHRINK", "").strip().lower() in {"1", "true", "yes", "on"}


def _age_is_fresh(ts: datetime | None) -> bool:
    from .cache import intel_max_age_days

    if ts is None:
        return False
    return (datetime.now(timezone.utc) - ts).days <= intel_max_age_days()


def _baseline_is_fresh(old: dict | None) -> bool:
    """기준선이 신선한가(캐시 신선도 기준과 같음) — 낡은 기준선으로는 새 데이터를 막지 않는다(정체 상한)."""
    return _age_is_fresh(_trusted_baseline_time(old))


def _covers_more(new: dict, old: dict | None) -> bool:
    """새 파일이 기존보다 대조 생태계를 더 담는가 — 그렇다면 시각이 조금 이르더라도 받는다(예: 직접 받은
    PyPI 전용 캐시 위에 PyPI+npm 공식 번들). 대조 범위가 넓은 쪽이 정탐에 유리하다. 단 새 파일 자체가
    신선할 때만 — 생태계가 많은 옛 번들로 되돌리는 길이 되지 않게(3차 적대적 검증 MEDIUM-2)."""
    if old is None or new.get("ecosystems") is None or old.get("ecosystems") is None:
        return False
    return set(new["ecosystems"]) > set(old["ecosystems"]) and _age_is_fresh(_parse_time(new.get("fetched_at")))


def _is_older_than_cache(new: dict, old: dict | None) -> bool:
    """새 파일이 기존 캐시보다 오래된 수집본인가 — 옛 번들(서명됐더라도)이 최신 캐시를 덮어 새 악성 항목을
    잃지 않게. 서명 여부와 무관하게 적용한다(공개된 옛 서명 번들로 되돌리기 차단)."""
    old_ts = _trusted_baseline_time(old)
    new_ts = _parse_time(new["fetched_at"])
    if old_ts is None or new_ts is None:
        return False
    return new_ts < old_ts and not _covers_more(new, old)


def _is_safe_member_name(fname: str) -> bool:
    """단일 파일명(구분자·`..`·절대경로·숨김 파일 없음)만 허용한다."""
    if not fname or fname in {".", ".."}:
        return False
    if "/" in fname or "\\" in fname or ":" in fname:
        return False
    return _SAFE_MEMBER_RE.match(fname) is not None


def export_bundle(
    zip_path: str | Path,
    *,
    cache_dir: Path | None = None,
    sign_seed: bytes | None = None,
    key_id: str | None = None,
    allow_shrink: bool = False,
) -> dict:
    """현재 인텔 캐시 전체를 manifest(sha256) 포함 zip으로 내보낸다.

    ``allow_shrink`` 는 manifest 에 '의도한 축소' 표시를 넣는다 — **서명된** 번들에서만 효력이 있어,
    받는 PC 가 목록 축소 검사를 건너뛴다(수집 방식 변경·대량 철회 같은 정당한 축소용, 수동 실행 전용).

    ``sign_seed`` 를 주면 manifest 바이트에 Ed25519 서명을 붙인다(``manifest.sig``). 서명은
    위조를 막는 장치다 — sha256 은 손상만 잡는다(signing.py 참조).
    """
    cache = IntelCache(cache_dir)
    source_ids = cache.list_sources()
    if not source_ids:
        return {"ok": False, "error": "캐시가 비어 있습니다 — 먼저 `gvskb update-intel --all`을 실행하세요.",
                "sources": []}

    out = Path(zip_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    files: list[dict] = []
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for sid in source_ids:
            p = cache.path_for(sid)
            data = p.read_bytes()
            entry = cache.load(sid)  # envelope sha 재검증 포함 — 변조 캐시는 내보내지 않는다
            if entry is None:
                return {"ok": False, "sources": [],
                        "error": f"캐시 '{sid}' 무결성 검증 실패 — update-intel로 다시 받으세요."}
            files.append({
                "source_id": sid,
                "filename": f"{sid}.json",
                "sha256": _sha256_bytes(data),
                "size": len(data),
                "fetched_at": entry.fetched_at,
                "item_count": entry.item_count,
                "ecosystems": entry.ecosystems,
            })
            zf.writestr(_CACHES_PREFIX + f"{sid}.json", data)
        manifest = {
            "bundle_format": BUNDLE_FORMAT_VERSION,
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tool": "vibecode-checker intel-bundle",
            "files": files,
        }
        if allow_shrink:
            manifest[MANIFEST_ALLOW_SHRINK] = True
        manifest_bytes = json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")
        zf.writestr(MANIFEST_NAME, manifest_bytes)
        signed_key: str | None = None
        if sign_seed is not None:
            sig_doc = sign_manifest(manifest_bytes, sign_seed, key_id)
            zf.writestr(SIG_MEMBER, json.dumps(sig_doc, ensure_ascii=False, indent=2))
            signed_key = sig_doc["key_id"]
    return {"ok": True, "bundle": str(out), "sources": [f["source_id"] for f in files],
            "file_count": len(files), "signed": sign_seed is not None, "key_id": signed_key}


def _check_signature(
    zf: zipfile.ZipFile, manifest_bytes: bytes, *, require: bool = False,
) -> tuple[bool, bool, str | None, str]:
    """(통과, 서명 있음, key_id, 사유). 서명이 있으면 맞아야 하고, 없으면 정책에 따른다.

    ``require`` 는 호출자가 출처상 서명이 반드시 있어야 한다고 아는 경우(공식 릴리스 주소)다.
    """
    if SIG_MEMBER not in zf.namelist():
        if require:
            return (False, False, None,
                    "서명 없는 번들 — 공식 배포 주소(intel-latest)의 번들은 항상 서명돼 있어야 합니다. "
                    "위조·배포 사고 의심으로 반입하지 않습니다.")
        if signature_required():
            return (False, False, None,
                    "서명 없는 번들 — GVSKB_INTEL_REQUIRE_SIGNATURE=1 정책에 따라 거부합니다. "
                    "서명된 공식 번들(intel-latest)을 쓰거나 관리자 키로 서명해 배포하세요.")
        return True, False, None, "서명 없음(허용 — 정책 미설정)"
    try:
        info = zf.getinfo(SIG_MEMBER)
        if info.file_size > MAX_SIG_BYTES:
            return False, True, None, f"서명 문서(manifest.sig)가 비정상적으로 큽니다({info.file_size:,}B) — 반입 중단."
        sig_doc = json.loads(zf.read(SIG_MEMBER).decode("utf-8"))
    except (KeyError, json.JSONDecodeError, UnicodeDecodeError,
            zipfile.BadZipFile, zlib.error, EOFError, OSError, RuntimeError):
        return False, True, None, "서명 문서(manifest.sig)가 손상됐습니다 — 반입 중단."
    ok, why = verify_manifest(manifest_bytes, sig_doc)
    if not ok:
        return (False, True, None,
                f"번들 서명 검증 실패 — {why}. 위조·변조 의심으로 반입을 전체 중단합니다.")
    return True, True, why, f"서명 확인(key_id={why})"


def import_bundle(
    zip_path: str | Path,
    *,
    cache_dir: Path | None = None,
    verify_only: bool = False,
    require_signature: bool = False,
    allow_shrink: bool = False,
) -> dict:
    """번들을 전수 검증 후 캐시 디렉터리로 반입한다. 검증 실패 시 전체 거부.

    검증 순서: 서명(있으면 반드시 일치, 정책에 따라 필수) → manifest → 파일별 sha256 전수 →
    파일별 envelope(내용 해시·항목 수·source_id) → 기존 캐시 대비 축소 검사.
    기존 캐시보다 **오래된** 파일은 덮어쓰지 않고 건너뛴다(``skipped_older``).
    ``verify_only`` 면 기록하지 않고 결과만 돌려준다(``verify_bundle``) — 기존 캐시와 비교하지 않는다.
    """
    src = Path(zip_path)
    if not src.exists():
        return {"ok": False, "error": f"번들 파일이 없습니다: {src}", "sources": []}

    try:
        zf = zipfile.ZipFile(src)
    except zipfile.BadZipFile:
        return {"ok": False, "error": "zip 형식이 아니거나 손상된 번들입니다.", "sources": []}

    with zf:
        try:
            if zf.getinfo(MANIFEST_NAME).file_size > MAX_MANIFEST_BYTES:
                return {"ok": False, "sources": [],
                        "error": f"manifest.json 이 비정상적으로 큽니다(상한 {MAX_MANIFEST_BYTES:,}B) — 반입 중단."}
            manifest_bytes = zf.read(MANIFEST_NAME)
            manifest = json.loads(manifest_bytes.decode("utf-8"))
        except (KeyError, json.JSONDecodeError, UnicodeDecodeError,
                zipfile.BadZipFile, zlib.error, EOFError, OSError, RuntimeError):
            # manifest 자체가 손상된 경우(압축 스트림 오류 포함)도 예외를 흘리지 않고 거부한다.
            return {"ok": False, "error": "manifest.json이 없거나 손상됐습니다 — 정식 export 번들이 아닙니다.",
                    "sources": []}

        # 0단계: 서명 — 파일 해시보다 먼저 본다. 해시는 번들이 **스스로** 주장하는 값이라
        # 위조자가 함께 고칠 수 있고, 서명만이 "누가 만들었나"를 말한다.
        sig_ok, signed, key_id, sig_note = _check_signature(zf, manifest_bytes, require=require_signature)
        if not sig_ok:
            return {"ok": False, "error": sig_note, "sources": [], "signed": signed}

        files = manifest.get("files") if isinstance(manifest, dict) else None
        if not files or not isinstance(files, list) or not all(isinstance(f, dict) for f in files):
            return {"ok": False, "error": "manifest에 파일 목록이 없습니다.", "sources": []}

        # 1단계: 전수 검증 (하나라도 실패하면 아무것도 쓰지 않는다).
        # 파일 바이트는 들고 있지 않는다 — 기록 단계에서 zip 에서 다시 읽고 해시를 다시 맞춘다(메모리 정점 축소).
        verified: list[tuple[str, str, dict]] = []
        seen_names: set[str] = set()
        for f in files:
            fname = str(f.get("filename", ""))
            # manifest 의 파일명은 **신뢰하지 않는다** — `../../x` 를 넣은 번들이
            # 캐시 밖에 파일을 썼다(재점검 실측 2026-08-29, zip-slip). 이름은 단일
            # 세그먼트여야 하고, 최종 경로가 캐시 디렉터리 안이어야 한다.
            if not _is_safe_member_name(fname):
                return {"ok": False, "sources": [],
                        "error": f"번들 파일명이 허용 범위 밖입니다: {fname!r} — 경로 조작 의심. 반입 중단."}
            # 소문자 `.json` 만 — 윈도는 대소문자를 가리지 않아 `OSV-MALICIOUS.json` 이 `osv-malicious.json` 을
            # 덮어쓰면서 축소 검사(소문자 이름 기준)를 비껴갔다(2026-11-08 적대적 검증 MEDIUM-1).
            if fname != fname.lower() or not fname.endswith(".json"):
                return {"ok": False, "sources": [],
                        "error": f"번들 파일명은 소문자 '.json' 이어야 합니다: {fname!r} — 반입 중단."}
            if fname in seen_names:
                return {"ok": False, "sources": [],
                        "error": f"번들에 같은 파일이 두 번 있습니다: {fname!r} — 반입 중단."}
            seen_names.add(fname)
            member = _CACHES_PREFIX + fname
            try:
                info = zf.getinfo(member)
            except KeyError:
                return {"ok": False, "sources": [],
                        "error": f"번들에 '{fname}'이 없습니다(manifest와 불일치) — 반입 중단."}
            if info.file_size > MAX_MEMBER_BYTES:
                return {"ok": False, "sources": [],
                        "error": f"'{fname}' 크기 {info.file_size:,}B 가 상한({MAX_MEMBER_BYTES:,}B)을 넘습니다 — 반입 중단."}
            try:
                data = zf.read(member)
            except KeyError:
                return {"ok": False, "sources": [],
                        "error": f"번들에 '{fname}'이 없습니다(manifest와 불일치) — 반입 중단."}
            except (zipfile.BadZipFile, zlib.error, EOFError, OSError, RuntimeError) as exc:
                # 압축 스트림 손상(비트 뒤집힘 등)은 sha256 비교 이전에 zlib 에서 터진다.
                # 예외를 흘리면 자동 당김(autopull)이 서버 기동을 멈춘다 — 거부로 바꾼다.
                return {"ok": False, "sources": [],
                        "error": f"'{fname}' 압축 데이터 손상({type(exc).__name__}) — 이동 중 변조·손상 가능. 반입을 전체 중단합니다."}
            if _sha256_bytes(data) != f.get("sha256"):
                return {"ok": False, "sources": [],
                        "error": f"'{fname}' sha256 불일치 — 이동 중 변조·손상 가능. 반입을 전체 중단합니다."}
            info_doc, problem = _inspect_envelope(fname, data)
            del data
            if info_doc is not None and not signed and _is_future(_parse_time(info_doc["fetched_at"])):
                # 서명 없는 번들만 — 1시간 넘게 미래인 수집본은 위조·시계 오류로 본다. 서명된 번들은 GitHub 실행기
                # 시계를 믿는다: 시계가 느린 PC(NTP 없는 망분리 PC)가 정상 공식 번들을 '미래'로 보고 계속 거부하면
                # 갱신이 멈춘다(4차 적대적 검증).
                info_doc, problem = None, f"'{fname}' 의 수집 시각({info_doc['fetched_at']})이 미래입니다(서명 없는 번들)"
            if info_doc is None:
                return {"ok": False, "sources": [], "signed": signed,
                        "error": f"{problem} — 체커가 읽을 수 없는 캐시가 들어 있어 반입을 전체 중단합니다."}
            verified.append((fname, str(f.get("sha256")), info_doc))

        # 서명된 manifest 의 '의도한 축소' 표시 — 서명이 없으면 누구나 적을 수 있으므로 무시한다.
        rebaseline = bool(signed and isinstance(manifest, dict) and manifest.get(MANIFEST_ALLOW_SHRINK) is True)

        if verify_only:
            return {
                "ok": True, "sources": [doc["source_id"] for _, _, doc in verified], "file_count": len(verified),
                "created_at": manifest.get("created_at", ""), "signed": signed, "key_id": key_id,
                "signature": sig_note, "allow_shrink": rebaseline,
                "item_counts": {doc["source_id"]: doc["item_count"] for _, _, doc in verified},
            }

        # 2단계: 기존 캐시와 비교 — 축소는 전체 거부, 더 오래된 파일은 건너뛴다.
        target = cache_dir or default_cache_dir()
        existing = IntelCache(target)
        shrink_ok = allow_shrink or _allow_shrink_env() or rebaseline
        to_write: list[tuple[str, str, dict]] = []
        skipped_older: list[str] = []
        rejected: list[dict] = []
        accepted_stale: list[str] = []
        strict = _strict_shrink()
        for fname, digest, doc in verified:
            old = existing.guard_info(doc["source_id"])
            if _is_older_than_cache(doc, old):
                skipped_older.append(doc["source_id"])
                continue
            # 서명 번들은 서명된 기준선에만 묶인다(위 '기준선 신뢰 규칙'). 낡은 기준선은 막지 않는다('정체 상한') —
            # 단 게시 전 재검증(엄격 모드)은 낡아도 막는다.
            trusted = old is not None and (not signed or bool(old.get("signed_key")))
            if trusted and not shrink_ok:
                problem = _shrink_problem(doc, old)
                if problem and (strict or _baseline_is_fresh(old)):
                    rejected.append({"source": doc["source_id"], "reason": problem})
                    continue
                if problem:
                    accepted_stale.append(f"{problem}(기존 캐시가 낡아 받아들임)")
            to_write.append((fname, digest, doc))

        # 3단계: 전부 통과한 경우에만 기록. 임시파일을 **모두** 먼저 쓴 뒤 연달아 교체한다 —
        # 교체 사이 간격이 짧을수록 다른 프로세스가 소스별로 다른 판을 섞어 읽을 틈이 줄어든다.
        target.mkdir(parents=True, exist_ok=True)
        target_resolved = target.resolve()
        cleanup_stale_temp_files(target)
        staged: list[tuple[Path, Path, dict]] = []
        def _discard_staged() -> None:
            for tmp, _, _ in staged:
                try:
                    tmp.unlink(missing_ok=True)
                except OSError:
                    pass

        try:
            for fname, digest, doc in to_write:
                dest = (target / fname)
                if dest.resolve().parent != target_resolved:
                    _discard_staged()
                    return {"ok": False, "sources": [],
                            "error": f"'{fname}' 의 기록 경로가 캐시 디렉터리를 벗어납니다 — 반입 중단."}
                data = zf.read(_CACHES_PREFIX + fname)
                if _sha256_bytes(data) != digest:  # 검증 뒤 zip 이 바뀐 경우까지 막는다
                    _discard_staged()
                    return {"ok": False, "sources": [],
                            "error": f"'{fname}' 이 검증 이후 바뀌었습니다 — 반입을 전체 중단합니다."}
                tmp = dest.with_name(f".{dest.name}.tmp-{os.getpid()}")
                tmp.write_bytes(data)
                del data
                staged.append((tmp, dest, doc))
        except (OSError, zipfile.BadZipFile, zlib.error, EOFError, RuntimeError, KeyError) as exc:
            _discard_staged()
            return {"ok": False, "sources": [],
                    "error": f"캐시 임시파일을 쓰지 못했습니다({exc}) — 아무것도 바꾸지 않았습니다."}

        written: list[str] = []
        for index, (tmp, dest, doc) in enumerate(staged):
            try:
                # 원자적 교체 + 재시도 — 윈도에서는 검사 프로세스가 대상 파일을 읽는 동안 교체가 거부된다.
                replace_with_retry(tmp, dest)
            except OSError as exc:
                for rest, _, _ in staged[index:]:
                    try:
                        rest.unlink(missing_ok=True)
                    except OSError:
                        pass
                return {"ok": False, "sources": written, "partial": bool(written), "signed": signed,
                        "error": (f"'{dest.name}' 교체 실패({exc}) — 다른 프로세스가 파일을 쥐고 있습니다. "
                                  f"바뀐 소스: {', '.join(written) or '없음'}. 잠시 뒤 다시 실행하세요.")}
            written.append(doc["source_id"])
            # 방금 envelope 해시를 검증했다 — 스탬프를 남겨 첫 검사가 수십 MB 를 다시 해시하지 않게 한다.
            # 서명 출처·생태계별 건수는 다음 반입의 축소 검사 기준선이 된다.
            write_verified_stamp(dest, doc["sha256"], fetched_at=doc["fetched_at"], item_count=doc["item_count"],
                                 signed_key=key_id if signed else None, eco_counts=doc.get("eco_counts"))

    return {
        "ok": True,
        "cache_dir": str(target),
        "sources": written,
        "skipped_older": skipped_older,
        "file_count": len(written),
        "created_at": manifest.get("created_at", ""),
        "signed": signed,
        "key_id": key_id,
        "signature": sig_note,
        "allow_shrink": rebaseline,
        # 축소로 받지 않은 소스 — 기존 캐시를 지켰다. 나머지 소스는 반입됐다.
        "rejected_shrink": rejected,
        "accepted_shrink_stale": accepted_stale,
        "warning": " / ".join(part for part in (
            ("; ".join(r["reason"] for r in rejected)
             + f" — 수집 사고나 위조로 보고 이 소스는 기존 캐시를 지켰습니다(나머지는 반입). 기존 캐시가 "
               f"'낡음'이 되면 다음 번들을 받습니다. 의도한 축소라면 `--allow-shrink` 또는 {ENV_ALLOW_SHRINK}=1.")
            if rejected else "",
            ("; ".join(accepted_stale) + " — 목록이 크게 줄었습니다. 배포처의 수집 상태를 확인하세요.")
            if accepted_stale else "",
        ) if part),
    }


def shrink_rejected(result: dict) -> list[str]:
    """반입 결과에서 축소로 거부된 소스 이름들."""
    return [r.get("source", "") for r in result.get("rejected_shrink") or []]


def verify_bundle(zip_path: str | Path) -> dict:
    """번들을 **쓰지 않고** 검증만 — 서명·manifest·파일 해시 전수. 망연계 수신 서버가 배포 전에 쓴다."""
    return import_bundle(zip_path, verify_only=True)
