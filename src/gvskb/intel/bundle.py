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
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from .cache import IntelCache, default_cache_dir

MANIFEST_NAME = "manifest.json"
_CACHES_PREFIX = "caches/"
BUNDLE_FORMAT_VERSION = 1


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def export_bundle(zip_path: str | Path, *, cache_dir: Path | None = None) -> dict:
    """현재 인텔 캐시 전체를 manifest(sha256) 포함 zip으로 내보낸다."""
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
        zf.writestr(MANIFEST_NAME, json.dumps(manifest, ensure_ascii=False, indent=2))
    return {"ok": True, "bundle": str(out), "sources": [f["source_id"] for f in files],
            "file_count": len(files)}


def import_bundle(zip_path: str | Path, *, cache_dir: Path | None = None) -> dict:
    """번들을 전수 검증 후 캐시 디렉터리로 반입한다. 검증 실패 시 전체 거부."""
    src = Path(zip_path)
    if not src.exists():
        return {"ok": False, "error": f"번들 파일이 없습니다: {src}", "sources": []}

    try:
        zf = zipfile.ZipFile(src)
    except zipfile.BadZipFile:
        return {"ok": False, "error": "zip 형식이 아니거나 손상된 번들입니다.", "sources": []}

    with zf:
        try:
            manifest = json.loads(zf.read(MANIFEST_NAME).decode("utf-8"))
        except (KeyError, json.JSONDecodeError):
            return {"ok": False, "error": "manifest.json이 없거나 손상됐습니다 — 정식 export 번들이 아닙니다.",
                    "sources": []}

        files = manifest.get("files") or []
        if not files:
            return {"ok": False, "error": "manifest에 파일 목록이 없습니다.", "sources": []}

        # 1단계: 전수 검증 (하나라도 실패하면 아무것도 쓰지 않는다)
        verified: list[tuple[str, bytes]] = []
        for f in files:
            fname = str(f.get("filename", ""))
            member = _CACHES_PREFIX + fname
            try:
                data = zf.read(member)
            except KeyError:
                return {"ok": False, "sources": [],
                        "error": f"번들에 '{fname}'이 없습니다(manifest와 불일치) — 반입 중단."}
            if _sha256_bytes(data) != f.get("sha256"):
                return {"ok": False, "sources": [],
                        "error": f"'{fname}' sha256 불일치 — 이동 중 변조·손상 가능. 반입을 전체 중단합니다."}
            verified.append((fname, data))

        # 2단계: 전부 통과한 경우에만 기록
        target = cache_dir or default_cache_dir()
        target.mkdir(parents=True, exist_ok=True)
        for fname, data in verified:
            (target / fname).write_bytes(data)

    return {
        "ok": True,
        "cache_dir": str(target),
        "sources": [f["source_id"] for f in files],
        "file_count": len(verified),
        "created_at": manifest.get("created_at", ""),
    }
