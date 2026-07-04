"""intel-bundle — 망분리 반입 번들의 export/import 무결성 보증."""
from __future__ import annotations

import json
import zipfile
from pathlib import Path

from gvskb.intel.bundle import export_bundle, import_bundle
from gvskb.intel.cache import IntelCache


def _seed_cache(cache_dir: Path) -> IntelCache:
    cache = IntelCache(cache_dir)
    cache.save("osv-malicious", "https://example/osv", [
        {"id": "MAL-1", "affected": [{"package": "evil", "ecosystem": "PyPI"}]},
    ], ecosystems=["PyPI"])
    cache.save("cisa-kev", "https://example/kev", [
        {"cveID": "CVE-2026-0001", "vendorProject": "X", "product": "Y"},
    ])
    return cache


def test_export_import_roundtrip(tmp_path: Path) -> None:
    src_dir = tmp_path / "src-cache"
    _seed_cache(src_dir)
    bundle = tmp_path / "반입.zip"

    exported = export_bundle(bundle, cache_dir=src_dir)
    assert exported["ok"] is True
    assert set(exported["sources"]) == {"osv-malicious", "cisa-kev"}

    dst_dir = tmp_path / "dst-cache"
    imported = import_bundle(bundle, cache_dir=dst_dir)
    assert imported["ok"] is True
    assert imported["file_count"] == 2

    # 반입된 캐시가 로드 계층 무결성 검증(envelope sha)까지 통과해야 한다
    dst = IntelCache(dst_dir)
    entry = dst.load("osv-malicious")
    assert entry is not None
    assert entry.item_count == 1
    assert entry.ecosystems == ["PyPI"]


def test_tampered_bundle_rejected_entirely(tmp_path: Path) -> None:
    """이동 중 변조된 번들은 부분 반입 없이 전체 거부돼야 한다."""
    src_dir = tmp_path / "src-cache"
    _seed_cache(src_dir)
    bundle = tmp_path / "b.zip"
    assert export_bundle(bundle, cache_dir=src_dir)["ok"]

    # zip 내부 파일 하나를 변조해 다시 포장
    tampered = tmp_path / "tampered.zip"
    with zipfile.ZipFile(bundle) as zin, zipfile.ZipFile(tampered, "w") as zout:
        for info in zin.infolist():
            data = zin.read(info.filename)
            if info.filename.endswith("cisa-kev.json"):
                data = data.replace(b"CVE-2026-0001", b"CVE-9999-9999")
            zout.writestr(info, data)

    dst_dir = tmp_path / "dst-cache"
    result = import_bundle(tampered, cache_dir=dst_dir)
    assert result["ok"] is False
    assert "sha256" in result["error"]
    assert not dst_dir.exists() or not list(dst_dir.glob("*.json"))  # 아무것도 안 씀


def test_non_bundle_zip_rejected(tmp_path: Path) -> None:
    plain = tmp_path / "plain.zip"
    with zipfile.ZipFile(plain, "w") as zf:
        zf.writestr("random.txt", "hello")
    result = import_bundle(plain, cache_dir=tmp_path / "dst")
    assert result["ok"] is False
    assert "manifest" in result["error"]


def test_export_empty_cache_refused(tmp_path: Path) -> None:
    result = export_bundle(tmp_path / "b.zip", cache_dir=tmp_path / "empty")
    assert result["ok"] is False
    assert "update-intel" in result["error"]


def test_manifest_records_freshness_metadata(tmp_path: Path) -> None:
    src_dir = tmp_path / "src-cache"
    _seed_cache(src_dir)
    bundle = tmp_path / "b.zip"
    export_bundle(bundle, cache_dir=src_dir)
    with zipfile.ZipFile(bundle) as zf:
        manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
    assert manifest["bundle_format"] == 1
    files = {f["source_id"]: f for f in manifest["files"]}
    assert files["osv-malicious"]["ecosystems"] == ["PyPI"]
    assert files["osv-malicious"]["fetched_at"]
    assert files["cisa-kev"]["sha256"]
