"""A14 — 위협정보 이름 색인. 빨라지기만 하고 판정은 같아야 한다. 색인을 믿을 수 없으면 전체 캐시로 돌아가야 한다.

적대적 시나리오: 조각 변조 · 캐시만 바뀌고 색인은 옛것 · 스탬프 삭제·위조 · 매니페스트의 폴더 경로 조작 ·
부분 항목 메모가 전체 색인과 섞임 · 폴더에 쓸 수 없음. 동일성: PyPI 이름 정규화 · npm 대소문자 · 스코프 이름 ·
생태계가 빈 항목 · 평평한/원형 package 표기.
"""
from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from gvskb.intel import name_index
from gvskb.intel.cache import IntelCache
from gvskb.intel.sources import osv
from gvskb.tools import check_package as cp


def _mal(vid: str, name: str, eco: str = "npm", *, versions=None, whole=False) -> dict:
    aff: dict = {"package": {"name": name, "ecosystem": eco}}
    if whole:
        aff["ranges"] = [{"type": "SEMVER", "events": [{"introduced": "0"}]}]
    if versions is not None:
        aff["versions"] = versions
    return osv._normalize({"id": vid, "summary": f"Malicious code in {name}", "modified": "2026-01-01T00:00:00Z",
                           "affected": [aff]})


def _vuln(vid: str, name: str, eco: str | None, introduced: str = "0", fixed: str = "2.0.0") -> dict:
    pkg = {"name": name}
    if eco:
        pkg["ecosystem"] = eco
    return {"id": vid, "aliases": [f"CVE-2026-{abs(hash(vid)) % 9000 + 1000}"], "summary": f"bug in {name}",
            "database_specific": {"severity": "HIGH"},
            "affected": [{"package": pkg, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": introduced}, {"fixed": fixed}]}]}]}


MAL = [
    _mal("MAL-1", "evil-pkg", whole=True),
    _mal("MAL-2", "chalk", versions=["5.6.1"]),
    _mal("MAL-3", "Evil_Py.Pkg", "PyPI", whole=True),
    _mal("MAL-4", "@scope/bad", versions=["1.0.0"]),
    _mal("MAL-5", "Mixed-Case", whole=True),
]
VULNS = [
    _vuln("GHSA-1", "requests", "PyPI"),
    _vuln("GHSA-2", "Flask_Login", "PyPI"),
    _vuln("GHSA-3", "lodash", "npm"),
    _vuln("GHSA-4", "noeco-lib", None),          # 생태계가 빈 항목 — 소비자는 모든 생태계와 맞춘다
    _vuln("GHSA-5", "chalk", "npm", introduced="1.0.0", fixed="1.0.1"),
]
NAMES = ["evil-pkg", "EVIL-PKG", "chalk", "Chalk", "evil-py-pkg", "evil_py.pkg", "Evil_Py.Pkg", "@scope/bad",
         "@SCOPE/BAD", "mixed-case", "requests", "Requests", "flask-login", "flask_login", "lodash", "noeco-lib",
         "Noeco_Lib", "nothing-here", "-", ""]


@pytest.fixture
def cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> IntelCache:
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path))
    monkeypatch.setenv("GVSKB_MODE", "offline")
    monkeypatch.setenv("GVSKB_INTEL_MAX_AGE_DAYS", "3650")
    monkeypatch.setattr(name_index, "_VIEW_COUNTS", {})
    monkeypatch.setattr(name_index, "_SHARD_MEMO", {})
    c = IntelCache(tmp_path)
    c.save("osv-malicious", "https://example.test", MAL, ecosystems=["PyPI", "npm"])
    c.save("osv-vulns", "https://example.test", VULNS, ecosystems=["PyPI", "npm"])
    return c


def _result(name: str, eco: str, version: str | None) -> str:
    label = cp.ECOSYSTEM_MAP[eco]
    r = cp._apply_mal_possible(cp._offline_cache_check(name, eco, label, version, local_mode=True))
    r.pop("checked_at", None)
    return json.dumps(r, sort_keys=True, ensure_ascii=False)


def _all_results() -> list[str]:
    return [_result(n, eco, v) for n in NAMES for eco in ("npm", "pypi") for v in ("1.0.0", "5.6.1", None)]


def test_index_answers_exactly_like_full_load(cache: IntelCache, monkeypatch: pytest.MonkeyPatch) -> None:
    assert name_index.build_all(cache) == ["osv-malicious", "osv-vulns"]
    monkeypatch.setattr(name_index, "VIEW_LOOKUP_LIMIT", 10 ** 9)
    with_index = _all_results()
    monkeypatch.setattr(cp, "load_for_package", lambda c, sid, name: c.load(sid))
    full = _all_results()
    assert with_index == full
    # 실제로 걸리는지(동일성이 '둘 다 전체 로딩'이라 같은 것이 아님을 확인)
    view = name_index.lookup(cache, "osv-malicious", "Evil_Py.Pkg")
    assert view is not None and "#name=evil-py-pkg" in view.sha256 and [i["id"] for i in view.items] == ["MAL-3"]
    assert name_index.lookup(cache, "osv-vulns", "noeco-lib").items[0]["id"] == "GHSA-4"


def test_verdicts_hold(cache: IntelCache) -> None:
    name_index.build_all(cache)
    assert json.loads(_result("chalk", "npm", "5.6.1"))["verdict"] == "malicious"
    assert json.loads(_result("EVIL-PKG", "npm", "9.9.9"))["verdict"] == "malicious"
    assert json.loads(_result("evil_py.pkg", "pypi", "1.0.0"))["verdict"] == "malicious"
    assert json.loads(_result("requests", "pypi", "1.0.0"))["verdict"] == "vulnerable"
    assert json.loads(_result("requests", "pypi", "2.0.0"))["verdict"] == "checked_clean"


def test_tampered_shard_falls_back_to_full_load(cache: IntelCache) -> None:
    name_index.build_all(cache)
    manifest = json.loads((cache.cache_dir / ".index" / "osv-malicious" / "manifest.json").read_text(encoding="utf-8"))
    shard = name_index._shard_of(name_index.index_key("chalk"))
    path = cache.cache_dir / ".index" / "osv-malicious" / manifest["dir"] / f"{shard}.json.gz"
    data = json.loads(gzip.decompress(path.read_bytes()))
    data["chalk"] = []                                   # 악성 권고를 지운 조각
    path.write_bytes(gzip.compress(json.dumps(data).encode()))
    assert name_index.lookup(cache, "osv-malicious", "chalk") is None
    name_index._SHARD_MEMO.clear()
    assert json.loads(_result("chalk", "npm", "5.6.1"))["verdict"] == "malicious"


def test_cache_replaced_without_reindex_is_ignored(cache: IntelCache) -> None:
    name_index.build_all(cache)
    # 새 캐시(악성 권고 추가)를 옛 판 체커처럼 색인 없이 쓴다 — 옛 색인으로 답하면 새 악성을 놓친다.
    IntelCache(cache.cache_dir).save("osv-malicious", "https://example.test",
                                     MAL + [_mal("MAL-9", "fresh-evil", whole=True)], ecosystems=["PyPI", "npm"])
    assert name_index.lookup(cache, "osv-malicious", "fresh-evil") is None
    assert json.loads(_result("fresh-evil", "npm", "1.0.0"))["verdict"] == "malicious"


@pytest.mark.parametrize("damage", ["remove_stamp", "forge_stamp_sha", "manifest_dir_traversal", "manifest_other_source",
                                    "manifest_format", "drop_shard_hash"])
def test_untrustworthy_index_is_not_used(cache: IntelCache, damage: str) -> None:
    name_index.build_all(cache)
    root = cache.cache_dir / ".index" / "osv-malicious"
    mpath = root / "manifest.json"
    manifest = json.loads(mpath.read_text(encoding="utf-8"))
    stamp = cache.path_for("osv-malicious").with_name("osv-malicious.json.verified")
    if damage == "remove_stamp":
        stamp.unlink()
    elif damage == "forge_stamp_sha":
        doc = json.loads(stamp.read_text(encoding="utf-8"))
        doc["sha256"] = "0" * 64
        stamp.write_text(json.dumps(doc), encoding="utf-8")
        manifest["source_sha256"] = "0" * 64
    elif damage == "manifest_dir_traversal":
        manifest["dir"] = "../../osv-vulns"
    elif damage == "manifest_other_source":
        manifest["source_id"] = "osv-vulns"
    elif damage == "manifest_format":
        manifest["key_scheme"] = "other"
    elif damage == "drop_shard_hash":
        manifest["shards"] = {}
    mpath.write_text(json.dumps(manifest), encoding="utf-8")
    name_index._SHARD_MEMO.clear()
    assert name_index.lookup(cache, "osv-malicious", "chalk") is None
    assert json.loads(_result("chalk", "npm", "5.6.1"))["verdict"] == "malicious"


def test_partial_view_does_not_poison_full_index_memo(cache: IntelCache) -> None:
    """부분 항목 CacheEntry 는 sha256 에 표식이 붙는다 — 같은 프로세스의 락파일 검사가 쓰는 전체 색인 메모와 섞이면 미탐."""
    from gvskb.intel.lookup import _indexed

    name_index.build_all(cache)
    view = name_index.lookup(cache, "osv-malicious", "chalk")
    idx_view = _indexed(view, "mal-by-name", cp._build_mal_index)
    full = cache.load("osv-malicious")
    idx_full = _indexed(full, "mal-by-name", cp._build_mal_index)
    assert ("npm", "evil-pkg") not in idx_view and ("npm", "evil-pkg") in idx_full


def test_many_lookups_switch_to_full_load(cache: IntelCache, monkeypatch: pytest.MonkeyPatch) -> None:
    name_index.build_all(cache)
    monkeypatch.setattr(name_index, "VIEW_LOOKUP_LIMIT", 3)
    calls = {"full": 0}
    real = cache.load

    def counting(sid):
        calls["full"] += 1
        return real(sid)

    monkeypatch.setattr(cache, "load", counting)
    entries = [name_index.load_for_package(cache, "osv-malicious", "chalk") for _ in range(5)]
    assert calls["full"] == 2 and all("#name=" in e.sha256 for e in entries[:3]) and "#" not in entries[4].sha256


def test_missing_index_is_built_on_first_full_load(cache: IntelCache) -> None:
    assert not (cache.cache_dir / ".index").exists()
    entry = name_index.load_for_package(cache, "osv-malicious", "chalk")
    assert entry is not None and "#" not in entry.sha256         # 첫 회는 전체
    assert (cache.cache_dir / ".index" / "osv-malicious" / "manifest.json").exists()
    name_index._VIEW_COUNTS.clear()                               # 다음 프로세스
    assert "#name=chalk" in name_index.load_for_package(cache, "osv-malicious", "chalk").sha256


def test_unwritable_index_dir_keeps_checks_working(cache: IntelCache, monkeypatch: pytest.MonkeyPatch) -> None:
    def deny(*a, **k):
        raise PermissionError("읽기 전용")

    monkeypatch.setattr(Path, "mkdir", deny)
    assert name_index.build(cache, "osv-malicious") is False
    assert json.loads(_result("chalk", "npm", "5.6.1"))["verdict"] == "malicious"


def test_rebuild_replaces_old_folder(cache: IntelCache) -> None:
    name_index.build_all(cache)
    first = json.loads((cache.cache_dir / ".index" / "osv-malicious" / "manifest.json").read_text(encoding="utf-8"))["dir"]
    IntelCache(cache.cache_dir).save("osv-malicious", "https://example.test", MAL[:2], ecosystems=["PyPI", "npm"])
    assert name_index.build(cache, "osv-malicious")
    root = cache.cache_dir / ".index" / "osv-malicious"
    second = json.loads((root / "manifest.json").read_text(encoding="utf-8"))["dir"]
    assert first != second and not (root / first).exists() and (root / second).exists()
    assert name_index.lookup(cache, "osv-malicious", "Mixed-Case").items == []


def test_bundle_import_and_update_build_index(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from gvskb.intel import bundle as bundle_mod
    from gvskb.intel import update as update_mod

    src = tmp_path / "src"
    monkeypatch.setenv("GVSKB_INTEL_MAX_AGE_DAYS", "3650")
    IntelCache(src).save("osv-malicious", "https://example.test", MAL, ecosystems=["PyPI", "npm"])
    zpath = tmp_path / "b.zip"
    bundle_mod.export_bundle(zpath, cache_dir=src)
    dest = tmp_path / "dest"
    result = bundle_mod.import_bundle(zpath, cache_dir=dest)
    assert result["ok"] and result["name_index"] == ["osv-malicious"]
    assert name_index.lookup(IntelCache(dest), "osv-malicious", "chalk").items[0]["id"] == "MAL-2"

    class _Adapter:
        merge = None
        ecosystems = None

        @staticmethod
        def fetch(client):
            return "https://example.test", MAL

    monkeypatch.setitem(update_mod.SOURCES, "osv-malicious", _Adapter)
    upd = tmp_path / "upd"
    res = update_mod.update_source("osv-malicious", cache=IntelCache(upd), client=object())
    assert res.status == "ok"
    assert name_index.lookup(IntelCache(upd), "osv-malicious", "evil-pkg") is not None
