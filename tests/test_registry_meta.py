"""A13 — 폐쇄망 레지스트리 정보 번들. 판정을 더할 뿐 악성·취약 판정을 지우지 못해야 하고, 위조·변조·옛 번들은 받지 않아야 한다."""
from __future__ import annotations

import asyncio
import hashlib
import json
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from gvskb.intel import name_index
from gvskb.intel.cache import IntelCache
from gvskb.intel.signing import generate_seed, public_key_from_seed, sign_manifest
from gvskb.intel.sources import osv
from gvskb.schema import PackageRegistryMetadata
from gvskb.tools import check_package as cp
from gvskb.tools import registry_meta as rm

NOW = datetime.now(timezone.utc)


def _iso(days_ago: float) -> str:
    return (NOW - timedelta(days=days_ago)).isoformat(timespec="seconds")


def _meta(*, exists=True, version="1.0.0", published_days=400, first_days=2000, license="MIT", scripts="none",
          version_exists=True, deprecated=None, fetched_days=1) -> dict:
    m = PackageRegistryMetadata(
        exists=exists, latest_version="9.9.9" if exists else None, queried_version=version,
        version_exists=version_exists if exists else None,
        version_published_at=_iso(published_days) if exists else None, version_age_days=0,
        first_published_at=_iso(first_days) if exists else None, package_age_days=0,
        license=license if exists else None, install_scripts=scripts,
        install_script_names=["postinstall"] if scripts == "present" else [], deprecated=deprecated,
        source="https://registry.example/x", fetched_at=_iso(fetched_days))
    return m.model_dump(mode="json")


def _row(eco: str, name: str, version: str | None, collected_days: float = 1, **kw) -> dict:
    return {"ecosystem": eco, "name": name, "version": version, "collected_at": _iso(collected_days),
            "meta": _meta(version=version, **kw)}


@pytest.fixture
def seed(monkeypatch: pytest.MonkeyPatch) -> bytes:
    s = generate_seed()
    monkeypatch.setenv("GVSKB_INTEL_TRUSTED_KEYS", f"org-test={public_key_from_seed(s).hex()}")
    return s


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("GVSKB_MODE", "offline")
    monkeypatch.setenv("GVSKB_INTEL_MAX_AGE_DAYS", "3650")
    monkeypatch.delenv("GVSKB_INTEL_REQUIRE_SIGNATURE", raising=False)
    monkeypatch.setattr(name_index, "_VIEW_COUNTS", {})
    monkeypatch.setattr(rm, "_INDEX_MEMO", {})
    c = IntelCache(tmp_path / "cache")
    mal = [osv._normalize({"id": "MAL-1", "summary": "Malicious code in evilpkg", "modified": "2026-01-01T00:00:00Z",
                           "affected": [{"package": {"name": "evilpkg", "ecosystem": "npm"},
                                         "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]})]
    vulns = [{"id": "GHSA-1", "aliases": ["CVE-2026-1111"], "summary": "bug", "database_specific": {"severity": "HIGH"},
              "affected": [{"package": {"name": "vulnlib", "ecosystem": "npm"},
                            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]}]}]
    c.save("osv-malicious", "https://example.test", mal, ecosystems=["PyPI", "npm"])
    c.save("osv-vulns", "https://example.test", vulns, ecosystems=["PyPI", "npm"])
    c.save("cisa-kev", "https://example.test", [])
    return tmp_path


def _bundle(tmp: Path, rows: list[dict], seed: bytes | None, name: str = "b.zip") -> Path:
    out = tmp / name
    rm.export_bundle(rows, out, sign_seed=seed, key_id="org-test" if seed else None)
    return out


def _check(name: str, version: str | None = "1.0.0", eco: str = "npm", env_grade: str | None = None, exact: bool = True) -> dict:
    return asyncio.run(cp.check_package_impl(name, ecosystem=eco, version=version, env_grade=env_grade,
                                             mode="local", version_exact=exact))


# ---------------------------------------------------------------- 요청·수집

def test_request_validation() -> None:
    good = rm.build_request([{"ecosystem": "npm", "name": "react", "versions": ["18.3.1", "18.3.1"], "department": "비밀"},
                             {"ecosystem": "pypi", "package_name": "Flask"}])
    assert "department" not in json.dumps(good, ensure_ascii=False)
    entries = rm.parse_request(json.dumps(good))
    assert entries == [("npm", "react", "18.3.1"), ("pypi", "Flask", None)]
    for bad in ({"schema": "other", "packages": []},
                {"schema": rm.REQUEST_SCHEMA, "packages": [{"ecosystem": "maven", "name": "x"}]},
                {"schema": rm.REQUEST_SCHEMA, "packages": [{"ecosystem": "npm", "name": "a\nb"}]},
                {"schema": rm.REQUEST_SCHEMA, "packages": [{"ecosystem": "npm", "name": " lead"}]}):
        with pytest.raises(rm.RegistryMetaError):
            rm.parse_request(json.dumps(bad))
    many = {"schema": rm.REQUEST_SCHEMA, "packages": [{"ecosystem": "npm", "name": f"p{i}"} for i in range(rm.MAX_PACKAGES + 1)]}
    with pytest.raises(rm.RegistryMetaError):
        rm.parse_request(json.dumps(many))


def test_collect_drops_unconfirmed() -> None:
    async def fake(name, eco, version=None, timeout=10.0):
        if name == "down":
            return PackageRegistryMetadata(exists=None, error="timeout")
        if name == "ghost":
            return PackageRegistryMetadata(exists=False, fetched_at=_iso(0))
        return PackageRegistryMetadata(exists=True, version_exists=True, fetched_at=_iso(0))

    rows, failed = asyncio.run(rm.collect([("npm", "ok", "1.0.0"), ("npm", "ghost", None), ("npm", "down", "1")], fetch=fake))
    assert [r["name"] for r in rows] == ["ghost", "ok"] and [f["name"] for f in failed] == ["down"]


# ---------------------------------------------------------------- 반입 검증

def test_signed_roundtrip(env: Path, seed: bytes) -> None:
    res = rm.import_bundle(_bundle(env, [_row("npm", "react", "18.3.1")], seed))
    assert res["ok"] and res["signed"] and res["key_id"] == "org-test" and res["added"] == 1
    meta, info = rm.lookup("npm", "React", "18.3.1")
    assert info["state"] == "hit" and meta.exists is True and meta.version_age_days == 400


def test_unsigned_follows_signature_policy(env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    b = _bundle(env, [_row("npm", "react", "18.3.1")], None)
    monkeypatch.setenv("GVSKB_INTEL_REQUIRE_SIGNATURE", "1")
    res = rm.import_bundle(b)
    assert not res["ok"] and "서명 없는" in res["error"]
    monkeypatch.delenv("GVSKB_INTEL_REQUIRE_SIGNATURE")
    res = rm.import_bundle(b)
    assert res["ok"] and not res["signed"] and "warning" in res


def _rewrite(src: Path, dst: Path, *, data: bytes | None = None, manifest: bytes | None = None, sig: bytes | None = None,
             extra: dict | None = None) -> Path:
    with zipfile.ZipFile(src) as z:
        members = {n: z.read(n) for n in z.namelist()}
    if data is not None:
        members[rm.DATA_NAME] = data
    if manifest is not None:
        members[rm.MANIFEST_NAME] = manifest
    if sig is not None:
        members["manifest.sig"] = sig
    members.update(extra or {})
    with zipfile.ZipFile(dst, "w") as z:
        for n, b in members.items():
            z.writestr(n, b)
    return dst


def test_tampering_is_rejected(env: Path, seed: bytes) -> None:
    good = _bundle(env, [_row("npm", "ghostpkg", None, exists=False)], seed)
    with zipfile.ZipFile(good) as z:
        data = json.loads(z.read(rm.DATA_NAME))
        manifest = json.loads(z.read(rm.MANIFEST_NAME))
    data["items"][0]["meta"]["exists"] = True                     # '없음'을 '있음'으로 바꿔 차단을 피하려는 변조
    forged = json.dumps(data).encode()
    # (1) 내용만 바꿈 → 해시 불일치
    assert "해시" in rm.import_bundle(_rewrite(good, env / "t1.zip", data=forged))["error"]
    # (2) manifest 해시까지 맞춤 → 서명 불일치
    manifest["files"][rm.DATA_NAME]["sha256"] = hashlib.sha256(forged).hexdigest()
    mb = json.dumps(manifest).encode()
    assert "서명" in rm.import_bundle(_rewrite(good, env / "t2.zip", data=forged, manifest=mb))["error"]
    # (3) 공격자 키로 다시 서명 → 신뢰 목록에 없는 키
    evil = generate_seed()
    sig = json.dumps(sign_manifest(mb, evil, "org-test")).encode()
    assert "서명" in rm.import_bundle(_rewrite(good, env / "t3.zip", data=forged, manifest=mb, sig=sig))["error"]
    # (4) 예상 밖 항목 · (5) 깨진 zip
    assert not rm.import_bundle(_rewrite(good, env / "t4.zip", extra={"../evil.txt": b"x"}))["ok"]
    (env / "t5.zip").write_bytes(b"PK\x03\x04garbage")
    assert not rm.import_bundle(env / "t5.zip")["ok"]
    assert rm.status()["state"] == "absent"                       # 아무것도 쓰지 않았다


def test_oversized_member_rejected(env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(rm, "MAX_DATA_BYTES", 100)
    res = rm.import_bundle(_bundle(env, [_row("npm", f"p{i}", "1.0.0") for i in range(5)], None))
    assert not res["ok"] and "너무 큽니다" in res["error"]


def test_merge_keeps_newer_and_clamps_future(env: Path, seed: bytes) -> None:
    rm.import_bundle(_bundle(env, [_row("npm", "react", "18.3.1", collected_days=1, license="MIT")], seed, "new.zip"))
    res = rm.import_bundle(_bundle(env, [_row("npm", "react", "18.3.1", collected_days=5, license="AGPL-3.0"),
                                         _row("npm", "vue", "3.0.0", collected_days=-30)], seed, "old.zip"))
    assert res["kept_newer"] == 1 and res["added"] == 1
    assert rm.lookup("npm", "react", "18.3.1")[0].license == "MIT"          # 옛 번들이 덮지 않았다
    _, info = rm.lookup("npm", "vue", "3.0.0")
    assert info["collected_age_days"] == 0                                  # 미래 시각은 반입 시각으로


def test_invalid_rows_dropped(env: Path, seed: bytes) -> None:
    rows = [_row("npm", "ok", "1.0.0"), {"ecosystem": "npm", "name": "x", "version": "1", "collected_at": _iso(1),
                                         "meta": {"exists": None}},
            {"ecosystem": "maven", "name": "y", "version": "1", "collected_at": _iso(1), "meta": _meta()},
            {"ecosystem": "npm", "name": "z", "version": "1", "collected_at": "어제", "meta": _meta()}]
    res = rm.import_bundle(_bundle(env, rows, seed))
    assert res["ok"] and res["item_count"] == 1 and res["rejected_rows"] == 3


def test_cache_is_not_an_intel_source(env: Path, seed: bytes) -> None:
    """위협정보 소스 목록(신선도·상태 화면)에 섞이면 30일 정보가 '위협정보 낡음'으로 보여 포털 점검이 멈출 수 있다."""
    rm.import_bundle(_bundle(env, [_row("npm", "react", "18.3.1")], seed))
    assert "registry-meta" not in IntelCache(env / "cache").list_sources()


# ---------------------------------------------------------------- 판정 사다리

def test_no_bundle_keeps_previous_behavior(env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    before = _check("cleanlib")
    monkeypatch.setattr(cp, "_apply_registry_meta", lambda result, *a, **k: result)
    plain = _check("cleanlib")
    before.pop("checked_at"); plain.pop("checked_at")
    assert before == plain and before["verdict"] == "checked_clean" and before["requires_review"] is True
    assert "registry_meta_state" not in before or before["registry_meta_state"] is None


def test_clean_with_meta_is_confirmed(env: Path, seed: bytes) -> None:
    rm.import_bundle(_bundle(env, [_row("npm", "cleanlib", "1.0.0")], seed))
    r = _check("cleanlib")
    assert r["verdict"] == "checked_clean" and r["requires_review"] is False and r["exists"] is True
    assert r["cooldown"]["ok"] is True and r["registry_meta_state"] == "hit" and "실재·발행일을 확인" in r["note"]


@pytest.mark.parametrize("kw,expect", [
    ({"published_days": 1}, ("cooldown_hold", True)),
    ({"version_exists": False}, ("version_not_found", True)),
    ({"license": "AGPL-3.0"}, ("checked_clean", True)),
    ({"scripts": "present"}, ("checked_clean", True)),
    ({"deprecated": True}, ("checked_clean", True)),
])
def test_meta_signals_keep_review(env: Path, seed: bytes, kw: dict, expect: tuple) -> None:
    rm.import_bundle(_bundle(env, [_row("npm", "cleanlib", "1.0.0", **kw)], seed))
    r = _check("cleanlib")
    assert (r["verdict"], r["requires_review"]) == expect


def test_ages_are_recomputed_now(env: Path, seed: bytes) -> None:
    rm.import_bundle(_bundle(env, [_row("npm", "cleanlib", "1.0.0", published_days=4, collected_days=3)], seed))
    assert _check("cleanlib", env_grade="E1")["verdict"] == "cooldown_hold"      # 4일 < 7일
    assert _check("cleanlib", env_grade="E0")["verdict"] == "checked_clean"      # 4일 >= 3일


def test_not_found_blocks_any_version(env: Path, seed: bytes) -> None:
    rm.import_bundle(_bundle(env, [_row("npm", "ghostpkg", None, exists=False)], seed))
    for v in ("1.0.0", "7.7.7", None):
        r = _check("ghostpkg", v)
        assert r["verdict"] == "not_found" and r["checked"] is False and r["requires_review"] is True


def test_threat_verdicts_cannot_be_erased(env: Path, seed: bytes) -> None:
    # 악성 패키지가 저장소에서 내려가면 수집 결과는 '없음'이다 — 그래도 판정은 악성이어야 한다(조치 문구가 다르다).
    rm.import_bundle(_bundle(env, [_row("npm", "vulnlib", "1.0.0"), _row("npm", "evilpkg", None, exists=False)], seed))
    r = _check("evilpkg")
    assert r["verdict"] == "malicious" and r["is_malicious_package"] is True
    r = _check("vulnlib")
    assert r["verdict"] == "vulnerable" and r["requires_review"] is True


def test_missing_and_stale_rows_stay_in_review(env: Path, seed: bytes) -> None:
    rm.import_bundle(_bundle(env, [_row("npm", "oldlib", "1.0.0", collected_days=45)], seed))
    r = _check("otherlib")
    assert r["verdict"] == "checked_clean" and r["requires_review"] is True and "아직 없습니다" in r["note"]
    assert r["registry_meta_state"] == "missing"
    r = _check("oldlib")
    assert r["requires_review"] is True and r["registry_meta_state"] == "stale" and "다시 수집" in r["note"]


def test_other_version_is_not_borrowed(env: Path, seed: bytes) -> None:
    rm.import_bundle(_bundle(env, [_row("npm", "cleanlib", "1.0.0")], seed))
    r = _check("cleanlib", "1.0.1")
    assert r["requires_review"] is True and r["registry_meta_state"] == "missing" and r["exists"] is None


def test_unpinned_does_not_lower_review(env: Path, seed: bytes) -> None:
    rm.import_bundle(_bundle(env, [_row("npm", "cleanlib", None)], seed))
    r = _check("cleanlib", None)
    assert r["requires_review"] is True


def test_stale_intel_stays_stale(env: Path, seed: bytes, monkeypatch: pytest.MonkeyPatch) -> None:
    rm.import_bundle(_bundle(env, [_row("npm", "cleanlib", "1.0.0")], seed))
    monkeypatch.setenv("GVSKB_INTEL_MAX_AGE_DAYS", "1")
    for sid in ("osv-malicious", "osv-vulns", "cisa-kev"):
        p = env / "cache" / f"{sid}.json"
        doc = json.loads(p.read_text(encoding="utf-8"))
        doc["fetched_at"] = _iso(10)
        p.write_text(json.dumps(doc), encoding="utf-8")
    r = _check("cleanlib")
    assert r["verdict"] == "checked_stale" and r["requires_review"] is True


def test_cli_headline_distinguishes_unknown_from_review() -> None:
    from gvskb.cli import _check_package_headline as h

    assert "판정 불가" in h({"checked": False, "verdict": "unknown"})
    assert "판정 불가" not in h({"checked": True, "verdict": "checked_clean", "check_mode": "local", "exists": None})
    assert "update-intel" not in h({"checked": True, "verdict": "checked_clean", "check_mode": "local", "exists": None})
    assert "오래돼" in h({"checked": True, "verdict": "checked_stale"})
    assert "저장소에 없는" in h({"checked": False, "verdict": "not_found"})
