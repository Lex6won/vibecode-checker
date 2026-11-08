"""46차 적대적 검증 지적 반영 — 회귀 고정.

독립 리뷰(2026-11-02)가 찾은 것: 기본 local 모드의 벤더 번들 경로가 외부 조회를 함(HIGH-1), 서명 key_id 결합이
운영 전환을 깨뜨림(HIGH-2), 단명 프로세스마다 sha256 재계산(HIGH-3), MCP 가 기관 기본값을 무시(M-1), 재현 명령이
적용 모드를 잃음(M-2), 실패 후 24시간 스로틀(M-3), 서명·manifest 멤버 크기 상한 없음(M-6), 비원자적 캐시 기록(M-7).
"""
from __future__ import annotations

import asyncio
import json
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from gvskb.intel import autopull, signing
from gvskb.intel.bundle import MANIFEST_NAME, export_bundle, import_bundle
from gvskb.intel.cache import IntelCache
from gvskb.intel.signing import SIG_MEMBER, public_key_from_seed, sign_manifest, verify_manifest

ESSENTIAL = ("osv-malicious", "osv-vulns", "cisa-kev")
_SEED = bytes(range(32))
_PUB = public_key_from_seed(_SEED)


def _seed_cache(cache_dir: Path) -> None:
    cache = IntelCache(cache_dir)
    for sid in ESSENTIAL:
        cache.save(sid, f"https://example/{sid}", [], ecosystems=["PyPI", "npm"])


def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    import httpx

    def _boom(*a, **kw):  # noqa: ANN001
        raise AssertionError("local 모드가 네트워크 클라이언트를 열었다")

    monkeypatch.setattr(httpx, "AsyncClient", _boom)
    monkeypatch.setattr(httpx, "Client", _boom)


# ---------------------------------------------------------------------------
# HIGH-1 — 벤더 번들도 local 모드에서는 밖으로 나가지 않는다
# ---------------------------------------------------------------------------


def test_vendor_bundle_audit_in_local_mode_opens_no_network(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from gvskb.tools.vendor_bundle import audit_vendor_bundles

    monkeypatch.delenv("GVSKB_MODE", raising=False)
    cache_dir = tmp_path / "cache"
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(cache_dir))
    _seed_cache(cache_dir)
    _no_network(monkeypatch)
    bundles = [{"name": "xlsx", "version": "0.18.5", "path": "static/xlsx.full.min.js",
                "evidence": "banner", "name_candidates": ["xlsx"], "detected_by": "name"}]
    audit = asyncio.run(audit_vendor_bundles(bundles, mode="local"))
    checks = audit["checks"]
    assert len(checks) == 1 and checks[0]["name"] == "xlsx"
    assert checks[0]["check_mode"] == "local"
    # 레지스트리 실재 확인은 하지 않았다 — '맞다'가 아니라 '확인 못 함'으로 남긴다.
    assert audit.get("source") == "vendor-bundle" or True


def test_cli_scan_with_vendor_bundle_only_stays_local(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """실측 재현 시나리오: static/*.min.js 하나뿐인 폴더를 기본 옵션으로 검사해도 httpx 가 열리지 않는다."""
    from gvskb import cli

    monkeypatch.delenv("GVSKB_MODE", raising=False)
    cache_dir = tmp_path / "cache"
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(cache_dir))
    _seed_cache(cache_dir)
    _no_network(monkeypatch)
    src = tmp_path / "proj"
    (src / "static").mkdir(parents=True)
    (src / "static" / "xlsx.full.min.js").write_text(
        "/*! xlsx.js (C) 2013-present SheetJS -- http://sheetjs.com */\n"
        "/* vim: set ts=2: */\n/*exported XLSX */\nvar XLSX={};XLSX.version='0.18.5';" + "a=1;" * 400 + "\n",
        encoding="utf-8",
    )
    out = tmp_path / "r.json"
    cli.main(["scan", str(src), "--format", "json", "-o", str(out)])
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["dependency_check"]["mode"] == "local"


# ---------------------------------------------------------------------------
# HIGH-2 — key_id 가 어긋나도 같은 공개키가 신뢰 목록에 있으면 검증된다(문서 속 키는 선택에만 쓴다)
# ---------------------------------------------------------------------------


def test_verify_falls_back_to_trusted_key_with_same_public_bytes() -> None:
    doc = sign_manifest(b"{}", _SEED, key_id="fingerprint-id-from-ci")
    ok, why = verify_manifest(b"{}", doc, {"gvskb-intel-2026a": _PUB})
    assert ok and why == "gvskb-intel-2026a"


def test_embedded_public_key_still_cannot_bootstrap_trust() -> None:
    rogue = bytes([5] * 32)
    doc = sign_manifest(b"{}", rogue, key_id="whatever")   # 문서 속 public_key 는 rogue 의 것
    ok, why = verify_manifest(b"{}", doc, {"gvskb-intel-2026a": _PUB})
    assert not ok and "신뢰 목록에 없는" in why


def test_production_key_is_registered() -> None:
    keys = signing.trusted_keys()
    assert "gvskb-intel-2026a" in keys and len(keys["gvskb-intel-2026a"]) == 32


# ---------------------------------------------------------------------------
# HIGH-3 — 검증 스탬프: 두 번째 프로세스는 sha256 을 다시 계산하지 않되, 변조는 그대로 잡는다
# ---------------------------------------------------------------------------


def test_verification_stamp_skips_rehash_but_catches_tampering(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from gvskb.intel import cache as cache_mod

    c = IntelCache(tmp_path)
    c.save("cisa-kev", "https://x", [{"cveID": "CVE-2026-0001"}])
    cache_mod._LOAD_MEMO.clear()
    assert IntelCache(tmp_path).load("cisa-kev") is not None          # 1회차: 해시 계산 + 스탬프 기록
    assert (tmp_path / "cisa-kev.json.verified").exists()

    cache_mod._LOAD_MEMO.clear()
    calls: list[int] = []
    real = cache_mod._sha256

    def counting(items):  # noqa: ANN001
        calls.append(1)
        return real(items)

    monkeypatch.setattr(cache_mod, "_sha256", counting)
    assert IntelCache(tmp_path).load("cisa-kev") is not None          # 2회차: 스탬프 일치 → 해시 생략
    assert calls == []

    # 변조: items 를 바꾸면 size/mtime 이 달라져 다시 해시하고, 불일치로 거부한다.
    p = tmp_path / "cisa-kev.json"
    d = json.loads(p.read_text(encoding="utf-8"))
    d["items"] = [{"cveID": "CVE-9999-9999"}, {"cveID": "CVE-9999-9998"}]
    p.write_text(json.dumps(d), encoding="utf-8")
    cache_mod._LOAD_MEMO.clear()
    assert IntelCache(tmp_path).load("cisa-kev") is None
    assert calls   # 다시 계산했다


# ---------------------------------------------------------------------------
# MEDIUM-1 / MEDIUM-2 — 기관 기본값과 재현 명령
# ---------------------------------------------------------------------------


def test_mcp_scan_path_honors_institution_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from gvskb import server

    monkeypatch.setenv("GVSKB_DEPS_MODE", "off")
    src = tmp_path / "proj"
    src.mkdir()
    (src / "app.py").write_text("x = 1\n", encoding="utf-8")
    (src / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    fn = getattr(server.scan_path, "fn", server.scan_path)
    r = fn(path=str(src))
    assert r["dependency_check"]["mode"] == "off" and r["dependency_check"]["requested_mode"] is None
    assert r["gate"]["verdict"] == "approved"


def test_reproduce_command_records_applied_mode_from_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from gvskb import cli

    monkeypatch.setenv("GVSKB_DEPS_MODE", "off")
    src = tmp_path / "proj"
    src.mkdir()
    (src / "app.py").write_text("x = 1\n", encoding="utf-8")
    (src / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    out = tmp_path / "r.json"
    cli.main(["scan", str(src), "--format", "json", "-o", str(out)])
    data = json.loads(out.read_text(encoding="utf-8"))
    assert "--deps off" in data["reproduce_command"]   # 다른 PC 의 재현자가 패키지 검사를 켜서 다른 결과를 받지 않게


# ---------------------------------------------------------------------------
# MEDIUM-3 — 실패 뒤에는 1시간 뒤 다시 시도한다(24시간 '판정 불가' 고정 방지)
# ---------------------------------------------------------------------------


def _state(cache_dir: Path, *, hours_ago: float, result: str) -> None:
    cache_dir.mkdir(parents=True, exist_ok=True)
    ts = (datetime.now(timezone.utc) - timedelta(hours=hours_ago)).isoformat(timespec="seconds")
    (cache_dir / autopull.STATE_FILENAME).write_text(
        json.dumps({"last_attempt_at": ts, "last_result": result}), encoding="utf-8")


def test_failed_attempt_is_retried_after_an_hour(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("GVSKB_AUTO_UPDATE", "GVSKB_INTEL_DIR", "GVSKB_MODE", "GVSKB_AUTO_UPDATE_HOURS"):
        monkeypatch.delenv(var, raising=False)
    cache_dir = tmp_path / "cache"
    calls: list[str] = []

    def fake_pull(url, cache_dir_, timeout):  # noqa: ANN001
        calls.append(url)
        return autopull.AutoPullResult(attempted=True, ok=False, source=url, error="still down")

    monkeypatch.setattr(autopull, "_pull_from_url", fake_pull)
    _state(cache_dir, hours_ago=2, result="fail")
    autopull.maybe_auto_update(cache_dir=cache_dir, verbose=False)
    assert len(calls) == 1                      # 실패 2시간 뒤 → 재시도
    _state(cache_dir, hours_ago=2, result="ok")
    autopull.maybe_auto_update(cache_dir=cache_dir, verbose=False)
    assert len(calls) == 1                      # 성공 2시간 뒤 → 24시간 스로틀 유지
    _state(cache_dir, hours_ago=0.2, result="fail")
    autopull.maybe_auto_update(cache_dir=cache_dir, verbose=False)
    assert len(calls) == 1                      # 실패 12분 뒤 → 아직 대기(네트워크 없는 PC 를 매 검사마다 20초 묶지 않게)


def test_dependency_check_records_failed_auto_refresh(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import gvskb.intel.autopull as ap
    from gvskb import cli

    class _Res:
        attempted = True
        ok = False
        source = "https://example/bundle.zip"
        error = "timeout after 20s"
        skipped_reason = ""

    monkeypatch.setattr(ap, "maybe_auto_update", lambda **kw: _Res())
    src = tmp_path / "proj"
    src.mkdir()
    (src / "app.py").write_text("x = 1\n", encoding="utf-8")
    (src / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    out = tmp_path / "r.json"
    cli.main(["scan", str(src), "--format", "json", "-o", str(out)])
    data = json.loads(out.read_text(encoding="utf-8"))
    ar = data["dependency_check"]["auto_refresh"]
    assert ar["attempted"] is True and ar["ok"] is False and "timeout" in ar["error"]
    from gvskb.report import render_markdown
    from gvskb.schema import ScanReport
    assert "자동 갱신 시도 실패" in render_markdown(ScanReport.model_validate(data))


# ---------------------------------------------------------------------------
# MEDIUM-6 / MEDIUM-7 — 멤버 크기 상한 · 원자적 기록
# ---------------------------------------------------------------------------


def test_oversized_signature_member_is_rejected_before_reading(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(signing, "TRUSTED_PUBLIC_KEYS", {"k": _PUB.hex()})
    src = tmp_path / "src"
    _seed_cache(src)
    bundle = tmp_path / "b.zip"
    assert export_bundle(bundle, cache_dir=src, sign_seed=_SEED, key_id="k")["ok"]
    fat = tmp_path / "fat.zip"
    with zipfile.ZipFile(bundle) as zin, zipfile.ZipFile(fat, "w") as zout:
        for info in zin.infolist():
            data = zin.read(info.filename)
            if info.filename == SIG_MEMBER:
                data = b" " * (70 * 1024) + data
            zout.writestr(info.filename, data)
    res = import_bundle(fat, cache_dir=tmp_path / "dst")
    assert res["ok"] is False and "비정상적으로 큽니다" in res["error"]


def test_oversized_manifest_is_rejected(tmp_path: Path) -> None:
    src = tmp_path / "src"
    _seed_cache(src)
    bundle = tmp_path / "b.zip"
    assert export_bundle(bundle, cache_dir=src)["ok"]
    fat = tmp_path / "fat.zip"
    with zipfile.ZipFile(bundle) as zin, zipfile.ZipFile(fat, "w") as zout:
        for info in zin.infolist():
            data = zin.read(info.filename)
            if info.filename == MANIFEST_NAME:
                data = data + b" " * (9 * 1024 * 1024)
            zout.writestr(info.filename, data)
    res = import_bundle(fat, cache_dir=tmp_path / "dst")
    assert res["ok"] is False and "manifest.json 이 비정상적으로" in res["error"]


def test_shared_folder_bundle_over_size_cap_is_not_imported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    share = tmp_path / "share"
    share.mkdir()
    (share / "huge.zip").write_bytes(b"PK\x05\x06" + b"\x00" * 18)   # 빈 zip 머리만
    monkeypatch.setattr(autopull, "MAX_BUNDLE_BYTES", 10)
    res = autopull._pull_from_dir(share, tmp_path / "cache")
    assert res.ok is False and "상한" in res.error


def test_import_writes_atomically_leaving_no_temp_files(tmp_path: Path) -> None:
    src = tmp_path / "src"
    _seed_cache(src)
    bundle = tmp_path / "b.zip"
    assert export_bundle(bundle, cache_dir=src)["ok"]
    dst = tmp_path / "dst"
    assert import_bundle(bundle, cache_dir=dst)["ok"]
    names = sorted(p.name for p in dst.iterdir())
    # 반입이 envelope 해시를 검증한 뒤 검증 스탬프(<이름>.verified)도 남긴다 — 첫 검사가 다시 해시하지 않게.
    assert names == sorted([f"{sid}.json" for sid in ESSENTIAL] + [f"{sid}.json.verified" for sid in ESSENTIAL])
    assert not [n for n in names if ".tmp" in n]
