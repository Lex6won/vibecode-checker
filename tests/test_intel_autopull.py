"""인텔 캐시 자동 당김 — 신선도 판단·스로틀·소스 계층·옵트아웃 테스트.

사용자가 `gvskb update-intel` 을 기억해 실행하지 않아도 최신 인텔로 검사하게
만드는 계층이다. 네트워크 없이(폴더 소스·모의 클라이언트) 동작을 고정한다.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from gvskb.intel import autopull
from gvskb.intel.autopull import (
    AutoPullResult,
    auto_update_enabled,
    autopull_status,
    cache_needs_refresh,
    maybe_auto_update,
    throttle_hours,
)
from gvskb.intel.bundle import export_bundle
from gvskb.intel.cache import IntelCache


def _seed_cache(cache_dir: Path, *, days_old: int = 0) -> None:
    """필수 소스(ESSENTIAL_SOURCES) 캐시를 전부 만든다(신선도 조작 가능).

    목록을 하드코딩하지 않는다 — 필수 소스가 늘 때(osv-vulns, 2026-08-31)마다
    이 헬퍼가 '필수 캐시 없음'에 걸려 테스트 3개가 엉뚱한 사유로 깨졌다.
    """
    cache = IntelCache(cache_dir)
    seed_items = {
        "osv-malicious": [{"id": "MAL-1"}],
        "osv-vulns": [{"id": "GHSA-1", "affected": []}],
        "cisa-kev": [{"cveID": "CVE-2026-1"}],
    }
    for sid in autopull.ESSENTIAL_SOURCES:
        eco = ["PyPI"] if sid.startswith("osv-") else None
        cache.save(sid, f"https://example/{sid}", seed_items.get(sid, [{"id": sid}]),
                   ecosystems=eco)
    if days_old:
        stamp = (datetime.now(timezone.utc) - timedelta(days=days_old)).isoformat(timespec="seconds")
        for sid in autopull.ESSENTIAL_SOURCES:
            p = cache.path_for(sid)
            data = json.loads(p.read_text(encoding="utf-8"))
            data["fetched_at"] = stamp
            p.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch):
    for var in ("GVSKB_AUTO_UPDATE", "GVSKB_AUTO_UPDATE_HOURS", "GVSKB_INTEL_DIR",
                "GVSKB_INTEL_URL", "GVSKB_MODE", "GVSKB_INTEL_MAX_AGE_DAYS"):
        monkeypatch.delenv(var, raising=False)


# ---------------------------------------------------------------------------
# 신선도 판단
# ---------------------------------------------------------------------------


def test_empty_cache_needs_refresh(tmp_path: Path) -> None:
    needs, reason = cache_needs_refresh(tmp_path)
    assert needs is True
    assert "없음" in reason


def test_fresh_cache_does_not_need_refresh(tmp_path: Path) -> None:
    _seed_cache(tmp_path)
    needs, _ = cache_needs_refresh(tmp_path)
    assert needs is False


def test_stale_cache_needs_refresh(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GVSKB_INTEL_MAX_AGE_DAYS", "7")
    _seed_cache(tmp_path, days_old=30)
    needs, reason = cache_needs_refresh(tmp_path)
    assert needs is True
    assert "신선도" in reason


# ---------------------------------------------------------------------------
# 옵트아웃 · 스로틀
# ---------------------------------------------------------------------------


def test_opt_out_disables_pull(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GVSKB_AUTO_UPDATE", "off")
    assert auto_update_enabled() is False
    r = maybe_auto_update(cache_dir=tmp_path, verbose=False)
    assert r.attempted is False
    assert "off" in r.skipped_reason


def test_fresh_cache_skips_pull(tmp_path: Path) -> None:
    _seed_cache(tmp_path)
    r = maybe_auto_update(cache_dir=tmp_path, verbose=False)
    assert r.attempted is False
    assert r.skipped_reason


def test_throttle_prevents_repeat_attempts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """캐시가 비어 있어도 재시도 간격 내에는 다시 두드리지 않는다."""
    monkeypatch.setenv("GVSKB_INTEL_DIR", str(tmp_path / "empty-dir"))
    (tmp_path / "empty-dir").mkdir()
    monkeypatch.setattr(  # 네트워크 폴백을 실패로 고정 — 스로틀만 검증한다
        autopull, "_pull_from_url",
        lambda url, cache_dir, timeout: AutoPullResult(attempted=True, ok=False, source=url, error="네트워크 없음"),
    )
    first = maybe_auto_update(cache_dir=tmp_path, verbose=False)
    assert first.attempted is True          # 1회차: 시도(번들 없어 실패)
    second = maybe_auto_update(cache_dir=tmp_path, verbose=False)
    assert second.attempted is False        # 2회차: 스로틀로 건너뜀
    assert "재시도 간격" in second.skipped_reason


def test_force_bypasses_throttle_and_freshness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _seed_cache(tmp_path)                   # 최신 캐시 — 평소라면 건너뜀
    monkeypatch.setenv("GVSKB_INTEL_DIR", str(tmp_path / "nope"))
    r = maybe_auto_update(cache_dir=tmp_path, force=True, verbose=False)
    assert r.attempted is True


def test_throttle_hours_configurable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GVSKB_AUTO_UPDATE_HOURS", "6")
    assert throttle_hours() == 6
    monkeypatch.setenv("GVSKB_AUTO_UPDATE_HOURS", "bad")
    assert throttle_hours() == 24           # 잘못된 값은 기본값으로


# ---------------------------------------------------------------------------
# 소스 계층 — 폴더(망분리) 우선
# ---------------------------------------------------------------------------


def test_pull_from_shared_folder(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """관리자가 공유폴더에 놓아둔 번들을 사용자가 조작 없이 자동 반입한다."""
    src_cache = tmp_path / "src-cache"
    _seed_cache(src_cache)
    share = tmp_path / "share"
    share.mkdir()
    assert export_bundle(share / "gvskb-intel-bundle.zip", cache_dir=src_cache)["ok"]

    target = tmp_path / "user-cache"
    monkeypatch.setenv("GVSKB_INTEL_DIR", str(share))
    r = maybe_auto_update(cache_dir=target, verbose=False)
    assert r.ok is True
    assert set(r.sources_updated or []) == set(autopull.ESSENTIAL_SOURCES)
    assert IntelCache(target).load("cisa-kev") is not None     # 실제로 반입됨


def test_offline_without_dir_is_skipped_not_network(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """망분리인데 폴더 미설정이면 외부 통신을 시도하지 않고 안내만 남긴다."""
    monkeypatch.setenv("GVSKB_MODE", "offline")

    def _boom(*a, **kw):
        raise AssertionError("오프라인에서 네트워크를 시도하면 안 된다")
    monkeypatch.setattr(autopull, "_pull_from_url", _boom)

    r = maybe_auto_update(cache_dir=tmp_path, verbose=False)
    assert r.attempted is False
    assert "GVSKB_INTEL_DIR" in r.skipped_reason


def test_offline_dir_failure_does_not_fall_back_to_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GVSKB_MODE", "offline")
    empty = tmp_path / "share"
    empty.mkdir()
    monkeypatch.setenv("GVSKB_INTEL_DIR", str(empty))

    def _boom(*a, **kw):
        raise AssertionError("오프라인에서 네트워크로 폴백하면 안 된다")
    monkeypatch.setattr(autopull, "_pull_from_url", _boom)

    r = maybe_auto_update(cache_dir=tmp_path, verbose=False)
    assert r.ok is False
    assert "오프라인" in r.error


def test_online_falls_back_from_dir_to_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """온라인에서는 폴더에 번들이 없으면 URL 로 넘어간다."""
    empty = tmp_path / "share"
    empty.mkdir()
    monkeypatch.setenv("GVSKB_INTEL_DIR", str(empty))
    called: dict = {}

    def _fake_url_pull(url, cache_dir, timeout):
        called["url"] = url
        return AutoPullResult(attempted=True, ok=True, source=url, sources_updated=["cisa-kev"])
    monkeypatch.setattr(autopull, "_pull_from_url", _fake_url_pull)

    monkeypatch.setenv("GVSKB_INTEL_URL", "https://internal.example/bundle.zip")
    r = maybe_auto_update(cache_dir=tmp_path, verbose=False)
    assert r.ok is True
    assert called["url"] == "https://internal.example/bundle.zip"   # 기관 엔드포인트 사용


def test_default_url_used_when_unset(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict = {}

    def _fake(url, cache_dir, timeout):
        seen["url"] = url
        return AutoPullResult(attempted=True, ok=True, source=url)
    monkeypatch.setattr(autopull, "_pull_from_url", _fake)

    maybe_auto_update(cache_dir=tmp_path, verbose=False)
    assert seen["url"] == autopull.DEFAULT_BUNDLE_URL   # 공개 사용자는 무설정 동작


# ---------------------------------------------------------------------------
# 무결성 — 변조 번들은 반입되지 않는다
# ---------------------------------------------------------------------------


def test_tampered_bundle_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import zipfile

    src_cache = tmp_path / "src"
    _seed_cache(src_cache)
    share = tmp_path / "share"
    share.mkdir()
    bundle = share / "b.zip"
    export_bundle(bundle, cache_dir=src_cache)

    # 캐시 내용을 바꿔치기하되 manifest 의 sha256 은 그대로 둔다.
    tampered = share / "tampered.zip"
    with zipfile.ZipFile(bundle) as zin, zipfile.ZipFile(tampered, "w") as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            if item.filename.endswith("cisa-kev.json"):
                data = b'{"evil": true}'
            zout.writestr(item, data)
    bundle.unlink()

    target = tmp_path / "user"
    monkeypatch.setenv("GVSKB_INTEL_DIR", str(share))
    monkeypatch.setenv("GVSKB_MODE", "offline")   # 네트워크 폴백 없이 폴더 결과만 검증
    r = maybe_auto_update(cache_dir=target, verbose=False)
    assert r.ok is False
    assert "sha256" in r.error or "변조" in r.error
    assert IntelCache(target).load("cisa-kev") is None    # 아무것도 쓰이지 않음


# ---------------------------------------------------------------------------
# 상태 노출
# ---------------------------------------------------------------------------


def test_status_reports_config_and_need(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path))
    monkeypatch.setenv("GVSKB_INTEL_URL", "https://reg.example/b.zip")
    st = autopull_status(tmp_path)
    assert st["enabled"] is True
    assert st["needs_refresh"] is True
    assert st["source_url"] == "https://reg.example/b.zip"


def test_state_file_records_attempt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    share = tmp_path / "share"
    share.mkdir()
    monkeypatch.setenv("GVSKB_INTEL_DIR", str(share))
    monkeypatch.setattr(
        autopull, "_pull_from_url",
        lambda url, cache_dir, timeout: AutoPullResult(attempted=True, ok=False, source=url, error="네트워크 없음"),
    )
    maybe_auto_update(cache_dir=tmp_path, verbose=False)
    state = json.loads((tmp_path / autopull.STATE_FILENAME).read_text(encoding="utf-8"))
    assert state["last_attempt_at"]
    assert state["last_result"] == "fail"      # 번들 없음 — 시도 기록은 남는다


def test_sha256_helper_matches_hashlib() -> None:
    from gvskb.intel.bundle import _sha256_bytes
    assert _sha256_bytes(b"abc") == hashlib.sha256(b"abc").hexdigest()
