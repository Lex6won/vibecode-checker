"""위협정보 번들 반입 — 축소 방지 · 옛 번들 건너뛰기 · 공식 주소 서명 필수 · 윈도 동시 접근.

2026-11-07 적대적 검증에서 확인한 것:
- 서명 없는 빈 번들이 `intel-sync` 를 통과해 악성 판정(chalk 5.6.1)이 '없음'으로 뒤집혔다.
- 서명된 번들이라도 항목 수를 보지 않아, 배포 파이프라인이 잘린 목록을 내보내면 그대로 퍼질 수 있었다.
- 검사가 캐시를 읽는 중에 갱신이 교체하면 PermissionError 로 반입이 중단되고 임시파일이 남았다.
"""
from __future__ import annotations

import json
import os
import time
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from gvskb.intel import autopull, cache as cache_mod, signing
from gvskb.intel.bundle import MANIFEST_NAME, _CACHES_PREFIX, export_bundle, import_bundle, shrink_rejected
from gvskb.intel.cache import (
    IntelCache,
    cleanup_stale_temp_files,
    entry_items_sha256,
    replace_with_retry,
)


def _envelope(sid: str, items: list[dict], *, fetched_at: str | None = None,
              ecosystems: list[str] | None = None) -> bytes:
    doc = {
        "schema_version": 2, "source_id": sid,
        "fetched_at": fetched_at or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "url": "https://example/test", "sha256": entry_items_sha256(items),
        "item_count": len(items), "items": items, "ecosystems": ecosystems,
    }
    return json.dumps(doc).encode("utf-8")


def _bundle(path: Path, files: dict[str, bytes]) -> Path:
    import hashlib

    with zipfile.ZipFile(path, "w") as zf:
        manifest = {"bundle_format": 1, "files": [
            {"source_id": name[:-5], "filename": name, "sha256": hashlib.sha256(data).hexdigest()}
            for name, data in files.items()]}
        zf.writestr(MANIFEST_NAME, json.dumps(manifest))
        for name, data in files.items():
            zf.writestr(_CACHES_PREFIX + name, data)
    return path


def _mal_items(n: int) -> list[dict]:
    return [{"id": f"MAL-{i}", "affected": [{"package": f"pkg{i}", "ecosystem": "npm"}]} for i in range(n)]


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("GVSKB_INTEL_ALLOW_SHRINK", signing.ENV_REQUIRE_SIGNATURE, signing.ENV_TRUSTED_KEYS):
        monkeypatch.delenv(name, raising=False)


def _seed(cache_dir: Path, n: int = 100, ecosystems: list[str] | None = None) -> IntelCache:
    c = IntelCache(cache_dir)
    c.save("osv-malicious", "https://example/osv", _mal_items(n), ecosystems=ecosystems or ["PyPI", "npm"])
    return c


# ── 축소 방지 ──
def test_empty_bundle_cannot_wipe_malicious_list(tmp_path: Path) -> None:
    cache_dir = tmp_path / "cache"
    _seed(cache_dir, 100)
    bundle = _bundle(tmp_path / "empty.zip", {"osv-malicious.json": _envelope("osv-malicious", [], ecosystems=["PyPI", "npm"])})
    res = import_bundle(bundle, cache_dir=cache_dir)
    assert res["ok"] is True and shrink_rejected(res) == ["osv-malicious"] and res["sources"] == []
    assert "비어" in res["warning"]
    entry = IntelCache(cache_dir).load("osv-malicious")
    assert entry is not None and entry.item_count == 100  # 기존 판정 근거가 그대로 남는다


def test_large_drop_rejected_small_drop_accepted(tmp_path: Path) -> None:
    cache_dir = tmp_path / "cache"
    _seed(cache_dir, 100)
    drop = _bundle(tmp_path / "drop.zip", {"osv-malicious.json": _envelope("osv-malicious", _mal_items(79), ecosystems=["PyPI", "npm"])})
    assert shrink_rejected(import_bundle(drop, cache_dir=cache_dir)) == ["osv-malicious"]
    ok = _bundle(tmp_path / "ok.zip", {"osv-malicious.json": _envelope("osv-malicious", _mal_items(90), ecosystems=["PyPI", "npm"])})
    res = import_bundle(ok, cache_dir=cache_dir)
    assert res["ok"] is True and res["sources"] == ["osv-malicious"]
    assert IntelCache(cache_dir).load("osv-malicious").item_count == 90


def test_shrink_override_by_flag_and_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cache_dir = tmp_path / "cache"
    _seed(cache_dir, 100)
    small = _bundle(tmp_path / "s.zip", {"osv-malicious.json": _envelope("osv-malicious", _mal_items(10), ecosystems=["PyPI", "npm"])})
    assert import_bundle(small, cache_dir=cache_dir, allow_shrink=True)["sources"] == ["osv-malicious"]
    _seed(cache_dir, 100)
    monkeypatch.setenv("GVSKB_INTEL_ALLOW_SHRINK", "1")
    assert import_bundle(small, cache_dir=cache_dir)["sources"] == ["osv-malicious"]


def test_lost_ecosystem_rejected(tmp_path: Path) -> None:
    """npm 을 빠뜨린 번들이 들어오면 npm 패키지가 전부 '대조 범위 밖'이 된다 — 거부한다."""
    cache_dir = tmp_path / "cache"
    _seed(cache_dir, 100, ecosystems=["PyPI", "npm"])
    pypi_only = _bundle(tmp_path / "p.zip", {"osv-malicious.json": _envelope("osv-malicious", _mal_items(150), ecosystems=["PyPI"])})
    res = import_bundle(pypi_only, cache_dir=cache_dir)
    assert shrink_rejected(res) == ["osv-malicious"] and "npm" in res["warning"]


def test_gaining_ecosystem_is_fine(tmp_path: Path) -> None:
    """개발 PC 가 직접 받은 PyPI 전용 캐시 위에 공식 번들(PyPI+npm)이 오는 평상시 경우."""
    cache_dir = tmp_path / "cache"
    _seed(cache_dir, 100, ecosystems=["PyPI"])
    full = _bundle(tmp_path / "f.zip", {"osv-malicious.json": _envelope("osv-malicious", _mal_items(500), ecosystems=["PyPI", "npm"])})
    assert import_bundle(full, cache_dir=cache_dir)["ok"] is True


def test_unguarded_rolling_source_may_shrink(tmp_path: Path) -> None:
    """최근 N일 창 소스(EPSS·NVD 최근)는 원래 줄었다 늘었다 한다 — 막지 않는다."""
    cache_dir = tmp_path / "cache"
    IntelCache(cache_dir).save("epss-recent", "u", [{"cve": f"CVE-{i}"} for i in range(100)])
    b = _bundle(tmp_path / "e.zip", {"epss-recent.json": _envelope("epss-recent", [{"cve": "CVE-1"}])})
    assert import_bundle(b, cache_dir=cache_dir)["ok"] is True


def test_shrunk_source_is_skipped_but_others_still_update(tmp_path: Path) -> None:
    """축소 거부는 그 소스만 — 예전처럼 번들 전체를 막으면 KEV·NVD 갱신까지 멈췄다(2차 적대적 검증)."""
    cache_dir = tmp_path / "cache"
    c = _seed(cache_dir, 100)
    c.save("cisa-kev", "u", [{"cveID": f"CVE-{i}"} for i in range(50)])
    b = _bundle(tmp_path / "mixed.zip", {
        "cisa-kev.json": _envelope("cisa-kev", [{"cveID": f"CVE-{i}"} for i in range(60)]),
        "osv-malicious.json": _envelope("osv-malicious", [], ecosystems=["PyPI", "npm"]),
    })
    res = import_bundle(b, cache_dir=cache_dir)
    assert res["ok"] is True and res["sources"] == ["cisa-kev"] and shrink_rejected(res) == ["osv-malicious"]
    assert IntelCache(cache_dir).load("cisa-kev").item_count == 60
    assert IntelCache(cache_dir).load("osv-malicious").item_count == 100


def test_integrity_failure_still_rejects_whole_bundle(tmp_path: Path) -> None:
    cache_dir = tmp_path / "cache"
    c = _seed(cache_dir, 100)
    c.save("cisa-kev", "u", [{"cveID": f"CVE-{i}"} for i in range(50)])
    before_kev = IntelCache(cache_dir).load("cisa-kev").sha256
    bad = json.loads(_envelope("osv-malicious", _mal_items(120)))
    bad["item_count"] = 7
    b = _bundle(tmp_path / "bad.zip", {
        "cisa-kev.json": _envelope("cisa-kev", [{"cveID": f"CVE-{i}"} for i in range(60)]),
        "osv-malicious.json": json.dumps(bad).encode(),
    })
    assert import_bundle(b, cache_dir=cache_dir)["ok"] is False
    assert IntelCache(cache_dir).load("cisa-kev").sha256 == before_kev  # 무결성 실패는 부분 반입 없음


def test_stale_baseline_does_not_block_shrink_forever(tmp_path: Path) -> None:
    """의도한 축소 표시를 놓친 PC — 기준선이 낡으면(기본 2일) 줄어든 데이터를 받는다(정체 상한)."""
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    old = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat(timespec="seconds")
    (cache_dir / "osv-malicious.json").write_bytes(_envelope("osv-malicious", _mal_items(100), fetched_at=old,
                                                             ecosystems=["PyPI", "npm"]))
    b = _bundle(tmp_path / "s.zip", {"osv-malicious.json": _envelope("osv-malicious", _mal_items(10), ecosystems=["PyPI", "npm"])})
    res = import_bundle(b, cache_dir=cache_dir)
    assert res["sources"] == ["osv-malicious"] and not shrink_rejected(res)


def test_wider_coverage_wins_even_if_slightly_older(tmp_path: Path) -> None:
    """직접 받은 PyPI 전용 캐시가 몇 시간 더 최신이어도, npm 까지 담은 번들은 받는다(npm 판정 공백 방지)."""
    cache_dir = tmp_path / "cache"
    _seed(cache_dir, 100, ecosystems=["PyPI"])
    earlier = (datetime.now(timezone.utc) - timedelta(hours=5)).isoformat(timespec="seconds")
    b = _bundle(tmp_path / "f.zip", {"osv-malicious.json": _envelope("osv-malicious", _mal_items(500), fetched_at=earlier,
                                                                       ecosystems=["PyPI", "npm"])})
    assert import_bundle(b, cache_dir=cache_dir)["sources"] == ["osv-malicious"]


# ── 기준선 신뢰(적대적 검증 HIGH-1) ──
@pytest.fixture
def signer(monkeypatch: pytest.MonkeyPatch):
    seed = signing.generate_seed()
    monkeypatch.setattr(signing, "TRUSTED_PUBLIC_KEYS", {"test-key": signing.public_key_from_seed(seed).hex()})
    return seed


def _signed_bundle(tmp_path: Path, seed: bytes, n: int, name: str = "signed.zip", *, ecosystems=None,
                   allow_shrink: bool = False) -> Path:
    src = tmp_path / f"src-{name}"
    import shutil

    shutil.rmtree(src, ignore_errors=True)
    _seed(src, n, ecosystems=ecosystems)
    out = tmp_path / name
    assert export_bundle(out, cache_dir=src, sign_seed=seed, key_id="test-key", allow_shrink=allow_shrink)["ok"]
    return out


def test_unsigned_poison_cannot_lock_out_signed_bundles(tmp_path: Path, signer: bytes) -> None:
    """서명 없는 번들로 생태계를 부풀려 놓아도 다음 공식(서명) 번들이 거부되면 안 된다 — 오염이 고정된다."""
    cache_dir = tmp_path / "cache"
    assert import_bundle(_signed_bundle(tmp_path, signer, 100), cache_dir=cache_dir)["ok"]
    poison = _bundle(tmp_path / "poison.zip", {"osv-malicious.json": _envelope(
        "osv-malicious", _mal_items(300), ecosystems=["PyPI", "npm", "Go"])})
    assert import_bundle(poison, cache_dir=cache_dir)["ok"] is True  # 서명 필수 정책이 없으면 들어온다(설계 한계)
    res = import_bundle(_signed_bundle(tmp_path, signer, 100, "next.zip"), cache_dir=cache_dir)
    assert res["ok"] is True and res["sources"] == ["osv-malicious"]
    assert IntelCache(cache_dir).load("osv-malicious").item_count == 100


def test_far_future_unsigned_file_is_clamped_to_import_time(tmp_path: Path, signer: bytes) -> None:
    """서명 없는 번들의 미래 수집 시각은 반입 시각으로 낮춰 기록한다 — 거부하면 시계 느린 PC 가 기관 번들을 못 받고,
    그대로 두면 캐시가 계속 '신선'으로 보이며 다음 공식 번들을 가린다(최종 적대적 검증)."""
    future = (datetime.now(timezone.utc) + timedelta(hours=20)).isoformat(timespec="seconds")
    poison = _bundle(tmp_path / "p.zip", {"osv-malicious.json": _envelope(
        "osv-malicious", _mal_items(100), fetched_at=future, ecosystems=["PyPI", "npm"])})
    cache_dir = tmp_path / "cache"
    res = import_bundle(poison, cache_dir=cache_dir)
    assert res["ok"] is True and res["clamped_future"] == ["osv-malicious"]
    cache_mod._LOAD_MEMO.clear()
    entry = IntelCache(cache_dir).load("osv-malicious")
    assert entry is not None and entry.fetched_at != future
    info = IntelCache(cache_dir).guard_info("osv-malicious")
    assert info["ecosystems"] == ["PyPI", "npm"]  # 키 순서 보존 — 꼬리에서 생태계를 계속 읽는다
    time.sleep(1.1)
    nxt = import_bundle(_signed_bundle(tmp_path, signer, 100), cache_dir=cache_dir)
    assert nxt["sources"] == ["osv-malicious"]


def test_clamp_survives_odd_header_and_stale_reported_value(tmp_path: Path) -> None:
    future = (datetime.now(timezone.utc) + timedelta(hours=20)).isoformat(timespec="seconds")
    doc = json.loads(_envelope("osv-malicious", _mal_items(5), fetched_at=future, ecosystems=["PyPI", "npm"]))
    doc = {"schema_version": 2, "source_id": "osv-malicious", "fetched_at": future,
           "reported_fetched_at": "2036-11-05T00:00:00+00:00", "url": "x\ud800",
           **{k: doc[k] for k in ("sha256", "item_count", "items", "ecosystems")}}
    b = _bundle(tmp_path / "odd.zip", {"osv-malicious.json": json.dumps(doc).encode("utf-8")})
    cache_dir = tmp_path / "cache"
    res = import_bundle(b, cache_dir=cache_dir)
    assert res["ok"] is True and res["clamped_future"] == ["osv-malicious"]
    written = json.loads((cache_dir / "osv-malicious.json").read_text(encoding="utf-8"))
    assert written["reported_fetched_at"] == future


def test_duplicate_fetched_at_key_rejected(tmp_path: Path) -> None:
    """머리에는 2099년, 실제 해석값은 지금 — peek 가 영원히 '신선'으로 보게 만드는 파일."""
    items = _mal_items(3)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    raw = ('{"schema_version": 2, "source_id": "osv-malicious", "fetched_at": "2099-01-01T00:00:00+00:00", '
           f'"fetched_at": "{now}", "url": "u", "sha256": "{entry_items_sha256(items)}", "item_count": 3, '
           f'"items": {json.dumps(items)}, "ecosystems": ["PyPI", "npm"]}}')
    b = _bundle(tmp_path / "dup.zip", {"osv-malicious.json": raw.encode("utf-8")})
    res = import_bundle(b, cache_dir=tmp_path / "cache")
    assert res["ok"] is False and "두 번" in res["error"]


def test_stamp_rewrite_keeps_signed_origin_when_content_same(tmp_path: Path, signer: bytes) -> None:
    """백업 복원·복사로 파일 시각만 바뀌어도 내용이 같으면 서명 기준선을 잃지 않는다(최종 적대적 검증 LOW-3)."""
    cache_dir = tmp_path / "cache"
    assert import_bundle(_signed_bundle(tmp_path, signer, 100), cache_dir=cache_dir)["ok"]
    p = cache_dir / "osv-malicious.json"
    later = time.time() + 5
    os.utime(p, (later, later))
    cache_mod._LOAD_MEMO.clear()
    assert IntelCache(cache_dir).load("osv-malicious") is not None  # 스탬프를 다시 쓴다
    assert IntelCache(cache_dir).guard_info("osv-malicious")["signed_key"] == "test-key"
    res = import_bundle(_signed_bundle(tmp_path, signer, 10, "cut.zip"), cache_dir=cache_dir)
    assert shrink_rejected(res) == ["osv-malicious"]


def test_slow_clock_pc_keeps_accepting_signed_bundles(tmp_path: Path, signer: bytes,
                                                      monkeypatch: pytest.MonkeyPatch) -> None:
    """시계가 13시간 느린 PC(NTP 없는 망분리 PC) — 서명 번들은 '미래'로 보여도 받고, 다음 날 번들도 받는다(4차 적대적 검증)."""
    from gvskb.intel import bundle as bundle_mod

    first = _signed_bundle(tmp_path, signer, 100)          # 실제 지금 수집
    real_dt = bundle_mod.datetime

    class SlowClock(real_dt):
        @classmethod
        def now(cls, tz=None):
            return real_dt.now(tz) - timedelta(hours=13)

    monkeypatch.setattr(bundle_mod, "datetime", SlowClock)
    monkeypatch.setattr(cache_mod, "_now_iso", lambda: (real_dt.now(timezone.utc) - timedelta(hours=13)).isoformat(timespec="seconds"))
    cache_dir = tmp_path / "cache"
    assert bundle_mod.verify_bundle(first)["ok"] is True
    res1 = import_bundle(first, cache_dir=cache_dir)
    assert res1["ok"] is True and res1["sources"] == ["osv-malicious"]
    time.sleep(1.1)
    res2 = import_bundle(_signed_bundle(tmp_path, signer, 100, "next.zip"), cache_dir=cache_dir)
    assert res2["ok"] is True and res2["sources"] == ["osv-malicious"] and res2["skipped_older"] == []


def test_near_future_unsigned_poison_cannot_shadow_signed_bundle(tmp_path: Path, signer: bytes) -> None:
    """허용 오차 안(59분) 미래 시각이라도 기준선 시각은 이 PC 에 들어온 시각으로 잘린다(3차 적대적 검증 HIGH-1)."""
    cache_dir = tmp_path / "cache"
    assert import_bundle(_signed_bundle(tmp_path, signer, 100), cache_dir=cache_dir)["ok"]
    near = (datetime.now(timezone.utc) + timedelta(minutes=59)).isoformat(timespec="seconds")
    poison_items = _mal_items(100)[1:] + [{"id": "MAL-X", "affected": [{"package": "x", "ecosystem": "npm"}]}]
    poison = _bundle(tmp_path / "p.zip", {"osv-malicious.json": _envelope(
        "osv-malicious", poison_items, fetched_at=near, ecosystems=["PyPI", "npm"])})
    assert import_bundle(poison, cache_dir=cache_dir)["ok"]
    time.sleep(1.1)  # 다음 공식 번들은 오염 반입 뒤에 수집된다
    res = import_bundle(_signed_bundle(tmp_path, signer, 100, "next.zip"), cache_dir=cache_dir)
    assert res["sources"] == ["osv-malicious"] and res["skipped_older"] == []
    ids = {i["id"] for i in IntelCache(cache_dir).load("osv-malicious").items}
    assert "MAL-0" in ids and "MAL-X" not in ids


def test_old_bundle_with_more_ecosystems_cannot_roll_back(tmp_path: Path, signer: bytes) -> None:
    """생태계가 더 많아도 낡은 번들은 '대조 범위 우선' 예외를 받지 못한다(3차 적대적 검증 MEDIUM-2)."""
    old_src = tmp_path / "old-src"
    old_src.mkdir()
    old_ts = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat(timespec="seconds")
    (old_src / "osv-malicious.json").write_bytes(_envelope("osv-malicious", _mal_items(500), fetched_at=old_ts,
                                                           ecosystems=["PyPI", "npm"]))
    old_bundle = tmp_path / "old.zip"
    assert export_bundle(old_bundle, cache_dir=old_src, sign_seed=signer, key_id="test-key")["ok"]
    cache_dir = tmp_path / "cache"
    _seed(cache_dir, 100, ecosystems=["PyPI"])
    res = import_bundle(old_bundle, cache_dir=cache_dir)
    assert res["skipped_older"] == ["osv-malicious"]


def test_strict_mode_blocks_shrink_even_on_stale_baseline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """게시 전 재검증(GVSKB_INTEL_STRICT_SHRINK=1)은 직전 번들이 낡아도 잘린 목록을 막는다(3차 MEDIUM-3)."""
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    old = (datetime.now(timezone.utc) - timedelta(days=4)).isoformat(timespec="seconds")
    (cache_dir / "osv-malicious.json").write_bytes(_envelope("osv-malicious", _mal_items(100), fetched_at=old,
                                                             ecosystems=["PyPI", "npm"]))
    b = _bundle(tmp_path / "s.zip", {"osv-malicious.json": _envelope("osv-malicious", _mal_items(10), ecosystems=["PyPI", "npm"])})
    loose = import_bundle(b, cache_dir=tmp_path / "copy-unused")  # 빈 캐시 — 비교 없음
    assert loose["ok"]
    monkeypatch.setenv("GVSKB_INTEL_STRICT_SHRINK", "1")
    res = import_bundle(b, cache_dir=cache_dir)
    assert shrink_rejected(res) == ["osv-malicious"]


def test_stale_baseline_shrink_is_accepted_with_warning(tmp_path: Path) -> None:
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    old = (datetime.now(timezone.utc) - timedelta(days=4)).isoformat(timespec="seconds")
    (cache_dir / "osv-malicious.json").write_bytes(_envelope("osv-malicious", _mal_items(100), fetched_at=old,
                                                             ecosystems=["PyPI", "npm"]))
    b = _bundle(tmp_path / "s.zip", {"osv-malicious.json": _envelope("osv-malicious", _mal_items(10), ecosystems=["PyPI", "npm"])})
    res = import_bundle(b, cache_dir=cache_dir)
    assert res["sources"] == ["osv-malicious"] and res["accepted_shrink_stale"] and "크게 줄었습니다" in res["warning"]


def test_signed_baseline_still_guards_against_signed_truncation(tmp_path: Path, signer: bytes) -> None:
    """배포 파이프라인이 잘린 목록을 서명해 내보낸 사고 — 서명 기준선이 있는 PC 는 거부한다."""
    cache_dir = tmp_path / "cache"
    assert import_bundle(_signed_bundle(tmp_path, signer, 100), cache_dir=cache_dir)["ok"]
    res = import_bundle(_signed_bundle(tmp_path, signer, 10, "cut.zip"), cache_dir=cache_dir)
    assert shrink_rejected(res) == ["osv-malicious"]


def test_signed_rebaseline_marker_allows_intended_shrink(tmp_path: Path, signer: bytes) -> None:
    cache_dir = tmp_path / "cache"
    assert import_bundle(_signed_bundle(tmp_path, signer, 100), cache_dir=cache_dir)["ok"]
    res = import_bundle(_signed_bundle(tmp_path, signer, 10, "rebase.zip", allow_shrink=True), cache_dir=cache_dir)
    assert res["ok"] is True and res["allow_shrink"] is True


def test_unsigned_rebaseline_marker_is_ignored(tmp_path: Path) -> None:
    cache_dir = tmp_path / "cache"
    _seed(cache_dir, 100)
    src = tmp_path / "src"
    _seed(src, 10)
    b = tmp_path / "u.zip"
    assert export_bundle(b, cache_dir=src, allow_shrink=True)["ok"]
    res = import_bundle(b, cache_dir=cache_dir)
    assert shrink_rejected(res) == ["osv-malicious"]


def test_unsigned_bundle_cannot_shrink_signed_baseline(tmp_path: Path, signer: bytes) -> None:
    cache_dir = tmp_path / "cache"
    assert import_bundle(_signed_bundle(tmp_path, signer, 100), cache_dir=cache_dir)["ok"]
    empty = _bundle(tmp_path / "e.zip", {"osv-malicious.json": _envelope("osv-malicious", [], ecosystems=["PyPI", "npm"])})
    assert shrink_rejected(import_bundle(empty, cache_dir=cache_dir)) == ["osv-malicious"]


def test_forged_future_stamp_does_not_lock_out(tmp_path: Path, signer: bytes) -> None:
    """스탬프에 서명 표시·거대 건수·미래 시각을 위조해도 미래 시각 기준선은 믿지 않는다."""
    cache_dir = tmp_path / "cache"
    assert import_bundle(_signed_bundle(tmp_path, signer, 100), cache_dir=cache_dir)["ok"]
    stamp_path = cache_dir / "osv-malicious.json.verified"
    stamp = json.loads(stamp_path.read_text(encoding="utf-8"))
    stamp["item_count"] = 10 ** 9
    stamp["fetched_at"] = (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(timespec="seconds")
    stamp_path.write_text(json.dumps(stamp), encoding="utf-8")
    res = import_bundle(_signed_bundle(tmp_path, signer, 100, "next.zip"), cache_dir=cache_dir)
    assert res["sources"] == ["osv-malicious"]


def test_old_signed_bundle_cannot_roll_back_newer_cache(tmp_path: Path, signer: bytes,
                                                        monkeypatch: pytest.MonkeyPatch) -> None:
    """공개된 옛 서명 번들을 공유 폴더에 놓아도 더 최신 캐시(직접 수집·스탬프 유실)를 되돌리지 못한다."""
    monkeypatch.setenv(signing.ENV_REQUIRE_SIGNATURE, "1")
    old_src = tmp_path / "old-src"
    old_src.mkdir()
    old_ts = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat(timespec="seconds")
    (old_src / "osv-malicious.json").write_bytes(_envelope("osv-malicious", _mal_items(80), fetched_at=old_ts,
                                                           ecosystems=["PyPI", "npm"]))
    old_bundle = tmp_path / "old.zip"
    assert export_bundle(old_bundle, cache_dir=old_src, sign_seed=signer, key_id="test-key")["ok"]
    cache_dir = tmp_path / "cache"
    _seed(cache_dir, 100)  # 직접 수집(서명 표시 없음)
    res = import_bundle(old_bundle, cache_dir=cache_dir)
    assert res["skipped_older"] == ["osv-malicious"]
    assert IntelCache(cache_dir).load("osv-malicious").item_count == 100


# ── 생태계별 건수 ──
def test_single_ecosystem_truncation_rejected(tmp_path: Path) -> None:
    """전체는 95% 남는데 PyPI 만 통째로 빠진 경우 — 전체 비율로는 못 잡는다."""
    cache_dir = tmp_path / "cache"
    items = _mal_items(9500) + [{"id": f"MAL-P{i}", "affected": [{"package": f"p{i}", "ecosystem": "PyPI"}]} for i in range(600)]
    IntelCache(cache_dir).save("osv-malicious", "u", items, ecosystems=["PyPI", "npm"])
    unsigned_baseline = _bundle(tmp_path / "base.zip", {"osv-malicious.json": _envelope("osv-malicious", items, ecosystems=["PyPI", "npm"])})
    assert import_bundle(unsigned_baseline, cache_dir=cache_dir)["ok"]
    cut = _bundle(tmp_path / "cut.zip", {"osv-malicious.json": _envelope("osv-malicious", _mal_items(9900), ecosystems=["PyPI", "npm"])})
    res = import_bundle(cut, cache_dir=cache_dir)
    assert shrink_rejected(res) == ["osv-malicious"] and "PyPI" in res["warning"]


def test_undeclared_side_ecosystem_drop_is_not_blocking(tmp_path: Path) -> None:
    """취약점 목록에 딸려 온 다른 생태계(Packagist 등)가 줄어도 막지 않는다 — 대조 대상이 아니다."""
    cache_dir = tmp_path / "cache"
    side = [{"id": f"GHSA-{i}", "affected": [{"package": {"name": f"x{i}", "ecosystem": "Packagist"}}]} for i in range(600)]
    base = [{"id": f"PYSEC-{i}", "affected": [{"package": {"name": f"p{i}", "ecosystem": "PyPI"}}]} for i in range(5000)]
    first = _bundle(tmp_path / "a.zip", {"osv-vulns.json": _envelope("osv-vulns", base + side, ecosystems=["PyPI", "npm"])})
    assert import_bundle(first, cache_dir=cache_dir)["ok"]
    second = _bundle(tmp_path / "b.zip", {"osv-vulns.json": _envelope("osv-vulns", base + side[:100], ecosystems=["PyPI", "npm"])})
    assert import_bundle(second, cache_dir=cache_dir)["ok"] is True


def test_osv_partial_download_fails_instead_of_claiming_coverage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """npm zip 을 못 받으면 예전에는 PyPI 만 담고 npm 도 '대조함'으로 적었다 — 이제 수집 실패로 직전 캐시를 지킨다."""
    import io

    from gvskb.intel.sources import osv
    from gvskb.intel.update import update_source

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("MAL-1.json", json.dumps({"id": "MAL-1", "affected": [{"package": {"name": "evil", "ecosystem": "PyPI"}}]}))
    pypi_zip = buf.getvalue()

    class Resp:
        def __init__(self, content: bytes) -> None:
            self.content = content

        def raise_for_status(self) -> None:
            return None

    class Client:
        def get(self, url: str):
            if "/npm/" in url:
                raise ConnectionError("proxy blocked")
            return Resp(pypi_zip)

    monkeypatch.setattr(osv, "_selected_ecosystems", lambda: ("PyPI", "npm"))
    monkeypatch.setattr(osv, "_RETRY_DELAYS", (0.0, 0.0))
    cache = IntelCache(tmp_path / "cache")
    cache.save("osv-malicious", "u", _mal_items(100), ecosystems=["PyPI", "npm"])
    res = update_source("osv-malicious", cache=cache, client=Client())
    assert res.status == "warn" and "npm" in res.error
    assert IntelCache(tmp_path / "cache").load("osv-malicious").item_count == 100


# ── 파일 이름 ──
@pytest.mark.parametrize("name", ["OSV-MALICIOUS.json", "Osv-malicious.json", "osv-malicious.JSON", "osv-malicious"])
def test_non_lowercase_or_non_json_names_rejected(tmp_path: Path, name: str) -> None:
    cache_dir = tmp_path / "cache"
    _seed(cache_dir, 100)
    sid = name[:-5] if name.lower().endswith(".json") else name
    b = _bundle(tmp_path / "c.zip", {name: _envelope(sid, [], ecosystems=["PyPI", "npm"])})
    res = import_bundle(b, cache_dir=cache_dir)
    assert res["ok"] is False
    assert IntelCache(cache_dir).load("osv-malicious").item_count == 100


def test_load_rejects_source_id_mismatch(tmp_path: Path) -> None:
    d = tmp_path / "cache"
    d.mkdir()
    (d / "osv-malicious.json").write_bytes(_envelope("OSV-MALICIOUS", []))
    cache_mod._LOAD_MEMO.clear()
    assert IntelCache(d).load("osv-malicious") is None


def test_duplicate_manifest_entries_rejected(tmp_path: Path) -> None:
    import hashlib

    data = _envelope("cisa-kev", [{"cveID": "CVE-1"}])
    b = tmp_path / "dup.zip"
    with zipfile.ZipFile(b, "w") as zf:
        entry = {"source_id": "cisa-kev", "filename": "cisa-kev.json", "sha256": hashlib.sha256(data).hexdigest()}
        zf.writestr(MANIFEST_NAME, json.dumps({"files": [entry, entry]}))
        zf.writestr(_CACHES_PREFIX + "cisa-kev.json", data)
    assert import_bundle(b, cache_dir=tmp_path / "cache")["ok"] is False


# ── 옛 번들 ──
def test_older_bundle_does_not_overwrite_newer_cache(tmp_path: Path) -> None:
    cache_dir = tmp_path / "cache"
    _seed(cache_dir, 100)  # 지금 시각
    old = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat(timespec="seconds")
    b = _bundle(tmp_path / "old.zip", {"osv-malicious.json": _envelope("osv-malicious", _mal_items(100), fetched_at=old,
                                                                         ecosystems=["PyPI", "npm"])})
    res = import_bundle(b, cache_dir=cache_dir)
    assert res["ok"] is True and res["sources"] == [] and res["skipped_older"] == ["osv-malicious"]
    assert IntelCache(cache_dir).load("osv-malicious").fetched_at != old


def test_future_dated_cache_does_not_block_updates(tmp_path: Path) -> None:
    """시계가 틀린 PC 가 미래 시각으로 받은 캐시는 '더 최신'으로 믿지 않는다 — 영원히 갱신이 막힌다."""
    cache_dir = tmp_path / "cache"
    future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(timespec="seconds")
    p = cache_dir / "osv-malicious.json"
    cache_dir.mkdir(parents=True)
    p.write_bytes(_envelope("osv-malicious", _mal_items(100), fetched_at=future, ecosystems=["PyPI", "npm"]))
    b = _bundle(tmp_path / "now.zip", {"osv-malicious.json": _envelope("osv-malicious", _mal_items(100), ecosystems=["PyPI", "npm"])})
    res = import_bundle(b, cache_dir=cache_dir)
    assert res["ok"] is True and res["sources"] == ["osv-malicious"]


# ── envelope 검사 ──
@pytest.mark.parametrize("mutate, needle", [
    (lambda d: d.update(item_count=5), "item_count"),
    (lambda d: d.update(source_id="cisa-kev"), "source_id"),
    (lambda d: d.update(sha256="0" * 64), "해시"),
    (lambda d: d.pop("sha256"), "해시"),
    (lambda d: d.update(items={"x": 1}), "items"),
])
def test_bad_envelope_rejected_before_write(tmp_path: Path, mutate, needle: str) -> None:
    doc = json.loads(_envelope("osv-malicious", _mal_items(3)))
    mutate(doc)
    b = _bundle(tmp_path / "bad.zip", {"osv-malicious.json": json.dumps(doc).encode()})
    cache_dir = tmp_path / "cache"
    res = import_bundle(b, cache_dir=cache_dir)
    assert res["ok"] is False and needle in res["error"]
    assert not (cache_dir / "osv-malicious.json").exists()


def test_imported_cache_loads_without_rehash_stamp(tmp_path: Path) -> None:
    src = tmp_path / "src"
    _seed(src, 5)
    b = tmp_path / "b.zip"
    assert export_bundle(b, cache_dir=src)["ok"]
    dst = tmp_path / "dst"
    assert import_bundle(b, cache_dir=dst)["ok"]
    stamp = json.loads((dst / "osv-malicious.json.verified").read_text(encoding="utf-8"))
    assert stamp["item_count"] == 5 and stamp["sha256"]
    assert IntelCache(dst).load("osv-malicious").item_count == 5


# ── 공식 주소 = 서명 필수 ──
def test_official_url_detection() -> None:
    assert autopull.is_official_url(autopull.DEFAULT_BUNDLE_URL)
    assert autopull.is_official_url("https://github.com/Lex6won/vibecode-checker/releases/download/intel-test/x.zip")
    assert not autopull.is_official_url("https://intranet.example/intel/gvskb-intel-bundle.zip")
    assert not autopull.is_official_url("https://github.com/someone/vibecode-checker/releases/download/intel-latest/x.zip")


def test_unsigned_bundle_rejected_when_signature_required(tmp_path: Path) -> None:
    src = tmp_path / "src"
    _seed(src, 5)
    b = tmp_path / "b.zip"
    assert export_bundle(b, cache_dir=src)["ok"]
    res = import_bundle(b, cache_dir=tmp_path / "dst", require_signature=True)
    assert res["ok"] is False and "서명" in res["error"]
    assert import_bundle(b, cache_dir=tmp_path / "dst2")["ok"] is True  # 정책 없는 기관 폴더 경로는 그대로


def test_signed_bundle_passes_when_required(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seed = signing.generate_seed()
    monkeypatch.setattr(signing, "TRUSTED_PUBLIC_KEYS", {"test-key": signing.public_key_from_seed(seed).hex()})
    src = tmp_path / "src"
    _seed(src, 5)
    b = tmp_path / "b.zip"
    assert export_bundle(b, cache_dir=src, sign_seed=seed, key_id="test-key")["ok"]
    assert import_bundle(b, cache_dir=tmp_path / "dst", require_signature=True)["ok"] is True


class _FakeResponse:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def iter_bytes(self):
        yield self._payload

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        return None


class _FakeClient:
    payload = b""

    def __init__(self, *a, **k) -> None:
        pass

    def stream(self, method: str, url: str) -> _FakeResponse:
        return _FakeResponse(self.payload)

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        return None


def test_pull_from_official_url_refuses_unsigned(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """GVSKB_INTEL_REQUIRE_SIGNATURE 를 안 켠 PC·예약 작업도 공식 주소에서는 서명 없는 번들을 받지 않는다."""
    import httpx

    src = tmp_path / "src"
    _seed(src, 5)
    b = tmp_path / "b.zip"
    assert export_bundle(b, cache_dir=src)["ok"]
    _FakeClient.payload = b.read_bytes()
    monkeypatch.setattr(httpx, "Client", _FakeClient)
    res = autopull._pull_from_url(autopull.DEFAULT_BUNDLE_URL, tmp_path / "cache", timeout=5)
    assert res.ok is False and "서명" in res.error
    other = autopull._pull_from_url("https://intranet.example/intel.zip", tmp_path / "cache2", timeout=5)
    assert other.ok is True


# ── 윈도 동시 접근 ──
def test_replace_retries_on_permission_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    src, dest = tmp_path / "a.tmp", tmp_path / "a.json"
    src.write_text("new", encoding="utf-8")
    dest.write_text("old", encoding="utf-8")
    real = os.replace
    calls = {"n": 0}

    def flaky(a, b):
        calls["n"] += 1
        if calls["n"] < 3:
            raise PermissionError(32, "being used by another process")
        return real(a, b)

    monkeypatch.setattr(cache_mod.os, "replace", flaky)
    monkeypatch.setattr(cache_mod, "_backoff", lambda attempt: None)
    replace_with_retry(src, dest)
    assert dest.read_text(encoding="utf-8") == "new" and calls["n"] == 3


def test_replace_gives_up_and_removes_temp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    src, dest = tmp_path / "a.tmp", tmp_path / "a.json"
    src.write_text("new", encoding="utf-8")
    dest.write_text("old", encoding="utf-8")

    def locked(a, b):
        raise PermissionError(32, "locked")

    monkeypatch.setattr(cache_mod.os, "replace", locked)
    monkeypatch.setattr(cache_mod, "_backoff", lambda attempt: None)
    with pytest.raises(PermissionError):
        replace_with_retry(src, dest)
    assert not src.exists() and dest.read_text(encoding="utf-8") == "old"


def test_import_reports_lock_failure_without_leftovers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    src = tmp_path / "src"
    _seed(src, 5)
    b = tmp_path / "b.zip"
    assert export_bundle(b, cache_dir=src)["ok"]
    dst = tmp_path / "dst"

    def locked(a, b):
        raise PermissionError(32, "locked")

    monkeypatch.setattr(cache_mod.os, "replace", locked)
    monkeypatch.setattr(cache_mod, "_backoff", lambda attempt: None)
    res = import_bundle(b, cache_dir=dst)
    assert res["ok"] is False and "교체 실패" in res["error"]
    assert not [p.name for p in dst.iterdir() if ".tmp" in p.name]


def test_busy_cache_read_is_not_memoized_as_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cache_dir = tmp_path / "cache"
    _seed(cache_dir, 5)
    cache_mod._LOAD_MEMO.clear()
    real = Path.read_text

    def busy(self, *a, **k):
        if self.name == "osv-malicious.json":
            raise PermissionError(32, "being used by another process")
        return real(self, *a, **k)

    monkeypatch.setattr(cache_mod, "_backoff", lambda attempt: None)
    monkeypatch.setattr(Path, "read_text", busy)
    assert IntelCache(cache_dir).load("osv-malicious") is None
    monkeypatch.setattr(Path, "read_text", real)
    entry = IntelCache(cache_dir).load("osv-malicious")  # 같은 프로세스, 파일 그대로 — 다시 읽어야 한다
    assert entry is not None and entry.item_count == 5


def test_stale_temp_files_are_cleaned_but_caches_kept(tmp_path: Path) -> None:
    d = tmp_path / "cache"
    _seed(d, 2)
    old_tmp = d / ".osv-malicious.json.tmp-999"
    old_stamp_tmp = d / "osv-malicious.json.verified.999.tmp"
    fresh_tmp = d / ".cisa-kev.json.tmp-1000"
    foreign = d / "notes.tmp"
    for p in (old_tmp, old_stamp_tmp, fresh_tmp, foreign):
        p.write_text("x", encoding="utf-8")
    past = time.time() - 7200
    for p in (old_tmp, old_stamp_tmp, foreign):
        os.utime(p, (past, past))
    assert cleanup_stale_temp_files(d) == 2
    assert not old_tmp.exists() and not old_stamp_tmp.exists()
    assert fresh_tmp.exists() and foreign.exists()
    assert (d / "osv-malicious.json").exists() and (d / "osv-malicious.json.verified").exists()


def test_save_is_atomic_and_leaves_no_temp(tmp_path: Path) -> None:
    d = tmp_path / "cache"
    _seed(d, 3)
    _seed(d, 4)
    assert not [p.name for p in d.iterdir() if ".tmp" in p.name]
    assert IntelCache(d).load("osv-malicious").item_count == 4
