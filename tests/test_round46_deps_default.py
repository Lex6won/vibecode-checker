"""46차 — 패키지(의존성) 검사는 **기본 실행**이고, 위협정보 상태가 게이트·보고서·종료코드에서 같은 말을 한다.

사용자 결정(2026-11-02): `--check-deps` 를 붙여야만 패키지를 보던 구조는 공무원에게 조용한 초록불이었다.
- 로컬 위협정보 대조(네트워크 없음)와 신선도 판정은 항상 한다.
- 위협정보가 없으면 '판정 불가'(종료코드 3), 오래됐으면 '조건부'(종료코드 1).
- 온라인 조회(`--deps online`)와 생략(`--deps off`)만 사용자가 고른다. 생략은 기록된다.
- MCP `scan_path` 도 CLI 와 같은 코드·같은 기본값으로 돈다(예전에는 의존성을 전혀 보지 않았다).
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from gvskb.cli import EXIT_FINDINGS_WARN, EXIT_OK, EXIT_UNDETERMINED
from gvskb.deps_check import MODE_LABELS, resolve_deps_mode, user_notice
from gvskb.intel.cache import IntelCache
from gvskb.report import render_markdown
from gvskb.schema import ScanReport

ESSENTIAL = ("osv-malicious", "osv-vulns", "cisa-kev")


def _seed_cache(cache_dir: Path, *, age_days: int = 0) -> None:
    """필수 위협정보 3종을 빈 목록으로 만든다(= 알려진 악성·취약 없음). age_days 로 수집 시각을 과거로."""
    cache = IntelCache(cache_dir)
    for sid in ESSENTIAL:
        cache.save(sid, f"https://example/{sid}", [], ecosystems=["PyPI", "npm"])
    if age_days:
        old = (datetime.now(timezone.utc) - timedelta(days=age_days)).isoformat(timespec="seconds")
        for sid in ESSENTIAL:
            p = cache.path_for(sid)
            d = json.loads(p.read_text(encoding="utf-8"))
            d["fetched_at"] = old   # 지문(sha256)은 items 만 덮으므로 수집 시각은 자유롭게 바꿀 수 있다
            p.write_text(json.dumps(d), encoding="utf-8")


def _project(tmp_path: Path, *, with_manifest: bool = True) -> Path:
    src = tmp_path / "proj"
    src.mkdir()
    (src / "app.py").write_text("total = 1\n", encoding="utf-8")
    if with_manifest:
        (src / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    return src


def _scan(src: Path, out: Path, *extra: str) -> tuple[int, dict]:
    from gvskb import cli

    rc = cli.main(["scan", str(src), "--format", "json", "-o", str(out), *extra])
    return rc, json.loads(out.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# 모드 결정
# ---------------------------------------------------------------------------


def test_default_mode_is_local(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GVSKB_DEPS_MODE", raising=False)
    monkeypatch.delenv("GVSKB_MODE", raising=False)
    assert resolve_deps_mode(None) == ("local", None)
    assert resolve_deps_mode("online") == ("online", None)
    assert resolve_deps_mode("off") == ("off", None)


def test_legacy_check_deps_means_online(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GVSKB_MODE", raising=False)
    assert resolve_deps_mode(None, legacy_check_deps=True) == ("online", None)
    # 명시한 --deps 가 구 옵션보다 우선한다.
    assert resolve_deps_mode("off", legacy_check_deps=True)[0] == "off"


def test_offline_downgrades_online_to_local_and_says_so(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GVSKB_MODE", "offline")
    mode, note = resolve_deps_mode("online")
    assert mode == "local" and note and "offline" in note


def test_env_default_and_unknown_values(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GVSKB_MODE", raising=False)
    monkeypatch.setenv("GVSKB_DEPS_MODE", "off")
    assert resolve_deps_mode(None) == ("off", None)
    monkeypatch.setenv("GVSKB_DEPS_MODE", "bogus")
    mode, note = resolve_deps_mode(None)
    assert mode == "local" and note and "bogus" in note
    assert set(MODE_LABELS) == {"local", "online", "off"}


# ---------------------------------------------------------------------------
# 게이트 · 종료코드 — 위협정보 상태별
# ---------------------------------------------------------------------------


def test_missing_intel_is_undetermined_not_approved(tmp_path: Path) -> None:
    """캐시 없음 + 패키지 있음 = 판정 불가(종료코드 3). 소스가 깨끗해도 '통과'가 아니다."""
    src = _project(tmp_path)
    rc, data = _scan(src, tmp_path / "r.json")
    assert rc == EXIT_UNDETERMINED
    gate = data["gate"]
    assert gate["verdict"] == "undetermined"
    assert gate["intel_gap"] == "missing"
    assert gate["dependency_check_mode"] == "local"
    assert "위협정보" in gate["reason"] and "통과" in gate["reason"]
    dc = data["dependency_check"]
    assert dc["mode"] == "local" and dc["manifests_found"] == 1 and dc["packages_parsed"] == 1
    assert dc["intel"]["state"] == "missing" and set(dc["intel"]["missing"]) == set(ESSENTIAL)
    # 재현 명령은 기본값이므로 --deps 를 달지 않는다.
    assert "--deps" not in data["reproduce_command"]


def test_fresh_intel_and_clean_package_is_approved(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cache_dir = tmp_path / "cache"
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(cache_dir))
    _seed_cache(cache_dir)
    src = _project(tmp_path)
    rc, data = _scan(src, tmp_path / "r.json")
    assert rc == EXIT_OK, data["gate"]["reason"]
    assert data["gate"]["verdict"] == "approved"
    assert data["gate"]["intel_gap"] == ""
    assert data["dependency_check"]["intel"]["state"] == "ok"
    audits = data["dependency_audit"]["audits"]
    assert len(audits) == 1 and audits[0]["manifest"] == "requirements.txt"
    check = audits[0]["checks"][0]
    assert check["verdict"] == "checked_clean" and check["check_mode"] == "local"
    # 사람에게 보이는 말은 '오프라인'이 아니라 '로컬 위협정보'다 — 온라인 PC 에서 "오프라인이라"는 틀린 말이다.
    assert "오프라인" not in (check.get("note") or "")


def test_stale_intel_is_conditional(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cache_dir = tmp_path / "cache"
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(cache_dir))
    monkeypatch.setenv("GVSKB_INTEL_MAX_AGE_DAYS", "2")
    _seed_cache(cache_dir, age_days=9)
    src = _project(tmp_path)
    rc, data = _scan(src, tmp_path / "r.json")
    assert rc == EXIT_FINDINGS_WARN
    gate = data["gate"]
    assert gate["verdict"] == "conditional"
    assert "intel_stale" in gate["conditional_criteria"]
    assert gate["intel_gap"] == "stale"
    assert "9일 전" in gate["reason"]
    assert data["dependency_check"]["intel"]["age_days"] == 9


def test_project_without_packages_is_not_punished_for_missing_intel(tmp_path: Path) -> None:
    """정적 페이지처럼 매니페스트가 없으면 위협정보가 없어도 잃은 것이 없다 — 판정은 그대로."""
    src = _project(tmp_path, with_manifest=False)
    rc, data = _scan(src, tmp_path / "r.json")
    assert rc == EXIT_OK
    assert data["gate"]["verdict"] == "approved"
    assert data["gate"]["intel_gap"] == ""
    dc = data["dependency_check"]
    assert dc["mode"] == "local" and dc["manifests_found"] == 0 and dc["packages_parsed"] == 0
    assert data["dependency_audit"] is None


def test_deps_off_skips_but_records_the_skip(tmp_path: Path) -> None:
    src = _project(tmp_path)
    rc, data = _scan(src, tmp_path / "r.json", "--deps", "off")
    assert rc == EXIT_OK   # 생략은 사용자의 선택 — 게이트는 막지 않되 보고서가 말한다
    dc = data["dependency_check"]
    assert dc["mode"] == "off" and dc["intel"] is None
    assert data["dependency_audit"] is None
    assert "--deps off" in data["reproduce_command"]
    md = render_markdown(ScanReport.model_validate(data))
    assert "패키지 검사를 생략했습니다" in md
    assert "패키지 검사 생략" in md          # 머리표 '판정 기준' 칸
    assert "의존성 검사 별도 필요" not in md  # 옛 배너는 기록 없는 구버전 JSON 에서만


def test_check_deps_alias_still_works_and_is_recorded_as_online(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """구 옵션 호환 — 망분리 환경에서는 online 이 local 로 내려가고 그 사실이 기록된다."""
    monkeypatch.setenv("GVSKB_MODE", "offline")
    cache_dir = tmp_path / "cache"
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(cache_dir))
    _seed_cache(cache_dir)
    src = _project(tmp_path)
    rc, data = _scan(src, tmp_path / "r.json", "--check-deps")
    assert rc == EXIT_OK
    dc = data["dependency_check"]
    assert dc["requested_mode"] == "online" and dc["mode"] == "local"
    assert dc["note"] and "offline" in dc["note"]
    assert "--deps online" in data["reproduce_command"]


# ---------------------------------------------------------------------------
# 보고서 문구 — 사용자에게 필요한 말만
# ---------------------------------------------------------------------------


def test_report_header_and_banner_for_missing_intel(tmp_path: Path) -> None:
    src = _project(tmp_path)
    _, data = _scan(src, tmp_path / "r.json")
    md = render_markdown(ScanReport.model_validate(data))
    assert "위협정보 없음" in md                       # 머리표
    assert "패키지 검사를 하지 못했습니다" in md         # 배너
    assert "gvskb update-intel" in md and "GVSKB_INTEL_DIR" in md
    # 패키지별 캐시 배너와 같은 조치를 두 번 말하지 않는다.
    assert md.count("update-intel") <= 4


def test_report_header_shows_intel_as_of_when_fresh(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cache_dir = tmp_path / "cache"
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(cache_dir))
    _seed_cache(cache_dir)
    src = _project(tmp_path)
    _, data = _scan(src, tmp_path / "r.json")
    md = render_markdown(ScanReport.model_validate(data))
    assert "위협정보" in md and "수집" in md
    assert "패키지 검사를 하지 못했습니다" not in md
    assert "위협정보가" not in md or "일 전 것입니다" not in md


def test_report_banner_for_stale_intel(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cache_dir = tmp_path / "cache"
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(cache_dir))
    _seed_cache(cache_dir, age_days=9)
    src = _project(tmp_path)
    _, data = _scan(src, tmp_path / "r.json")
    md = render_markdown(ScanReport.model_validate(data))
    assert "위협정보가 9일 전 것입니다" in md
    assert "조건부" in md
    assert "9일 경과" in md   # 머리표


def test_user_notice_matches_banner_meaning() -> None:
    assert "생략" in (user_notice({"mode": "off"}) or "")
    missing = user_notice({"mode": "local", "packages_parsed": 3, "intel": {"state": "missing"}})
    assert missing and "통과" in missing and "update-intel" in missing
    stale = user_notice({"mode": "local", "packages_parsed": 3, "intel": {"state": "stale", "age_days": 5}})
    assert stale and "5일 전" in stale
    assert user_notice({"mode": "local", "packages_parsed": 0, "intel": {"state": "missing"}}) is None
    assert user_notice({"mode": "local", "packages_parsed": 2, "intel": {"state": "ok"}}) is None


# ---------------------------------------------------------------------------
# 네트워크 0 — 로컬 모드는 어떤 경우에도 밖으로 나가지 않는다
# ---------------------------------------------------------------------------


def test_local_mode_never_opens_a_network_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import httpx

    def _boom(*a, **kw):  # noqa: ANN001
        raise AssertionError("local 모드가 네트워크 클라이언트를 열었다")

    monkeypatch.setattr(httpx, "AsyncClient", _boom)
    monkeypatch.setattr(httpx, "Client", _boom)
    cache_dir = tmp_path / "cache"
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(cache_dir))
    _seed_cache(cache_dir)
    src = _project(tmp_path)
    rc, data = _scan(src, tmp_path / "r.json")
    assert rc == EXIT_OK and data["dependency_check"]["mode"] == "local"


def test_auto_refresh_is_attempted_for_local_mode_but_not_for_off(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """번들 내려받기는 프로젝트 정보를 보내지 않으므로 로컬 모드에서도 시도한다. off 는 아무것도 안 한다."""
    import gvskb.intel.autopull as ap

    calls: list[dict] = []

    class _Res:
        attempted = False
        ok = False
        source = ""
        error = ""
        skipped_reason = "test"

    def fake(**kw):
        calls.append(kw)
        return _Res()

    monkeypatch.setattr(ap, "maybe_auto_update", fake)
    src = _project(tmp_path)
    _scan(src, tmp_path / "r1.json")
    assert len(calls) == 1
    _scan(src, tmp_path / "r2.json", "--deps", "off")
    assert len(calls) == 1


# ---------------------------------------------------------------------------
# MCP — scan_path 도 같은 기본값
# ---------------------------------------------------------------------------


def test_mcp_scan_path_runs_dependency_check_by_default(tmp_path: Path) -> None:
    from gvskb import server

    fn = getattr(server.scan_path, "fn", server.scan_path)
    src = _project(tmp_path)
    r = fn(path=str(src))
    assert r["dependency_check"]["mode"] == "local"
    assert r["gate"]["intel_gap"] == "missing"
    assert r["gate"]["verdict"] == "undetermined"
    r_off = fn(path=str(src), deps="off")
    assert r_off["dependency_check"]["mode"] == "off"
    assert r_off["gate"]["verdict"] == "approved"


def test_mcp_scan_path_with_fresh_intel_includes_audit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from gvskb import server

    cache_dir = tmp_path / "cache"
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(cache_dir))
    _seed_cache(cache_dir)
    fn = getattr(server.scan_path, "fn", server.scan_path)
    r = fn(path=str(_project(tmp_path)))
    assert r["gate"]["verdict"] == "approved"
    assert r["dependency_audit"]["audits"][0]["checks"][0]["verdict"] == "checked_clean"


def test_mcp_scan_path_runs_inside_a_running_event_loop(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """fastmcp 가 동기 도구를 루프 스레드에서 부르더라도 asyncio.run 충돌 없이 끝나야 한다."""
    import asyncio

    from gvskb import server

    cache_dir = tmp_path / "cache"
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(cache_dir))
    _seed_cache(cache_dir)
    fn = getattr(server.scan_path, "fn", server.scan_path)
    src = _project(tmp_path)

    async def _call():
        return fn(path=str(src))

    r = asyncio.run(_call())
    assert r["dependency_check"]["manifests_found"] == 1
