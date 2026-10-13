"""릴리스 신선도 장치 — "구판 체커로 만든 보고서가 스스로 말한다" (27차, 2026-10-13).

배경: 다른 기관 PC 가 git+https 로 받은 0.4.0 이 수정본이 나온 뒤에도 갱신되지 않아
서버와 다른 판정(STARS 오탐 15건)을 냈고, 보고서만으로는 구판임을 알 수 없었다.
네트워크 없이(모의 fetch) 동작을 고정한다.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from gvskb import cli, release_check
from gvskb.release_check import (
    check_for_update,
    is_newer,
    notice_text,
    parse_version,
    pick_latest,
    stamp_report,
)
from gvskb.report import render_html, render_markdown
from gvskb.scanner import scan_code


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    for var in ("GVSKB_UPDATE_CHECK", "GVSKB_UPDATE_CHECK_HOURS", "GVSKB_MODE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path / "cache"))


def _release(tag: str, *, prerelease: bool = False, draft: bool = False, wheel: bool = True) -> dict:
    assets = []
    if wheel:
        ver = tag.lstrip("v")
        base = f"https://github.com/Lex6won/vibecode-checker/releases/download/{tag}/"
        assets = [
            {"name": f"vibecode_checker-{ver}-py3-none-any.whl", "browser_download_url": base + f"vibecode_checker-{ver}-py3-none-any.whl"},
            {"name": f"vibecode_checker-{ver}-py3-none-any.whl.sha256", "browser_download_url": base + f"vibecode_checker-{ver}-py3-none-any.whl.sha256"},
        ]
    return {"tag_name": tag, "prerelease": prerelease, "draft": draft, "assets": assets,
            "html_url": f"https://github.com/Lex6won/vibecode-checker/releases/tag/{tag}",
            "published_at": "2026-10-13T12:00:00Z"}


# ---------------------------------------------------------------------------
# 버전 비교 · 릴리스 선택
# ---------------------------------------------------------------------------

def test_parse_and_compare_versions() -> None:
    assert parse_version("v0.4.2") == (0, 4, 2)
    assert parse_version("0.10.0") == (0, 10, 0)
    assert parse_version("intel-latest") is None
    assert is_newer("v0.4.2", "0.4.1")
    assert is_newer("0.5", "0.4.9")
    assert not is_newer("0.4.1", "0.4.1")
    assert not is_newer("0.4.0", "0.4.1")
    assert not is_newer(None, "0.4.1") and not is_newer("v1", None)


def test_pick_latest_ignores_intel_bundle_prerelease_and_draft() -> None:
    releases = [
        _release("intel-latest", prerelease=True),   # 매일 갱신되는 인텔 번들 — 목록 맨 위
        _release("v0.5.0", draft=True),
        _release("v0.4.10"),
        _release("v0.4.2"),
        _release("v0.4.9", prerelease=True),
    ]
    best = pick_latest(releases)
    assert best and best["tag"] == "v0.4.10" and best["version"] == "0.4.10"
    assert best["wheel_url"].endswith("v0.4.10/vibecode_checker-0.4.10-py3-none-any.whl")
    assert pick_latest([_release("intel-latest", prerelease=True)]) is None


# ---------------------------------------------------------------------------
# check_for_update — 캐시 · 옵트아웃 · 실패 침묵
# ---------------------------------------------------------------------------

def test_check_reports_update_and_caches_for_ttl(tmp_path: Path) -> None:
    calls: list[float] = []

    def fetch(timeout: float):
        calls.append(timeout)
        return pick_latest([_release("v9.9.9")])

    first = check_for_update(installed="0.4.1", fetch=fetch)
    assert first and first["update_available"] and first["latest"] == "9.9.9"
    assert first["install_command"].startswith("pip install --force-reinstall https://github.com/")
    assert first["source"] == "network"
    second = check_for_update(installed="0.4.1", fetch=fetch)
    assert second and second["source"] == "cache" and second["update_available"]
    assert len(calls) == 1, "TTL 안에서는 네트워크를 다시 쓰지 않는다"
    third = check_for_update(installed="0.4.1", fetch=fetch, force=True)
    assert third["source"] == "network" and len(calls) == 2


def test_check_is_quiet_when_up_to_date_or_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    def fetch(_t: float):
        return pick_latest([_release("v0.4.2")])

    info = check_for_update(installed="0.4.2", fetch=fetch)
    assert info and not info["update_available"]
    assert notice_text(info) is None

    monkeypatch.setenv("GVSKB_UPDATE_CHECK", "off")
    assert check_for_update(installed="0.0.1", fetch=fetch) is None
    monkeypatch.delenv("GVSKB_UPDATE_CHECK")
    monkeypatch.setenv("GVSKB_MODE", "offline")
    assert check_for_update(installed="0.0.1", fetch=fetch) is None


def test_network_failure_is_silent_and_remembered(tmp_path: Path) -> None:
    calls = []

    def fetch(_t: float):
        calls.append(1)
        raise ConnectionError("proxy blocked")

    assert check_for_update(installed="0.4.1", fetch=fetch) is None
    assert check_for_update(installed="0.4.1", fetch=fetch) is None
    assert len(calls) == 1, "실패도 TTL 동안 기억해 검사마다 타임아웃을 기다리지 않는다"
    state = json.loads((tmp_path / "cache" / release_check.STATE_FILENAME).read_text(encoding="utf-8"))
    assert "proxy blocked" in state["error"]


def test_expired_cache_refetches(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    old = (datetime.now(timezone.utc) - timedelta(hours=30)).isoformat(timespec="seconds")
    (cache / release_check.STATE_FILENAME).write_text(
        json.dumps({"checked_at": old, "latest": pick_latest([_release("v0.4.1")])}), encoding="utf-8")
    info = check_for_update(installed="0.4.1", fetch=lambda _t: pick_latest([_release("v0.4.3")]))
    assert info["source"] == "network" and info["latest"] == "0.4.3"


# ---------------------------------------------------------------------------
# 보고서가 스스로 "구판"이라고 말한다
# ---------------------------------------------------------------------------

def test_stale_checker_is_stamped_into_report_and_rendered(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    monkeypatch.setattr(release_check, "fetch_latest",
                        lambda timeout=3.0: pick_latest([_release("v9.0.0")]))
    report = scan_code("x = 1\n", filename="a.py")
    info = stamp_report(report)
    assert info and report.checker_update["update_available"] is True
    assert "구판" in capsys.readouterr().err
    md = render_markdown(report)
    html = render_html(report)
    for out in (md, html):
        assert "구판 체커" in out and "9.0.0" in out and "pip install --force-reinstall" in out
    # JSON 왕복 — 구버전 소비자도 필드를 모른 채 파싱할 수 있다
    data = report.model_dump(mode="json")
    assert data["checker_update"]["latest"] == "9.0.0"


def test_current_checker_leaves_report_clean(monkeypatch: pytest.MonkeyPatch) -> None:
    from gvskb import __version__
    monkeypatch.setattr(release_check, "fetch_latest",
                        lambda timeout=3.0: pick_latest([_release(f"v{__version__}")]))
    report = scan_code("x = 1\n", filename="a.py")
    stamp_report(report)
    assert report.checker_update and not report.checker_update["update_available"]
    assert "구판 체커" not in render_markdown(report)


def test_scan_cli_stamps_checker_update(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(release_check, "fetch_latest",
                        lambda timeout=3.0: pick_latest([_release("v9.0.0")]))
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    out = tmp_path / "r.json"
    rc = cli.main(["scan", str(tmp_path), "--format", "json", "-o", str(out)])
    assert rc == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["checker_update"]["update_available"] is True


# ---------------------------------------------------------------------------
# gvskb upgrade · doctor
# ---------------------------------------------------------------------------

def test_upgrade_prints_command_without_running(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    monkeypatch.setattr(release_check, "fetch_latest",
                        lambda timeout=3.0: pick_latest([_release("v9.0.0")]))
    import subprocess
    monkeypatch.setattr(subprocess, "call", lambda *a, **k: pytest.fail("--run 없이 pip 를 실행하면 안 된다"))
    rc = cli.main(["upgrade"])
    out = capsys.readouterr().out
    assert rc == cli.EXIT_FINDINGS_WARN
    assert "pip install --force-reinstall https://github.com/Lex6won/vibecode-checker/releases/download/v9.0.0/" in out


def test_upgrade_up_to_date(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    from gvskb import __version__
    monkeypatch.setattr(release_check, "fetch_latest",
                        lambda timeout=3.0: pick_latest([_release(f"v{__version__}")]))
    assert cli.main(["upgrade"]) == cli.EXIT_OK
    assert "최신입니다" in capsys.readouterr().out


def test_upgrade_run_uses_this_interpreter(monkeypatch: pytest.MonkeyPatch) -> None:
    import subprocess
    import sys

    monkeypatch.setattr(release_check, "fetch_latest",
                        lambda timeout=3.0: pick_latest([_release("v9.0.0")]))
    seen: list[list[str]] = []
    monkeypatch.setattr(subprocess, "call", lambda cmd, *a, **k: (seen.append(list(cmd)), 0)[1])
    assert cli.main(["upgrade", "--run"]) == cli.EXIT_OK
    assert seen[0][:5] == [sys.executable, "-m", "pip", "install", "--force-reinstall"]
    assert seen[0][5].endswith("vibecode_checker-9.0.0-py3-none-any.whl")
    assert seen[1] == [sys.executable, "-m", "gvskb", "status"]


def test_doctor_warns_on_stale_release(monkeypatch: pytest.MonkeyPatch) -> None:
    from gvskb import diagnostics
    monkeypatch.setattr(release_check, "fetch_latest",
                        lambda timeout=3.0: pick_latest([_release("v9.0.0")]))
    [c] = diagnostics.check_release_freshness()
    assert c["status"] == "warn" and "9.0.0" in c["value"] and "gvskb upgrade" in c["note"]
    monkeypatch.setenv("GVSKB_UPDATE_CHECK", "off")
    [c] = diagnostics.check_release_freshness()
    assert c["status"] == "ok"
