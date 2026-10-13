"""설치본이 최신 릴리스인가 — GitHub 릴리스 대조(비차단 · 하루 캐시 · 옵트아웃).

왜 있나(2026-10-13): 다른 기관 PC 가 `git+https://…` 로 0.4.0 을 설치한 뒤 수정본이 나와도
같은 버전 번호라 pip 가 갱신하지 않았고, 그 PC 의 보고서(STARS)는 서버와 다른 판정(오탐 15건)을
냈다. 검토자는 보고서만 보고는 "구판 체커로 만든 결과"라는 사실을 알 수 없었다.

이 모듈은 세 곳에서 쓰인다.

1. ``gvskb scan`` / MCP ``scan_path`` — 결과에 ``checker_update`` 를 새겨 **보고서가 스스로
   "구판 엔진으로 만들었다"고 말하게** 한다(머리표 '판정 기준' 칸). stderr 한 줄도 낸다.
2. ``gvskb upgrade`` — 최신 wheel 주소와 설치 명령을 출력하고(``--run`` 이면 실행).
3. ``gvskb doctor`` — 네트워크 점검 묶음에서 WARN.

원칙: **절대 검사를 막지 않는다.** 네트워크 실패·차단·망분리는 전부 ``None``(모름) 이고,
실패도 캐시해 검사마다 3초씩 기다리지 않는다. ``GVSKB_UPDATE_CHECK=off`` 또는
``GVSKB_MODE=offline`` 이면 네트워크를 전혀 건드리지 않는다.
"""
from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from . import __version__

REPO = "Lex6won/vibecode-checker"
RELEASES_API = f"https://api.github.com/repos/{REPO}/releases?per_page=30"
RELEASES_PAGE = f"https://github.com/{REPO}/releases/latest"

STATE_FILENAME = ".release-check.json"
DEFAULT_TTL_HOURS = 24
DEFAULT_TIMEOUT = 3.0

_FALSY = {"0", "off", "false", "no"}
#: 릴리스 태그 형식 — `v0.4.2`. `intel-latest`(인텔 번들, 매일 갱신) 는 여기서 걸러진다.
_TAG_RE = re.compile(r"^v?(\d+(?:\.\d+)*)$")
_LEADING_NUM_RE = re.compile(r"^v?(\d+(?:\.\d+)*)")


def enabled() -> bool:
    """릴리스 확인 활성 여부. 망분리(``GVSKB_MODE=offline``)·``GVSKB_UPDATE_CHECK=off`` 면 끈다."""
    if os.environ.get("GVSKB_MODE", "").strip().lower() == "offline":
        return False
    raw = os.environ.get("GVSKB_UPDATE_CHECK", "").strip().lower()
    return raw not in _FALSY


def ttl_hours() -> int:
    raw = os.environ.get("GVSKB_UPDATE_CHECK_HOURS", "").strip()
    try:
        return max(1, int(raw)) if raw else DEFAULT_TTL_HOURS
    except ValueError:
        return DEFAULT_TTL_HOURS


def parse_version(text: str | None) -> tuple[int, ...] | None:
    """`v0.4.2` / `0.4.2` → (0, 4, 2). 숫자 점 표기가 아니면 None."""
    if not text:
        return None
    m = _LEADING_NUM_RE.match(str(text).strip())
    if not m:
        return None
    return tuple(int(p) for p in m.group(1).split("."))


def is_newer(candidate: str | None, installed: str | None) -> bool:
    """candidate 가 installed 보다 높은가. 둘 중 하나라도 못 읽으면 False(모르면 조용히)."""
    a, b = parse_version(candidate), parse_version(installed)
    if a is None or b is None:
        return False
    width = max(len(a), len(b))
    return a + (0,) * (width - len(a)) > b + (0,) * (width - len(b))


def install_command(wheel_url: str) -> str:
    return f"pip install --force-reinstall {wheel_url}"


def pick_latest(releases: list[dict]) -> dict | None:
    """릴리스 목록에서 **정식 버전 태그** 중 가장 높은 것.

    초안(draft)·시험판(prerelease)·`intel-latest` 같은 비버전 태그는 제외한다. GitHub 의
    `releases/latest` 하나만 믿지 않는 이유: '최신' 표시는 사람이 바꿀 수 있고, 인텔 번들
    릴리스가 매일 갱신되며 목록 맨 위에 온다.
    """
    best: dict | None = None
    best_ver: tuple[int, ...] = ()
    for rel in releases or []:
        if not isinstance(rel, dict) or rel.get("draft") or rel.get("prerelease"):
            continue
        tag = str(rel.get("tag_name") or "")
        if not _TAG_RE.match(tag):
            continue
        ver = parse_version(tag) or ()
        if ver > best_ver:
            best, best_ver = rel, ver
    if best is None:
        return None
    wheel_url = None
    sha256_url = None
    for asset in best.get("assets") or []:
        name = str(asset.get("name") or "")
        url = asset.get("browser_download_url")
        if name.endswith(".whl"):
            wheel_url = url
        elif name.endswith(".whl.sha256"):
            sha256_url = url
    tag = str(best["tag_name"])
    return {
        "tag": tag,
        "version": tag[1:] if tag.startswith("v") else tag,
        "wheel_url": wheel_url,
        "sha256_url": sha256_url,
        "page_url": best.get("html_url") or RELEASES_PAGE,
        "published_at": best.get("published_at"),
    }


def fetch_latest(timeout: float = DEFAULT_TIMEOUT) -> dict | None:
    """GitHub 릴리스 API 조회. 실패는 예외로 올린다(호출자가 캐시·침묵을 결정)."""
    import httpx

    headers = {"Accept": "application/vnd.github+json",
               "User-Agent": f"vibecode-checker/{__version__}"}
    with httpx.Client(timeout=timeout, follow_redirects=True, headers=headers) as client:
        resp = client.get(RELEASES_API)
        resp.raise_for_status()
        data = resp.json()
    if not isinstance(data, list):
        raise ValueError("릴리스 목록 형식이 아닙니다")
    return pick_latest(data)


def _state_path(cache_dir: Path | None) -> Path:
    if cache_dir is None:
        from .intel.cache import default_cache_dir
        cache_dir = default_cache_dir()
    return Path(cache_dir) / STATE_FILENAME


def _read_state(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_state(path: Path, state: dict) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")
    except OSError:
        pass  # 상태 파일은 편의 장치 — 못 써도 검사는 진행


def _hours_since(stamp: str | None) -> float | None:
    if not stamp:
        return None
    try:
        then = datetime.fromisoformat(str(stamp))
    except ValueError:
        return None
    if then.tzinfo is None:
        then = then.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - then).total_seconds() / 3600


def _build(latest: dict | None, installed: str, *, source: str, checked_at: str) -> dict | None:
    if not latest:
        return None
    newer = is_newer(latest.get("version"), installed)
    wheel = latest.get("wheel_url")
    return {
        "installed": installed,
        "latest": latest.get("version"),
        "tag": latest.get("tag"),
        "update_available": newer,
        "wheel_url": wheel,
        "page_url": latest.get("page_url") or RELEASES_PAGE,
        "install_command": install_command(wheel) if wheel else None,
        "checked_at": checked_at,
        "source": source,
    }


def check_for_update(
    *,
    installed: str | None = None,
    cache_dir: Path | None = None,
    force: bool = False,
    timeout: float = DEFAULT_TIMEOUT,
    fetch: Callable[[float], dict | None] | None = None,
) -> dict | None:
    """최신 릴리스 대조 결과. **예외를 던지지 않고**, 모르면 None.

    반환 dict: installed · latest · tag · update_available · wheel_url · page_url ·
    install_command · checked_at · source(``network`` | ``cache``).
    같은 TTL(기본 24시간) 안에서는 네트워크를 다시 쓰지 않는다 — 실패도 기억해
    망이 막힌 PC 에서 검사마다 타임아웃을 기다리지 않게 한다.
    """
    if not enabled():
        return None
    installed = installed or __version__
    path = _state_path(cache_dir)
    state = _read_state(path)
    age = _hours_since(state.get("checked_at"))
    if not force and age is not None and age < ttl_hours():
        return _build(state.get("latest"), installed, source="cache",
                      checked_at=str(state.get("checked_at")))

    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    fetcher = fetch or fetch_latest
    try:
        latest = fetcher(timeout)
        _write_state(path, {"checked_at": now, "latest": latest, "error": None})
    except Exception as exc:  # noqa: BLE001 — 네트워크 실패가 검사를 막으면 안 된다
        _write_state(path, {"checked_at": now, "latest": None, "error": str(exc)[:300]})
        return None
    return _build(latest, installed, source="network", checked_at=now)


def notice_text(info: dict | None) -> str | None:
    """구판일 때 사람에게 보여줄 한 줄. 최신이거나 모르면 None."""
    if not info or not info.get("update_available"):
        return None
    cmd = info.get("install_command") or f"릴리스 페이지: {info.get('page_url') or RELEASES_PAGE}"
    return (
        f"이 체커는 구판({info.get('installed')})입니다 — 최신 {info.get('latest')} "
        f"({info.get('tag')}). 갱신: {cmd}  (또는 `gvskb upgrade`)"
    )


def stamp_report(report, *, cache_dir: Path | None = None, stream=None) -> dict | None:
    """ScanReport 에 ``checker_update`` 를 새기고, 구판이면 stderr 에 한 줄 알린다.

    보고서 객체가 필드를 모르는 구버전이어도 예외 없이 넘어간다.
    """
    try:
        info = check_for_update(cache_dir=cache_dir)
    except Exception:  # noqa: BLE001 — 방어: 어떤 경우에도 검사 결과를 막지 않는다
        info = None
    try:
        report.checker_update = info
    except Exception:  # noqa: BLE001
        pass
    text = notice_text(info)
    if text:
        print(f"[gvskb] ⚠ {text}", file=stream or sys.stderr)
    return info
