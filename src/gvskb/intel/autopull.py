"""인텔 캐시 자동 당김 — 사용자가 '갱신'을 의식하지 않게 만드는 계층.

문제: 인텔 번들은 매일 자동 생성되지만, 각 PC 는 스스로 갱신되지 않았다.
사용자가 ``gvskb update-intel`` 을 기억해 실행해야 했고, 잊으면 캐시가 비거나
낡아 KEV 대조·악성 판정이 조용히 약해졌다(정직하게 stale 표시는 되지만,
사용자에게 수동 작업을 요구하는 설계 자체가 실패다).

해법: **서버 기동/검사 시점에 스스로 신선도를 확인하고, 낡았으면 당겨온다.**

- **스로틀**: 하루 1회만 시도한다(성공·실패 무관). 시도 기록은 캐시 디렉터리의
  ``.autopull-state.json`` 에 남는다 — 매 호출마다 네트워크를 두드리지 않는다.
- **비차단**: 당김 실패가 검사를 막지 않는다. 실패해도 스캔은 계속되고 결과에
  낡음이 정직하게 표시된다.
- **옵트아웃**: ``GVSKB_AUTO_UPDATE=off`` 로 완전히 끈다(기관이 갱신 시점을
  통제하고 싶을 때). 기본값은 on.
- **무결성**: 어떤 경로로 받든 기존 검증을 그대로 통과해야만 반영된다
  (번들 manifest sha256 전수 검증 + 로드 시 envelope sha256 재검증).

소스 계층(우선순위):

1. ``GVSKB_INTEL_DIR`` — 로컬/공유 폴더의 번들 파일. **망분리 1순위**.
   관리자가 공유폴더에 번들을 놓아두면, 각 PC 가 자기 캐시보다 새 번들을
   발견했을 때 자동 반입한다(사용자 조작 0회).
2. ``GVSKB_INTEL_URL`` — 번들 zip 을 받을 HTTP(S) 주소. 기관 레지스트리가
   완성되면 이 값만 내부 배포 엔드포인트로 바꾸면 된다.
3. 기본값 — 공개 GitHub 릴리스(``intel-latest``). 오픈소스 사용자·인터넷망
   사용자는 아무 설정 없이 최신 위협 인텔을 받는다.

``GVSKB_MODE=offline`` 이면 1번(폴더)만 시도한다 — 망분리에서 외부 통신을
시도하지 않는다는 원칙을 지키면서도, 반입된 번들은 자동 반영한다.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .bundle import import_bundle
from .cache import IntelCache, default_cache_dir, intel_max_age_days

# 공개 기본 소스 — GitHub Actions 가 매일 03:00 KST 갱신하는 고정 URL.
DEFAULT_BUNDLE_URL = (
    "https://github.com/Lex6won/vibecode-checker/releases/download/"
    "intel-latest/gvskb-intel-bundle.zip"
)

STATE_FILENAME = ".autopull-state.json"
DEFAULT_THROTTLE_HOURS = 24

# 자동 당김이 '있어야 한다'고 보는 핵심 소스 — 하나라도 없으면 낡음 이전에
# '비어 있음'이므로 즉시 당김 대상이다.
ESSENTIAL_SOURCES = ("osv-malicious", "cisa-kev")

_TRUTHY = {"1", "true", "yes", "on"}
_FALSY = {"0", "false", "no", "off"}


@dataclass
class AutoPullResult:
    """자동 당김 1회 시도 결과 — doctor/server_status 가 그대로 노출한다."""

    attempted: bool = False
    ok: bool = False
    skipped_reason: str = ""
    source: str = ""             # 실제로 사용한 소스(경로 또는 URL)
    sources_updated: list[str] | None = None
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "attempted": self.attempted,
            "ok": self.ok,
            "skipped_reason": self.skipped_reason,
            "source": self.source,
            "sources_updated": self.sources_updated or [],
            "error": self.error,
        }


def auto_update_enabled() -> bool:
    """자동 당김 활성 여부. GVSKB_AUTO_UPDATE=off 로 끈다(기본 on)."""
    raw = os.environ.get("GVSKB_AUTO_UPDATE", "").strip().lower()
    if raw in _FALSY:
        return False
    return True


def throttle_hours() -> int:
    """당김 재시도 최소 간격(시간). GVSKB_AUTO_UPDATE_HOURS 로 조정."""
    raw = os.environ.get("GVSKB_AUTO_UPDATE_HOURS", "").strip()
    try:
        return max(1, int(raw)) if raw else DEFAULT_THROTTLE_HOURS
    except ValueError:
        return DEFAULT_THROTTLE_HOURS


def bundle_dir() -> Path | None:
    """번들 파일을 찾을 폴더(망분리 공유폴더). GVSKB_INTEL_DIR."""
    raw = os.environ.get("GVSKB_INTEL_DIR", "").strip()
    return Path(raw) if raw else None


def bundle_url() -> str:
    """번들을 받을 주소. GVSKB_INTEL_URL 미설정 시 공개 GitHub 릴리스."""
    return os.environ.get("GVSKB_INTEL_URL", "").strip() or DEFAULT_BUNDLE_URL


def _is_offline() -> bool:
    return os.environ.get("GVSKB_MODE", "").lower() == "offline"


def _state_path(cache_dir: Path) -> Path:
    return cache_dir / STATE_FILENAME


def _read_state(cache_dir: Path) -> dict:
    try:
        return json.loads(_state_path(cache_dir).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _write_state(cache_dir: Path, **fields) -> None:
    """시도 기록. 실패해도 조용히 넘어간다(상태 파일은 편의 장치일 뿐)."""
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        state = _read_state(cache_dir)
        state.update(fields)
        state["last_attempt_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        _state_path(cache_dir).write_text(
            json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    except OSError:
        pass


def _hours_since_last_attempt(cache_dir: Path) -> float | None:
    raw = _read_state(cache_dir).get("last_attempt_at")
    if not raw:
        return None
    try:
        ts = datetime.fromisoformat(str(raw))
    except (ValueError, TypeError):
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - ts).total_seconds() / 3600.0


def cache_needs_refresh(cache_dir: Path | None = None) -> tuple[bool, str]:
    """(갱신 필요 여부, 사유). 비어 있거나 신선도 초과면 True."""
    cache = IntelCache(cache_dir)
    missing = [sid for sid in ESSENTIAL_SOURCES if cache.load(sid) is None]
    if missing:
        return True, f"필수 인텔 캐시 없음: {', '.join(missing)}"
    stale = [sid for sid in ESSENTIAL_SOURCES
             if (e := cache.load(sid)) is not None and e.is_stale()]
    if stale:
        return True, f"캐시 신선도({intel_max_age_days()}일) 초과: {', '.join(stale)}"
    return False, "캐시가 최신입니다"


def _latest_bundle_in_dir(d: Path) -> Path | None:
    """폴더에서 가장 최근 수정된 zip 번들을 고른다."""
    if not d.is_dir():
        return None
    candidates = sorted(d.glob("*.zip"), key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0] if candidates else None


def _pull_from_dir(d: Path, cache_dir: Path | None) -> AutoPullResult:
    """공유폴더 번들 반입 — 망분리 1순위 경로."""
    bundle = _latest_bundle_in_dir(d)
    if bundle is None:
        return AutoPullResult(attempted=True, ok=False, source=str(d),
                              error="폴더에서 번들(zip)을 찾지 못했습니다")
    res = import_bundle(bundle, cache_dir=cache_dir)
    if res.get("ok"):
        return AutoPullResult(attempted=True, ok=True, source=str(bundle),
                              sources_updated=res.get("sources") or [])
    return AutoPullResult(attempted=True, ok=False, source=str(bundle),
                          error=str(res.get("error", "반입 실패")))


def _pull_from_url(url: str, cache_dir: Path | None, timeout: float) -> AutoPullResult:
    """HTTP(S) 번들 다운로드 후 반입. 검증은 import_bundle 이 담당한다."""
    import httpx

    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            resp = client.get(url)
            resp.raise_for_status()
            payload = resp.content
    except Exception as exc:  # noqa: BLE001 — 네트워크 실패가 검사를 막으면 안 된다
        return AutoPullResult(attempted=True, ok=False, source=url,
                              error=f"번들 다운로드 실패: {exc!s}")

    tmp = Path(tempfile.gettempdir()) / "gvskb-autopull-bundle.zip"
    try:
        tmp.write_bytes(payload)
        res = import_bundle(tmp, cache_dir=cache_dir)
    except OSError as exc:
        return AutoPullResult(attempted=True, ok=False, source=url,
                              error=f"임시 파일 처리 실패: {exc!s}")
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass

    if res.get("ok"):
        return AutoPullResult(attempted=True, ok=True, source=url,
                              sources_updated=res.get("sources") or [])
    return AutoPullResult(attempted=True, ok=False, source=url,
                          error=str(res.get("error", "반입 실패")))


def maybe_auto_update(
    *,
    cache_dir: Path | None = None,
    force: bool = False,
    timeout: float = 30.0,
    verbose: bool = True,
) -> AutoPullResult:
    """필요하면 인텔 번들을 당겨 캐시를 갱신한다. 실패는 조용히 넘긴다.

    force=True 는 신선도·스로틀 검사를 건너뛴다(수동 `gvskb update-intel --auto`).
    """
    cdir = cache_dir or default_cache_dir()

    if not auto_update_enabled():
        return AutoPullResult(skipped_reason="GVSKB_AUTO_UPDATE=off (자동 갱신 비활성)")

    if not force:
        needs, reason = cache_needs_refresh(cdir)
        if not needs:
            return AutoPullResult(skipped_reason=reason)
        hours = _hours_since_last_attempt(cdir)
        limit = throttle_hours()
        if hours is not None and hours < limit:
            return AutoPullResult(
                skipped_reason=f"최근 {hours:.1f}시간 전 시도함(재시도 간격 {limit}시간)"
            )

    # 소스 우선순위: 폴더(망분리·기관 배포) → URL(기관 레지스트리 또는 공개 릴리스)
    d = bundle_dir()
    result: AutoPullResult
    if d is not None:
        result = _pull_from_dir(d, cache_dir)
        if not result.ok and _is_offline():
            # 망분리에서는 외부 통신으로 넘어가지 않는다.
            result.error += " (오프라인 모드 — 외부 다운로드는 시도하지 않음)"
            _write_state(cdir, last_result="fail", last_source=result.source)
            if verbose:
                print(f"[gvskb] ⚠ 인텔 자동 갱신 실패: {result.error}", file=sys.stderr)
            return result
        if result.ok:
            _write_state(cdir, last_result="ok", last_source=result.source)
            if verbose:
                print(f"[gvskb] 인텔 캐시 자동 갱신 완료 ← {result.source}", file=sys.stderr)
            return result
    elif _is_offline():
        res = AutoPullResult(
            skipped_reason=(
                "오프라인 모드이며 GVSKB_INTEL_DIR 미설정 — 자동 갱신 경로가 없습니다. "
                "관리자가 배포한 번들 폴더를 GVSKB_INTEL_DIR 로 지정하세요."
            )
        )
        return res

    result = _pull_from_url(bundle_url(), cache_dir, timeout)
    _write_state(cdir, last_result="ok" if result.ok else "fail", last_source=result.source)
    if verbose:
        if result.ok:
            print(f"[gvskb] 인텔 캐시 자동 갱신 완료 ← {result.source}", file=sys.stderr)
        else:
            print(f"[gvskb] ⚠ 인텔 자동 갱신 실패(검사는 계속): {result.error}", file=sys.stderr)
    return result


def autopull_status(cache_dir: Path | None = None) -> dict:
    """진단용 상태 요약 — doctor/server_status 가 노출한다."""
    cdir = cache_dir or default_cache_dir()
    needs, reason = cache_needs_refresh(cdir)
    state = _read_state(cdir)
    return {
        "enabled": auto_update_enabled(),
        "needs_refresh": needs,
        "reason": reason,
        "throttle_hours": throttle_hours(),
        "source_dir": str(bundle_dir()) if bundle_dir() else "",
        "source_url": bundle_url(),
        "last_attempt_at": state.get("last_attempt_at", ""),
        "last_result": state.get("last_result", ""),
        "last_source": state.get("last_source", ""),
    }
