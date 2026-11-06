"""패키지(의존성) 검사 — **기본 실행** 계층 (46차, 2026-11-02).

## 왜 기본인가

바이브코딩으로 만든 앱은 직접 쓴 코드보다 가져다 쓴 패키지가 훨씬 많다. 실제 악용이
확인된 취약점·악성 패키지는 소스 룰로는 잡히지 않는다 — 그런데 패키지 검사는
``--check-deps`` 를 붙여야만 돌았고, 공무원은 그 옵션을 모른다. 옵션 없이 "승인"이
나오는 결과는 이 도구가 가장 경계하는 **조용한 초록불**이었다(사용자 결정 2026-11-02).

## 세 층으로 나눈다

옵션 하나가 로컬 대조와 외부 조회를 한 덩어리로 켜고 껐기 때문에 기본값 논쟁이 생겼다.
층을 나누면 사라진다.

1. **로컬 대조(항상)** — 매니페스트·락파일을 로컬 위협정보 캐시(OSV 취약점·악성, CISA KEV,
   EPSS, NVD, KNVD)와 대조한다. 프로젝트 정보는 PC 밖으로 나가지 않는다.
2. **신선도 판정(항상)** — 캐시가 없으면 '판정 불가', 오래됐으면 '조건부'. 결과를 믿어도
   되는지와 안 되면 무엇을 하면 되는지를 보고서가 스스로 말한다.
3. **온라인 조회(옵션, ``--deps online``)** — 공식 저장소 실재·발행일·쿨다운 확인과
   OSV 실시간 조회. 패키지명·버전이 외부로 나가므로 사용자가 고른다.

위협정보 번들 **내려받기**(autopull)는 3층이 아니라 1층의 전제다 — 프로젝트 정보를
하나도 보내지 않고 받기만 하므로 로컬 모드에서도 켜 둔다. 망분리(``GVSKB_MODE=offline``)
와 옵트아웃(``GVSKB_AUTO_UPDATE=off``)은 그대로 존중한다.

## 모드

- ``local``(기본) — 1·2층. ``GVSKB_DEPS_MODE`` 환경변수로 기관 기본값을 바꿀 수 있다.
- ``online`` — 1·2·3층. 예전 ``--check-deps`` 와 같다(별칭으로 유지).
- ``off`` — 패키지 검사 생략. 생략했다는 사실이 보고서에 남는다.
"""
from __future__ import annotations

import asyncio
import os
import re
import sys
from pathlib import Path

from .schema import ScanReport

DEPS_MODES: tuple[str, ...] = ("local", "online", "off")
DEFAULT_DEPS_MODE = "local"
ENV_DEPS_MODE = "GVSKB_DEPS_MODE"

#: 사람이 읽는 모드 이름 — 보고서·터미널이 같은 말을 쓴다.
MODE_LABELS: dict[str, str] = {
    "local": "로컬 위협정보 대조(네트워크 없음)",
    "online": "온라인 조회(OSV·공식 저장소, 패키지명·버전만 전송)",
    "off": "생략(사용자 지정)",
}


def _is_offline() -> bool:
    return os.environ.get("GVSKB_MODE", "").lower() == "offline"


def resolve_deps_mode(
    requested: str | None,
    *,
    legacy_check_deps: bool = False,
) -> tuple[str, str | None]:
    """(적용 모드, 조정 사유). 요청값 → ``--check-deps`` 별칭 → 환경변수 → 기본값(local).

    망분리 모드에서 ``online`` 을 요청하면 외부 통신을 하지 않는 ``local`` 로 내리고
    그 사실을 사유로 돌려준다 — 조용히 바꾸면 "온라인으로 검사했다"는 기록이 거짓이 된다.
    모르는 값은 기본값으로 가되 역시 사유를 남긴다.
    """
    note: str | None = None
    mode = (requested or "").strip().lower() or None
    if mode is None and legacy_check_deps:
        mode = "online"
    if mode is None:
        env = os.environ.get(ENV_DEPS_MODE, "").strip().lower()
        if env in DEPS_MODES:
            mode = env
        elif env:
            note = f"{ENV_DEPS_MODE}={env!r} 는 알 수 없는 값 — 기본값 {DEFAULT_DEPS_MODE} 적용"
    if mode not in DEPS_MODES:
        if mode is not None:
            note = f"알 수 없는 패키지 검사 모드 {mode!r} — 기본값 {DEFAULT_DEPS_MODE} 적용"
        mode = DEFAULT_DEPS_MODE
    if mode == "online" and _is_offline():
        mode = "local"
        note = "GVSKB_MODE=offline(망분리) — 온라인 조회 대신 로컬 위협정보 대조로 수행"
    return mode, note


# ---------------------------------------------------------------------------
# 위협정보(인텔) 캐시 상태 — 시스템 단위로 한 번만 계산한다.
# ---------------------------------------------------------------------------

def intel_state(cache_dir: Path | None = None) -> dict:
    """필수 위협정보 캐시의 존재·신선도 → ``{"state": "ok"|"stale"|"missing", ...}``.

    ``as_of`` 는 필수 소스 중 **가장 오래된** 수집 시각이다 — 보고서 머리표에 한 번 적히는
    값이므로 가장 보수적인 쪽을 쓴다. 패키지별 ``intel_cache`` 집계(check_package)와 달리
    이 값은 **검사 결과와 무관하게** 캐시만 보고 정한다: 취약점 0건이라 캐시를 열 일이
    없었던 검사도 "그 캐시가 신선했는가"는 말해야 하기 때문이다.
    """
    from .intel.autopull import ESSENTIAL_SOURCES
    from .intel.cache import IntelCache, intel_max_age_days

    cache = IntelCache(cache_dir)
    limit = intel_max_age_days()
    sources: dict[str, dict] = {}
    missing: list[str] = []
    stale: list[str] = []
    oldest: str | None = None
    for sid in ESSENTIAL_SOURCES:
        try:
            entry = cache.load(sid)
        except Exception:  # noqa: BLE001 — 손상 캐시는 '없음'으로 본다(무결성 실패 = 신뢰 불가)
            entry = None
        if entry is None:
            missing.append(sid)
            sources[sid] = {"fetched_at": None, "age_days": None, "stale": True}
            continue
        age = entry.age_days()
        is_stale = entry.is_stale(limit)
        if is_stale:
            stale.append(sid)
        sources[sid] = {"fetched_at": entry.fetched_at, "age_days": age, "stale": is_stale}
        if entry.fetched_at and (oldest is None or entry.fetched_at < oldest):
            oldest = entry.fetched_at
    if missing:
        state = "missing"
    elif stale:
        state = "stale"
    else:
        state = "ok"
    ages = [s["age_days"] for s in sources.values() if s["age_days"] is not None]
    return {
        "state": state,
        "mal_old_format": cache.mal_old_format(),
        "as_of": oldest,
        "age_days": max(ages) if ages else None,
        "max_age_days": limit,
        "sources": sources,
        "missing": missing,
        "stale": stale,
    }


def format_as_of(as_of: str | None) -> str:
    """ISO 시각 → ``11.02 03:17`` 처럼 짧게(한국 공문 표기). 파싱 실패면 앞 16자."""
    if not as_of:
        return ""
    from datetime import datetime, timezone

    try:
        dt = datetime.fromisoformat(str(as_of))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        local = dt.astimezone()
        return local.strftime("%m.%d %H:%M")
    except (ValueError, TypeError):
        return str(as_of)[:16]


# ---------------------------------------------------------------------------
# 위협정보 자동 갱신 — 검사 직전, 비차단.
# ---------------------------------------------------------------------------

def auto_refresh_intel(*, timeout: float = 20.0) -> dict | None:
    """검사 직전 위협정보 번들을 **비차단**으로 당긴다(하루 1회, 낡았거나 없을 때만).

    실패·망분리·옵트아웃은 조용히 넘어가되 **무엇을 했는지는 돌려준다** — 보고서가
    "갱신을 시도했으나 실패했다"를 적을 수 있어야 담당자가 다음 행동을 고를 수 있다.
    받기만 하고 보내는 것은 없으므로 로컬 모드에서도 돈다.
    """
    try:
        from .intel.autopull import maybe_auto_update

        res = maybe_auto_update(timeout=timeout, verbose=False)
    except Exception as exc:  # noqa: BLE001 — 갱신 실패가 검사를 막으면 안 된다
        return {"attempted": False, "ok": False, "error": str(exc), "source": "", "skipped_reason": ""}
    out = {
        "attempted": bool(getattr(res, "attempted", False)),
        "ok": bool(getattr(res, "ok", False)),
        "source": str(getattr(res, "source", "") or ""),
        "error": str(getattr(res, "error", "") or ""),
        "skipped_reason": str(getattr(res, "skipped_reason", "") or ""),
    }
    if out["attempted"]:
        if out["ok"]:
            print(f"[gvskb] 위협정보 자동 갱신 ← {out['source']}", file=sys.stderr)
        else:
            print(f"[gvskb] ⚠ 위협정보 자동 갱신 실패(검사는 계속): {out['error']}", file=sys.stderr)
    return out


# ---------------------------------------------------------------------------
# 매니페스트 수집 · 감사 실행 — cli._run_dependency_audit 의 본문을 옮겨 CLI·MCP 가 공유한다.
# ---------------------------------------------------------------------------

def _norm_pkg(name: str, ecosystem: str) -> str:
    """패키지 이름 비교용 정규화. pypi 는 ``-``/``_``/``.`` 를 구분하지 않는다(PEP 503)."""
    low = name.strip().lower()
    return re.sub(r"[-_.]+", "-", low) if ecosystem.lower() == "pypi" else low


def _direct_dependency_names(
    found: list[tuple[Path, str, str, str]], ecosystem: str,
) -> set[str]:
    """매니페스트에 **직접 적힌** 패키지 이름 집합.

    락파일이 있어 검사에서 건너뛴 매니페스트도 읽는다 — 여기서 필요한 것은 검사가
    아니라 '무엇이 직접 의존성인가'라는 목록이고, 그건 락파일에는 없다(락파일은
    직접·전이를 구분하지 않고 평면으로 담는다).
    """
    from .scanner import parse_manifest_packages

    names: set[str] = set()
    for p, _rel, eco, kind in found:
        if kind != "manifest" or eco != ecosystem:
            continue
        try:
            text = p.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeDecodeError):
            continue
        for pkg in parse_manifest_packages(text, eco):
            n = str(pkg.get("name") or "").strip()
            if n:
                names.add(_norm_pkg(n, eco))
    return names


_LOCK_NAMES = {
    "poetry.lock": "pypi", "uv.lock": "pypi",
    "package-lock.json": "npm", "pnpm-lock.yaml": "npm", "yarn.lock": "npm",
}


def classify_manifest(name: str) -> tuple[str, str] | None:
    """파일명 → (ecosystem, kind). kind: 'lock' | 'manifest'. 해당 없으면 None."""
    low = name.lower()
    if low in _LOCK_NAMES:
        return _LOCK_NAMES[low], "lock"
    # `requirements.lock.txt`·`requirements-lock.txt`·`constraints.txt` — 고정 전수 목록이다. 매니페스트로
    # 보면 기본 상한 20개만 조회된다(실측 2026-10-15 챗봇: 111개 중 20개).
    if low.startswith(("requirements", "constraints")) and low.endswith(".txt") and (
            ".lock" in low or "-lock" in low or "_lock" in low or low.startswith("constraints")):
        return "pypi", "lock"
    if low.startswith("requirements") and low.endswith(".txt"):
        return "pypi", "manifest"
    if low == "pyproject.toml":
        # PEP 621 · poetry — 현대 Python 프로젝트의 주 매니페스트. 이것을 못 읽어
        # 체커가 **자기 의존성을 한 번도 검사하지 못했다**(재점검 2026-08-29).
        return "pypi", "manifest"
    if low == "package.json":
        return "npm", "manifest"
    return None


def find_manifests(root: Path, report: ScanReport) -> tuple[list[tuple[Path, str, str]], list[tuple[Path, str, str, str]]]:
    """스캔 결과에서 검사할 매니페스트를 고른다 → (검사 대상, 발견 전체).

    requirements*.txt(pypi)는 스캔에서 제외(skipped)되고 package.json(npm)은 스캔
    대상(scanned)이므로 두 목록을 모두 본다. 같은 디렉터리·같은 생태계에 락파일이
    있으면 매니페스트는 건너뛴다 — 락파일이 상위 집합(전이 의존성 포함, 버전 고정)이다.
    """
    found: list[tuple[Path, str, str, str]] = []  # (경로, 표시명, eco, kind)
    if root.is_file():
        hit = classify_manifest(root.name)
        if hit:
            found.append((root, root.name, hit[0], hit[1]))
    else:
        seen: set[str] = set()
        for rel in [s.path for s in report.skipped_files] + list(report.scanned_files):
            name = rel.replace("\\", "/").rsplit("/", 1)[-1]
            hit = classify_manifest(name)
            if not hit or rel in seen:
                continue
            seen.add(rel)
            p = root / rel
            if p.is_file():
                found.append((p, rel, hit[0], hit[1]))

    lock_dirs = {
        (rel.replace("\\", "/").rsplit("/", 1)[0] if "/" in rel.replace("\\", "/") else "", eco)
        for _, rel, eco, kind in found if kind == "lock"
    }
    manifests: list[tuple[Path, str, str]] = []  # (절대경로, 표시명, ecosystem)
    for p, rel, eco, kind in found:
        norm = rel.replace("\\", "/")
        d = norm.rsplit("/", 1)[0] if "/" in norm else ""
        if kind == "manifest" and (d, eco) in lock_dirs:
            continue  # 락파일이 이미 상위 집합을 검사한다
        manifests.append((p, rel, eco))
    return manifests, found


async def run_dependency_audit_async(
    root: Path,
    report: ScanReport,
    *,
    mode: str | None = None,
    env_grade: str | None = None,
    include_installed: bool = False,
    refresh: bool = True,
) -> dict | None:
    """매니페스트·설치 흔적·벤더 번들을 찾아 패키지 취약·악성 검사를 수행한다.

    ``mode``: ``local``(로컬 캐시만) · ``online``(OSV·저장소 조회) · ``None``(예전 동작 —
    ``GVSKB_MODE=offline`` 이면 로컬, 아니면 온라인). ``off`` 면 아무것도 하지 않는다.
    검사할 것이 없으면 None — 호출자가 "패키지 없음"과 "검사 안 함"을 구분해 기록한다.
    """
    from .tools.check_package import _MAX_PACKAGES, audit_manifest

    if mode == "off":
        return None
    manifests, found = find_manifests(root, report)

    # 벤더 번들(static/*.min.js)은 매니페스트가 없어도 검사 대상이다 — 매니페스트도
    # node_modules 도 없는 프로젝트에서는 이것이 **유일한 컴포넌트 발견 경로**다.
    vendor_bundles = list(getattr(report, "vendor_bundles", None) or [])

    if not manifests and not include_installed and not vendor_bundles:
        return None

    # 검사 전에 위협정보 캐시를 **비차단**으로 갱신한다(하루 1회, 신선도 초과 시만, 실패해도 계속).
    # 결과는 버리지 않고 기록으로 넘긴다 — "갱신을 시도했으나 실패했다"를 보고서가 말해야 한다.
    refresh_result = auto_refresh_intel() if refresh else None

    out: list[dict] = []
    for p, rel, eco in manifests:
        try:
            text = p.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeDecodeError) as exc:
            out.append({
                "ecosystem": eco, "manifest": rel, "verdict": "unparsed",
                "requires_review": True, "parsed_count": 0, "checked_count": 0,
                "unchecked_count": 0, "blocked": False, "checks": [],
                "note": f"파일을 읽지 못했습니다: {exc}",
            })
            continue
        # filename 을 넘겨야 락파일 형식을 파일명으로 확정할 수 있다.
        # 프로젝트 검사는 매니페스트를 끝까지 본다 — 21번째 줄의 악성이 승인으로 빠졌다(적대적 검증 2026-11-06).
        audit = await audit_manifest(text, ecosystem=eco, limit=_MAX_PACKAGES, env_grade=env_grade, filename=rel, mode=mode)
        audit["manifest"] = rel
        out.append(audit)

    # 설치 흔적(.venv·휠·node_modules)까지 확대 — 매니페스트에 적힌 직접
    # 의존성만 보면 **전이 의존성의 취약점을 통째로 놓친다**(상용 SCA 대비
    # 유일한 실질 격차였음). 목록만 읽고 패키지를 실행하지 않는다.
    if include_installed:
        from .tools.installed_packages import collect_installed_packages, to_requirements_text

        inv = collect_installed_packages(root)
        for eco, pkgs in (("pypi", inv["pypi"]), ("npm", inv["npm"])):
            if not pkgs:
                continue
            text = to_requirements_text(pkgs, ecosystem=eco)
            audit = await audit_manifest(
                text, ecosystem=eco, limit=len(pkgs), env_grade=env_grade, mode=mode,
            )
            audit["manifest"] = f"<설치된 패키지: {eco}>"
            audit["source"] = "installed-inventory"
            audit["inventory_stats"] = inv["stats"]
            # 설치본 중 **매니페스트에 이름이 있는 것은 직접 의존성**이다
            # (레지스트리 요청 §3). 이름은 매니페스트에, 정확한 버전은 설치
            # 흔적에 있으므로 둘을 합쳐야 "직접 의존성 + 실제 버전"이 되고,
            # 그 판단은 둘 다 읽는 이쪽에서만 할 수 있다.
            direct = _direct_dependency_names(found, eco)
            for c in audit.get("checks", []):
                c["source_scope"] = (
                    "manifest" if _norm_pkg(str(c.get("name", "")), eco) in direct
                    else "installed"
                )
            # 라이선스는 설치 메타데이터에서만 얻을 수 있다 — 검사 결과에 병기.
            lic_by_name = {
                str(p.get("name", "")).lower(): p.get("license") for p in pkgs
            }
            for c in audit.get("checks", []):
                lic = lic_by_name.get(str(c.get("name", "")).lower())
                if lic and not (c.get("registry_metadata") or {}).get("license"):
                    c.setdefault("registry_metadata", {})
                    if isinstance(c["registry_metadata"], dict):
                        c["registry_metadata"]["license"] = lic
                    c["license_source"] = "installed-metadata"
            out.append(audit)

    # 벤더 번들(`static/*.min.js`) — 그 자체가 프로젝트가 실행하는 남의 코드다.
    # 실측(공공 Flask 프로젝트): `xlsx 0.18.5` 가 CVE-2023-30533 등에 해당하는데, 예전에는
    # '빌드 산출물'로 제외돼 매니페스트·설치본 어느 경로에도 걸리지 않았다.
    if vendor_bundles:
        from .tools.vendor_bundle import audit_vendor_bundles

        out.append(await audit_vendor_bundles(vendor_bundles, env_grade=env_grade, mode=mode))
    return {"audits": out, "auto_refresh": refresh_result}


def run_dependency_audit(
    root: Path,
    report: ScanReport,
    *,
    mode: str | None = None,
    env_grade: str | None = None,
    include_installed: bool = False,
    refresh: bool = True,
) -> dict | None:
    """동기 래퍼 — CLI·MCP 공용.

    MCP 서버의 동기 도구가 이벤트 루프 스레드 안에서 불릴 수 있다. 그 자리에서 ``asyncio.run``
    을 부르면 "이미 루프가 돌고 있다"로 죽으므로, 루프가 있으면 **별도 스레드의 새 루프**에서
    돌리고 결과만 받아 온다. 어느 쪽이든 호출자는 그냥 dict 를 받는다.
    """
    coro = run_dependency_audit_async(
        root, report, mode=mode, env_grade=env_grade,
        include_installed=include_installed, refresh=refresh,
    )
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix="gvskb-deps") as ex:
        return ex.submit(asyncio.run, coro).result()


# ---------------------------------------------------------------------------
# 결과를 보고서에 새긴다.
# ---------------------------------------------------------------------------

def attach_dependency_check(
    report: ScanReport,
    *,
    mode: str,
    requested: str | None,
    audit: dict | None,
    note: str | None = None,
) -> dict:
    """``report.dependency_audit``·``report.dependency_check`` 를 채우고 기록을 돌려준다.

    ``off`` 도 기록한다 — 생략은 사용자의 선택이지만 보고서는 그 선택을 말해야 한다.
    위협정보 상태는 모드와 무관하게 적는다(온라인도 KEV 교차 대조는 로컬 캐시를 쓴다).
    """
    audits = list((audit or {}).get("audits") or [])
    if audits:
        report.dependency_audit = audit
    parsed = sum(int(a.get("parsed_count") or 0) for a in audits)
    # '매니페스트' 는 매니페스트·락파일에서 온 감사만 센다 — 설치본·벤더 번들 감사는 따로.
    manifests = sum(1 for a in audits if a.get("source") not in ("installed-inventory", "vendor-bundle"))
    # 위협정보 상태는 **패키지를 실제로 봤을 때만** 계산한다 — 캐시 적재(수만 건 JSON 파싱 + sha256)는
    # 싸지 않다. 매니페스트가 없는 정적 페이지 검사가 그 비용을 매번 내서는 안 된다(검증 지적).
    state = intel_state() if (mode != "off" and audits) else None
    record = {
        "mode": mode,
        "mode_label": MODE_LABELS.get(mode, mode),
        "requested_mode": requested,
        "manifests_found": manifests,
        "audits_total": len(audits),
        "packages_parsed": parsed,
        "intel": state,
        "auto_refresh": (audit or {}).get("auto_refresh"),
        "note": note,
    }
    report.dependency_check = record
    # 결론 박스 머리표가 쓰는 기준일 — 오프라인 스캐너가 이미 채웠으면 그대로 둔다.
    if state and state.get("sources") and not report.intel_freshness:
        fresh = {
            sid: str(s["fetched_at"])[:10]
            for sid, s in state["sources"].items() if s.get("fetched_at")
        }
        if fresh:
            report.intel_freshness = fresh
    return record


def user_notice(record: dict | None) -> str | None:
    """터미널에 한 줄로 알릴 말 — 보고서 배너와 **같은 뜻, 더 짧게**. 정상이면 None."""
    if not record:
        return None
    mode = record.get("mode")
    if mode == "off":
        return "패키지 검사를 생략했습니다(--deps off). 패키지 취약점은 이 결과에 없습니다."
    intel = record.get("intel") or {}
    state = intel.get("state")
    if state == "missing" and record.get("packages_parsed"):
        return (
            "⛔ 패키지 검사를 하지 못했습니다 — 위협정보가 이 PC에 없습니다. "
            "이 결과를 '통과'로 쓰지 마세요. (인터넷망) `gvskb update-intel` 후 재검사 · "
            "(폐쇄망) 관리자가 배포한 위협정보 폴더를 GVSKB_INTEL_DIR 로 지정" + refresh_failure_note(record)
        )
    if state == "stale" and record.get("packages_parsed"):
        age = intel.get("age_days")
        when = f"{age}일 전" if age is not None else "오래된"
        return (
            f"⚠ 위협정보가 {when} 것입니다 — 그 사이 알려진 취약점은 반영되지 않았습니다. "
            "(인터넷망) `gvskb update-intel` · (폐쇄망) 전산 담당자에게 위협정보 갱신 요청" + refresh_failure_note(record)
        )
    return None


def refresh_failure_note(record: dict | None) -> str:
    """자동 갱신을 시도했는데 실패했으면 그 사실과 사유를 한 조각으로. 아니면 빈 문자열."""
    ar = (record or {}).get("auto_refresh") or {}
    if ar.get("attempted") and not ar.get("ok"):
        err = str(ar.get("error") or "사유 미상").strip()
        return f" (자동 갱신 시도 실패: {err[:160]})"
    return ""
