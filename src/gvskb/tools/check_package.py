"""Package reputation and vulnerability checks using OSV.dev.

When ``GVSKB_MODE=offline``, this module does not call OSV. Instead it consults
the on-disk intel cache populated by ``gvskb update-intel`` (CISA KEV + OSV
malicious feed). This keeps air-gapped agencies usable: as long as their
cache is current, they still get malicious-package verdicts. If no cache is
present we are honest about it — the result reports ``checked=False`` and
points the operator at ``gvskb update-intel``.
"""
from __future__ import annotations

import asyncio
import os
import re
from datetime import datetime, timezone
from collections.abc import Callable
from typing import Literal

import httpx

from ..intel.cache import IntelCache
from ..schema import CooldownCheck, PackageCheckResult, PackageRegistryMetadata
from ..vcps import cooldown_days_for, license_verdict
from .package_metadata import fetch_registry_metadata

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
ECOSYSTEM_MAP = {
    "pypi": "PyPI",
    "npm": "npm",
}


def _is_offline() -> bool:
    """Honor GVSKB_MODE=offline so air-gapped agencies see a clean degraded mode."""
    return os.environ.get("GVSKB_MODE", "").lower() == "offline"


# 편집거리 typosquat 비교용 인기 패키지 (상위 다운로드 일부). 완전한 목록이
# 아니라 흔한 오타 표적만 둔다 — 신호용이며 차단 근거가 아니다.
_POPULAR_PYPI = frozenset({
    "requests", "urllib3", "numpy", "pandas", "flask", "django", "pytest",
    "pillow", "scipy", "setuptools", "pyyaml", "cryptography", "boto3",
    "certifi", "jinja2", "click", "sqlalchemy", "openai", "tensorflow",
    "torch", "scikit-learn", "matplotlib", "beautifulsoup4", "selenium",
    "fastapi", "pydantic", "httpx", "aiohttp", "redis", "celery",
})
_POPULAR_NPM = frozenset({
    "express", "lodash", "react", "axios", "chalk", "commander", "moment",
    "webpack", "vue", "next", "typescript", "eslint", "prettier", "jest",
    "minimist", "debug", "async", "request", "bluebird", "underscore",
})


def _levenshtein(a: str, b: str) -> int:
    """Edit distance, short-circuited when length gap already exceeds 2."""
    if abs(len(a) - len(b)) > 2:
        return 99
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[-1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _squat_distance(heuristics: dict) -> int | None:
    """가장 가까운 인기 패키지와의 편집거리(없으면 None)."""
    hits = heuristics.get("typosquat_suspects") or []
    return int(hits[0]["edit_distance"]) if hits else None


def _typosquat_suspects(name: str, ecosystem: str) -> list[dict]:
    """Popular packages within edit distance 1–2 of this name (likely typos)."""
    pool = _POPULAR_NPM if ecosystem.lower() == "npm" else _POPULAR_PYPI
    n = name.lower()
    if n in pool or len(n) < 5:        # exact match is fine; short names too noisy
        return []
    hits = []
    for pkg in pool:
        d = _levenshtein(n, pkg)
        if 1 <= d <= 2:
            hits.append({"similar_to": pkg, "edit_distance": d})
    return sorted(hits, key=lambda h: h["edit_distance"])


def _basic_heuristics(name: str, ecosystem: str = "pypi") -> dict:
    hyphen_count = name.count("-")
    underscore_count = name.count("_")
    looks_compound = hyphen_count + underscore_count >= 2
    has_ai_keywords = bool(re.search(r"(ai|gpt|llm|copilot|tool|helper|agent)", name, re.I))
    typosquat = _typosquat_suspects(name, ecosystem)
    return {
        "hyphen_count": hyphen_count,
        "underscore_count": underscore_count,
        "name_length": len(name),
        "looks_compound_name": looks_compound,
        "has_ai_keywords": has_ai_keywords,
        "typosquat_suspects": typosquat,
        "typosquat_warning": (
            f"'{name}'는 인기 패키지 '{typosquat[0]['similar_to']}'와 매우 유사합니다"
            f"(편집거리 {typosquat[0]['edit_distance']}). 오타·타이포스쿼팅 가능성을 "
            "확인하고, 의도한 패키지가 맞는지 출처를 검증하세요."
            if typosquat else None
        ),
        "note": (
            "복합 이름과 AI 관련 키워드는 slopsquatting/typosquatting 검토 신호일 수 있습니다. "
            "이 휴리스틱만으로 차단하지 말고 출처, 다운로드, maintainer, advisory를 함께 확인하세요."
        ),
    }


def _osv_advisories_for(items: list[dict], name: str, ecosystem_label: str) -> list[dict]:
    """Return cached OSV MAL advisories whose ``affected`` list mentions this package."""
    name_l = name.lower()
    eco_l = ecosystem_label.lower()
    hits: list[dict] = []
    for item in items:
        for aff in item.get("affected", []) or []:
            pkg = (aff.get("package") or "").lower()
            eco = (aff.get("ecosystem") or "").lower()
            if pkg == name_l and eco == eco_l:
                hits.append({
                    "id": item.get("id"),
                    "summary": (item.get("summary") or "")[:200],
                    "modified": item.get("modified"),
                })
                break
    return hits


def _enrich_with_epss_nvd(kev_signals: list[dict], cache: "IntelCache") -> list[str]:
    """KEV 신호에 EPSS 악용확률·NVD CVSS를 CVE 기준으로 병기한다.

    매일 수집되는 epss-recent/nvd-recent 캐시를 판정 화면에 실제로 활용하는
    지점이다 — 보안팀이 "악용 가능성이 얼마나 되는 취약점인지"를 조회 없이
    보고서에서 바로 읽고 우선순위를 정할 수 있다. 캐시가 없으면 조용히 생략.
    Returns the list of cache source_ids actually used.
    """
    if not kev_signals:
        return []
    used: list[str] = []
    epss_entry = cache.load("epss-recent")
    nvd_entry = cache.load("nvd-recent")
    epss_by_cve = {i.get("cve"): i for i in (epss_entry.items if epss_entry else [])}
    nvd_by_cve = {i.get("id"): i for i in (nvd_entry.items if nvd_entry else [])}
    hit_epss = hit_nvd = False
    for sig in kev_signals:
        cve = sig.get("cveID")
        e = epss_by_cve.get(cve)
        if e:
            hit_epss = True
            sig["epss_score"] = e.get("epss")            # 30일 내 악용 관측 확률(0~1)
            sig["epss_percentile"] = e.get("percentile")
        n = nvd_by_cve.get(cve)
        if n:
            hit_nvd = True
            sig["cvss31_base_score"] = n.get("cvss31_base_score")
            sig["cvss31_severity"] = n.get("cvss31_severity")
    if hit_epss:
        used.append("epss-recent")
    if hit_nvd:
        used.append("nvd-recent")
    return used


def _kev_signals_for(items: list[dict], name: str) -> list[dict]:
    """Return KEV entries whose vendorProject/product name matches the package.

    KEV is vendor/product-centric, not package-centric, so this is a *secondary*
    signal — a true positive needs the operator to confirm the link. We still
    surface it because matches on well-known names (log4j, lodash) are useful.
    """
    name_l = name.lower()
    hits: list[dict] = []
    for item in items:
        product = (item.get("product") or "").lower()
        vendor = (item.get("vendorProject") or "").lower()
        if name_l == product or name_l == vendor:
            hits.append({
                "cveID": item.get("cveID"),
                "vendorProject": item.get("vendorProject"),
                "product": item.get("product"),
                "vulnerabilityName": item.get("vulnerabilityName"),
                "dateAdded": item.get("dateAdded"),
            })
    return hits


def _engine_version() -> str | None:
    try:
        from gvskb import __version__
        return __version__
    except Exception:  # pragma: no cover - defensive
        return None


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# OSV/GHSA 심각도 표기 정규화 — SafePackageRecord.checks.max_cve 등급 산출용.
_SEVERITY_NORMALIZE = {
    "LOW": "LOW", "MODERATE": "MEDIUM", "MEDIUM": "MEDIUM",
    "HIGH": "HIGH", "CRITICAL": "CRITICAL",
}
_SEVERITY_RANK = {"NONE": 0, "UNKNOWN": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}


def _max_cve_from_vulns(vulns: list[dict]) -> str:
    """OSV 취약점 목록 → 최고 심각도 등급(NONE~CRITICAL).

    database_specific.severity(GHSA 계열)와 affected[].ecosystem_specific.severity
    를 본다. 취약점은 있는데 심각도 표기가 하나도 없으면 'UNKNOWN' — 낮음이
    아니라 미상이며, 미상은 '안전'이 아니다(C6 판정 시 검토 대상).
    """
    if not vulns:
        return "NONE"
    best = "UNKNOWN"
    for v in vulns:
        candidates: list[str] = []
        ds = (v.get("database_specific") or {}).get("severity")
        if ds:
            candidates.append(str(ds).upper())
        for aff in v.get("affected") or []:
            es = (aff.get("ecosystem_specific") or {}).get("severity")
            if es:
                candidates.append(str(es).upper())
        for c in candidates:
            norm = _SEVERITY_NORMALIZE.get(c)
            if norm and _SEVERITY_RANK[norm] > _SEVERITY_RANK[best]:
                best = norm
    return best


def _advisory_severity(vuln: dict) -> str:
    """advisory 1건의 심각도. 패키지 전체 최고값과 **같은 출처**를 쓴다.

    표기가 없으면 'UNKNOWN' — 낮음이 아니라 미상이고, 미상은 안전이 아니다.
    """
    return _max_cve_from_vulns([vuln])


def _version_key(version: str) -> tuple[int, ...] | None:
    """'12.3.0' → (12, 3, 0). 숫자 마디로만 비교하고, 못 읽으면 None.

    ``packaging`` 을 의존성에 추가하지 않으려고 최소 구현만 둔다. 프리릴리스·
    빌드 메타데이터(``1.2.0-rc1``·``+build``)는 앞 숫자 마디까지만 본다.
    **못 읽으면 추측하지 않고 None** 을 돌려준다 — 틀린 버전을 권고하느니
    권고하지 않는 편이 낫다.
    """
    core = re.split(r"[-+ ]", str(version).strip(), maxsplit=1)[0]
    parts = core.split(".")
    if not parts or not all(p.isdigit() for p in parts if p != ""):
        return None
    nums = [int(p) for p in parts if p != ""]
    return tuple(nums) if nums else None


def _highest_version(versions: list[str]) -> str | None:
    """비교 가능한 것 중 가장 높은 버전. 하나도 못 읽으면 None."""
    ranked = [(k, v) for v in versions if (k := _version_key(v)) is not None]
    if not ranked:
        return None
    return max(ranked, key=lambda kv: kv[0])[1]


#: 프리릴리스 꼬리표. 운영에 올릴 버전으로 권고해서는 안 된다.
_PRERELEASE_RE = re.compile(r"-(?:rc|alpha|beta|next|canary|dev|pre|preview|snapshot)", re.I)


def _is_prerelease(version: str) -> bool:
    """``8.0.0-rc.6`` 처럼 정식 출시 전 버전인가.

    ``_version_key`` 는 ``-`` 앞만 보므로 ``8.0.0-rc.6`` 과 ``8.0.0`` 을 같은 값으로
    읽는다. 그 결과 rc 가 안정판 ``7.29.6`` 을 이겨 **공공기관 운영에 alpha 를
    올리라는 권고**가 나갔다(2026-08-08 실측). 비교 이전에 걸러야 한다.
    """
    return bool(_PRERELEASE_RE.search(str(version)))


def _advisory_fix_ranges(vuln: dict, *, name: str, eco: str) -> list[tuple[str | None, str]]:
    """``(도입 버전, 고쳐진 버전)`` 쌍 — 어느 브랜치의 수정인지 알아야 한다.

    ``_advisory_fixed_versions`` 는 이 쌍을 평탄화해 ``fixed`` 만 남긴다. 그러면
    ``[7.29.6, 8.0.0-rc.6]`` 이 "7.x 브랜치 수정"과 "8.x 브랜치 수정"이라는 사실이
    사라져, 7.28.4 를 쓰는 사람에게 8.0.0-rc.6 을 권고하게 된다. 반대로 무턱대고
    **낮은 쪽을 고르면 미탐**이 된다 — 내 버전이 그 브랜치가 아닐 수 있기 때문이다.
    그래서 경계를 보존해 ``introduced <= 현재 < fixed`` 인 구간만 고른다.
    """
    from .installed_packages import _normalize

    want = _normalize(name) if eco.lower() == "pypi" else name.lower()
    out: list[tuple[str | None, str]] = []
    for aff in vuln.get("affected") or []:
        pkg = aff.get("package") or {}
        pkg_name = str(pkg.get("name") or "")
        norm = _normalize(pkg_name) if eco.lower() == "pypi" else pkg_name.lower()
        if pkg_name and norm != want:
            continue
        if pkg.get("ecosystem") and str(pkg["ecosystem"]).lower() != eco.lower():
            continue
        for rng in aff.get("ranges") or []:
            introduced: str | None = None
            for ev in rng.get("events") or []:
                if ev.get("introduced") is not None:
                    introduced = str(ev["introduced"])
                fixed = ev.get("fixed")
                if fixed:
                    out.append((introduced, str(fixed)))
                    introduced = None  # 다음 쌍을 위해 초기화
    return out


def _advisory_fixed_versions(vuln: dict, *, name: str, eco: str) -> list[str]:
    """이 advisory 가 '어느 버전에서 고쳐졌는지' — OSV affected[].ranges[].events[].fixed.

    **왜 필요한가(실측)**: 예전에는 이 값을 통째로 버려서 보고서가 "취약점 26건"
    까지만 말하고 **어느 버전으로 올려야 하는지**는 말하지 못했다. 담당자가 결국
    직접 찾아야 했고, 수정 프롬프트도 "공식 배포처를 확인해 정하세요"로 판단을
    사용자에게 넘겼다.

    다른 패키지의 ``affected`` 항목(전이 의존성)이 섞여 들어오므로 이름·생태계가
    일치하는 것만 본다 — 남의 패키지 버전을 우리 권고로 내면 안 된다.
    """
    from .installed_packages import _normalize

    want = _normalize(name) if eco.lower() in ("pypi", "pypi") else name.lower()
    out: list[str] = []
    for aff in vuln.get("affected") or []:
        pkg = aff.get("package") or {}
        pkg_name = str(pkg.get("name") or "")
        norm = _normalize(pkg_name) if eco.lower() == "pypi" else pkg_name.lower()
        if pkg_name and norm != want:
            continue
        if pkg.get("ecosystem") and str(pkg["ecosystem"]).lower() != eco.lower():
            continue
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                fixed = ev.get("fixed")
                if fixed and str(fixed) not in out:
                    out.append(str(fixed))
    return out


#: 수정 방법을 담을 가능성이 높은 순서. WEB 은 뉴스·블로그가 섞이므로 뒤로 둔다.
_REF_PRIORITY = ("ADVISORY", "FIX", "WEB", "PACKAGE", "REPORT")


def _advisory_references(vuln: dict, limit: int = 2) -> list[str]:
    """OSV ``references`` 중 **조치에 쓸 수 있는** 주소 몇 개.

    **왜 필요한가(실측 2026-08-08)**: ``xlsx 0.18.5`` 는 권고 버전이 ``None`` 이었다.
    npm 에 수정 버전이 없으니 그 자체는 옳다 — 그런데 **수정본은 존재한다**.
    SheetJS 가 배포를 자체 CDN 으로 옮겼을 뿐이고, 그 안내가 OSV ``references`` 에
    들어 있는데 우리가 이 필드를 저장하지 않아 전달하지 못했다. 담당자에게는
    "권고 버전 없음"이 "고칠 방법 없음"으로 읽힌다.
    """
    refs = vuln.get("references") or []
    picked: list[str] = []
    for want in _REF_PRIORITY:
        for r in refs:
            if not isinstance(r, dict):
                continue
            url = str(r.get("url") or "").strip()
            if not url.lower().startswith(("http://", "https://")):
                continue
            if str(r.get("type") or "").upper() == want and url not in picked:
                picked.append(url)
                if len(picked) >= limit:
                    return picked
    return picked


def _advisory_cvss_vector(vuln: dict) -> str | None:
    """OSV 가 준 CVSS 벡터를 **그대로** 옮긴다 — 우리가 점수를 계산하지 않는다.

    ``max_cve`` 는 ``"HIGH"`` 같은 **라벨**이라 게이트가 "CVSS 7.0 이상 차단" 같은
    정책을 쓸 수 없다. 그렇다고 벡터에서 점수를 직접 산출하면 **틀린 CVSS 를 우리
    이름으로 내보내게** 된다 — 없는 것보다 나쁘다. 벡터는 표준이고 기계 판독이
    되며 원문과 대조할 수 있으므로, 통과시키는 것이 정확하고 안전하다.
    """
    for s in vuln.get("severity") or []:
        if not isinstance(s, dict):
            continue
        score = str(s.get("score") or "").strip()
        if score.upper().startswith("CVSS:"):
            return score
    return None


def _advisory_rows(vulns: list[dict], *, name: str, eco: str) -> list[dict]:
    """보고서·프롬프트에 실을 advisory 목록.

    **상한을 두지 않는다.** 예전에는 ``vulns[:5]`` 로 잘라, 26건을 조회해 놓고
    5건만 남겼다. 숫자는 26이라 적으면서 내역은 5건뿐이라 **나머지 21건은 어디에도
    없었다** — 조용한 절단이다. 잘라야 한다면 자른 사실을 값으로 남겨야 한다.
    """
    rows: list[dict] = []
    for v in vulns:
        rows.append({
            "id": v.get("id"),
            "severity": _advisory_severity(v),
            "summary": (v.get("summary") or v.get("details") or "")[:200],
            "fixed_versions": _advisory_fixed_versions(v, name=name, eco=eco),
            # 브랜치 경계를 보존한 원본 — 권고 버전 산출에만 쓴다(보고서 표시는
            # 기존대로 fixed_versions). 평탄화된 목록만으로는 어느 수정이 내
            # 브랜치의 것인지 알 수 없다.
            "fixed_ranges": _advisory_fix_ranges(v, name=name, eco=eco),
            # 원문·조치 안내 주소. 권고 버전이 없을 때 "그럼 어떻게 고치나"의 답이
            # 여기 있다(레지스트리 밖 배포로 옮긴 패키지 등).
            "references": _advisory_references(v),
            # 표준 CVSS 벡터(있을 때만). 게이트가 자체 임계값으로 채점할 수 있게
            # 원문 그대로 싣는다 — 우리가 점수를 만들지는 않는다.
            "cvss_vector": _advisory_cvss_vector(v),
            "modified": v.get("modified"),
        })
    return rows


def _advisory_target(row: dict, current: str | None) -> str | None:
    """advisory 하나를 해소하는 **가장 가까운** 버전.

    예전에는 advisory 안에서도 ``max`` 를 골랐다. 그런데 ``fixed_versions`` 는
    브랜치별 수정본 목록이라, ``[7.29.6, 8.0.0-rc.6]`` 에서 최댓값을 고르면
    7.28.4 사용자에게 **불필요한 메이저 업그레이드 + 프리릴리스**를 권고한다
    (2026-08-08 실측: 취약 59건 중 16건이 이 형태였다). 담당자는 "이건 못 하겠다"
    하고 **조치 자체를 포기**한다 — 오탐보다 나쁜 결과다.

    반대로 무조건 최솟값을 고르면 **미탐**이 된다. 내 버전이 그 수정이 적용된
    브랜치가 아닐 수 있기 때문이다. 그래서 순서는:

    1. ``introduced <= 현재 < fixed`` 인 구간의 ``fixed`` (브랜치 일치 — 가장 정확)
    2. 현재보다 높은 안정 버전 중 최소
    3. 안정 버전이 하나도 없으면 프리릴리스라도 (정보를 잃지 않기 위해)
    """
    ranges = row.get("fixed_ranges") or []
    cur = _version_key(current) if current else None

    if cur is not None:
        matched: list[str] = []
        for introduced, fixed in ranges:
            fk = _version_key(fixed)
            if fk is None:
                continue
            ik = _version_key(introduced) if introduced else (0,)
            if ik is None:
                ik = (0,)
            if ik <= cur < fk:
                matched.append(fixed)
        stable = [v for v in matched if not _is_prerelease(v)]
        if stable:
            return min(stable, key=lambda v: _version_key(v) or ())
        if matched:
            return min(matched, key=lambda v: _version_key(v) or ())

    cands = [v for v in (row.get("fixed_versions") or []) if _version_key(v) is not None]
    if not cands:
        return None
    if cur is not None:
        ahead = [v for v in cands if (_version_key(v) or ()) > cur]
        stable_ahead = [v for v in ahead if not _is_prerelease(v)]
        if stable_ahead:
            return min(stable_ahead, key=lambda v: _version_key(v) or ())
        if ahead:
            return min(ahead, key=lambda v: _version_key(v) or ())
    stable = [v for v in cands if not _is_prerelease(v)]
    return _highest_version(stable or cands)


def _recommended_version(rows: list[dict], current: str | None = None) -> str | None:
    """나열된 취약점을 **모두** 넘어서는 최소 상한 — '이 버전 이상으로 올리세요'.

    advisory 안에서는 내 브랜치에 가장 가까운 수정본을 고르고(``_advisory_target``),
    advisory 사이에서는 **최댓값**을 고른다 — 하나라도 안 넘으면 남는 취약점이
    생기기 때문이다. 하나라도 fixed 를 모르면 **None** 을 돌려준다: '올리면 다
    해결된다'는 잘못된 안심을 주지 않는다.
    """
    if not rows:
        return None
    tops: list[str] = []
    for r in rows:
        top = _advisory_target(r, current)
        if top is None:
            return None
        tops.append(top)
    return _highest_version(tops)


def _kev_cache_state(cache: IntelCache | None = None) -> dict:
    """KEV 캐시 상태 — 대조 **결과를 해석하려면 반드시 함께 있어야 하는 값**.

    ``in_kev=False`` 는 '악용 목록에 없다'일 수도, '대조하지 못했다'일 수도 있다.
    상태를 싣지 않으면 두 경우가 화면에서 똑같아 보인다 — 실측으로 온라인 경로가
    로컬 KEV 캐시에 의존하면서 그 의존을 결과에 전혀 표시하지 않고 있었다.
    캐시가 6개월 낡아 최근 악용 등재를 모르는 상태에서도 판정은 조용히 나갔다.
    """
    cache = cache or IntelCache()
    entry = cache.load("cisa-kev")
    if entry is None:
        return {"state": "missing", "fetched_at": None}
    return {
        "state": "stale" if entry.is_stale() else "ok",
        "fetched_at": entry.fetched_at,
    }


def _kev_cve_hits(vulns: list[dict], cache: IntelCache | None = None) -> list[dict]:
    """취약점의 CVE alias 를 CISA KEV 캐시와 교차 대조 — 실제 악용 중인지 확인.

    vendor/product 이름 매칭(_kev_signals_for)보다 강한 패키지 수준 신호다.
    온라인 모드에서도 로컬 KEV 캐시가 있으면 활용한다(추가 네트워크 비용 0).
    캐시가 없으면 빈 목록 — '악용 없음'이 아니라 '대조 못 함'이다.
    """
    cache = cache or IntelCache()
    kev_entry = cache.load("cisa-kev")
    if kev_entry is None:
        return []
    cve_ids: set[str] = set()
    for v in vulns:
        vid = str(v.get("id", ""))
        if vid.startswith("CVE-"):
            cve_ids.add(vid)
        for alias in v.get("aliases") or []:
            if str(alias).startswith("CVE-"):
                cve_ids.add(str(alias))
    if not cve_ids:
        return []
    hits = []
    for item in kev_entry.items:
        if item.get("cveID") in cve_ids:
            hits.append({
                "cveID": item.get("cveID"),
                "vulnerabilityName": item.get("vulnerabilityName"),
                "dateAdded": item.get("dateAdded"),
                "match": "cve_alias",  # 이름 매칭보다 강한 확정 신호
            })
    return hits


def _evaluate_cooldown(
    meta: PackageRegistryMetadata | None,
    env_grade: str | None,
) -> CooldownCheck:
    """쿨다운(C1) 판정 — 발행일 미상이면 ok=None(판정 불가, '통과' 아님)."""
    days, grade = cooldown_days_for(env_grade)
    age = meta.version_age_days if meta is not None else None
    return CooldownCheck(
        cooldown_days=days,
        env_grade=grade,
        version_age_days=age,
        ok=None if age is None else age >= days,
    )


def _coverage_gap_note(
    ecosystem_label: str,
    covered_ecosystems: list[str],
    *,
    osv_file_present: bool,
) -> str:
    """악성 피드 커버리지 공백의 **원인별** 안내문.

    담당자가 그대로 따라 하면 공백이 실제로 닫히는 문장이어야 한다. 세 갈래:
      (a) osv 캐시 자체가 없음/버려짐 → 캐시를 만들어 반입 (파일이 있으면 무결성 실패)
      (b) 캐시는 있으나 이 생태계가 opt-in → 해당 환경변수를 켜고 다시 받기
      (c) 그 외(기본 수집 대상인데 안 담김) → 원인 미상, 갱신 후 커버리지 재확인
    """
    from ..intel.sources.osv import OPT_IN_ECOSYSTEMS

    coverage = f"(캐시 커버리지: {covered_ecosystems or '없음'})"

    if not covered_ecosystems:
        cause = (
            "악성 패키지 피드(osv-malicious) 캐시가 무결성 검증에 실패해 무시되었습니다"
            if osv_file_present else
            "악성 패키지 피드(osv-malicious) 캐시가 없습니다"
        )
        return (
            f"{cause} — {ecosystem_label} 패키지의 악성 등록 여부를 대조하지 못했습니다"
            f"('이상 없음'이 아닙니다). 외부망에서 `gvskb update-intel --all` 로 캐시를 "
            "만든 뒤 `gvskb intel-bundle export` → (반입) → `gvskb intel-bundle import` "
            "로 옮기세요."
        )

    if ecosystem_label in OPT_IN_ECOSYSTEMS:
        return (
            f"오프라인 캐시가 {ecosystem_label} 생태계를 포함하지 않습니다{coverage}. "
            f"{ecosystem_label} 은 용량이 커서 기본 수집 대상이 아닙니다 — 외부망에서 "
            "GVSKB_OSV_INCLUDE_NPM=1 을 설정하고 `gvskb update-intel --all` 을 실행한 뒤 "
            "캐시를 반입하세요."
        )

    return (
        f"오프라인 캐시가 {ecosystem_label} 생태계를 포함하지 않습니다{coverage}. "
        f"{ecosystem_label} 은 기본 수집 대상이므로 캐시가 불완전한 상태입니다 — 외부망에서 "
        "`gvskb update-intel --all` 을 다시 실행하고 `gvskb doctor` 로 커버리지를 확인한 뒤 "
        "반입하세요."
    )


def _offline_cache_check(name: str, ecosystem: str, ecosystem_label: str) -> dict:
    """Consult the local intel cache and return a unified PackageCheckResult dict.

    오프라인은 실재·발행일·CVE 를 확인할 수 없다 — exists=None, max_cve=UNKNOWN
    으로 '미확인'을 명시한다. 미확인은 '안전'이 아니다.
    """
    cache = IntelCache()
    osv_entry = cache.load("osv-malicious")
    kev_entry = cache.load("cisa-kev")

    base = dict(
        name=name,
        ecosystem=ecosystem,
        offline=True,
        exists=None,  # 오프라인 — 공식 저장소 실재 미확인
        registry_metadata=None,
        max_cve="UNKNOWN",  # CVE DB 미보유 — '없음'이 아니라 '미확인'
        heuristics=_basic_heuristics(name, ecosystem),
        engine_version=_engine_version(),
        checked_at=_now_iso(),
    )

    if osv_entry is None and kev_entry is None:
        # 캐시 없는 오프라인은 "통과"가 아니라 "판정 불가"다.
        return PackageCheckResult(
            **base,
            checked=False,
            verdict="unknown",
            verdict_severity="info",
            requires_review=True,
            note=(
                "GVSKB_MODE=offline 이며 로컬 인텔 캐시가 비어 있습니다. "
                "`gvskb update-intel` 을 먼저 실행해 OSV malicious feed와 CISA KEV 캐시를 만든 뒤 다시 검사하세요."
            ),
            disclaimer=(
                "이 결과는 휴리스틱 보조 신호이며 캐시 기반 검사가 수행되지 않았습니다. "
                "기관 허용 목록·sigstore/SBOM 정책에 따른 별도 검토가 필요합니다."
            ),
        ).model_dump(mode="json")

    advisories: list[dict] = []
    cache_sources_used: list[str] = []
    cache_freshness: dict[str, str] = {}
    stale_sources: list[str] = []

    if osv_entry is not None:
        cache_sources_used.append("osv-malicious")
        cache_freshness["osv-malicious"] = osv_entry.fetched_at
        if osv_entry.is_stale():
            stale_sources.append("osv-malicious")
        advisories.extend(_osv_advisories_for(osv_entry.items, name, ecosystem_label))

    kev_signals: list[dict] = []
    if kev_entry is not None:
        cache_sources_used.append("cisa-kev")
        cache_freshness["cisa-kev"] = kev_entry.fetched_at
        if kev_entry.is_stale():
            stale_sources.append("cisa-kev")
        kev_signals = _kev_signals_for(kev_entry.items, name)
        # KEV 매칭이 있으면 EPSS 악용확률·NVD CVSS를 병기해 우선순위 근거 제공.
        cache_sources_used.extend(_enrich_with_epss_nvd(kev_signals, cache))

    # 생태계 커버리지 — 악성 판정을 '깨끗함'으로 내리려면 osv-malicious 캐시가
    # *이 생태계를 실제로 담고 있어야* 한다. v1 캐시(ecosystems 미기록)는 당시
    # 기본 수집이 PyPI뿐이었으므로 ["PyPI"]로 간주한다. KEV는 vendor/product
    # 중심의 보조 신호일 뿐 '깨끗함'의 근거가 아니다.
    covered_ecosystems = (osv_entry.ecosystems or ["PyPI"]) if osv_entry is not None else []
    osv_covers = ecosystem_label in covered_ecosystems

    has_malicious = bool(advisories)
    severity = "high" if has_malicious else ("medium" if kev_signals else "info")

    base.update(
        verdict_severity=severity,
        is_malicious_package=has_malicious,
        vulnerability_count=len(advisories),
        malicious_advisory_count=len(advisories),
        advisories=advisories,
        kev_signals=kev_signals,
        in_kev=bool(kev_signals),
        # KEV 캐시를 실제로 열었을 때만 True. `cache_sources_used` 가 비었는지로
        # 추론하면 안 된다 — 악성 피드만 있고 KEV 가 없으면 목록은 비어 있지 않은데
        # KEV 대조는 되지 않은 상태다.
        kev_checked=kev_entry is not None,
        cache_sources_used=cache_sources_used,
        cache_freshness=cache_freshness,
        cache_ecosystems=covered_ecosystems,
        cache_stale_sources=stale_sources,
        source="local intel cache (GVSKB_MODE=offline)",
        disclaimer=(
            "오프라인 캐시 기반 검사입니다. 캐시 갱신 시점 이후의 신규 advisory는 반영되지 않습니다. "
            "운영 반영 전 `gvskb update-intel` 최신 실행 시각을 확인하세요."
        ),
    )

    if has_malicious:
        # 양성 판정(악성 발견)은 캐시가 오래됐어도 유효한 신호다.
        note = None
        if stale_sources:
            note = f"캐시가 오래됐습니다({', '.join(stale_sources)}) — 그래도 악성 판정은 유효합니다."
        return PackageCheckResult(
            **base, checked=True, verdict="malicious", requires_review=True, note=note,
        ).model_dump(mode="json")

    if not osv_covers:
        # 이 생태계의 악성 피드가 캐시에 없다 → '깨끗함'이 아니라 '판정 불가'.
        #
        # 안내는 원인별로 갈라야 한다. 전부 "GVSKB_OSV_INCLUDE_NPM=1 을 설정하라"로
        # 보내면 **PyPI 를 물어본 담당자가 npm 을 켜라는 엉뚱한 지시를 받는다** —
        # PyPI 는 항상 기본 수집 대상이라 그 변수와 무관하고, 실제 원인은 osv 캐시가
        # 없거나 무결성 검증에 걸려 버려진 것이다(실측 발견). 판정은 맞아도 안내가
        # 틀리면 담당자가 엉뚱한 조치를 하고 공백은 그대로 남는다.
        note = _coverage_gap_note(
            ecosystem_label, covered_ecosystems,
            osv_file_present=cache.path_for("osv-malicious").exists(),
        )
        return PackageCheckResult(
            **base,
            checked=False,
            verdict="unknown",
            requires_review=True,
            note=note,
        ).model_dump(mode="json")

    if stale_sources:
        # 신선도 초과 캐시의 '깨끗함'은 확정이 아니다 — 검토 필요로 승격.
        from ..intel.cache import intel_max_age_days
        return PackageCheckResult(
            **base,
            checked=True,
            verdict="checked_stale",
            requires_review=True,
            note=(
                f"캐시가 신선도 기준({intel_max_age_days()}일)을 초과했습니다: "
                f"{', '.join(stale_sources)}. 이 '이상 없음'은 오래된 데이터 기준입니다 — "
                "외부망에서 `gvskb update-intel` 후 캐시를 다시 반입하세요."
            ),
        ).model_dump(mode="json")

    # 여기까지 왔다는 것은 **"악성 피드에 없다"** 일 뿐, "알려진 취약점이 없다"가 아니다.
    #
    # 실측 사고: 하네스 두 개가 `.mcp.json` 에 GVSKB_MODE=offline 을 박아 두고 있어
    # 온라인 PC 에서도 오프라인 경로를 탔다. 그 경로가 `checked_clean` ·
    # `requires_review=False` 를 돌려주는 바람에 **취약점 26건짜리 pillow 12.2.0 이
    # '이상 없음'** 으로 통과했다(온라인: vulnerable/high). 오프라인 캐시에는 악성 피드와
    # KEV 만 있고 CVE DB 자체가 없어, 이 경로는 구조적으로 CVE 를 볼 수 없다.
    #
    # 그래서 '검사했고 깨끗함'이 아니라 **'악성은 대조했고 CVE 는 확인 못 함'** 으로
    # 돌려준다. `checked=False` 는 집계에서 '판정 불가'로 세어져 보고서의
    # "판정 불가 N건 — '안전'이 아닙니다" 로 이어진다(이미 있는 정직한 자리).
    # KEV 신호가 있으면 그것만으로도 '이상 없음'일 수 없다.
    kev_note = (
        " CISA KEV 목록에 이 이름과 일치하는 항목이 있습니다 — 우선 확인하세요."
        if kev_signals else ""
    )
    return PackageCheckResult(
        **base,
        checked=False,
        verdict="unknown",
        requires_review=True,
        note=(
            "오프라인 캐시에 **악성 등록은 없습니다**. 다만 오프라인에는 CVE 데이터가 "
            "없어 **알려진 취약점 여부는 확인하지 못했습니다**('이상 없음'이 아닙니다). "
            "취약점까지 보려면 외부망에서 검사하거나(GVSKB_MODE 를 offline 로 고정하지 "
            "마세요) 온라인 검사 결과를 반입하세요." + kev_note
        ),
    ).model_dump(mode="json")


# ---------------------------------------------------------------------------
# Manifest audit — shared by MCP scan_dependencies and `gvskb scan --check-deps`
# ---------------------------------------------------------------------------

# 락파일 시그니처 — 락파일을 requirements/package.json 파서에 넣으면 가짜
# 패키지명(name/version/description 같은 키워드)이 추출돼 "0건 → ok" 또는
# 쓰레기 OSV 질의가 나간다. 파싱 *전에* 감지해 정직하게 거절한다.
_LOCKFILE_HINTS: tuple[tuple[str, str], ...] = (
    ("[[package]]", "poetry.lock"),
    ('"lockfileVersion"', "package-lock.json"),
    ("# yarn lockfile", "yarn.lock"),
    ("lockfileVersion:", "pnpm-lock.yaml"),
)


def _detect_lockfile(manifest_text: str) -> str | None:
    head = manifest_text[:2000]
    for needle, label in _LOCKFILE_HINTS:
        if needle in head:
            return label
    return None


def _unparsed_result(ecosystem: str, note: str) -> dict:
    """파싱 0건은 '안전(ok)'이 아니라 '검사되지 않음'이다 — 거짓 통과 방지."""
    return {
        "ecosystem": ecosystem,
        "parsed_count": 0,
        "checked_count": 0,
        "unchecked_count": 0,
        "blocked": False,
        "requires_review": True,
        "verdict": "unparsed",
        "packages": [],
        "checks": [],
        "note": note,
        "disclaimer": (
            "파싱된 패키지가 0건입니다 — '안전'이 아니라 '검사되지 않음'입니다. "
            "requirements.txt(pypi) 또는 package.json(npm) 원본 매니페스트로 다시 검사하세요."
        ),
    }


def _aggregate_intel_cache(checks: list[dict]) -> dict:
    """패키지별 캐시 상태를 매니페스트 1건의 시스템 상태로 집계.

    ``state``: ``ok`` | ``stale`` | ``missing`` | ``not_used``

    - ``stale``  — 낡은 캐시로 판정했다. 그 이후 등재분은 반영되지 않았다.
    - ``missing`` — 캐시가 없어 대조 자체를 못 했다. '이상 없음'이 아니다.
    - ``not_used`` — 캐시를 볼 일이 없었다(취약점 0건 등). 문제 아님.

    가장 나쁜 상태가 대표값이 된다 — 일부만 낡았어도 보고서는 낡음을 알려야 한다.
    """
    stale: set[str] = set()
    used: set[str] = set()
    missing = False
    dates: dict[str, str] = {}
    for c in checks:
        used.update(c.get("cache_sources_used") or [])
        stale.update(c.get("cache_stale_sources") or [])
        for k, v in (c.get("cache_freshness") or {}).items():
            # 여러 패키지가 같은 캐시를 봤다면 가장 오래된 기준일을 남긴다.
            if v and (k not in dates or str(v) < dates[k]):
                dates[k] = str(v)
        # 취약점이 있는데 KEV 캐시를 못 썼다면 대조를 못 한 것이다.
        if c.get("vulnerability_count") and not (c.get("cache_sources_used") or []):
            missing = True
    if stale:
        state = "stale"
    elif missing:
        state = "missing"
    elif used:
        state = "ok"
    else:
        state = "not_used"
    return {
        "state": state,
        "sources_used": sorted(used),
        "stale_sources": sorted(stale),
        "as_of": dates or None,
    }


# ---------------------------------------------------------------------------
# 기관 레지스트리 판정 반영 (연동합의 §4-1·§4-2)
#
# 원칙: **로컬 탐지가 최종 안전망이다.** 기관 승인은 시점의 판단이고 위협 정보는
# 그 뒤에도 갱신된다. 승인된 버전이 나중에 악성으로 등재되면 승인이 그것을 가려서는
# 안 된다 — 그러면 만료일까지 초록불이 유지된다(승인 3개월이면 3개월간).
#
# 그래서 APPROVED 응답을 받아도 **로컬 인텔 캐시 대조는 반드시 수행**한다.
# 생략되는 것은 원격 OSV 조회뿐이다.
# ---------------------------------------------------------------------------

# 캐시가 이만큼 낡으면 '승인 + 대조함'이라고 말할 수 없다. is_stale() 보다 관대한
# 2차 임계값 — 낡음은 배너로 알리되(시스템 문제), 이 선을 넘으면 개별 검토로 올린다.
_APPROVAL_STALE_GRACE_DAYS = 30


def _cache_age_days(freshness: dict | None) -> int | None:
    """캐시 기준일 중 **가장 오래된** 것의 경과일. 확인 불가면 None."""
    if not freshness:
        return None
    oldest: int | None = None
    for raw in freshness.values():
        try:
            ts = datetime.fromisoformat(str(raw))
        except ValueError:
            continue
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - ts).days
        oldest = age if oldest is None else max(oldest, age)
    return oldest


# 우리가 해석할 수 있는 판정. 여기 없는 값(오류 표식·신설 상태·빈 값)은 '판정을
# 받지 못한 것'으로 다룬다 — 모르는 값을 통과로 읽으면, 상대가 상태를 하나 늘릴
# 때마다 우리 쪽에 조용한 초록불이 하나씩 생긴다.
_KNOWN_REGISTRY_STATUSES = frozenset({"APPROVED", "REJECTED", "UNDER_REVIEW", "UNKNOWN"})


def apply_registry_decision(local: dict, decision: dict) -> dict:
    """레지스트리 판정 + 로컬 대조 결과 → 최종 판정(연동합의 §4-2 3분기 규칙).

    ``local`` 은 **로컬 인텔 캐시 대조만** 수행한 결과다(원격 OSV 미조회).
    ``decision`` 은 레지스트리 응답(``status``·``max_env``·``expires_at`` 등).

    순수 함수다 — 네트워크 없이 규칙만 검증할 수 있어야 하기 때문이다.
    """
    status = str(decision.get("status") or "").upper()
    out = dict(local)
    # 배치가 200 이라고 모든 항목이 답을 받은 것은 아니다. 상대가 부분 실패를
    # 허용하도록 고친 뒤로 실패는 **항목 단위**로 온다 — 아는 판정이 아니면
    # '조회했고 이상 없음'으로 두지 않는다. 조용한 초록불이 빨간불보다 위험하다.
    out["registry_status"] = "ok" if status in _KNOWN_REGISTRY_STATUSES else "item_failed"
    out["registry_decision"] = decision

    if status == "REJECTED":
        # 차단은 더 강한 신호이고 추가 분석이 판정을 뒤집지 않는다 — 즉시 확정.
        #
        # ``stale`` 은 TTL 이 지났는데도 삭제하지 않고 강등해 둔 캐시 차단이다
        # (registry_client._cache_get). **판정은 똑같이 차단**이다 — 조회 실패로
        # 차단이 풀리면 레지스트리 도달을 방해하는 것만으로 우회가 되기 때문이다
        # (합의 §4-5). 다만 방금 받은 차단과 8일째 확인 못 한 차단은 담당자가
        # 할 일이 다르다: 후자는 '해제됐는지 확인'이 남아 있다. 판정이 같다고
        # 안내까지 같으면, 도구는 자기가 무엇을 모르는지 말하지 않는 셈이 된다.
        stale_block = bool(decision.get("stale"))
        note = (
            "기관 레지스트리가 이 패키지를 **차단**했습니다"
            + (f" (사유: {decision['rejected_reason']})" if decision.get("rejected_reason") else "")
            + ". 사용하지 마세요."
        )
        if stale_block:
            note += (
                " ⚠ 이 차단은 **로컬 캐시에 남아 있던 것**이며 최근 레지스트리에서 "
                "다시 확인하지 못했습니다(보관 기한 초과). 차단은 그대로 유지됩니다 — "
                "조회에 실패했다고 차단이 풀리지는 않습니다. 해제 여부는 레지스트리 "
                "복구 후 재검사로 확인하세요."
            )
        out.update(
            verdict="registry_rejected",
            verdict_severity="critical",
            requires_review=True,
            registry_stale=stale_block,
            note=note,
        )
        return out

    if status != "APPROVED":
        # UNDER_REVIEW · UNKNOWN — 자체 분석으로 진행한다(여기서는 표시만 남긴다).
        return out

    # ── APPROVED ── 로컬 탐지가 이기는지 먼저 본다(원칙 4).
    if local.get("is_malicious_package") or local.get("verdict") == "malicious":
        out["note"] = (
            "⚠ 기관 레지스트리는 승인했으나 **로컬 위협 정보에서 악성으로 확인**됩니다. "
            "승인 이후 등재됐을 수 있습니다 — 기관 보안담당자에게 즉시 알리세요. "
            + (local.get("note") or "")
        ).strip()
        return out  # verdict=malicious 유지
    if local.get("kev_signals"):
        out["note"] = (
            "⚠ 기관 승인 패키지이나 CISA KEV(실제 악용) 신호가 있습니다 — 확인이 필요합니다. "
            + (local.get("note") or "")
        ).strip()
        return out

    # ── 캐시 신선도에 따라 갈린다 ──
    stale = bool(local.get("cache_stale_sources")) or not local.get("cache_sources_used")
    age = _cache_age_days(local.get("cache_freshness"))
    over_grace = age is not None and age > _APPROVAL_STALE_GRACE_DAYS

    out.update(
        verdict="registry_approved",
        verdict_severity="info",
        is_malicious_package=False,
        # 대조를 실제로 했는지를 정직하게 싣는다. False 는 '안전'이 아니라 '판정 못 함'.
        checked=not stale,
        # 낡음은 '번들 반입 한 번'으로 풀리는 시스템 문제라 개별 검토로 올리지
        # 않는다(배너로 알린다). 다만 유예를 넘기면 그때는 판정을 신뢰할 수 없다.
        requires_review=bool(over_grace) or (stale and age is None),
    )
    approver = decision.get("approved_by") or "기관 레지스트리"
    base = f"{approver}가 승인한 패키지입니다"
    if decision.get("expires_at"):
        base += f"(승인 만료 {decision['expires_at']})"
    if not stale:
        out["note"] = base + ". 로컬 위협 정보 대조에서도 이상이 없었습니다."
    elif over_grace:
        out["note"] = (
            base + f". 다만 로컬 위협 정보가 {age}일 낡아 대조를 신뢰할 수 없습니다"
            " — 인텔 번들을 반입한 뒤 재검사하세요."
        )
    else:
        out["note"] = (
            base + ". 로컬 위협 정보가 낡아 **이번에 대조하지는 못했습니다**"
            "(checked=false) — 인텔 번들 반입을 권장합니다."
        )
    return out


# 규모 상수 — 락파일은 매니페스트와 자릿수가 다르다.
_MANIFEST_DEFAULT_LIMIT = 20     # 직접 의존성만 — 사람이 훑어볼 규모
# 락파일 기본 상한. 500 이던 시절 실측(2026-08-08)에서 `lexdiff` 의 pnpm-lock 은
# 전이 의존성이 **906개**였고 406개가 조용히 잘렸다 — 트리의 45% 를 안 보고 "검사됨"
# 이라 적은 것이다. 요즘 npm 프로젝트는 900개를 우습게 넘으므로 방어 상한
# (`_MAX_PACKAGES`)까지 올린다. 잘리면 `truncated_count` 로 보고서에 드러난다.
_LOCKFILE_DEFAULT_LIMIT = 2000   # 전이 의존성 포함 — 트리 전체
_MAX_PACKAGES = 2000             # 방어 상한(무한 대기 방지)


#: OSV 조회 재시도 — 일시 실패에만. 4xx 는 다시 물어도 같은 답이므로 재시도하지 않는다.
_OSV_RETRIES = 2
_OSV_BACKOFF = (0.5, 1.5)


def _is_transient(exc: Exception) -> bool:
    """다시 시도하면 달라질 수 있는 실패인가.

    **왜 필요한가(실측 2026-08-08)**: `kordoc` 의 패키지 375개 중 **117개(31%)** 가
    ``error`` 로 확정됐는데, 그중 77건이 ``getaddrinfo failed`` — DNS 일시 실패였다.
    한 번만 다시 물었으면 대부분 회수됐을 것을, 재시도 없이 '판정 불가'로 굳혔다.

    반대로 4xx 는 재시도하면 안 된다. 같은 답이 오는데 서버만 괴롭히고, 무엇보다
    **실패를 늦게 알게 된다.**
    """
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code >= 500 or exc.response.status_code == 429
    return isinstance(exc, (httpx.ConnectError, httpx.ConnectTimeout,
                            httpx.ReadTimeout, httpx.WriteTimeout,
                            httpx.PoolTimeout, httpx.RemoteProtocolError))


async def _osv_query(payload: dict, *, timeout: float,
                     client: "httpx.AsyncClient | None" = None) -> dict:
    """OSV 질의 — 일시 실패는 물러났다가 다시 묻는다.

    ``client`` 를 받으면 연결을 재사용한다. 예전에는 패키지마다 ``AsyncClient`` 를
    새로 열어, 락파일 906개면 TLS 핸드셰이크도 906번이었다. 느린 것보다 나쁜 것은
    연결이 많을수록 **일시 실패가 늘어난다**는 점이다.
    """
    last: Exception | None = None
    for attempt in range(_OSV_RETRIES + 1):
        try:
            if client is not None:
                resp = await client.post(OSV_QUERY_URL, json=payload)
                resp.raise_for_status()
                return resp.json()
            async with httpx.AsyncClient(timeout=timeout) as own:
                resp = await own.post(OSV_QUERY_URL, json=payload)
                resp.raise_for_status()
                return resp.json()
        except httpx.HTTPError as exc:
            last = exc
            if attempt >= _OSV_RETRIES or not _is_transient(exc):
                raise
            await asyncio.sleep(_OSV_BACKOFF[min(attempt, len(_OSV_BACKOFF) - 1)])
    raise last  # pragma: no cover - 루프가 반드시 반환하거나 raise 한다


def _concurrency() -> int:
    """동시 조회 수. 순차 실행이면 락파일 800건이 곧 800회 왕복이 된다.

    기본 8 은 기관 레지스트리 권고값과 같고, OSV·PyPI 에도 무례하지 않은 수준이다.
    """
    try:
        n = int(os.environ.get("GVSKB_CHECK_CONCURRENCY", "8"))
    except ValueError:
        return 8
    return max(1, min(n, 32))


async def audit_manifest(
    manifest_text: str,
    ecosystem: Literal["pypi", "npm"] = "pypi",
    limit: int | None = None,
    env_grade: str | None = None,
    filename: str = "",
    on_progress: "Callable[[int, int, str], None] | None" = None,
) -> dict:
    """의존성 매니페스트·**락파일**을 파싱해 패키지별 취약·악성 검사를 수행한다.

    온라인: 공식 저장소 실재·발행일 확인 + OSV.dev 조회(패키지명·버전만 전송).
    오프라인(GVSKB_MODE=offline): 로컬 인텔 캐시 기반 — 판정 불가는 '안전'이
    아니라 requires_review로 표시. env_grade(E0~E2)는 쿨다운 기준일을 결정한다.

    락파일을 받으면 **전이 의존성까지** 검사한다. 실무 취약점은 대부분 거기에
    있고 매니페스트에는 적히지 않는다. 락파일이 생태계를 확정하므로 인자로 받은
    ``ecosystem`` 보다 파일 쪽을 신뢰한다.

    ``limit`` 을 주지 않으면 형식에 맞춰 정한다(매니페스트 20 · 락파일 500).
    잘린 경우 ``truncated_count`` 로 **반드시 드러낸다** — 일부만 검사하고
    전부 검사한 것처럼 보이면 그게 조용한 초록불이다.
    """
    from ..scanner import parse_manifest_packages  # 지연 import — 경량 경로 유지
    from .lockfiles import parse_lockfile

    source_kind = "manifest"
    lock = parse_lockfile(manifest_text, filename)
    if lock is not None:
        source_kind = "lockfile"
        lock_format = lock["format"]
        if lock["ecosystem"] != ecosystem:
            # 파일 형식이 생태계를 확정한다 — 인자가 틀렸으면 파일을 따른다.
            ecosystem = lock["ecosystem"]  # type: ignore[assignment]
        packages = lock["packages"]
        if not packages:
            return _unparsed_result(
                ecosystem,
                f"{lock_format} 을(를) 인식했으나 패키지를 읽지 못했습니다"
                "(형식 손상 가능). 검사되지 않았으므로 '이상 없음'이 아닙니다.",
            )
    else:
        lock_format = None
        packages = parse_manifest_packages(manifest_text, ecosystem)
        if not packages:
            return _unparsed_result(ecosystem, "이 텍스트에서 패키지를 파싱하지 못했습니다. 형식·ecosystem을 확인하세요.")

    effective_limit = limit if limit is not None else (
        _LOCKFILE_DEFAULT_LIMIT if source_kind == "lockfile" else _MANIFEST_DEFAULT_LIMIT
    )
    effective_limit = max(0, min(effective_limit, _MAX_PACKAGES))
    limited = packages[:effective_limit]
    truncated = len(packages) - len(limited)

    # 순차 실행이면 락파일 800건이 곧 800회 왕복이다 — 동시 실행하되 상한을 둔다.
    sem = asyncio.Semaphore(_concurrency())
    done = 0
    total = len(limited)

    async def _one(package: dict, client: "httpx.AsyncClient | None") -> dict:
        nonlocal done
        async with sem:
            result = await check_package_impl(
                name=str(package["name"]),
                version=str(package["version"]) if package.get("version") else None,
                ecosystem=ecosystem,
                env_grade=env_grade,
                client=client,
            )
        done += 1
        if on_progress is not None:
            try:
                on_progress(done, total, str(package.get("name") or ""))
            except Exception:  # pragma: no cover - 진행 표시가 검사를 막으면 안 된다
                pass
        # 경계값 검사는 남기되 **관측이 아니라 가정**임을 싣는다. `requests>=2.28` 을
        # 2.28 로 판정해 놓고 그것을 '이 프로젝트가 쓰는 버전의 사실'로 다루면,
        # 실제로 2.31.0 이 깔린 프로젝트에 2.28 의 취약점을 보고하게 된다.
        #
        # 표시는 값으로만 남기고 문장은 붙이지 않는다 — 조치가 "락파일을 쓰거나
        # --include-installed 를 켜라" 한 건이므로 알림도 한 건이다(집계는 호출자가
        # 한다). 패키지마다 같은 문장을 달면 매니페스트 20건짜리에서 같은 안내가
        # 20번 나오고, 그러면 담당자는 그 사이의 진짜 위험도 함께 넘긴다.
        if package.get("version") and not package.get("version_exact", True):
            result["version_exact"] = False
        return result

    # 기관 레지스트리 조회를 **자체 분석과 병렬로** 돌린다. 직렬이면 지연이 둘의
    # 합이 되어 "조회가 자체 분석보다 느리면 의미 없다"는 전제를 깬다(합의 §6-3).
    from . import registry_client as _rc

    registry_on, _ = _rc.is_enabled()
    lookup_task = (
        asyncio.ensure_future(_rc.lookup_batch(
            [{"ecosystem": ecosystem, "name": p["name"], "version": p.get("version")}
             for p in limited],
            env_grade=env_grade,
        ))
        if registry_on else None
    )

    # 연결을 하나로 모은다 — 906개면 예전에는 TLS 핸드셰이크도 906번이었고,
    # 연결이 많을수록 일시 실패(getaddrinfo)가 늘었다. 오프라인 모드는 네트워크를
    # 쓰지 않으므로 열지 않는다.
    if _is_offline():
        checks = list(await asyncio.gather(*(_one(p, None) for p in limited)))
    else:
        pool = httpx.Limits(max_connections=_concurrency(),
                            max_keepalive_connections=_concurrency())
        async with httpx.AsyncClient(timeout=10.0, limits=pool) as shared:
            checks = list(await asyncio.gather(*(_one(p, shared) for p in limited)))

    # 판정마다 출처를 붙인다. 하네스 집행계약 §4-0 이 이 값으로 `unknown` 차단
    # 범위를 정하는데(사람이 고른 것만 차단), 일부 판정에만 붙어 있으면 같은
    # 패키지가 어느 경로로 검사됐느냐에 따라 막히거나 안 막히게 된다.
    # 설치본 경로는 호출자가 매니페스트와 대조해 덮어쓴다(직접/전이 구분).
    default_scope = "lockfile" if source_kind == "lockfile" else "manifest"
    for c in checks:
        c.setdefault("source_scope", default_scope)

    registry_status = "disabled"
    registry_error: dict | None = None
    if lookup_task is not None:
        decisions = await lookup_task
        registry_error = decisions.pop("__error__", None)
        if registry_error:
            # 실패 종류를 그대로 옮긴다. 422(형식 거부)와 연결 실패는 담당자가
            # 할 일이 정반대라 — 스키마 교정 vs 기다렸다 재시도 — 뭉치면 안 된다.
            registry_status = str(registry_error.get("status") or "unreachable")
        elif not decisions and limited:
            # 오류 표식 없이 결과가 통째로 비었다 — 도달 실패로 본다.
            registry_status = "unreachable"
        else:
            registry_status = "ok"

        # 부분 실패여도 **받은 판정은 반영한다**. 청크 하나가 거부됐다고 나머지의
        # 기관 차단까지 버리면, 부분 실패 자체가 차단 우회 수단이 된다.
        # 판정을 못 받은 것에는 실패 사유를 그대로 붙여 '조회 안 됨'을 남긴다.
        merged: list[dict] = []
        for c in checks:
            purl = f"pkg:{c.get('ecosystem')}/{c.get('name')}" + (
                f"@{c['version']}" if c.get("version") else ""
            )
            d = decisions.get(purl)
            merged.append(apply_registry_decision(c, d) if d else
                          _rc.annotate_status(c, registry_status))
        checks = merged
    # critical 을 빠뜨리면 기관이 명시적으로 차단한 패키지(registry_rejected)가
    # 집계에서 통째로 누락된다 — 사다리 최상단이 게이트를 못 지나는 셈이다.
    blocked = any(
        c.get("is_malicious_package") or c.get("verdict_severity") in ("high", "critical")
        for c in checks
    )
    # 판정 불가(캐시 없는 오프라인·API 실패)를 "안전"으로 오해하지 않도록 실제
    # 검사된 수와 판정 불가 수를 분리하고, 검토 필요 여부를 명시한다.
    # 알려진 취약점(CVE)이 있는 패키지도 'ok'가 아니라 검토 대상이다 — 악성만
    # 걸러내고 취약 버전을 통과시키면 보안팀이 거짓 안심을 하게 된다.
    actually_checked = sum(1 for c in checks if c.get("checked", False))
    unchecked = len(checks) - actually_checked
    has_vulns = any(c.get("vulnerability_count") for c in checks)
    not_found = sum(1 for c in checks if c.get("verdict") == "not_found")
    # 경계값 판정 수 — 조치가 하나이므로 여기서 세어 배너 한 줄로 알린다.
    bounded = sum(1 for c in checks if c.get("version_exact") is False)
    hold = sum(1 for c in checks if c.get("verdict") == "cooldown_hold")
    # 잘린 패키지는 '검사되지 않음'이다 — 이걸 조용히 넘기면 트리의 일부만 보고
    # 전부 본 것처럼 알리게 된다. 검토 대상으로 올리고 수치로도 드러낸다.
    requires_review = (
        blocked or unchecked > 0 or has_vulns or truncated > 0
        or any(c.get("requires_review") for c in checks)
    )
    verdict = "blocked" if blocked else ("review_required" if requires_review else "ok")
    return {
        "source_kind": source_kind,          # manifest | lockfile
        "lockfile_format": lock_format,      # 예: package-lock.json (매니페스트면 None)
        "truncated_count": truncated,        # limit 로 잘려 검사되지 않은 수
        "concurrency": _concurrency(),
        # 도달 실패는 패키지가 아니라 **시스템**의 문제다 — 배너 1개로 알린다.
        "registry_status": registry_status,
        # 실패의 규모(몇 청크 중 몇 개, 어떤 HTTP 코드). 배너는 무엇을 고칠지만
        # 말하고, 얼마나 잃었는지는 여기서 확인한다. 실패 없으면 None.
        "registry_error": registry_error,
        # 인텔 캐시 상태는 **패키지가 아니라 시스템의 문제**다. 조치는 "번들 반입"
        # 한 번이므로 패키지 수백 건에 같은 깃발을 꽂으면 담당자가 그것을 무시하게
        # 되고, 그러면 그 사이의 진짜 위험도 함께 묻힌다. 집계해서 한 번만 알린다.
        "intel_cache": _aggregate_intel_cache(checks),
        "ecosystem": ecosystem,
        "parsed_count": len(packages),
        "checked_count": actually_checked,
        "unchecked_count": unchecked,
        "not_found_count": not_found,   # 실재하지 않는 패키지(슬롭스쿼팅 의심) 수
        # 매니페스트 제약의 경계값으로 판정한 수(`requests>=2.28` → 2.28).
        # 실제 설치 버전이 아닐 수 있다 — 배너 1줄로만 알린다.
        "bounded_version_count": bounded,
        "hold_count": hold,             # 쿨다운 대기(HOLD) 수 — 위험 확정이 아니라 대기 권고
        "env_grade": env_grade,
        "blocked": blocked,
        "requires_review": requires_review,
        "verdict": verdict,
        "packages": limited,
        "checks": checks,
        "engine_version": _engine_version(),
        "checked_at": _now_iso(),
        "disclaimer": (
            "취약점 API에는 패키지명과 ecosystem만 전송합니다. "
            "unchecked_count>0 이면 일부 패키지가 '판정 불가'(캐시 없는 오프라인·API 실패)이며 '안전'이 아닙니다. "
            + (
                f"truncated_count={truncated} — limit 로 잘려 **검사되지 않은** 패키지가 있습니다. "
                "limit 를 올려 재검사하세요."
                if truncated else
                ("전이 의존성을 포함한 락파일 기준 검사입니다."
                 if source_kind == "lockfile" else
                 "매니페스트에 적힌 직접 의존성만 검사했습니다 — 전이 의존성은 "
                 "락파일(package-lock.json·poetry.lock 등)을 넣어야 검사됩니다.")
            )
        ),
    }


_ONLINE_DISCLAIMER = (
    "이 검사는 OSV.dev·공식 저장소 메타데이터·이름 기반 휴리스틱을 활용한 보조 신호입니다. "
    "공식 보안 검토, 기관 허용 패키지 정책, lockfile/SBOM 검사를 대체하지 않습니다."
)


async def check_package_impl(
    name: str,
    ecosystem: Literal["pypi", "npm"] = "pypi",
    version: str | None = None,
    timeout: float = 10.0,
    env_grade: str | None = None,
    client: "httpx.AsyncClient | None" = None,
) -> dict:
    eco = ECOSYSTEM_MAP.get(ecosystem.lower())
    if not eco:
        return PackageCheckResult(
            name=name,
            ecosystem=ecosystem,
            checked=False,
            verdict="error",
            error=f"unsupported ecosystem: {ecosystem} (allowed: pypi, npm)",
            engine_version=_engine_version(),
            checked_at=_now_iso(),
        ).model_dump(mode="json")

    if _is_offline():
        result = _offline_cache_check(name, ecosystem, eco)
        if version is not None:
            result["version"] = version
        # 오프라인은 발행일을 알 수 없어 쿨다운 판정 불가(ok=None) — '통과' 아님.
        result["cooldown"] = _evaluate_cooldown(None, env_grade).model_dump(mode="json")
        return result

    # ① 실재 확인 + 메타데이터(발행일·라이선스·설치스크립트) — VCPS C4/C1/C2/LIC.
    meta = await fetch_registry_metadata(name, ecosystem, version=version, timeout=timeout)
    heuristics = _basic_heuristics(name, ecosystem)

    base = dict(
        name=name,
        version=version,
        ecosystem=ecosystem,
        exists=meta.exists,
        registry_metadata=meta,
        heuristics=heuristics,
        engine_version=_engine_version(),
        checked_at=_now_iso(),
        disclaimer=_ONLINE_DISCLAIMER,
    )

    if meta.exists is False:
        # 존재하지 않는 패키지 — AI 가 지어냈을 가능성(슬롭스쿼팅)이 가장 높은
        # 신호다. 과거에는 OSV 빈 응답 때문에 "취약점 0건"으로 가장 깨끗해
        # 보였다(역효과). VCPS-C4-EXISTENCE: BLOCK.
        squat = heuristics.get("typosquat_warning")
        return PackageCheckResult(
            **base,
            checked=False,  # 취약점 검사 자체가 무의미(대상 부재)
            verdict="not_found",
            verdict_severity="high",
            requires_review=True,
            source=meta.source,
            note=(
                f"'{name}'은(는) 공식 저장소({eco})에 존재하지 않습니다. "
                "AI가 지어낸 이름(슬롭스쿼팅)일 가능성이 높습니다 — 설치 시도 자체가 위험하며, "
                "공식 문서에서 정확한 패키지명을 확인하세요."
                + (f" 참고: {squat}" if squat else "")
            ),
        ).model_dump(mode="json")

    # ② OSV 취약점·악성 조회 (C6) — 패키지명·버전만 전송.
    payload: dict = {"package": {"name": name, "ecosystem": eco}}
    if version:
        payload["version"] = version

    try:
        data = await _osv_query(payload, timeout=timeout, client=client)
    except httpx.HTTPError as exc:
        return PackageCheckResult(
            **base,
            checked=False,
            verdict="error",
            requires_review=True,
            error=f"OSV API failure: {exc!s}",
            cooldown=_evaluate_cooldown(meta, env_grade),
            license_verdict=license_verdict(meta.license) if meta.license else None,
        ).model_dump(mode="json")

    vulns = data.get("vulns", []) or []
    malicious_advisories = [v for v in vulns if str(v.get("id", "")).startswith("MAL-")]
    has_malicious = bool(malicious_advisories)
    max_cve = _max_cve_from_vulns(vulns)

    # ③ CISA KEV 교차 대조 — 실제 악용 중인 취약점이면 심각도와 무관하게 차단급.
    # 온라인 모드에서도 이 대조는 **로컬 캐시**를 쓴다. 그 의존을 결과에 싣지
    # 않으면 캐시가 없거나 낡아도 in_kev=false 가 '악용 없음'처럼 보인다.
    kev_hits: list[dict] = []
    kev_cache = {"state": "not_needed", "fetched_at": None}
    if vulns:
        _intel = IntelCache()
        kev_hits = _kev_cve_hits(vulns, _intel)
        kev_cache = _kev_cache_state(_intel)
    in_kev = bool(kev_hits)

    # ④ 쿨다운(C1)·라이선스(LIC)·설치 스크립트(C2) 판정.
    cooldown = _evaluate_cooldown(meta, env_grade)
    lic_verdict = license_verdict(meta.license) if meta.license else None

    notes: list[str] = []
    if meta.error:
        notes.append(meta.error)
    if meta.install_scripts == "present":
        notes.append(
            f"설치 스크립트({', '.join(meta.install_script_names)})가 있습니다 — "
            "보안 점검보다 먼저 실행되므로 `--ignore-scripts` 설치를 권장합니다(VCPS C2)."
        )
    if meta.deprecated:
        notes.append("npm에서 deprecated 로 표시된 패키지입니다 — 유지보수 중단 신호.")
    if lic_verdict == "review_required":
        notes.append(
            f"라이선스({meta.license})는 배포 형태에 따라 제약이 있을 수 있어 검토가 필요합니다"
            "(내부 운영 도구는 대체로 문제 없음)."
        )
    if in_kev:
        notes.append("이 패키지의 취약점이 CISA KEV(실제 악용 목록)에 있습니다 — 예외 없이 조치하세요.")
    elif kev_cache["state"] == "missing":
        notes.append(
            "CISA KEV 캐시가 없어 '실제 악용 중인지' 대조하지 못했습니다 — "
            "`gvskb update-intel` 후 재검사하세요. 이 결과의 in_kev=false 는 "
            "'악용 없음'이 아니라 '대조 못 함'입니다."
        )
    elif kev_cache["state"] == "stale":
        notes.append(
            f"CISA KEV 캐시가 오래됐습니다({str(kev_cache['fetched_at'])[:10]} 기준) — "
            "그 이후 악용 목록에 오른 취약점은 반영되지 않았습니다."
        )

    # 판정 사다리: malicious > vulnerable > cooldown_hold > checked_clean.
    if has_malicious:
        verdict, severity = "malicious", "high"
    elif vulns:
        verdict = "vulnerable"
        if version is None:
            # 버전 미지정 조회는 OSV가 *전체 버전 이력*의 취약점을 반환한다 —
            # 최신 버전은 이미 조치됐을 수 있으므로 차단(high)이 아니라 검토로
            # 캡핑하고, 버전을 지정한 재검사를 유도한다(과차단 방지).
            severity = "medium"
            notes.append(
                f"버전 미지정 — 이 취약점 {len(vulns)}건은 과거 버전 포함 전체 이력입니다. "
                "사용할 버전을 지정해 재검사하세요(최신 버전은 조치됐을 수 있음)."
            )
        else:
            severity = "high" if (in_kev or max_cve in ("HIGH", "CRITICAL")) else "medium"
    elif cooldown.ok is False:
        # 발행 직후 버전 — 위험이 확인된 게 아니라 '아직 신뢰할 수 없음'(HOLD).
        verdict, severity = "cooldown_hold", "medium"
        notes.append(
            f"버전 발행 후 {cooldown.version_age_days}일밖에 지나지 않았습니다"
            f"(기준 {cooldown.cooldown_days}일, 등급 {cooldown.env_grade}). "
            "오염된 신규 버전은 대부분 수 시간~수 일 내 발각·삭제됩니다 — 기다렸다 설치하세요(VCPS C1)."
        )
    elif meta.version_exists is False:
        # 패키지는 있는데 **요청한 버전이 없다** — 설치가 안 되거나(오타), 스쿼터가
        # 자리만 잡아 둔 패키지(latest 0.0.0)에 존재하지 않는 버전을 적어 둔 경우.
        # 예전엔 발행일 None → cooldown.ok=None 으로 흡수돼 '이상 없음'이 됐다.
        verdict, severity = "version_not_found", "high"
        notes.append(
            f"'{name}' 은(는) 저장소에 있지만 버전 {version} 은 존재하지 않습니다"
            f"(최신 {meta.latest_version}). 버전 오타이거나 자리차지 패키지일 수 있습니다 — "
            "공식 문서에서 이름과 버전을 함께 확인하세요."
        )
    elif _squat_distance(heuristics) == 1:
        # 인기 패키지와 1자 차이 — 레지스트리에 **존재하더라도** 통과시키지 않는다.
        # 존재가 면죄부가 되면 스쿼터가 이름을 등록해 둔 바로 그 상황에서 뚫린다.
        verdict, severity = "suspicious_name", "high"
    else:
        verdict, severity = "checked_clean", "info"

    requires_review = (
        has_malicious or bool(vulns) or cooldown.ok is False
        or cooldown.ok is None            # 발행일 미상 — 쿨다운 판정 불가는 통과가 아니다
        or meta.exists is None            # 실재 미확인(조회 실패)은 검토 대상
        or meta.version_exists is False
        or _squat_distance(heuristics) in (1, 2)   # 2자 차이도 사람이 봐야 한다
        or meta.install_scripts == "present"
        or lic_verdict == "review_required"
        or bool(meta.deprecated)
    )

    advisory_rows = _advisory_rows(vulns, name=name, eco=eco)

    return PackageCheckResult(
        **base,
        checked=True,
        verdict=verdict,
        verdict_severity=severity,
        requires_review=requires_review,
        is_malicious_package=has_malicious,
        vulnerability_count=len(vulns),
        malicious_advisory_count=len(malicious_advisories),
        max_cve=max_cve,
        in_kev=in_kev,
        # 'missing' 일 때만 False 다. 'not_needed'(취약점 0건)는 대조할 대상이
        # 없었던 것이고 KEV 는 CVE 기반이므로 in_kev=false 가 사실로 성립한다.
        kev_checked=kev_cache["state"] != "missing",
        kev_signals=kev_hits,
        cooldown=cooldown,
        license_verdict=lic_verdict,
        advisories=advisory_rows,
        recommended_version=_recommended_version(advisory_rows, version),
        source="OSV.dev v1/query + " + (meta.source or "registry metadata"),
        # 온라인 경로도 KEV 대조에 로컬 캐시를 쓴다 — 어떤 캐시를 썼고 얼마나
        # 낡았는지 결과가 스스로 밝혀야 보고서가 집계해 배너로 알릴 수 있다.
        cache_sources_used=["cisa-kev"] if kev_cache["state"] in ("ok", "stale") else [],
        cache_freshness=(
            {"cisa-kev": str(kev_cache["fetched_at"])} if kev_cache["fetched_at"] else {}
        ),
        cache_stale_sources=["cisa-kev"] if kev_cache["state"] == "stale" else [],
        note=" ".join(notes) if notes else None,
    ).model_dump(mode="json")
