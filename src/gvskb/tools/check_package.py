"""Package reputation and vulnerability checks using OSV.dev.

When ``GVSKB_MODE=offline``, this module does not call OSV. Instead it consults
the on-disk intel cache populated by ``gvskb update-intel`` (CISA KEV + OSV
malicious feed). This keeps air-gapped agencies usable: as long as their
cache is current, they still get malicious-package verdicts. If no cache is
present we are honest about it — the result reports ``checked=False`` and
points the operator at ``gvskb update-intel``.
"""
from __future__ import annotations

import os
import re
from datetime import datetime, timezone
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
        return PackageCheckResult(
            **base,
            checked=False,
            verdict="unknown",
            requires_review=True,
            note=(
                f"오프라인 캐시가 {ecosystem_label} 생태계를 포함하지 않습니다"
                f"(캐시 커버리지: {covered_ecosystems or '없음'}). "
                "외부망에서 `gvskb update-intel --all` 실행 시 npm까지 받으려면 "
                "GVSKB_OSV_INCLUDE_NPM=1 을 설정한 뒤 캐시를 반입하세요."
            ),
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

    return PackageCheckResult(
        **base, checked=True, verdict="checked_clean", requires_review=False,
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


async def audit_manifest(
    manifest_text: str,
    ecosystem: Literal["pypi", "npm"] = "pypi",
    limit: int = 20,
    env_grade: str | None = None,
) -> dict:
    """의존성 매니페스트를 파싱해 패키지별 취약·악성 검사를 수행한다.

    온라인: 공식 저장소 실재·발행일 확인 + OSV.dev 조회(패키지명·버전만 전송).
    오프라인(GVSKB_MODE=offline): 로컬 인텔 캐시 기반 — 판정 불가는 '안전'이
    아니라 requires_review로 표시. env_grade(E0~E2)는 쿨다운 기준일을 결정한다.
    """
    from ..scanner import parse_manifest_packages  # 지연 import — 경량 경로 유지

    lock = _detect_lockfile(manifest_text)
    if lock:
        return _unparsed_result(
            ecosystem,
            f"락파일 형식({lock})은 이 도구가 파싱하지 못합니다. "
            "원본 매니페스트(requirements.txt·package.json)를 검사하세요.",
        )

    packages = parse_manifest_packages(manifest_text, ecosystem)
    if not packages:
        return _unparsed_result(ecosystem, "이 텍스트에서 패키지를 파싱하지 못했습니다. 형식·ecosystem을 확인하세요.")

    limited = packages[: max(0, min(limit, 100))]
    checks = []
    for package in limited:
        checks.append(
            await check_package_impl(
                name=str(package["name"]),
                version=str(package["version"]) if package.get("version") else None,
                ecosystem=ecosystem,
                env_grade=env_grade,
            )
        )
    blocked = any(c.get("is_malicious_package") or c.get("verdict_severity") == "high" for c in checks)
    # 판정 불가(캐시 없는 오프라인·API 실패)를 "안전"으로 오해하지 않도록 실제
    # 검사된 수와 판정 불가 수를 분리하고, 검토 필요 여부를 명시한다.
    # 알려진 취약점(CVE)이 있는 패키지도 'ok'가 아니라 검토 대상이다 — 악성만
    # 걸러내고 취약 버전을 통과시키면 보안팀이 거짓 안심을 하게 된다.
    actually_checked = sum(1 for c in checks if c.get("checked", False))
    unchecked = len(checks) - actually_checked
    has_vulns = any(c.get("vulnerability_count") for c in checks)
    not_found = sum(1 for c in checks if c.get("verdict") == "not_found")
    hold = sum(1 for c in checks if c.get("verdict") == "cooldown_hold")
    requires_review = blocked or unchecked > 0 or has_vulns or any(c.get("requires_review") for c in checks)
    verdict = "blocked" if blocked else ("review_required" if requires_review else "ok")
    return {
        # 인텔 캐시 상태는 **패키지가 아니라 시스템의 문제**다. 조치는 "번들 반입"
        # 한 번이므로 패키지 수백 건에 같은 깃발을 꽂으면 담당자가 그것을 무시하게
        # 되고, 그러면 그 사이의 진짜 위험도 함께 묻힌다. 집계해서 한 번만 알린다.
        "intel_cache": _aggregate_intel_cache(checks),
        "ecosystem": ecosystem,
        "parsed_count": len(packages),
        "checked_count": actually_checked,
        "unchecked_count": unchecked,
        "not_found_count": not_found,   # 실재하지 않는 패키지(슬롭스쿼팅 의심) 수
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
            "운영 반영 전 lockfile/SBOM 기준 재검사를 권장합니다."
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

    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            resp = await client.post(OSV_QUERY_URL, json=payload)
            resp.raise_for_status()
            data = resp.json()
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
    else:
        verdict, severity = "checked_clean", "info"

    requires_review = (
        has_malicious or bool(vulns) or cooldown.ok is False
        or meta.exists is None            # 실재 미확인(조회 실패)은 검토 대상
        or meta.install_scripts == "present"
        or lic_verdict == "review_required"
        or bool(meta.deprecated)
    )

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
        kev_signals=kev_hits,
        cooldown=cooldown,
        license_verdict=lic_verdict,
        advisories=[
            {
                "id": v.get("id"),
                "summary": (v.get("summary") or "")[:200],
                "modified": v.get("modified"),
            }
            for v in vulns[:5]
        ],
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
