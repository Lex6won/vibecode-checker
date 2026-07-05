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
from typing import Literal

import httpx

from ..intel.cache import IntelCache

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


def _offline_cache_check(name: str, ecosystem: str, ecosystem_label: str) -> dict:
    """Consult the local intel cache and return a check_package-compatible dict."""
    cache = IntelCache()
    osv_entry = cache.load("osv-malicious")
    kev_entry = cache.load("cisa-kev")

    if osv_entry is None and kev_entry is None:
        return {
            "name": name,
            "ecosystem": ecosystem,
            "checked": False,
            # 캐시 없는 오프라인은 "통과"가 아니라 "판정 불가"다 — 사용자가
            # 안전으로 오해하지 않도록 verdict/requires_review를 명시한다.
            "verdict": "unknown",
            "requires_review": True,
            "offline": True,
            "verdict_severity": "info",
            "heuristics": _basic_heuristics(name, ecosystem),
            "cache_sources_used": [],
            "note": (
                "GVSKB_MODE=offline 이며 로컬 인텔 캐시가 비어 있습니다. "
                "`gvskb update-intel` 을 먼저 실행해 OSV malicious feed와 CISA KEV 캐시를 만든 뒤 다시 검사하세요."
            ),
            "disclaimer": (
                "이 결과는 휴리스틱 보조 신호이며 캐시 기반 검사가 수행되지 않았습니다. "
                "기관 허용 목록·sigstore/SBOM 정책에 따른 별도 검토가 필요합니다."
            ),
        }

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

    result = {
        "name": name,
        "ecosystem": ecosystem,
        "offline": True,
        "verdict_severity": severity,
        "is_malicious_package": has_malicious,
        "vulnerability_count": len(advisories),
        "malicious_advisory_count": len(advisories),
        "advisories": advisories,
        "kev_signals": kev_signals,
        "cache_sources_used": cache_sources_used,
        "cache_freshness": cache_freshness,
        "cache_ecosystems": covered_ecosystems,
        "cache_stale_sources": stale_sources,
        "heuristics": _basic_heuristics(name, ecosystem),
        "source": "local intel cache (GVSKB_MODE=offline)",
        "disclaimer": (
            "오프라인 캐시 기반 검사입니다. 캐시 갱신 시점 이후의 신규 advisory는 반영되지 않습니다. "
            "운영 반영 전 `gvskb update-intel` 최신 실행 시각을 확인하세요."
        ),
    }

    if has_malicious:
        # 양성 판정(악성 발견)은 캐시가 오래됐어도 유효한 신호다.
        result.update({"checked": True, "verdict": "malicious", "requires_review": True})
        if stale_sources:
            result["note"] = f"캐시가 오래됐습니다({', '.join(stale_sources)}) — 그래도 악성 판정은 유효합니다."
        return result

    if not osv_covers:
        # 이 생태계의 악성 피드가 캐시에 없다 → '깨끗함'이 아니라 '판정 불가'.
        result.update({
            "checked": False,
            "verdict": "unknown",
            "requires_review": True,
            "note": (
                f"오프라인 캐시가 {ecosystem_label} 생태계를 포함하지 않습니다"
                f"(캐시 커버리지: {covered_ecosystems or '없음'}). "
                "외부망에서 `gvskb update-intel --all` 실행 시 npm까지 받으려면 "
                "GVSKB_OSV_INCLUDE_NPM=1 을 설정한 뒤 캐시를 반입하세요."
            ),
        })
        return result

    if stale_sources:
        # 신선도 초과 캐시의 '깨끗함'은 확정이 아니다 — 검토 필요로 승격.
        from ..intel.cache import intel_max_age_days
        result.update({
            "checked": True,
            "verdict": "checked_stale",
            "requires_review": True,
            "note": (
                f"캐시가 신선도 기준({intel_max_age_days()}일)을 초과했습니다: "
                f"{', '.join(stale_sources)}. 이 '이상 없음'은 오래된 데이터 기준입니다 — "
                "외부망에서 `gvskb update-intel` 후 캐시를 다시 반입하세요."
            ),
        })
        return result

    result.update({"checked": True, "verdict": "checked_clean", "requires_review": False})
    return result


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


async def audit_manifest(
    manifest_text: str,
    ecosystem: Literal["pypi", "npm"] = "pypi",
    limit: int = 20,
) -> dict:
    """의존성 매니페스트를 파싱해 패키지별 취약·악성 검사를 수행한다.

    온라인: OSV.dev 조회(패키지명·버전만 전송). 오프라인(GVSKB_MODE=offline):
    로컬 인텔 캐시 기반 — 판정 불가는 '안전'이 아니라 requires_review로 표시.
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
    requires_review = blocked or unchecked > 0 or has_vulns or any(c.get("requires_review") for c in checks)
    verdict = "blocked" if blocked else ("review_required" if requires_review else "ok")
    return {
        "ecosystem": ecosystem,
        "parsed_count": len(packages),
        "checked_count": actually_checked,
        "unchecked_count": unchecked,
        "blocked": blocked,
        "requires_review": requires_review,
        "verdict": verdict,
        "packages": limited,
        "checks": checks,
        "disclaimer": (
            "취약점 API에는 패키지명과 ecosystem만 전송합니다. "
            "unchecked_count>0 이면 일부 패키지가 '판정 불가'(캐시 없는 오프라인·API 실패)이며 '안전'이 아닙니다. "
            "운영 반영 전 lockfile/SBOM 기준 재검사를 권장합니다."
        ),
    }


async def check_package_impl(
    name: str,
    ecosystem: Literal["pypi", "npm"] = "pypi",
    version: str | None = None,
    timeout: float = 10.0,
) -> dict:
    eco = ECOSYSTEM_MAP.get(ecosystem.lower())
    if not eco:
        return {
            "name": name,
            "ecosystem": ecosystem,
            "error": f"unsupported ecosystem: {ecosystem} (allowed: pypi, npm)",
            "checked": False,
        }

    if _is_offline():
        result = _offline_cache_check(name, ecosystem, eco)
        if version is not None:
            result["version"] = version
        return result

    payload: dict = {"package": {"name": name, "ecosystem": eco}}
    if version:
        payload["version"] = version

    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            resp = await client.post(OSV_QUERY_URL, json=payload)
            resp.raise_for_status()
            data = resp.json()
        except httpx.HTTPError as exc:
            return {
                "name": name,
                "version": version,
                "ecosystem": ecosystem,
                "checked": False,
                "error": f"OSV API failure: {exc!s}",
                "heuristics": _basic_heuristics(name, ecosystem),
            }

    vulns = data.get("vulns", []) or []
    malicious_advisories = [v for v in vulns if str(v.get("id", "")).startswith("MAL-")]
    has_malicious = bool(malicious_advisories)
    severity = "high" if has_malicious else ("medium" if vulns else "info")

    return {
        "name": name,
        "version": version,
        "ecosystem": ecosystem,
        "checked": True,
        "verdict_severity": severity,
        "is_malicious_package": has_malicious,
        "vulnerability_count": len(vulns),
        "malicious_advisory_count": len(malicious_advisories),
        "advisories": [
            {
                "id": v.get("id"),
                "summary": (v.get("summary") or "")[:200],
                "modified": v.get("modified"),
            }
            for v in vulns[:5]
        ],
        "heuristics": _basic_heuristics(name, ecosystem),
        "source": "OSV.dev v1/query",
        "disclaimer": (
            "이 검사는 OSV.dev와 이름 기반 휴리스틱을 활용한 보조 신호입니다. "
            "공식 보안 검토, 기관 허용 패키지 정책, lockfile/SBOM 검사를 대체하지 않습니다."
        ),
    }
