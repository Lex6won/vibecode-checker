"""NVD CVE API 2.0 — recently modified CVE lookup.

We query the NVD CVE 2.0 API for the last ``RECENT_DAYS`` window so the local
cache stays small. API key is optional: if ``NVD_API_KEY`` is set we send it
as the ``apiKey`` header, which raises the per-IP rate limit substantially.

The full historical feed is out of scope for the vibecode-checker cache —
operators with the bandwidth budget can mirror NVD via the official JSON 2.0
feed and then point ``--cache-dir`` at that location.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any

from .base import HttpFetcher, SourceAdapter, register_source

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RECENT_DAYS = 7  # NVD enforces lastModStartDate windows <= 120 days


def _iso_z(d: datetime) -> str:
    # NVD requires extended ISO 8601 with milliseconds, no offset suffix
    return d.strftime("%Y-%m-%dT%H:%M:%S.000")


def _normalize(item: dict) -> dict:
    cve = item.get("cve") or {}
    descriptions = cve.get("descriptions") or []
    desc_en = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
    metrics = cve.get("metrics") or {}
    cvss31 = (metrics.get("cvssMetricV31") or [{}])[0].get("cvssData", {}) if metrics else {}
    return {
        "id": cve.get("id"),
        "published": cve.get("published"),
        "lastModified": cve.get("lastModified"),
        "vulnStatus": cve.get("vulnStatus"),
        "description": desc_en[:600],
        "cvss31_base_score": cvss31.get("baseScore"),
        "cvss31_severity": cvss31.get("baseSeverity"),
        "cwes": [
            {"value": w.get("value")}
            for c in (cve.get("weaknesses") or [])
            for w in (c.get("description") or [])
            if w.get("lang") == "en"
        ],
    }


def fetch_nvd_recent(client: HttpFetcher) -> tuple[str, list[dict]]:
    end = datetime.now(timezone.utc).replace(tzinfo=None)
    start = end - timedelta(days=RECENT_DAYS)
    params: dict[str, Any] = {
        "lastModStartDate": _iso_z(start),
        "lastModEndDate": _iso_z(end),
        "resultsPerPage": 2000,
    }
    headers: dict[str, str] = {}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    resp = client.get(NVD_API_URL, params=params, headers=headers)
    resp.raise_for_status()
    data = resp.json() or {}
    items = [_normalize(v) for v in data.get("vulnerabilities", []) if v.get("cve")]
    return NVD_API_URL, items


#: 누적 캐시 상한(항목 수). NVD 는 연간 십수만 건이 수정되므로 무제한 누적은
#: 반입 번들을 수십 MB 씩 키운다. 이 캐시의 용도는 KEV 신호·오프라인 취약점의
#: CVSS 병기(우선순위 근거)라 최근 수정분 위주면 충분하다 — lastModified 가
#: 최신인 것부터 남긴다. 기관이 더 넓게 원하면 GVSKB_NVD_CACHE_MAX 로 올린다.
DEFAULT_CACHE_MAX = 50_000


def _cache_max() -> int:
    raw = os.environ.get("GVSKB_NVD_CACHE_MAX", "")
    try:
        return max(1000, int(raw)) if raw else DEFAULT_CACHE_MAX
    except ValueError:
        return DEFAULT_CACHE_MAX


def merge_nvd(prev_items: list[dict], new_items: list[dict]) -> list[dict]:
    """CVE ID 기준 병합 — 새 수집분이 이긴다(더 최신 lastModified).

    예전에는 매일 "최근 7일" 창으로 **덮어써서**, 8일 전에 수정된 CVE 의 CVSS 가
    캐시에서 사라졌다. 누적하면 시간이 지날수록 커버리지가 넓어진다.
    """
    by_id: dict[str, dict] = {str(i.get("id")): i for i in prev_items if i.get("id")}
    for i in new_items:
        if i.get("id"):
            by_id[str(i["id"])] = i
    merged = sorted(by_id.values(),
                    key=lambda i: str(i.get("lastModified") or ""), reverse=True)
    return merged[:_cache_max()]


register_source(SourceAdapter(
    id="nvd-recent",
    description=(
        f"NIST NVD CVE API 2.0 — CVEs modified in the last {RECENT_DAYS} days, "
        "merged cumulatively into the local cache (newest-modified kept first)"
    ),
    fetch=fetch_nvd_recent,
    merge=merge_nvd,
))
