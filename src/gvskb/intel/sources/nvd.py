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


register_source(SourceAdapter(
    id="nvd-recent",
    description=f"NIST NVD CVE API 2.0 — CVEs modified in the last {RECENT_DAYS} days",
    fetch=fetch_nvd_recent,
))
