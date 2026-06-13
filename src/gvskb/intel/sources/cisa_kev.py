"""CISA Known Exploited Vulnerabilities catalog.

CISA publishes a single JSON file listing CVEs they have evidence are
actively exploited, along with a remediation due date for U.S. federal agencies.
We download the whole catalog and store normalized records so that subsequent
scans can flag dependencies that match a KEV-listed CVE.

We intentionally keep only the fields useful for downstream gating; this also
keeps the cache small and avoids re-distributing the full document.
"""
from __future__ import annotations

from .base import HttpFetcher, SourceAdapter, register_source

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Fields we keep — see the upstream schema at
# https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json
_KEEP_FIELDS = (
    "cveID",
    "vendorProject",
    "product",
    "vulnerabilityName",
    "dateAdded",
    "shortDescription",
    "requiredAction",
    "dueDate",
    "knownRansomwareCampaignUse",
    "cwes",
)


def _normalize(entry: dict) -> dict:
    out: dict = {k: entry.get(k) for k in _KEEP_FIELDS if k in entry}
    # Always present, used as the primary key downstream
    out.setdefault("cveID", entry.get("cveID", ""))
    return out


def fetch_cisa_kev(client: HttpFetcher) -> tuple[str, list[dict]]:
    """Fetch and normalize the CISA KEV catalog. Caller controls timeouts."""
    resp = client.get(CISA_KEV_URL)
    resp.raise_for_status()
    data = resp.json()
    raw = data.get("vulnerabilities", [])
    return CISA_KEV_URL, [_normalize(v) for v in raw]


register_source(SourceAdapter(
    id="cisa-kev",
    description="CISA Known Exploited Vulnerabilities Catalog",
    fetch=fetch_cisa_kev,
))
