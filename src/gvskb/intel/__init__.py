"""Real-time security intelligence — cache + source adapters.

This package centralizes the fetching, normalizing, and on-disk caching of
external vulnerability feeds (CISA KEV, OSV.dev, NVD, EPSS, ...). The MCP
server and the gvskb CLI both read from the same cache so that an
offline / air-gapped client can keep operating with the last known data.

Security principles (consistent with the public-sector policy):
- Only package names, versions, ecosystems, and CVE IDs are sent to external APIs.
- No source code, no personal information ever leaves the local machine.
- Network failures degrade to WARN, never ERROR, so air-gapped deployments work.
"""
from __future__ import annotations

from .cache import CACHE_VERSION, CacheEntry, IntelCache, default_cache_dir
from .promote import DEFAULT_PROPOSED_DIR, PromoteResult, promote_kev_to_rules, render_kev_rule
from .update import IntelUpdateError, IntelUpdateResult, update_source, update_sources

__all__ = [
    "CACHE_VERSION",
    "CacheEntry",
    "IntelCache",
    "default_cache_dir",
    "DEFAULT_PROPOSED_DIR",
    "PromoteResult",
    "promote_kev_to_rules",
    "render_kev_rule",
    "IntelUpdateError",
    "IntelUpdateResult",
    "update_source",
    "update_sources",
]
