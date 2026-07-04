"""OSV.dev — extract malicious-package advisories from the public dataset.

OSV publishes per-ecosystem zip dumps at
``https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip``.
These contain every advisory for the ecosystem as individual JSON files. We
download the zip(s), keep only entries whose ID starts with ``MAL-`` (the
malicious-package prefix), normalize them, and hand the result back to the
update orchestrator. The on-disk cache key (``osv-malicious``) is unchanged
so downstream consumers — ``check_package`` in particular — keep working.

Defaults are conservative to respect agency network budgets:

- **PyPI** (~24 MB compressed) is fetched by default.
- **npm** (~200 MB) is fetched only when ``GVSKB_OSV_INCLUDE_NPM`` is set to a
  truthy value, since first-sync on a slow agency link can be painful.

Fetch failures degrade quietly: the adapter returns whatever advisories it
managed to collect so the rest of the cache refresh continues.
"""
from __future__ import annotations

import io
import json
import os
import zipfile
from typing import Iterable

from .base import HttpFetcher, SourceAdapter, register_source

GCS_BASE_URL = "https://osv-vulnerabilities.storage.googleapis.com"

# Ecosystems we may pull from. Order is intentional: PyPI is small and always on.
_DEFAULT_ECOSYSTEMS: tuple[str, ...] = ("PyPI",)
_OPT_IN_ECOSYSTEMS: tuple[str, ...] = ("npm",)

_KEEP = ("id", "summary", "modified", "published", "aliases", "affected")
_TRUTHY = {"1", "true", "yes", "on"}


def _selected_ecosystems() -> tuple[str, ...]:
    """Decide which ecosystems to download this run."""
    selected = list(_DEFAULT_ECOSYSTEMS)
    if os.environ.get("GVSKB_OSV_INCLUDE_NPM", "").lower() in _TRUTHY:
        for eco in _OPT_IN_ECOSYSTEMS:
            if eco not in selected:
                selected.append(eco)
    return tuple(selected)


def _zip_url(ecosystem: str) -> str:
    return f"{GCS_BASE_URL}/{ecosystem}/all.zip"


def _normalize(vuln: dict) -> dict:
    """Trim a raw OSV entry to the fields ``check_package`` actually reads."""
    out: dict = {k: vuln.get(k) for k in _KEEP if k in vuln}
    aff = vuln.get("affected") or []
    out["affected"] = [
        {
            "package": (a.get("package") or {}).get("name"),
            "ecosystem": (a.get("package") or {}).get("ecosystem"),
        }
        for a in aff
        if a.get("package")
    ]
    return out


def _iter_mal_entries(zip_bytes: bytes) -> Iterable[dict]:
    """Yield normalized MAL- entries from an OSV ecosystem zip dump."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except zipfile.BadZipFile:
        return
    with zf:
        for info in zf.infolist():
            filename = info.filename.rsplit("/", 1)[-1]
            if not filename.startswith("MAL-") or not filename.endswith(".json"):
                continue
            try:
                with zf.open(info) as fh:
                    data = json.load(fh)
            except (json.JSONDecodeError, KeyError, OSError):
                continue
            if not str(data.get("id", "")).startswith("MAL-"):
                continue
            yield _normalize(data)


def fetch_osv_malicious(client: HttpFetcher) -> tuple[str, list[dict]]:
    """Download OSV ecosystem zip(s) and return all MAL-prefix advisories.

    The first ecosystem URL is reported back so the cache envelope records a
    meaningful origin. Network or parsing failures for individual ecosystems
    are swallowed — partial results beat a failed refresh.
    """
    ecosystems = _selected_ecosystems()
    primary_url = _zip_url(ecosystems[0])
    seen: dict[str, dict] = {}
    for eco in ecosystems:
        url = _zip_url(eco)
        try:
            resp = client.get(url)
            resp.raise_for_status()
            content = getattr(resp, "content", None)
            if content is None:
                content = resp.read() if hasattr(resp, "read") else b""
        except Exception:
            continue
        for item in _iter_mal_entries(content):
            vid = str(item.get("id", ""))
            if vid and vid not in seen:
                seen[vid] = item
    return primary_url, list(seen.values())


register_source(SourceAdapter(
    id="osv-malicious",
    description=(
        "OSV.dev malicious-package advisories (MAL- prefix). Default ecosystem: PyPI; "
        "set GVSKB_OSV_INCLUDE_NPM=1 to also download the npm dataset (~200 MB)."
    ),
    fetch=fetch_osv_malicious,
    ecosystems=lambda: list(_selected_ecosystems()),
))
