"""check_package — offline mode must consult the local intel cache.

In air-gapped agencies the OSV API is unreachable. `update-intel` populates
~/.gvskb/cache/ (or $GVSKB_CACHE_DIR) so check_package can still answer
"is this package known-malicious?" without network. These tests pin that
behavior so the offline path is more than a heuristic placeholder.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from gvskb.tools.check_package import check_package_impl


def _write_cache(cache_dir: Path, source_id: str, items: list[dict]) -> None:
    cache_dir.mkdir(parents=True, exist_ok=True)
    envelope = {
        "schema_version": 1,
        "source_id": source_id,
        "fetched_at": "2026-06-01T00:00:00+00:00",
        "url": "https://example/test",
        "sha256": "deadbeef",
        "item_count": len(items),
        "items": items,
    }
    (cache_dir / f"{source_id}.json").write_text(
        json.dumps(envelope, ensure_ascii=False), encoding="utf-8"
    )


@pytest.fixture
def offline_with_cache(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    monkeypatch.setenv("GVSKB_MODE", "offline")
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path))
    return tmp_path


# ---------------------------------------------------------------------------
# Cache HIT — OSV malicious feed
# ---------------------------------------------------------------------------


def test_offline_osv_cache_hit_flags_malicious(offline_with_cache: Path) -> None:
    """A package name listed in cached OSV MAL advisories must be flagged."""
    _write_cache(
        offline_with_cache,
        "osv-malicious",
        [
            {
                "id": "MAL-2026-1234",
                "summary": "Test malicious package for unit test",
                "modified": "2026-05-01T00:00:00Z",
                "affected": [
                    {"package": "evilpkg", "ecosystem": "PyPI"},
                ],
            }
        ],
    )

    result = asyncio.run(check_package_impl(name="evilpkg", ecosystem="pypi"))

    assert result["offline"] is True
    assert result["checked"] is True, "cache lookup must count as a real check"
    assert result["is_malicious_package"] is True
    assert result["verdict_severity"] == "high"
    assert any(a["id"] == "MAL-2026-1234" for a in result.get("advisories", []))
    assert "osv-malicious" in result.get("cache_sources_used", [])


def test_offline_osv_ecosystem_must_match(offline_with_cache: Path) -> None:
    """An advisory for npm:foo must NOT match a pypi:foo lookup."""
    _write_cache(
        offline_with_cache,
        "osv-malicious",
        [
            {
                "id": "MAL-2026-9999",
                "affected": [{"package": "foo", "ecosystem": "npm"}],
            }
        ],
    )

    result = asyncio.run(check_package_impl(name="foo", ecosystem="pypi"))
    assert result.get("is_malicious_package") is not True


# ---------------------------------------------------------------------------
# Cache MISS but cache present — clean result, still counts as checked
# ---------------------------------------------------------------------------


def test_offline_cache_present_no_match_returns_info(offline_with_cache: Path) -> None:
    _write_cache(offline_with_cache, "osv-malicious", [])
    _write_cache(offline_with_cache, "cisa-kev", [])

    result = asyncio.run(check_package_impl(name="requests", ecosystem="pypi"))

    assert result["offline"] is True
    assert result["checked"] is True
    assert result["is_malicious_package"] is False
    assert result["verdict_severity"] == "info"
    assert "osv-malicious" in result.get("cache_sources_used", [])
    assert "heuristics" in result


# ---------------------------------------------------------------------------
# CISA KEV — secondary signal when package name appears in vendorProject/product
# ---------------------------------------------------------------------------


def test_offline_kev_product_match_raises_signal(offline_with_cache: Path) -> None:
    """If package name matches a KEV product, surface it as a secondary signal."""
    _write_cache(
        offline_with_cache,
        "cisa-kev",
        [
            {
                "cveID": "CVE-2021-44228",
                "vendorProject": "Apache",
                "product": "Log4j2",
                "vulnerabilityName": "Apache Log4j2 RCE",
                "dateAdded": "2021-12-10",
            }
        ],
    )

    result = asyncio.run(check_package_impl(name="log4j2", ecosystem="pypi"))

    assert result["offline"] is True
    assert any(
        sig.get("cveID") == "CVE-2021-44228"
        for sig in result.get("kev_signals", [])
    ), "KEV product-name match should surface as a secondary signal"


# ---------------------------------------------------------------------------
# No cache at all — clear guidance, no false confidence
# ---------------------------------------------------------------------------


def test_offline_no_cache_returns_clear_guidance(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """When no cache exists, do not claim a real check — tell the operator to update-intel."""
    monkeypatch.setenv("GVSKB_MODE", "offline")
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path / "empty"))

    result = asyncio.run(check_package_impl(name="anything", ecosystem="pypi"))

    assert result["offline"] is True
    assert result["checked"] is False
    assert "heuristics" in result
    assert "update-intel" in result.get("note", "")
    assert result.get("cache_sources_used", []) == []


# ---------------------------------------------------------------------------
# Backwards compatibility — the original Stage-5 contract still holds
# ---------------------------------------------------------------------------


def test_offline_marker_still_set_when_cache_present(offline_with_cache: Path) -> None:
    """The Stage-5 contract (`offline=True`, `heuristics` present) must remain."""
    _write_cache(offline_with_cache, "osv-malicious", [])
    result = asyncio.run(check_package_impl(name="x", ecosystem="pypi"))
    assert result["offline"] is True
    assert "heuristics" in result
