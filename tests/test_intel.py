"""Intel cache + adapter + update-intel CLI 동작 확인.

네트워크 호출은 fake HTTP client로 격리합니다 — 실제 OSV/CISA 서버에 의존
하지 않으므로 망분리 환경 CI에서도 통과합니다.
"""
from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path
from typing import Any

import pytest

from gvskb import cli
from gvskb.intel import IntelCache, update_source, update_sources
from gvskb.intel.sources import cisa_kev, osv
from gvskb.intel.sources.base import SOURCES


# ---------------------------------------------------------------------------
# Fake HTTP client — minimal subset used by the adapters
# ---------------------------------------------------------------------------

class FakeResponse:
    def __init__(self, payload: Any = None, status_code: int = 200,
                 content: bytes | None = None) -> None:
        self._payload = payload
        self.status_code = status_code
        self.content = content if content is not None else b""

    def json(self) -> Any:
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeClient:
    def __init__(self, get_payload: Any = None, post_payload: Any = None,
                 get_content_by_url: dict[str, bytes] | None = None) -> None:
        self._get = get_payload
        self._post = post_payload
        self._content_by_url = get_content_by_url or {}
        self.get_calls: list[str] = []
        self.post_calls: list[tuple[str, dict]] = []

    def get(self, url: str, **_kw) -> FakeResponse:
        self.get_calls.append(url)
        if url in self._content_by_url:
            return FakeResponse(content=self._content_by_url[url])
        return FakeResponse(self._get)

    def post(self, url: str, *, json=None, **_kw) -> FakeResponse:
        self.post_calls.append((url, json))
        return FakeResponse(self._post)

    def close(self) -> None:
        pass


def _make_osv_zip(entries: list[dict]) -> bytes:
    """Build an in-memory OSV-style zip with one JSON file per entry."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for entry in entries:
            name = f"{entry['id']}.json"
            zf.writestr(name, json.dumps(entry))
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Adapter unit tests
# ---------------------------------------------------------------------------

def test_cisa_kev_adapter_normalizes_records() -> None:
    payload = {
        "vulnerabilities": [
            {
                "cveID": "CVE-2025-99999",
                "vendorProject": "ExampleCorp",
                "product": "Widget",
                "vulnerabilityName": "Auth bypass",
                "dateAdded": "2026-04-01",
                "shortDescription": "...",
                "requiredAction": "Patch",
                "dueDate": "2026-05-01",
                "knownRansomwareCampaignUse": "Known",
                "extra_field_we_drop": "x",
            }
        ]
    }
    client = FakeClient(get_payload=payload)
    url, items = cisa_kev.fetch_cisa_kev(client)
    assert url.endswith("known_exploited_vulnerabilities.json")
    assert len(items) == 1
    assert items[0]["cveID"] == "CVE-2025-99999"
    assert "extra_field_we_drop" not in items[0]


def test_osv_adapter_extracts_only_mal_entries_from_pypi_zip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GCS dump contains every advisory; the adapter must keep only MAL-* ones."""
    monkeypatch.delenv("GVSKB_OSV_INCLUDE_NPM", raising=False)
    pypi_zip = _make_osv_zip([
        {"id": "GHSA-aaa-bbb", "summary": "regular advisory"},
        {
            "id": "MAL-2026-0001",
            "summary": "malicious pkg",
            "modified": "2026-05-01T00:00:00Z",
            "affected": [{"package": {"name": "evil-pkg", "ecosystem": "PyPI"}}],
        },
    ])
    client = FakeClient(get_content_by_url={
        f"{osv.GCS_BASE_URL}/PyPI/all.zip": pypi_zip,
    })

    url, items = osv.fetch_osv_malicious(client)

    assert url.endswith("/PyPI/all.zip")
    assert client.get_calls == [f"{osv.GCS_BASE_URL}/PyPI/all.zip"]
    ids = [i["id"] for i in items]
    assert ids == ["MAL-2026-0001"]
    assert items[0]["affected"][0]["package"] == "evil-pkg"
    assert items[0]["affected"][0]["ecosystem"] == "PyPI"


def test_osv_adapter_skips_npm_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GVSKB_OSV_INCLUDE_NPM", raising=False)
    client = FakeClient(get_content_by_url={
        f"{osv.GCS_BASE_URL}/PyPI/all.zip": _make_osv_zip([]),
    })
    osv.fetch_osv_malicious(client)
    assert all("/npm/" not in u for u in client.get_calls)


def test_osv_adapter_includes_npm_when_env_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GVSKB_OSV_INCLUDE_NPM", "1")
    pypi_zip = _make_osv_zip([
        {"id": "MAL-2026-PYPI", "affected": [{"package": {"name": "p", "ecosystem": "PyPI"}}]},
    ])
    npm_zip = _make_osv_zip([
        {"id": "MAL-2026-NPM", "affected": [{"package": {"name": "n", "ecosystem": "npm"}}]},
    ])
    client = FakeClient(get_content_by_url={
        f"{osv.GCS_BASE_URL}/PyPI/all.zip": pypi_zip,
        f"{osv.GCS_BASE_URL}/npm/all.zip": npm_zip,
    })

    _, items = osv.fetch_osv_malicious(client)
    ids = {i["id"] for i in items}
    assert ids == {"MAL-2026-PYPI", "MAL-2026-NPM"}


def test_osv_adapter_dedupes_when_same_id_in_multiple_zips(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GVSKB_OSV_INCLUDE_NPM", "1")
    same = {"id": "MAL-2026-DUP", "affected": [{"package": {"name": "x", "ecosystem": "PyPI"}}]}
    client = FakeClient(get_content_by_url={
        f"{osv.GCS_BASE_URL}/PyPI/all.zip": _make_osv_zip([same]),
        f"{osv.GCS_BASE_URL}/npm/all.zip": _make_osv_zip([same]),
    })
    _, items = osv.fetch_osv_malicious(client)
    assert [i["id"] for i in items] == ["MAL-2026-DUP"]


def test_osv_adapter_tolerates_network_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GVSKB_OSV_INCLUDE_NPM", raising=False)

    class FailingClient:
        def get(self, *a, **kw):
            raise RuntimeError("network down")

    url, items = osv.fetch_osv_malicious(FailingClient())
    assert items == []
    assert url.startswith("https://")


def test_osv_adapter_tolerates_corrupt_zip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GVSKB_OSV_INCLUDE_NPM", raising=False)
    client = FakeClient(get_content_by_url={
        f"{osv.GCS_BASE_URL}/PyPI/all.zip": b"not a zip",
    })
    _, items = osv.fetch_osv_malicious(client)
    assert items == []


# ---------------------------------------------------------------------------
# Cache + orchestrator tests
# ---------------------------------------------------------------------------

def test_cache_roundtrip(tmp_path: Path) -> None:
    cache = IntelCache(tmp_path)
    entry = cache.save("test-src", "https://example.com", [{"id": "a"}, {"id": "b"}])
    assert entry.item_count == 2
    assert entry.sha256
    loaded = cache.load("test-src")
    assert loaded is not None
    assert loaded.items == [{"id": "a"}, {"id": "b"}]
    assert loaded.url == "https://example.com"


def test_cache_returns_none_for_missing_source(tmp_path: Path) -> None:
    cache = IntelCache(tmp_path)
    assert cache.load("does-not-exist") is None


def test_update_source_writes_cache(tmp_path: Path) -> None:
    cache = IntelCache(tmp_path)
    client = FakeClient(get_payload={"vulnerabilities": [
        {"cveID": "CVE-2026-1", "vendorProject": "x", "product": "y"},
    ]})
    result = update_source("cisa-kev", cache=cache, client=client)
    assert result.ok
    assert result.item_count == 1
    assert (tmp_path / "cisa-kev.json").exists()


def test_update_source_warn_on_network_failure_with_cache(tmp_path: Path) -> None:
    cache = IntelCache(tmp_path)
    cache.save("cisa-kev", "x", [{"cveID": "old"}])  # seed

    class FailingClient:
        def get(self, *a, **kw): raise RuntimeError("offline")
        def post(self, *a, **kw): raise RuntimeError("offline")
        def close(self): pass

    result = update_source("cisa-kev", cache=cache, client=FailingClient())
    assert result.status == "warn"
    assert "offline" in result.error


def test_update_sources_iterates_known_adapters(tmp_path: Path, monkeypatch) -> None:
    # Avoid real network by monkeypatching the client factory
    import gvskb.intel.update as update_mod

    class FakeClientFactory:
        def __init__(self, *a, **kw): pass
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def get(self, url, **kw): return FakeResponse({"vulnerabilities": []})
        def post(self, url, **kw): return FakeResponse({"vulns": []})
        def close(self): pass

    monkeypatch.setattr(update_mod, "_client_factory", lambda timeout=30.0: FakeClientFactory())
    cache = IntelCache(tmp_path)
    results = update_sources(cache=cache)
    ids = {r.source_id for r in results}
    assert {"cisa-kev", "osv-malicious"} <= ids


# ---------------------------------------------------------------------------
# CLI tests
# ---------------------------------------------------------------------------

def test_cli_update_intel_from_cache_reports_missing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = cli.main([
        "update-intel", "--source", "cisa-kev",
        "--from-cache", "--json",
        "--cache-dir", str(tmp_path),
    ])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload[0]["status"] == "warn"
    assert payload[0]["error"] == "no cached data"
    assert rc == cli.EXIT_FINDINGS_WARN


def test_cli_update_intel_from_cache_after_seed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cache = IntelCache(tmp_path)
    cache.save("cisa-kev", "x", [{"cveID": "CVE-X"}])
    rc = cli.main([
        "update-intel", "--source", "cisa-kev",
        "--from-cache", "--json",
        "--cache-dir", str(tmp_path),
    ])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload[0]["status"] == "ok"
    assert payload[0]["item_count"] == 1
    assert rc == cli.EXIT_OK


def test_cli_update_intel_requires_source_or_all(capsys: pytest.CaptureFixture[str]) -> None:
    rc = cli.main(["update-intel"])
    assert rc == cli.EXIT_USAGE


def test_registered_sources_include_kev_and_osv() -> None:
    assert "cisa-kev" in SOURCES
    assert "osv-malicious" in SOURCES


# ---------------------------------------------------------------------------
# search_rules status filter
# ---------------------------------------------------------------------------

def test_search_rules_approved_only_excludes_proposed() -> None:
    from gvskb.loader import load_all_rules
    from gvskb.search import simple_search
    from gvskb.schema import Status

    rules = load_all_rules(Path(__file__).resolve().parent.parent / "rules")
    # Existing repo should be all approved, but verify the filter shape works.
    hits = simple_search(rules, "프롬프트", approved_only=True, limit=5)
    for r in hits:
        assert r.status == Status.approved


def test_search_rules_status_filter_matches_specific_status() -> None:
    from gvskb.loader import load_all_rules
    from gvskb.search import simple_search

    rules = load_all_rules(Path(__file__).resolve().parent.parent / "rules")
    # 'proposed' returns no rules in the current repo, which is the expected
    # state until update-intel writes auto-generated rules in Stage 2b.
    hits = simple_search(rules, "프롬프트", status="proposed", limit=5)
    assert hits == []
