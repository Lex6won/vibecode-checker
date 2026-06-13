"""promote (KEV→proposed MD), NVD adapter, EPSS adapter, and CLI integration."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from gvskb import cli
from gvskb.intel import IntelCache, promote_kev_to_rules, render_kev_rule
from gvskb.intel.sources import epss, nvd
from gvskb.loader import load_rule


# ---------------------------------------------------------------------------
# Render + promote
# ---------------------------------------------------------------------------

def _kev_sample() -> dict:
    return {
        "cveID": "CVE-2025-99999",
        "vendorProject": "ExampleCorp",
        "product": "Widget",
        "vulnerabilityName": "Authentication Bypass",
        "dateAdded": "2026-04-01",
        "shortDescription": "Allows remote attackers to ...",
        "requiredAction": "Apply vendor patch",
        "dueDate": "2026-05-01",
        "knownRansomwareCampaignUse": "Known",
        "cwes": ["CWE-287"],
    }


def test_render_kev_rule_produces_valid_loader_input(tmp_path: Path) -> None:
    rule_id, md = render_kev_rule(_kev_sample())
    assert rule_id == "INTEL-KEV-CVE-2025-99999"
    f = tmp_path / f"{rule_id}.md"
    f.write_text(md, encoding="utf-8")
    rule = load_rule(f)
    assert rule.id == rule_id
    assert rule.status.value == "proposed"
    assert rule.source_layer.value == "realtime"
    assert rule.severity.value == "critical"  # ransomware-linked
    assert any("CISA" in s.publisher for s in rule.sources)


def test_render_kev_rule_severity_high_when_no_ransomware() -> None:
    item = _kev_sample()
    item["knownRansomwareCampaignUse"] = "Unknown"
    _, md = render_kev_rule(item)
    assert "severity: high" in md


def test_render_kev_rule_skips_when_no_cve_id() -> None:
    with pytest.raises(ValueError):
        render_kev_rule({"vendorProject": "x"})


def test_promote_creates_files_and_skips_existing(tmp_path: Path) -> None:
    cache = IntelCache(tmp_path / "cache")
    entry = cache.save("cisa-kev", "https://example.com", [_kev_sample(), {
        "cveID": "CVE-2026-1111",
        "vendorProject": "Y",
        "product": "Z",
        "vulnerabilityName": "Path traversal",
        "knownRansomwareCampaignUse": "Unknown",
    }])
    rules_dir = tmp_path / "rules"
    result = promote_kev_to_rules(entry, rules_dir)
    assert result.created == ["INTEL-KEV-CVE-2025-99999", "INTEL-KEV-CVE-2026-1111"]
    assert (rules_dir / "INTEL-KEV-CVE-2025-99999.md").exists()

    # Second run skips existing files
    result2 = promote_kev_to_rules(entry, rules_dir)
    assert result2.created == []
    assert sorted(result2.skipped_existing) == sorted(result.created)


def test_promote_overwrite_replaces_files(tmp_path: Path) -> None:
    cache = IntelCache(tmp_path / "cache")
    entry = cache.save("cisa-kev", "x", [_kev_sample()])
    rules_dir = tmp_path / "rules"
    promote_kev_to_rules(entry, rules_dir)
    # tamper with the file
    p = rules_dir / "INTEL-KEV-CVE-2025-99999.md"
    original = p.read_text(encoding="utf-8")
    p.write_text("changed", encoding="utf-8")
    promote_kev_to_rules(entry, rules_dir, overwrite=True)
    assert p.read_text(encoding="utf-8") == original


def test_promote_rejects_non_kev_cache(tmp_path: Path) -> None:
    cache = IntelCache(tmp_path / "cache")
    entry = cache.save("osv-malicious", "x", [])
    with pytest.raises(ValueError):
        promote_kev_to_rules(entry, tmp_path / "rules")


# ---------------------------------------------------------------------------
# NVD adapter
# ---------------------------------------------------------------------------

class FakeResp:
    def __init__(self, payload, status_code=200):
        self._p = payload
        self.status_code = status_code

    def json(self):
        return self._p

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError("http error")


def test_nvd_adapter_normalizes_cve_records() -> None:
    payload = {
        "vulnerabilities": [
            {"cve": {
                "id": "CVE-2026-12345",
                "published": "2026-05-01T00:00:00",
                "lastModified": "2026-05-30T00:00:00",
                "vulnStatus": "Analyzed",
                "descriptions": [{"lang": "en", "value": "Description here"}],
                "metrics": {
                    "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}],
                },
                "weaknesses": [{"description": [{"lang": "en", "value": "CWE-89"}]}],
            }},
        ]
    }

    class FakeClient:
        def get(self, url, params=None, headers=None):
            assert url.startswith("https://services.nvd.nist.gov")
            assert "lastModStartDate" in params
            return FakeResp(payload)

    url, items = nvd.fetch_nvd_recent(FakeClient())
    assert url.startswith("https://services.nvd.nist.gov")
    assert items[0]["id"] == "CVE-2026-12345"
    assert items[0]["cvss31_base_score"] == 9.8
    assert items[0]["cwes"] == [{"value": "CWE-89"}]


def test_nvd_adapter_sends_api_key_header_when_env_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NVD_API_KEY", "test-key")
    seen_headers: dict = {}

    class FakeClient:
        def get(self, url, params=None, headers=None):
            seen_headers.update(headers or {})
            return FakeResp({"vulnerabilities": []})

    nvd.fetch_nvd_recent(FakeClient())
    assert seen_headers.get("apiKey") == "test-key"


# ---------------------------------------------------------------------------
# EPSS adapter
# ---------------------------------------------------------------------------

def test_epss_adapter_normalizes_records() -> None:
    payload = {
        "status": "OK",
        "data": [
            {"cve": "CVE-2026-11111", "epss": "0.85", "percentile": "0.99", "date": "2026-05-31"},
            {"cve": "CVE-2026-22222", "epss": "0.05", "percentile": "0.50", "date": "2026-05-31"},
        ],
    }

    class FakeClient:
        def get(self, url, params=None, headers=None):
            assert "epss" in url
            assert "days" in params
            return FakeResp(payload)

    url, items = epss.fetch_epss_recent(FakeClient())
    assert url.startswith("https://api.first.org")
    assert items[0]["cve"] == "CVE-2026-11111"
    assert items[0]["epss"] == 0.85


def test_epss_adapter_returns_empty_on_non_ok_status() -> None:
    class FakeClient:
        def get(self, url, params=None, headers=None):
            return FakeResp({"status": "error", "data": []})

    _, items = epss.fetch_epss_recent(FakeClient())
    assert items == []


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------

def test_cli_update_intel_promote_warns_without_kev_cache(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = cli.main([
        "update-intel", "--source", "cisa-kev",
        "--from-cache", "--promote", "--json",
        "--cache-dir", str(tmp_path / "cache"),
        "--rules-dir", str(tmp_path / "rules"),
    ])
    out = capsys.readouterr().out
    payload = json.loads(out)
    statuses = {r["source_id"]: r["status"] for r in payload}
    # cisa-kev cache absent → warn; promote step also warns because cache missing
    assert statuses["cisa-kev"] == "warn"
    assert statuses["promote-kev"] == "warn"
    assert rc == cli.EXIT_FINDINGS_WARN


def test_cli_update_intel_promote_writes_proposed_rules(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cache_dir = tmp_path / "cache"
    cache = IntelCache(cache_dir)
    cache.save("cisa-kev", "x", [_kev_sample()])
    rules_dir = tmp_path / "rules"

    rc = cli.main([
        "update-intel", "--source", "cisa-kev",
        "--from-cache", "--promote", "--json",
        "--cache-dir", str(cache_dir),
        "--rules-dir", str(rules_dir),
    ])
    out = capsys.readouterr().out
    payload = json.loads(out)
    promote = next(r for r in payload if r["source_id"] == "promote-kev")
    assert promote["status"] == "ok"
    assert promote["delta"] == 1
    assert (rules_dir / "INTEL-KEV-CVE-2025-99999.md").exists()
    assert rc == cli.EXIT_OK
