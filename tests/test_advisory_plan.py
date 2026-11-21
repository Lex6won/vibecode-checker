"""K3 — 권고 우선순위와 올릴 버전 계획. 판정은 바꾸지 않고 정렬·요약만 더한다.

실측(2026-11-21): mlflow 2.9.0 은 권고 127건이 같은 무게로 나왔고 권고 버전은 비어 있었다. 같은 취약점이 GHSA·PYSEC 두
이름으로 중복됐고, 한쪽에 수정판 정보가 없다는 이유로 전체 권고 버전이 None 이었다.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from gvskb.intel.cache import IntelCache
from gvskb.tools import check_package as cp
from gvskb.tools.advisory_plan import cvss_remote_unauthenticated, prioritize, summarize, upgrade_plan

NET = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
AUTH = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
LOCAL = "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def _row(vid: str, sev: str, vector: str | None = None, aliases: list[str] | None = None, fixed: str | None = None) -> dict:
    return {"id": vid, "aliases": aliases or [], "severity": sev, "cvss_vector": vector,
            "fixed_versions": [fixed] if fixed else [], "fixed_ranges": [("0", fixed)] if fixed else []}


def test_cvss_vector_reading() -> None:
    assert cvss_remote_unauthenticated(NET) is True
    assert cvss_remote_unauthenticated(AUTH) is False
    assert cvss_remote_unauthenticated(LOCAL) is False
    assert cvss_remote_unauthenticated("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N") is True
    assert cvss_remote_unauthenticated(None) is None
    assert cvss_remote_unauthenticated("HIGH") is None          # 벡터가 아니면 모름 — 추측하지 않는다


def test_priority_order_and_summary() -> None:
    rows = [
        _row("GHSA-low", "LOW", NET),
        _row("GHSA-high-auth", "HIGH", AUTH),
        _row("GHSA-crit-net", "CRITICAL", NET),
        _row("GHSA-kev", "MEDIUM", AUTH, aliases=["CVE-2026-0001"]),
        _row("GHSA-high-net", "HIGH", NET),
        _row("PYSEC-unknown", "UNKNOWN"),
    ]
    out = prioritize(rows, {"CVE-2026-0001"})
    assert [r["id"] for r in out] == ["GHSA-kev", "GHSA-crit-net", "GHSA-high-net", "GHSA-high-auth", "GHSA-low", "PYSEC-unknown"]
    assert [r["priority"] for r in out] == ["kev", "remote-unauth", "remote-unauth", "high", "other", "other"]
    assert len(out) == len(rows) and rows[0].get("priority") is None, "원본 행은 바꾸지 않고, 하나도 빠뜨리지 않는다"
    assert summarize(out) == {"total": 6, "kev": 1, "remote_unauthenticated": 3, "critical_high": 3}


def test_upgrade_plan_groups_aliases_and_never_overclaims() -> None:
    rows = prioritize([
        _row("GHSA-a", "HIGH", NET, aliases=["CVE-2026-1"], fixed="2.0.0"),
        _row("PYSEC-a", "UNKNOWN", aliases=["CVE-2026-1", "GHSA-a"]),            # 같은 취약점, 이쪽엔 수정판 정보 없음
        _row("GHSA-b", "MEDIUM", AUTH, fixed="2.5.0"),
        _row("GHSA-c", "CRITICAL", NET),                                          # 수정판을 모르는 급한 것
    ])
    plan = upgrade_plan(rows, "1.0.0", cp._advisory_target, cp._highest_version)
    assert plan["issues"] == 3, "별칭이 겹치는 권고는 한 건"
    assert plan["version"] == "2.5.0" and plan["resolves"] == 2 and plan["unfixed"] == 1
    assert plan["unfixed_ids"] == ["GHSA-c"] and plan["urgent_unfixed_ids"] == ["GHSA-c"]
    assert plan["complete"] is False, "하나라도 모르면 '올리면 전부 해소'라고 하지 않는다"
    # 기존 권고 버전의 뜻은 그대로 — 하나라도 모르면 None
    assert cp._recommended_version(rows, "1.0.0") is None

    full = upgrade_plan(rows[:0] + [r for r in rows if r["id"] != "GHSA-c"], "1.0.0", cp._advisory_target, cp._highest_version)
    assert full["complete"] is True and full["version"] == "2.5.0" and full["unfixed"] == 0
    assert upgrade_plan([], "1.0.0", cp._advisory_target, cp._highest_version) is None
    none_known = upgrade_plan(prioritize([_row("GHSA-z", "HIGH")]), "1.0.0", cp._advisory_target, cp._highest_version)
    assert none_known["version"] is None and none_known["complete"] is False and none_known["unfixed"] == 1


def _vuln(vid: str, fixed: str | None, sev: str, vector: str, cve: str) -> dict:
    events = [{"introduced": "0"}] + ([{"fixed": fixed}] if fixed else [])
    return {"id": vid, "aliases": [cve], "summary": "bug", "database_specific": {"severity": sev},
            "severity": [{"type": "CVSS_V3", "score": vector}],
            "affected": [{"package": {"name": "lib", "ecosystem": "npm"}, "ranges": [{"type": "ECOSYSTEM", "events": events}]}]}


@pytest.fixture
def cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path))
    monkeypatch.setenv("GVSKB_MODE", "offline")
    monkeypatch.setenv("GVSKB_INTEL_MAX_AGE_DAYS", "3650")
    c = IntelCache(tmp_path)
    c.save("osv-malicious", "https://example.test", [], ecosystems=["PyPI", "npm"])
    c.save("osv-vulns", "https://example.test", [
        _vuln("GHSA-medium", "1.5.0", "MODERATE", AUTH, "CVE-2026-0010"),
        _vuln("GHSA-nofix", None, "HIGH", AUTH, "CVE-2026-0011"),
        _vuln("GHSA-remote", "2.0.0", "CRITICAL", NET, "CVE-2026-0012"),
        _vuln("GHSA-exploited", "1.2.0", "MODERATE", AUTH, "CVE-2026-0013"),
    ], ecosystems=["PyPI", "npm"])
    c.save("cisa-kev", "https://example.test", [{"cveID": "CVE-2026-0013", "vulnerabilityName": "lib bug", "dateAdded": "2026-11-01"}])


def test_local_check_sorts_and_plans_without_changing_the_verdict(cache: None) -> None:
    r = asyncio.run(cp.check_package_impl("lib", ecosystem="npm", version="1.0.0", mode="local"))
    assert r["verdict"] == "vulnerable" and r["vulnerability_count"] == 4 and r["in_kev"] is True
    assert [a["id"] for a in r["advisories"]] == ["GHSA-exploited", "GHSA-remote", "GHSA-nofix", "GHSA-medium"]
    assert r["advisories"][0]["priority"] == "kev" and r["advisories"][1]["remote_unauthenticated"] is True
    assert r["advisory_summary"] == {"total": 4, "kev": 1, "remote_unauthenticated": 1, "critical_high": 2}
    assert r["recommended_version"] is None, "수정판을 모르는 권고가 있으면 기존 값은 그대로 None"
    plan = r["upgrade_plan"]
    assert plan["version"] == "2.0.0" and plan["resolves"] == 3 and plan["unfixed"] == 1 and plan["complete"] is False


def test_report_says_how_far_an_upgrade_gets() -> None:
    from gvskb.report import _pkg_upgrade_hint, _upgrade_hint

    plan = {"version": "3.17.2", "issues": 66, "resolves": 39, "unfixed": 27, "urgent_unfixed_ids": ["GHSA-x"], "complete": False}
    text = _upgrade_hint(None, None, "2.9.0", plan)
    assert "3.17.2" in text and "66건 중 39건" in text and "27건은 수정판 정보가 없습니다" in text and "1건" in text
    assert "3.17.2" in _pkg_upgrade_hint({"recommended_version": None, "upgrade_plan": plan})
    # 확정된 권고 버전이 있으면 그 문장이 그대로다
    assert _upgrade_hint("2.0.0", None, "1.0.0", {"version": "2.0.0", "complete": True, "unfixed": 0}) == "**2.0.0 이상**으로 올린 뒤 다시 검사하세요"
    # 아는 수정판이 하나도 없으면 기존 문장으로
    assert "찾지 못했습니다" in _upgrade_hint(None, None, "1.0.0", {"version": None, "unfixed": 2, "complete": False})
