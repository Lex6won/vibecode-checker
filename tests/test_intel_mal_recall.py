"""악성 권고 대조의 미탐 경로 — 오탐을 줄이면서 놓치게 된 경우를 하나씩 막는다(적대적 검증 2026-11-06).

버전 지목 권고에는 탈취된 정상 패키지(chalk 5.6.1)와 위장 패키지가 섞여 있다. PyPI 권고의 46%가 버전 열거다.
"""
from __future__ import annotations

import asyncio

import pytest

from gvskb.gate import gate_status
from gvskb.intel.cache import IntelCache
from gvskb.schema import ScanReport, ScanSummary
from gvskb.scanner import parse_manifest_packages
from gvskb.tools.check_package import (
    _classify_mal_advisories,
    _known_legit_package,
    _mal_covers_whole_package,
    _mal_scope,
    _npm_range_bounds,
    _version_in_affected,
    _version_key,
    apply_registry_decision,
    check_package_impl,
)
from gvskb.intel.sources.osv import _mal_affected


# ── 버전 비교 ──────────────────────────────────────────────────────────
@pytest.mark.parametrize("a,b", [("1.0", "1.0.0"), ("1.3.0", "1.3"), ("2", "2.0.0"), ("0.0.0", "0"), ("1.0.0+build", "1")])
def test_trailing_zero_is_the_same_version(a, b):
    assert _version_key(a) == _version_key(b)


def test_version_key_ordering_survives_zero_stripping():
    ordered = ["0", "0.0.1", "0.1", "1", "1.0.1", "1.1", "2"]
    keys = [_version_key(v) for v in ordered]
    assert keys == sorted(keys) and len(set(keys)) == len(keys)


@pytest.mark.parametrize("aff,version", [
    ({"versions": ["1.0.0"]}, "1.0"),
    ({"versions": ["1.0"]}, "1.0.0"),
    ({"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "1.0.1"}]}]}, "1.0"),
])
def test_zero_padded_spelling_still_hits(aff, version):
    assert _mal_scope(aff, version, True, recognized=False, ecosystem="PyPI") == ("hit", "")


def test_prerelease_is_not_the_final_release():
    assert _version_in_affected({"versions": ["1.0.0-beta.1"]}, "1.0.0") is False
    assert _version_in_affected({"versions": ["1.0.0"]}, "1.0.0-beta.1") is False
    assert _version_in_affected({"versions": ["1.0.0-beta.1"]}, "1.0.0-BETA.1") is True
    assert _version_in_affected({"versions": ["1.0.0"]}, "1.0.0+build.5") is True


def test_prerelease_inside_and_outside_window():
    window = {"ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.0.1"}]}]}
    assert _version_in_affected(window, "1.0.1-rc.1") is True     # 1.0.1 정식판보다 앞이다
    assert _version_in_affected(window, "1.0.0-rc.1") is False    # 1.0.0 정식판보다 앞이다
    assert _version_in_affected(window, "1.0.1") is False


# ── 매니페스트 파서 ────────────────────────────────────────────────────
@pytest.mark.parametrize("spec", ["5.6", "1", "1.14", "5.x", "^5.6.1", "~5.6.1", ">=5", "latest", "*"])
def test_npm_incomplete_or_range_is_not_pinned(spec):
    pkg = parse_manifest_packages('{"dependencies":{"chalk":"%s"}}' % spec, "npm")[0]
    assert pkg["version_exact"] is False


@pytest.mark.parametrize("spec,version", [("5.6.1", "5.6.1"), ("=5.6.1", "5.6.1"), ("v5.6.1", "5.6.1"), ("5.6.1-beta.1", "5.6.1-beta.1")])
def test_npm_full_version_is_pinned(spec, version):
    pkg = parse_manifest_packages('{"dependencies":{"chalk":"%s"}}' % spec, "npm")[0]
    assert pkg["version_exact"] is True and pkg["version"] == version


def test_npm_alias_reads_the_installed_package():
    pkg = parse_manifest_packages('{"dependencies":{"x":"npm:axios@1.14.1","y":"npm:@scope/pkg@^2.0.0"}}', "npm")
    assert (pkg[0]["name"], pkg[0]["version"], pkg[0]["version_exact"]) == ("axios", "1.14.1", True)
    assert (pkg[1]["name"], pkg[1]["version"], pkg[1]["version_exact"]) == ("@scope/pkg", "2.0.0", False)


def test_npm_caret_keeps_spec_for_range_evaluation():
    assert parse_manifest_packages('{"dependencies":{"chalk":"^4.1.2"}}', "npm")[0]["spec"] == "^4.1.2"


@pytest.mark.parametrize("line,exact", [
    ("evil[x]==12.15.13", True), ("evil[a,b]==12.15.13", True), ("evil===12.15.13", True), ("evil [x] == 12.15.13", True),
    ("evil[x]>=12.15.13", False), ("evil!=12.15.13", False),
])
def test_pypi_extras_and_triple_equals_keep_the_version(line, exact):
    pkg = parse_manifest_packages(line + "\n", "pypi")[0]
    assert pkg["name"] == "evil" and pkg["version"] == "12.15.13" and pkg["version_exact"] is exact


# ── 판정 규칙 표 ───────────────────────────────────────────────────────
LISTED = {"versions": ["12.15.13"]}


@pytest.mark.parametrize("version,exact,recognized,expected", [
    # 지목 버전은 누구든 차단
    ("12.15.13", True, True, "hit"), ("12.15.13", True, False, "hit"),
    # 지목보다 낮은 번호 — 정상 패키지면 오염 이전 판이지만, 근거가 없으면 낮은 번호만 적어 통과할 수 있다
    ("1.0.0", True, True, "miss"), ("1.0.0", True, False, "possible"),
    # 지목보다 새로운 판 — 정상 패키지면 수정판, 아니면 신고 뒤에 올라온 판일 수 있다
    ("12.15.14", True, True, "miss"), ("12.15.14", True, False, "possible"),
    # 버전을 모르면 정상 패키지는 확인 필요, 근거 없는 패키지는 차단
    (None, True, True, "possible"), (None, True, False, "hit"),
    ("12.15.13", False, True, "possible"), ("12.15.13", False, False, "hit"),
    ("not-a-version", True, True, "possible"), ("not-a-version", True, False, "hit"),
])
def test_scope_table(version, exact, recognized, expected):
    assert _mal_scope(LISTED, version, exact, recognized=recognized, ecosystem="PyPI")[0] == expected


@pytest.mark.parametrize("recognized", [True, False])
def test_whole_package_hits_regardless(recognized):
    assert _mal_scope({"whole": True}, "1.0.0", True, recognized=recognized) == ("hit", "")


def test_old_format_cache_blocks_unrecognized_and_flags_recognized():
    assert _mal_scope({}, "1.0.0", True, recognized=False) == ("hit", "advisory_without_versions")
    assert _mal_scope({}, "1.0.0", True, recognized=True) == ("possible", "advisory_without_versions")


def test_closed_window_is_outside_even_when_unrecognized():
    aff = {"ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.2.11"}]}]}
    assert _mal_scope(aff, "2.3.3", True, recognized=False, ecosystem="npm") == ("miss", "")


def test_open_window_is_inside():
    aff = {"ranges": [{"type": "SEMVER", "events": [{"introduced": "2.0.0"}]}]}
    assert _mal_scope(aff, "3.0.0", True, recognized=False, ecosystem="npm") == ("hit", "")


def test_npm_partial_version_cannot_be_treated_as_pinned_by_any_caller():
    # 호출자가 version_exact=True 로 넘겨도(gg package check --version 5.6) 5.6.1 을 놓치지 않는다.
    aff = {"versions": ["5.6.1"]}
    assert _mal_scope(aff, "5.6", True, recognized=True, ecosystem="npm")[0] == "possible"
    assert _mal_scope(aff, "5.6", True, recognized=False, ecosystem="npm")[0] == "hit"


@pytest.mark.parametrize("spec,bounds", [
    ("^4.1.2", ("4.1.2", "5.0.0")), ("~4.1.2", ("4.1.2", "4.2.0")), ("~4", ("4.0.0", "5.0.0")),
    ("^0.2.3", ("0.2.3", "0.3.0")), ("^0.0.3", ("0.0.3", "0.0.4")),
])
def test_npm_range_bounds(spec, bounds):
    assert _npm_range_bounds(spec) == (_version_key(bounds[0]), _version_key(bounds[1]))


@pytest.mark.parametrize("spec", [None, "", ">=1", "1.x", "latest", "^1.2.3 || ^2"])
def test_npm_range_bounds_refuses_other_spellings(spec):
    assert _npm_range_bounds(spec) is None


@pytest.mark.parametrize("spec,recognized,expected", [
    ("^4.1.2", True, "miss"),       # chalk ^4 는 5.6.1 이 될 수 없다
    ("^4.1.2", False, "possible"),  # 지목보다 앞 구간이어도 근거가 없으면 통과가 아니다
    ("^5.3.0", True, "possible"),   # 5.6.1 을 받을 수 있다
    ("^5.3.0", False, "hit"),
    ("^5.6.2", True, "miss"),       # 지목보다 뒤 구간
    ("^5.6.2", False, "possible"),
])
def test_npm_range_excluding_listed_version(spec, recognized, expected):
    aff = {"versions": ["5.6.1"]}
    assert _mal_scope(aff, spec.lstrip("^~"), False, recognized=recognized, ecosystem="npm", spec=spec)[0] == expected


def test_zero_start_spelling_counts_as_whole_package():
    assert _mal_covers_whole_package({"ranges": [{"type": "SEMVER", "events": [{"introduced": "0.0.0"}]}]})
    raw = {"package": {"name": "x", "ecosystem": "npm"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0.0.0"}]}]}
    assert _mal_affected(raw).get("whole") is True


# ── 정상 패키지 근거 ───────────────────────────────────────────────────
class _Entry:
    source_id = "osv-vulns"

    def __init__(self, items, sha):
        self.items, self.sha256 = items, sha


def test_legit_signal_sources():
    vulns = _Entry([
        {"id": "GHSA-1", "summary": "XSS", "affected": [{"package": {"name": "Real_Lib", "ecosystem": "PyPI"}}]},
        {"id": "GHSA-2", "aliases": ["MAL-2025-1"], "summary": "x", "affected": [{"package": {"name": "alias-squat", "ecosystem": "PyPI"}}]},
        {"id": "GHSA-3", "summary": "Embedded malicious code", "affected": [{"package": {"name": "text-squat", "ecosystem": "PyPI"}}]},
    ], "legit-signal-test")
    assert _known_legit_package("real-lib", "PyPI", vulns)
    assert not _known_legit_package("alias-squat", "PyPI", vulns)
    assert not _known_legit_package("text-squat", "PyPI", vulns)
    assert not _known_legit_package("beautifulsoup-requests", "PyPI", vulns)
    assert _known_legit_package("ansi-styles", "npm", None)     # 내장 목록
    assert _known_legit_package("axios", "npm", None)
    assert not _known_legit_package("ansi-styles", "PyPI", None)   # 생태계가 다르면 근거가 아니다


def test_classify_keeps_stronger_scope_and_reason():
    mal = _Entry([
        {"id": "MAL-1", "affected": [{"package": "squat", "ecosystem": "PyPI", "versions": ["1.0.0"]}]},
        {"id": "MAL-2", "affected": [{"package": "squat", "ecosystem": "PyPI", "whole": True}]},
    ], "classify-test")
    mal.source_id = "osv-malicious"
    hits, possible = _classify_mal_advisories(mal, "squat", "PyPI", None, True)
    assert {h["id"] for h in hits} == {"MAL-1", "MAL-2"} and possible == []
    assert next(h for h in hits if h["id"] == "MAL-2").get("reason") is None
    assert next(h for h in hits if h["id"] == "MAL-1")["reason"] == "version_unpinned"


# ── 끝까지 — 실제 캐시 형식 ────────────────────────────────────────────
@pytest.fixture
def intel(tmp_path, monkeypatch):
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path))
    monkeypatch.setenv("GVSKB_MODE", "")
    cache = IntelCache(tmp_path)
    mal = [
        {"id": "MAL-HIJACK", "summary": "m", "affected": [{"package": "chalk", "ecosystem": "npm", "versions": ["5.6.1"]}]},
        {"id": "MAL-SQUAT", "summary": "m", "affected": [{"package": "beautifulsoup-requests", "ecosystem": "PyPI", "versions": ["12.15.13"]}]},
        {"id": "MAL-WHOLE", "summary": "m", "affected": [{"package": "pure-evil", "ecosystem": "PyPI", "whole": True}]},
    ]
    cache.save("osv-malicious", "test", mal, ecosystems=["PyPI", "npm"])
    cache.save("cisa-kev", "test", [])
    cache.save("osv-vulns", "test", [], ecosystems=["PyPI", "npm"])
    return cache


def _check(name, eco, version=None, exact=True, spec=None):
    return asyncio.run(check_package_impl(name, ecosystem=eco, version=version, version_exact=exact, mode="local", version_spec=spec))


def test_e2e_hijacked_popular_package(intel):
    assert _check("chalk", "npm", "5.6.1")["is_malicious_package"] is True
    clean = _check("chalk", "npm", "5.3.0")
    assert clean["is_malicious_package"] is False and not clean["malicious_possible"]
    unpinned = _check("chalk", "npm")
    assert unpinned["is_malicious_package"] is False and unpinned["malicious_possible"]
    assert "악성 등록 없음" not in unpinned["note"] and "**악성 등록은 없습니다**" not in unpinned["note"]


def test_e2e_squat_never_silently_clean(intel):
    assert _check("beautifulsoup-requests", "pypi", "12.15.13")["is_malicious_package"] is True
    assert _check("beautifulsoup-requests", "pypi", "12.15.13.0")["is_malicious_package"] is True
    newer = _check("beautifulsoup-requests", "pypi", "12.15.14")
    assert newer["is_malicious_package"] is False and newer["malicious_possible"]
    assert newer["requires_review"] is True and "정상 패키지" in newer["note"]
    unpinned = _check("beautifulsoup-requests", "pypi")
    assert unpinned["is_malicious_package"] is True and "고정" in unpinned["note"]


def test_e2e_whole_package_blocks_in_every_spelling(intel):
    for version, exact in ((None, True), ("1.0.0", True), ("1.0.0", False)):
        assert _check("pure-evil", "pypi", version, exact)["is_malicious_package"] is True


def test_e2e_manifest_extras_reach_the_advisory(intel):
    from gvskb.tools.check_package import audit_manifest

    audit = asyncio.run(audit_manifest("beautifulsoup-requests[x]==12.15.13\n", ecosystem="pypi", mode="local"))
    assert audit["checks"][0]["is_malicious_package"] is True


def test_e2e_npm_partial_manifest_is_not_clean(intel):
    from gvskb.tools.check_package import audit_manifest

    audit = asyncio.run(audit_manifest('{"dependencies":{"chalk":"5.6"}}', ecosystem="npm", mode="local"))
    assert audit["checks"][0]["malicious_possible"]


def test_e2e_caret_outside_reaches_scope(intel):
    from gvskb.tools.check_package import audit_manifest

    audit = asyncio.run(audit_manifest('{"dependencies":{"chalk":"^4.1.2"}}', ecosystem="npm", mode="local"))
    assert not audit["checks"][0]["malicious_possible"] and not audit["checks"][0]["is_malicious_package"]


def test_old_format_cache_detected_and_refreshed(tmp_path, monkeypatch):
    from gvskb.intel.autopull import cache_needs_refresh

    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path))
    cache = IntelCache(tmp_path)
    cache.save("osv-malicious", "t", [{"id": "MAL-1", "affected": [{"package": "x", "ecosystem": "npm"}]}], ecosystems=["PyPI", "npm"])
    assert cache.mal_old_format() is True
    needs, reason = cache_needs_refresh(tmp_path)
    assert needs and ("구형식" in reason or "없음" in reason)
    cache.save("osv-malicious", "t", [{"id": "MAL-1", "affected": [{"package": "x", "ecosystem": "npm", "whole": True}]}], ecosystems=["PyPI", "npm"])
    assert cache.mal_old_format() is False


def test_old_format_cache_still_blocks_whole_malware(tmp_path, monkeypatch):
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path))
    monkeypatch.setenv("GVSKB_MODE", "")
    cache = IntelCache(tmp_path)
    cache.save("osv-malicious", "t", [
        {"id": "MAL-1", "affected": [{"package": "real-evil", "ecosystem": "PyPI"}]},
        {"id": "MAL-2", "affected": [{"package": "chalk", "ecosystem": "npm"}]},
    ], ecosystems=["PyPI", "npm"])
    cache.save("osv-vulns", "t", [], ecosystems=["PyPI", "npm"])
    evil = _check("real-evil", "pypi", "1.0.0")
    assert evil["is_malicious_package"] is True and "구형식" in evil["note"]
    popular = _check("chalk", "npm", "5.3.0")
    assert popular["is_malicious_package"] is False and popular["malicious_possible"]
    assert "update-intel" in popular["note"]


# ── 레지스트리·게이트 ──────────────────────────────────────────────────
def test_registry_approval_does_not_hide_possible():
    local = {"name": "chalk", "verdict": "checked_clean", "requires_review": True, "note": "n",
             "malicious_possible": [{"id": "MAL-1"}], "cache_sources_used": ["osv-malicious"]}
    out = apply_registry_decision(local, {"status": "APPROVED"})
    assert out["verdict"] != "registry_approved" and "악성 권고" in out["note"]


def _report(**audit):
    summary = ScanSummary(finding_count=0, by_severity={}, by_decision={})
    return ScanReport(target=".", scanned_files=["a.py"], summary=summary, findings=[],
                      dependency_audit={"audits": [{"ecosystem": "pypi", "checks": [], **audit}]})


def test_gate_does_not_approve_truncated_manifest():
    gate = gate_status(_report(truncated_count=5, parsed_count=25))
    assert gate["verdict"] == "conditional" and "dependency_truncated" in gate["conditional_criteria"]
    assert gate["dependency_truncated"] == 5 and "5종" in gate["reason"]


def test_project_scan_reads_manifest_beyond_default_limit(intel, tmp_path):
    from gvskb.deps_check import attach_dependency_check, run_dependency_audit
    from gvskb.scanner import scan_path

    project = tmp_path / "proj"
    project.mkdir()
    lines = [f"safe-pkg-{i}==1.0.0" for i in range(25)] + ["pure-evil==1.0.0"]
    (project / "requirements.txt").write_text(chr(10).join(lines), encoding="utf-8")
    report = scan_path(str(project))
    audit = run_dependency_audit(project, report, mode="local", refresh=False)
    attach_dependency_check(report, mode="local", requested="local", audit=audit)
    gate = gate_status(report)
    assert gate["verdict"] == "blocked" and gate["dependency_truncated"] == 0


# ── 차단되면 무엇을 해야 하는가 ───────────────────────────────────────
def _gate_for(tmp_path, requirements: str) -> dict:
    from gvskb.deps_check import attach_dependency_check, run_dependency_audit
    from gvskb.scanner import scan_path

    project = tmp_path / "proj"
    project.mkdir()
    (project / "requirements.txt").write_text(requirements, encoding="utf-8")
    (project / "a.py").write_text("x = 1", encoding="utf-8")   # 소스 0개는 그 자체로 판정 불가다
    report = scan_path(str(project))
    attach_dependency_check(report, mode="local", requested="local", audit=run_dependency_audit(project, report, mode="local", refresh=False))
    return gate_status(report)


def test_unverified_block_says_it_is_not_confirmed_and_what_to_do(intel, tmp_path):
    gate = _gate_for(tmp_path, "beautifulsoup-requests\n")
    assert gate["verdict"] == "blocked"
    row = gate["block_reasons"][0]
    assert row["malicious_kind"] == "unverified" and row["labels"] == ["악성 권고 — 버전 미확인"]
    assert row["versions"] == ["12.15.13"]
    reason = gate["reason"]
    assert "악성으로 확정된 것은 아닙니다" in reason and "12.15.13" in reason
    for step in ("공식 저장소", "제거하고 올바른 패키지", "고정", "설치된 버전을 확인", "보안담당자"):
        assert step in reason, step
    assert "PC 는 점검(비밀값" not in reason, "must not read like a confirmed infection"


def test_confirmed_block_says_remove_and_check_pc(intel, tmp_path):
    gate = _gate_for(tmp_path, "pure-evil==1.0.0\n")
    row = gate["block_reasons"][0]
    assert row["malicious_kind"] == "confirmed" and row["labels"] == ["악성 패키지"]
    assert "악성으로 확인됐습니다" in gate["reason"]
    for step in ("제거", "PC", "보안담당자", "대체 패키지"):
        assert step in gate["reason"], step
    assert "확정된 것은 아닙니다" not in gate["reason"]


def test_listed_version_is_confirmed_not_unverified(intel, tmp_path):
    gate = _gate_for(tmp_path, "beautifulsoup-requests==12.15.13\n")
    assert gate["block_reasons"][0]["malicious_kind"] == "confirmed"


@pytest.mark.parametrize("line", ["beautifulsoup-requests==1.0.0", "beautifulsoup-requests==0.0.1", "beautifulsoup-requests==12.15.14"])
def test_low_number_pin_is_not_a_way_around(intel, tmp_path, line):
    gate = _gate_for(tmp_path, f"{line}\n")
    assert gate["verdict"] == "conditional", gate["verdict"]
    assert "malicious_possible" in gate["conditional_criteria"]
    assert "정상 패키지인지 확인" in gate["reason"]


def test_legit_package_low_pin_stays_clean(intel, tmp_path):
    from gvskb.tools.check_package import audit_manifest

    audit = asyncio.run(audit_manifest('{"dependencies":{"chalk":"4.1.2"}}', ecosystem="npm", mode="local"))
    assert not audit["checks"][0]["malicious_possible"] and not audit["checks"][0]["is_malicious_package"]


def test_report_shows_the_action_not_upgrade_hint(intel, tmp_path):
    from gvskb.deps_check import attach_dependency_check, run_dependency_audit
    from gvskb.gate import attach_gate
    from gvskb.report import render_markdown
    from gvskb.scanner import scan_path

    project = tmp_path / "proj"
    project.mkdir()
    (project / "requirements.txt").write_text("beautifulsoup-requests\n", encoding="utf-8")
    report = scan_path(str(project))
    attach_dependency_check(report, mode="local", requested="local", audit=run_dependency_audit(project, report, mode="local", refresh=False))
    attach_gate(report)
    text = render_markdown(report)
    assert "악성 권고 — 버전 미확인" in text and "공식 저장소에서 이 이름이 의도한 패키지인지" in text
    assert "안전한 상위 버전을 찾지 못했습니다" not in text
    assert "악성 의심" not in text


def test_old_format_block_tells_to_refresh(tmp_path, monkeypatch):
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path / "c"))
    monkeypatch.setenv("GVSKB_MODE", "")
    cache = IntelCache(tmp_path / "c")
    cache.save("osv-malicious", "t", [{"id": "MAL-1", "affected": [{"package": "real-evil", "ecosystem": "PyPI"}]}], ecosystems=["PyPI", "npm"])
    cache.save("osv-vulns", "t", [], ecosystems=["PyPI", "npm"])
    gate = _gate_for(tmp_path, "real-evil==1.0.0\n")
    assert gate["block_reasons"][0]["malicious_kind"] == "old_format"
    assert "update-intel" in gate["reason"]


def test_malicious_kind_table():
    from gvskb.gate import malicious_kind

    assert malicious_kind({}) is None
    assert malicious_kind({"is_malicious_package": True}) == "confirmed"
    assert malicious_kind({"is_malicious_package": True, "advisories": [{"id": "MAL-1"}]}) == "confirmed"
    assert malicious_kind({"is_malicious_package": True, "advisories": [{"id": "MAL-1", "reason": "version_unpinned"}]}) == "unverified"
    assert malicious_kind({"is_malicious_package": True, "advisories": [{"id": "MAL-1", "reason": "version_unpinned"}, {"id": "MAL-2"}]}) == "confirmed"
    assert malicious_kind({"is_malicious_package": True, "advisories": [{"id": "MAL-1", "reason": "advisory_without_versions"}]}) == "old_format"
