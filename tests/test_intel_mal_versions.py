"""악성 권고의 영향 범위 — 특정 버전 오염이 패키지 전체 차단이 되지 않게 한다(실측 2026-11-05).

위협정보 수집기가 영향 버전을 버려 로컬 모드에서 react 18.3.1 · axios 1.7.9 · chalk 5.3.0 · debug 4.3.7 ·
fastapi 0.115.6 이 전부 '악성'(사유 기록으로 넘길 수 없는 차단)으로 나왔다. 권고 원문은 react·fastapi 는 철회,
나머지는 특정 버전만이다. 반대 방향도 고정한다: 실제 악성 버전과 패키지 전체 악성은 계속 차단해야 한다.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from gvskb.gate import gate_status
from gvskb.intel.cache import IntelCache
from gvskb.intel.sources import osv
from gvskb.schema import ScanReport
from gvskb.tools.check_package import _mal_scope, _offline_cache_check, _apply_mal_possible


def _raw(vid: str, name: str, eco: str = "npm", *, versions=None, ranges=None, withdrawn=None) -> dict:
    aff: dict = {"package": {"name": name, "ecosystem": eco}}
    if versions is not None:
        aff["versions"] = versions
    if ranges is not None:
        aff["ranges"] = ranges
    d = {"id": vid, "summary": f"Malicious code in {name}", "modified": "2026-01-01T00:00:00Z", "affected": [aff]}
    if withdrawn:
        d["withdrawn"] = withdrawn
    return d


WHOLE = [{"type": "SEMVER", "events": [{"introduced": "0"}]}]


@pytest.fixture(autouse=True)
def approved_legit_packages(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """이 파일의 정상 패키지는 보안담당자가 지정한 것으로 둔다. 지정이 없는 경우는 test_intel_mal_recall 이 본다."""
    listed = tmp_path / "approved-packages.json"
    names = ("axios", "chalk", "debug", "lodash", "express", "react")
    listed.write_text('{"packages":[' + ",".join('{"ecosystem":"npm","name":"%s"}' % n for n in names) + "]}", encoding="utf-8")
    monkeypatch.setenv("GVSKB_APPROVED_PACKAGES", str(listed))


@pytest.fixture
def cache_with(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path))
    monkeypatch.setenv("GVSKB_MODE", "offline")

    def write(*raw: dict) -> None:
        items = [osv._normalize(r) for r in raw if not r.get("withdrawn")]
        IntelCache(tmp_path).save("osv-malicious", "https://example.test", items, ecosystems=["PyPI", "npm"])

    return write


def _check(name: str, eco: str = "npm", version: str | None = "1.0.0", exact: bool = True) -> dict:
    label = {"npm": "npm", "pypi": "PyPI"}[eco]
    return _apply_mal_possible(_offline_cache_check(name, eco, label, version, version_exact=exact))


# ---------------------------------------------------------------- 수집기

def test_normalize_keeps_version_scope_and_compacts_whole_packages() -> None:
    whole = osv._normalize(_raw("MAL-1", "evil", ranges=WHOLE, versions=["1.0.0"]))
    assert whole["affected"] == [{"package": "evil", "ecosystem": "npm", "whole": True}]
    listed = osv._normalize(_raw("MAL-2", "axios", versions=["0.30.4", "1.14.1"]))
    assert listed["affected"][0]["versions"] == ["0.30.4", "1.14.1"] and "whole" not in listed["affected"][0]
    bounded = osv._normalize(_raw("MAL-3", "lib", ranges=[{"type": "SEMVER", "events": [{"introduced": "0"}, {"last_affected": "1.2.0"}]}]))
    assert "whole" not in bounded["affected"][0] and bounded["affected"][0]["ranges"]
    git_only = osv._normalize(_raw("MAL-4", "gitlib", ranges=[{"type": "GIT", "events": [{"introduced": "0"}]}]))
    assert "whole" not in git_only["affected"][0], "커밋 범위는 버전 비교 재료가 아니다"


def test_collector_drops_withdrawn_mal() -> None:
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("MAL-1.json", json.dumps(_raw("MAL-1", "react", versions=["35.0.0"], withdrawn="2024-07-01T00:00:00Z")))
        z.writestr("MAL-2.json", json.dumps(_raw("MAL-2", "chalk", versions=["5.6.1"])))

    class Resp:
        content = buf.getvalue()

        def raise_for_status(self) -> None:
            return None

    class Client:
        def get(self, url: str) -> Resp:
            return Resp()

    _, items = osv.fetch_osv_malicious(Client())
    assert [i["id"] for i in items] == ["MAL-2"]


# ---------------------------------------------------------------- 판정: 오탐이 줄어야 한다

@pytest.mark.parametrize("name,version", [("axios", "1.7.9"), ("axios", "1.15.0"), ("chalk", "5.3.0"), ("debug", "4.3.7")])
def test_clean_version_of_a_compromised_package_is_not_malicious(cache_with, name: str, version: str) -> None:
    cache_with(_raw("MAL-A", "axios", versions=["0.30.4", "1.14.1"]), _raw("MAL-C", "chalk", versions=["5.6.1"]),
               _raw("MAL-D", "debug", versions=["4.4.2"]))
    r = _check(name, version=version)
    assert r["verdict"] != "malicious" and not r["is_malicious_package"] and not r["malicious_possible"]


def test_withdrawn_advisory_blocks_nothing(cache_with) -> None:
    cache_with(_raw("MAL-R", "react", versions=["35.0.0", "1.0.0"], withdrawn="2024-07-01T00:00:00Z"))
    assert not _check("react", version="18.3.1")["is_malicious_package"]
    assert not _check("react", version="35.0.0")["is_malicious_package"], "철회된 권고는 지목 버전도 막지 않는다"


# ---------------------------------------------------------------- 판정: 정탐은 유지돼야 한다

@pytest.mark.parametrize("name,version", [("axios", "1.14.1"), ("axios", "0.30.4"), ("chalk", "5.6.1"), ("debug", "4.4.2")])
def test_listed_version_stays_malicious(cache_with, name: str, version: str) -> None:
    cache_with(_raw("MAL-A", "axios", versions=["0.30.4", "1.14.1"]), _raw("MAL-C", "chalk", versions=["5.6.1"]),
               _raw("MAL-D", "debug", versions=["4.4.2"]))
    r = _check(name, version=version)
    assert r["verdict"] == "malicious" and r["is_malicious_package"]


@pytest.mark.parametrize("version,exact", [("1.0.0", True), ("9.9.9", True), ("1.0.0", False), (None, True)])
def test_whole_package_malicious_is_blocked_whatever_the_version(cache_with, version, exact) -> None:
    cache_with(_raw("MAL-W", "evil-squat", ranges=WHOLE))
    assert _check("evil-squat", version=version, exact=exact)["verdict"] == "malicious"


def test_range_scoped_advisory_matches_inside_only(cache_with) -> None:
    cache_with(_raw("MAL-G", "lib", ranges=[{"type": "SEMVER", "events": [{"introduced": "2.0.0"}, {"fixed": "2.1.0"}]}]))
    assert _check("lib", version="2.0.5")["verdict"] == "malicious"
    assert _check("lib", version="2.1.0")["verdict"] != "malicious"
    assert _check("lib", version="1.9.0")["verdict"] != "malicious"


def test_pypi_name_is_normalized_like_the_index(cache_with) -> None:
    """정탐 보강: 표기만 다른 이름도 같은 패키지다(PEP 503)."""
    cache_with(_raw("MAL-P", "evil_pkg.name", "PyPI", ranges=[{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]))
    assert _check("Evil-Pkg-Name", eco="pypi")["verdict"] == "malicious"
    assert _check("evil_pkg_name", eco="pypi")["verdict"] == "malicious"


def test_other_ecosystem_with_same_name_is_not_a_hit(cache_with) -> None:
    cache_with(_raw("MAL-N", "gunicorn", "npm", ranges=WHOLE))
    assert _check("gunicorn", eco="pypi", version="21.2.0")["verdict"] != "malicious"
    assert _check("gunicorn", eco="npm", version="1.0.0")["verdict"] == "malicious"


# ---------------------------------------------------------------- 판정 불가: 안전이라고도 악성이라고도 하지 않는다

@pytest.mark.parametrize("version,exact,reason", [(None, True, "version_unpinned"), ("1.6.0", False, "version_range")])
def test_unknown_install_version_is_possible_not_clean(cache_with, version, exact, reason) -> None:
    cache_with(_raw("MAL-A", "axios", versions=["0.30.4", "1.14.1"]))
    r = _check("axios", version=version, exact=exact)
    assert not r["is_malicious_package"] and r["verdict"] != "malicious"
    assert r["malicious_possible"][0]["id"] == "MAL-A" and r["malicious_possible"][0]["reason"] == reason
    assert r["malicious_possible"][0]["versions"] == ["0.30.4", "1.14.1"]
    assert r["requires_review"] is True and "버전을 고정" in r["note"]


def test_old_format_cache_is_possible_with_refresh_hint(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """구형식 캐시(이름만) — 전부 차단하던 것을 '판정 불가 + 재반입 안내'로(결정 D13)."""
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path))
    monkeypatch.setenv("GVSKB_MODE", "offline")
    IntelCache(tmp_path).save("osv-malicious", "u", [{"id": "MAL-O", "summary": "s", "affected": [{"package": "chalk", "ecosystem": "npm"}]}],
                              ecosystems=["npm"])
    r = _check("chalk", version="5.3.0")
    assert not r["is_malicious_package"] and r["malicious_possible"][0]["reason"] == "advisory_without_versions"
    assert "위협정보를 다시 받으세요" in r["note"]


def test_unparsable_version_is_possible() -> None:
    assert _mal_scope({"versions": ["1.0.0"]}, "not a version!!", True)[0] == "possible"
    assert _mal_scope({"whole": True}, "not a version!!", True)[0] == "hit"


# ---------------------------------------------------------------- 게이트

def _report_with(check: dict) -> ScanReport:
    return ScanReport.model_validate({
        "target": ".", "scanned_files": ["a.py"], "skipped_files": [], "findings": [],
        "summary": {"finding_count": 0, "blocked": False, "by_severity": {}, "by_decision": {}},
        "dependency_audit": {"audits": [{"ecosystem": "npm", "manifest": "package.json", "checks": [check]}]},
    })


def test_gate_conditional_for_possible_blocked_for_hit() -> None:
    base = {"name": "axios", "version": None, "ecosystem": "npm", "checked": True, "verdict": "checked_clean", "kev_checked": True}
    g = gate_status(_report_with({**base, "malicious_possible": [{"id": "MAL-A", "versions": ["1.14.1"], "reason": "version_unpinned"}]}))
    assert g["verdict"] == "conditional" and "malicious_possible" in g["conditional_criteria"]
    assert g["malicious_possible"][0]["advisories"] == ["MAL-A"] and "버전을 고정" in g["reason"]
    g = gate_status(_report_with({**base, "version": "1.14.1", "verdict": "malicious", "is_malicious_package": True}))
    assert g["verdict"] == "blocked" and not g["malicious_possible"]


def test_status_reports_cache_format(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from gvskb import diagnostics

    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path))
    assert diagnostics.intel_summary()["mal_versioned"] is None
    cache = IntelCache(tmp_path)
    cache.save("osv-malicious", "u", [{"id": "MAL-O", "affected": [{"package": "x", "ecosystem": "npm"}]}], ecosystems=["npm"])
    assert diagnostics.intel_summary()["mal_versioned"] is False
    cache.save("osv-malicious", "u", [osv._normalize(_raw("MAL-W", "x", ranges=WHOLE))], ecosystems=["npm"])
    assert diagnostics.intel_summary()["mal_versioned"] is True
