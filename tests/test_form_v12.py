"""보안성검토 서식 v1.2 AI체커 8개 항목 결과표(설계 A4) — 검사하지 못한 것을 '적합'으로 쓰지 않는다."""
from __future__ import annotations

from pathlib import Path

from gvskb.form_v12 import ITEMS, NG, OK, REVIEW, UNDETERMINED, form_v12_table
from gvskb.gate import attach_gate
from gvskb.scanner import scan_code, scan_path
from gvskb.schema import ScanReport


def _rows(report: ScanReport) -> dict[str, dict]:
    return {r["key"]: r for r in form_v12_table(report)["items"]}


def _with_deps(report: ScanReport, checks: list[dict], *, mode: str = "local", intel: str = "ok") -> ScanReport:
    report.dependency_audit = {"audits": [{"ecosystem": "pypi", "manifest": "requirements.txt", "checks": checks}]}
    report.dependency_check = {"mode": mode, "intel": {"state": intel}}
    return report


def _clean(name: str, **extra) -> dict:
    return {"name": name, "version": "1.0.0", "ecosystem": "pypi", "checked": True, "verdict": "checked_clean",
            "exists": True, "license_verdict": "allowed",
            "registry_metadata": {"repository_url": "https://example.test/repo"}, **extra}


def test_table_has_the_eight_form_items_in_form_order() -> None:
    t = form_v12_table(scan_code("x = 1\n", filename="a.py"))
    assert [r["label"] for r in t["items"]] == [label for _, label in ITEMS]
    assert len(t["items"]) == 8 and t["version"] == "1"
    assert all(r["result"] in (OK, NG, REVIEW, UNDETERMINED) for r in t["items"])


def test_secret_finding_is_not_ok_and_suppressed_is_not_counted() -> None:
    r = scan_code("API_KEY = 'sk-proj-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE1234'\n", filename="a.py")
    assert _rows(r)["secret"]["result"] in (NG, REVIEW)
    assert _rows(r)["secret"]["rules"]
    for f in r.findings:
        f.suppressed = True
    assert _rows(r)["secret"]["result"] == OK


def test_no_manifest_means_review_not_ok() -> None:
    rows = _rows(scan_code("x = 1\n", filename="a.py"))
    for key in ("public_vuln", "unknown_origin", "malicious_package", "license"):
        assert rows[key]["result"] == REVIEW, key
        assert "의존성 목록" in rows[key]["basis"]


def test_missing_intel_is_undetermined() -> None:
    r = _with_deps(scan_code("x = 1\n", filename="a.py"), [_clean("requests", checked=False)], intel="missing")
    rows = _rows(r)
    assert rows["public_vuln"]["result"] == UNDETERMINED
    assert rows["malicious_package"]["result"] == UNDETERMINED


def test_deps_off_is_undetermined() -> None:
    r = _with_deps(scan_code("x = 1\n", filename="a.py"), [_clean("requests", checked=False)], mode="off")
    assert _rows(r)["public_vuln"]["result"] == UNDETERMINED


def test_local_mode_does_not_claim_origin_or_license() -> None:
    """로컬 모드는 레지스트리를 묻지 않는다 — 실재·라이선스가 비어 있으면 '확인 필요'다."""
    r = _with_deps(scan_code("x = 1\n", filename="a.py"),
                   [_clean("requests", exists=None, license_verdict=None)])
    rows = _rows(r)
    assert rows["unknown_origin"]["result"] == REVIEW and "실재 확인 안 함" in rows["unknown_origin"]["basis"]
    assert rows["license"]["result"] == REVIEW and "조회 안 함" in rows["license"]["basis"]
    assert rows["public_vuln"]["result"] == OK


def test_package_signals_map_to_items() -> None:
    r = _with_deps(scan_code("x = 1\n", filename="a.py"), [
        _clean("goodpkg"),
        _clean("vulnpkg", verdict="vulnerable", vulnerability_count=2),
        _clean("evilpkg", verdict="malicious", is_malicious_package=True),
        _clean("ghostpkg", verdict="not_found", exists=False),
        _clean("gplpkg", license_verdict="review_required"),
        _clean("typopkg", verdict="suspicious_name"),
    ])
    rows = _rows(r)
    assert rows["public_vuln"]["result"] == NG and "vulnpkg" in rows["public_vuln"]["basis"]
    assert rows["malicious_package"]["result"] == NG and "evilpkg" in rows["malicious_package"]["basis"]
    assert rows["unknown_origin"]["result"] == NG and "ghostpkg" in rows["unknown_origin"]["basis"]
    assert rows["license"]["result"] == REVIEW and "gplpkg" in rows["license"]["basis"]
    t = form_v12_table(r)
    assert t["overall"] == NG


def test_suspicious_name_alone_is_review() -> None:
    r = _with_deps(scan_code("x = 1\n", filename="a.py"), [_clean("goodpkg"), _clean("typopkg", verdict="suspicious_name")])
    assert _rows(r)["malicious_package"]["result"] == REVIEW


def test_all_clean_dependencies_are_ok() -> None:
    r = _with_deps(scan_code("x = 1\n", filename="a.py"), [_clean("a"), _clean("b")])
    rows = _rows(r)
    for key in ("public_vuln", "unknown_origin", "malicious_package", "license"):
        assert rows[key]["result"] == OK, key


def test_eol_runtime_is_not_ok(tmp_path: Path) -> None:
    (tmp_path / ".python-version").write_text("3.7\n", encoding="utf-8")
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    rows = _rows(scan_path(tmp_path))
    assert rows["eol"]["result"] in (NG, REVIEW)


def test_attach_gate_stamps_form_v12_and_gate_is_unchanged() -> None:
    r = scan_code("API_KEY = 'sk-proj-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE1234'\n", filename="a.py")
    attach_gate(r)
    assert r.form_v12 and len(r.form_v12["items"]) == 8
    verdict = r.gate["verdict"]
    r.form_v12 = None
    attach_gate(r)
    assert r.gate["verdict"] == verdict


def test_old_json_without_form_v12_still_loads() -> None:
    old = scan_code("x = 1\n", filename="a.py").model_dump(mode="json")
    old.pop("form_v12", None)
    assert ScanReport.model_validate(old).form_v12 is None


def test_ok_basis_never_claims_safety() -> None:
    t = form_v12_table(scan_code("x = 1\n", filename="a.py"))
    for row in t["items"]:
        assert "안전" not in row["basis"] and "위험 없음" not in row["basis"]
    assert "안전 보증이 아닙니다" in t["note"]


def test_eol_without_declared_runtime_is_review_not_ok(tmp_path: Path) -> None:
    """버전을 선언하지 않았으면 지원 종료를 판단할 근거가 없다 — 적합이 아니다."""
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    assert _rows(scan_path(tmp_path))["eol"]["result"] == REVIEW


def test_eol_with_supported_runtime_is_ok_and_pins_are_recorded(tmp_path: Path) -> None:
    (tmp_path / ".python-version").write_text("3.13\n", encoding="utf-8")
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    r = scan_path(tmp_path)
    assert r.runtime_pins and r.runtime_pins[0]["runtime"] == "python"
    row = _rows(r)["eol"]
    assert row["result"] == OK and "python 3.13" in row["basis"]


def test_possible_malicious_is_not_ok() -> None:
    r = _with_deps(scan_code("x = 1\n", filename="a.py"), [
        _clean("axios", version=None, malicious_possible=[{"id": "MAL-1", "versions": ["1.14.1"], "reason": "version_unpinned"}])])
    assert _rows(r)["malicious_package"]["result"] == REVIEW


def test_missing_repository_url_is_review_when_registry_was_queried() -> None:
    r = _with_deps(scan_code("x = 1\n", filename="a.py"), [_clean("norepo", registry_metadata={"repository_url": None})], mode="online")
    row = _rows(r)["unknown_origin"]
    assert row["result"] == REVIEW and "norepo" in row["basis"]
    r = _with_deps(scan_code("x = 1\n", filename="a.py"), [_clean("withrepo", registry_metadata={"repository_url": "https://example.test/r"})], mode="online")
    assert _rows(r)["unknown_origin"]["result"] == OK
