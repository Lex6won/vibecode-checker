"""변이 시험에서 생존한 경계 — 빠져도 다른 테스트가 잡지 못하던 판정과 표시를 고정한다."""
from __future__ import annotations

from pathlib import Path

import pytest

from gvskb.form_v12 import NG, REVIEW, form_v12_table
from gvskb.gate import gate_status
from gvskb.report import render_html, render_markdown
from gvskb.sbom import to_cyclonedx
from gvskb.sbom_html import render_sbom_html
from gvskb.scanner import scan_code, scan_path
from gvskb.schema import ScanReport, ScanSummary
from gvskb.tools.check_package import _apply_mal_possible, _mal_scope


def _rows(report: ScanReport) -> dict[str, dict]:
    return {r["key"]: r for r in form_v12_table(report)["items"]}


# ── SBOM HTML 이스케이프 ───────────────────────────────────────────────
def _doc(**component) -> dict:
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {"component": {"name": "app", "bom-ref": "app"}},
            "components": [{"type": "library", "name": "x", "version": "1", "bom-ref": "pkg:npm/x@1", **component}]}


@pytest.mark.parametrize("url", ["javascript:alert(1)", "JaVaScRiPt:alert(1)", "data:text/html,x", " javascript:alert(1)"])
def test_sbom_html_drops_dangerous_urls(url: str) -> None:
    html = render_sbom_html(_doc(externalReferences=[{"type": "website", "url": url}]), source_name="s.json", source_sha256="0")
    assert f'href="{url}"' not in html


def test_sbom_html_keeps_https_urls() -> None:
    html = render_sbom_html(_doc(externalReferences=[{"type": "website", "url": "https://example.test/a"}]), source_name="s.json", source_sha256="0")
    assert 'href="https://example.test/a"' in html


def test_sbom_html_escapes_attribute_quotes() -> None:
    html = render_sbom_html(_doc(name='x" onmouseover="alert(1)'), source_name="s.json", source_sha256="0")
    assert 'x" onmouseover="alert(1)' not in html.split('<script id="sbom-data"')[0]


def test_sbom_html_json_block_cannot_close_script() -> None:
    html = render_sbom_html(_doc(name="</script><script>alert(1)</script>&>"), source_name="s.json", source_sha256="0")
    block = html.split('<script id="sbom-data" type="application/json">')[1].split("</script>")[0]
    assert not any(ch in block for ch in "<>&")


# ── 판정 ──────────────────────────────────────────────────────────────
def test_unparsed_version_never_reads_as_miss() -> None:
    assert _mal_scope({"versions": ["1.0.0"]}, "not-a-version", True, recognized=True) == ("possible", "version_unparsed")
    assert _mal_scope({"versions": ["1.0.0"]}, "not-a-version", True, recognized=False) == ("hit", "version_unparsed")


def test_possible_raises_review_and_severity() -> None:
    out = _apply_mal_possible({"verdict": "checked_clean", "verdict_severity": "info", "note": "악성 등록 없음", "malicious_possible": [{"id": "MAL-1", "reason": "version_unpinned", "versions": ["1.0.0"]}]})
    assert out["requires_review"] is True and out["verdict_severity"] == "medium" and "MAL-1" in out["note"] and "1.0.0" in out["note"]


def _dep_report(check: dict) -> ScanReport:
    summary = ScanSummary(finding_count=0, by_severity={}, by_decision={})
    return ScanReport(target=".", scanned_files=["a.py"], summary=summary, findings=[],
                      dependency_audit={"audits": [{"ecosystem": "npm", "checks": [check]}]})


def test_gate_reports_possible_as_conditional_and_report_shows_action() -> None:
    report = _dep_report({"name": "chalk", "version": "5", "checked": True, "verdict": "checked_clean", "malicious_possible": [{"id": "MAL-1", "versions": ["5.6.1"]}]})
    gate = gate_status(report)
    assert gate["verdict"] == "conditional" and "malicious_possible" in gate["conditional_criteria"]
    assert gate["malicious_possible"][0]["versions"] == ["5.6.1"]
    report.gate = gate
    text = render_markdown(report)
    assert "`chalk`" in text and "공식 저장소에서 정상 패키지인지 확인하고 다시 검사하세요" in text, "the next-action line must be there"


def test_sbom_carries_possible_and_malicious_properties() -> None:
    report = _dep_report({"name": "chalk", "version": "5.3.0", "ecosystem": "npm", "checked": True, "verdict": "checked_clean", "malicious_possible": [{"id": "MAL-1"}]})
    doc = to_cyclonedx(report.dependency_audit, name="app")
    names = {p["name"]: p["value"] for p in doc["components"][0].get("properties", [])}
    assert "MAL-1" in names["gvskb:malicious_possible"]
    evil = _dep_report({"name": "evil", "version": "1.0.0", "ecosystem": "npm", "checked": True, "verdict": "malicious", "is_malicious_package": True})
    names = {p["name"]: p["value"] for p in to_cyclonedx(evil.dependency_audit, name="app")["components"][0].get("properties", [])}
    assert names["gvskb:is_malicious_package"] == "true"


# ── 서식 ──────────────────────────────────────────────────────────────
def test_suppressed_findings_are_not_counted() -> None:
    report = scan_code('API_KEY = "AKIAABCDEFGHIJKLMNOP"\n', filename="a.py")
    assert _rows(report)["secret"]["result"] in (NG, REVIEW)
    for finding in report.findings:
        finding.suppressed = True
    assert _rows(report)["secret"]["count"] == 0


def test_live_block_finding_is_ng_and_attenuated_is_review() -> None:
    report = scan_code('API_KEY = "AKIAABCDEFGHIJKLMNOP"\n', filename="a.py")
    secrets = [f for f in report.findings if f.category == "secret-scanning"]
    assert secrets, "fixture must produce a secret finding"
    for finding in secrets:
        finding.decision = type(finding.decision).block
        finding.severity_adjusted = None
    assert _rows(report)["secret"]["result"] == NG
    for finding in secrets:
        finding.severity_adjusted = "test-path"
    assert _rows(report)["secret"]["result"] == REVIEW


def test_pii_category_reaches_its_row() -> None:
    report = scan_code('resident = "901231-1234567"\n', filename="a.py")
    if any(f.category == "privacy-public-sector" for f in report.findings):
        assert _rows(report)["pii"]["result"] in (NG, REVIEW)
    else:
        pytest.skip("이 표기를 잡는 개인정보 룰이 이 언어에 없음")


def test_malicious_code_category_reaches_its_row(tmp_path: Path) -> None:
    # 숨은 문자는 hidden-code 범주다.
    (tmp_path / "a.py").write_text("x = 1  # \u202e숨은 방향 문자\n", encoding="utf-8")
    report = scan_path(str(tmp_path))
    hidden = [f for f in report.findings if f.category == "hidden-code"]
    assert hidden, "fixture must produce a hidden-code finding"
    for finding in report.findings:   # 범주만으로 올라와야 한다(실행 계열 CWE 경로와 구분)
        finding.cwe = []
    row = _rows(report)["malicious_code"]
    assert row["result"] in (NG, REVIEW), row
    assert hidden[0].rule_id in row["rules"]


def test_missing_repository_url_only_when_registry_answered(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    report = scan_path(str(tmp_path))
    report.dependency_audit = {"audits": [{"ecosystem": "pypi", "checks": [
        {"name": "a", "version": "1.0.0", "checked": True, "verdict": "checked_clean", "exists": True, "registry_metadata": {"repository_url": None}}]}]}
    report.dependency_check = {"mode": "online", "intel": {"state": "ok"}, "packages_parsed": 1}
    assert "소스 저장소 주소가 없는" in _rows(report)["unknown_origin"]["basis"]


@pytest.mark.parametrize("path,text,expected", [
    (".nvmrc", "24\n", "node 24"),
    ("package.json", '{"name":"a","engines":{"node":">=22"}}', "node >=22"),
    (".github/workflows/ci.yml", "jobs:\n  a:\n    steps:\n      - uses: actions/setup-python@v5\n        with:\n          python-version: '3.12'\n", "python 3.12"),
    ("Dockerfile", "FROM python:3.12-slim\n", "python 3.12-slim"),
])
def test_every_surface_records_runtime_pins(path: str, text: str, expected: str, tmp_path: Path) -> None:
    target = tmp_path / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    report = scan_path(str(tmp_path))
    assert expected in {f'{p["runtime"]} {p["spec"]}' for p in report.runtime_pins}


def test_report_renders_form_table_and_skips_empty_table(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    report = scan_path(str(tmp_path))
    report.form_v12 = form_v12_table(report)
    assert "AI 체커 점검 항목" in render_markdown(report) and "AI 체커 점검 항목" in render_html(report)
    report.form_v12 = {"items": []}
    assert "AI 체커 점검 항목" not in render_markdown(report)
    assert render_html(report)
