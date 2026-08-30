"""승인된 예외(.gvskb-exceptions.yaml) — 게이트 통과 + 기록 유지 + 만료 자동 복귀."""
from __future__ import annotations

import json
from pathlib import Path

from gvskb.report import render_html, render_markdown, render_sarif
from gvskb.scanner import scan_path

_VULN = 'import os\nos.system("cp /data/" + fname)\n'


def _write_project(tmp_path: Path, exceptions_yaml: str | None) -> Path:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "app.py").write_text(_VULN, encoding="utf-8")
    if exceptions_yaml is not None:
        (proj / ".gvskb-exceptions.yaml").write_text(exceptions_yaml, encoding="utf-8")
    return proj


def _valid_exception(rule_id: str = "GOV-CMD-INJECTION-001", expires: str = "2099-12-31") -> str:
    return (
        "exceptions:\n"
        f"  - rule_id: {rule_id}\n"
        "    file: app.py\n"
        "    reason: 내부 배치 전용 — 외부 입력 없음\n"
        "    approved_by: 김보안(정보보안담당관)\n"
        f"    expires: {expires}\n"
    )


def test_no_exceptions_file_changes_nothing(tmp_path: Path) -> None:
    report = scan_path(_write_project(tmp_path, None))
    assert report.summary.blocked is True
    assert report.suppression_summary is None
    assert all(not f.suppressed for f in report.findings)


def test_valid_exception_unblocks_but_keeps_finding(tmp_path: Path) -> None:
    report = scan_path(_write_project(tmp_path, _valid_exception()))
    sup = [f for f in report.findings if f.suppressed]
    assert sup, "매칭된 발견이 suppressed 표시돼야 한다"
    assert all("GOV-CMD-INJECTION-001" in (f.rule_id, *f.also_matched) for f in sup)
    assert "김보안" in (sup[0].suppress_reason or "")
    # 요약·차단 판정은 비억제 기준. (S-8 이후 KISA-PY-INPUT-05 는 같은 발견의 also_matched 다.)
    assert report.summary.finding_count == len([f for f in report.findings if not f.suppressed])
    assert report.suppression_summary["applied"] >= 1


def test_all_findings_suppressed_clears_gate(tmp_path: Path) -> None:
    # 같은 줄을 잡는 두 룰 모두 예외 처리하면 게이트(blocked)가 풀린다.
    yaml_text = _valid_exception() + (
        "  - rule_id: KISA-PY-INPUT-05\n"
        "    file: app.py\n"
        "    reason: 내부 배치 전용 — 외부 입력 없음\n"
        "    approved_by: 김보안(정보보안담당관)\n"
        "    expires: 2099-12-31\n"
    )
    report = scan_path(_write_project(tmp_path, yaml_text))
    assert report.summary.blocked is False
    assert report.summary.finding_count == 0
    # S-8 병합 후 같은 줄의 두 룰은 발견 1건(근거 룰 2개)이다 — 기록은 유지.
    assert len([f for f in report.findings if f.suppressed]) >= 1


def test_expired_exception_is_ignored_and_reported(tmp_path: Path) -> None:
    report = scan_path(_write_project(tmp_path, _valid_exception(expires="2020-01-01")))
    assert report.summary.blocked is True  # 만료 → 다시 차단
    assert all(not f.suppressed for f in report.findings)
    assert report.suppression_summary["expired"], "만료 예외가 리포트로 전달돼야 한다"
    md = render_markdown(report)
    assert "만료된 예외" in md


def test_missing_required_fields_invalidates_exception(tmp_path: Path) -> None:
    yaml_text = (
        "exceptions:\n"
        "  - rule_id: GOV-CMD-INJECTION-001\n"
        "    file: app.py\n"
        "    reason: 사유만 있고 승인자·만료 없음\n"
    )
    report = scan_path(_write_project(tmp_path, yaml_text))
    assert report.summary.blocked is True  # 무효 예외는 억제하지 않는다
    assert report.suppression_summary["invalid"]


def test_report_renders_suppression_section_and_active_stats(tmp_path: Path) -> None:
    report = scan_path(_write_project(tmp_path, _valid_exception()))
    md = render_markdown(report)
    html = render_html(report)
    for out in (md, html):
        assert "승인된 예외" in out
        assert "김보안" in out
        assert "GOV-CMD-INJECTION-001" in out  # 사라지지 않고 내역에 남는다


def test_sarif_marks_suppressions(tmp_path: Path) -> None:
    report = scan_path(_write_project(tmp_path, _valid_exception()))
    sarif = render_sarif(report)
    blob = json.dumps(sarif, ensure_ascii=False)
    assert '"suppressions"' in blob
    supp = [r for r in sarif["runs"][0]["results"] if r.get("suppressions")]
    assert supp and supp[0]["suppressions"][0]["kind"] == "external"


def test_audit_records_approve_bypass(tmp_path: Path, monkeypatch) -> None:
    audit_dir = tmp_path / "audit"
    monkeypatch.setenv("GVSKB_AUDIT_DIR", str(audit_dir))
    scan_path(_write_project(tmp_path, _valid_exception()))
    raw = list(audit_dir.glob("audit-*.jsonl"))[0].read_text(encoding="utf-8")
    events = [json.loads(line) for line in raw.strip().splitlines()]
    bypass = [e for e in events if e["event_type"] == "approve_bypass"]
    assert bypass, "억제 적용은 approve_bypass 감사 이벤트로 남아야 한다"
    assert "김보안" in bypass[0]["redacted_evidence"]
