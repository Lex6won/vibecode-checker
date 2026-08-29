"""자기검사 9차 — 보고서가 자기 결과를 정직하게 말하는가(P-1~P-12). 수치는 맞았고
결함은 의미·문구였다: 재현 명령이 --check-deps 를 잃고, HTML 이 .md 경로를 자기
위치라 하고, "비밀값 129건 재발급" 중 98건은 도구가 스스로 낮춘 것이었다.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from gvskb.report import render_html, render_markdown
from gvskb.scanner import scan_code
from gvskb.schema import ScanReport


def _cli(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "gvskb.cli", *args], capture_output=True, text=True,
        env={**os.environ, "PYTHONPATH": "src", "PYTHONUTF8": "1"}, cwd=cwd,
    )


# ── P-1 재현 명령이 JSON 에 실리고, report 경로에서 손실되지 않는다 ──
def test_reproduce_command_survives_json_roundtrip(tmp_path: Path):
    (tmp_path / "app.py").write_text('password = "hunter2plus9"\n', encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("flask==0.12.2\n", encoding="utf-8")
    out = tmp_path / "r.json"
    _cli("scan", str(tmp_path), "--format", "json", "--output", str(out), "--check-deps",
         "--max-files", "700", "--profile", "dev-quick", "--fail-on", "never")
    data = json.loads(out.read_text(encoding="utf-8"))
    assert "--check-deps" in data["reproduce_command"] and "--max-files 700" in data["reproduce_command"]
    html = render_html(ScanReport.model_validate(data))
    assert "--check-deps" in html and "재현 명령 미기록" not in html


def test_legacy_json_without_reproduce_command_says_so():
    rep = scan_code('password = "hunter2plus9"', filename="app.py")
    rep.dependency_audit = {"audits": [{"ecosystem": "pypi", "checks": []}]}
    md = render_markdown(rep)
    assert "재현 명령 미기록" in md and "--check-deps" in md


# ── P-2 자기 위치 ──
def test_html_states_its_own_path_not_the_markdown_twin(tmp_path: Path):
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    _cli("scan", str(tmp_path), "--format", "html", "--output", str(tmp_path / "out" / "r"), "--fail-on", "never")
    html = (tmp_path / "out" / "r.html").read_text(encoding="utf-8")
    md = (tmp_path / "out" / "r.md").read_text(encoding="utf-8")
    assert "r.html" in html.split("이 보고서 위치")[1][:200]
    assert "r.md" in md.split("이 보고서 위치")[1][:200]


# ── P-4 비밀값 집계에서 감쇄분을 가른다 ──
def test_exposure_counts_separate_attenuated():
    from gvskb.gate import _exposure_counts
    code = 'password = "hunter2plus9"\nrrn = "900101-1234567"\n'
    live = scan_code(code, filename="app.py")
    test = scan_code(code, filename="tests/test_app.py")
    a, b = _exposure_counts(live), _exposure_counts(test)
    assert a["secret"] >= 1 and a["secret_live"] == a["secret"] and a["secret_attenuated"] == 0
    assert b["secret"] == a["secret"] and b["secret_live"] == 0 and b["secret_attenuated"] == b["secret"]


def test_verdict_text_does_not_demand_reissue_for_attenuated_only():
    from gvskb.gate import gate_status
    rep = scan_code('password = "hunter2plus9"', filename="tests/test_app.py")
    reason = gate_status(rep)["reason"]
    assert "반드시 재발급" not in reason and "테스트·문서" in reason


# ── P-5 수정 프롬프트 위치 목록은 자르지 않는다 ──
def test_fix_prompt_lists_every_location():
    code = "\n".join(f"x{i} = eval(v{i})" for i in range(12))
    rep = scan_code(code, filename="app.py")
    md = render_markdown(rep)
    block = md.split("수정 프롬프트")[1]
    assert "외 " not in block.split("GOV-CODE-EXEC-001")[1][:400]
    assert "line 12" in block or "12" in block


# ── P-7 룰셋 지문은 항상 병기 ──
def test_criteria_cell_always_carries_digest():
    rep = scan_code("x = 1", filename="app.py")
    rep.ruleset_version, rep.ruleset_digest = "2026.08.29", "abcdef0123456789"
    from gvskb.report import _criteria_cell
    assert "abcdef012345" in _criteria_cell(rep)


# ── P-11 건과 종을 더하지 않는다 ──
def test_summary_does_not_add_count_and_kind():
    rep = scan_code('password = "hunter2plus9"', filename="app.py")
    rep.dependency_audit = {"audits": [{"ecosystem": "pypi", "source_kind": "manifest", "checks": [
        {"name": "flask", "version": "0.12.2", "ecosystem": "pypi", "checked": True, "verdict": "vulnerable",
         "verdict_severity": "high", "vulnerability_count": 2, "max_cve": "HIGH"}]}]}
    md = render_markdown(rep)
    assert "총 조치 대상" not in md or "+" in md.split("총 조치 대상")[1][:60]


# ── P-10 악성 0 이면 '악성'을 말하지 않는다 ──
def test_dep_clause_omits_malicious_when_zero():
    from gvskb.report import _dep_verdict_clause
    rep = scan_code("x = 1", filename="app.py")
    rep.dependency_audit = {"audits": [{"ecosystem": "pypi", "source_kind": "manifest", "checks": [
        {"name": "flask", "version": "0.12.2", "ecosystem": "pypi", "checked": True, "verdict": "vulnerable",
         "verdict_severity": "high", "vulnerability_count": 2, "max_cve": "HIGH"}]}]}
    assert "악성" not in _dep_verdict_clause(rep) and "취약 패키지 1종" in _dep_verdict_clause(rep)
