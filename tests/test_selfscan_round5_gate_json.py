"""자기검사 5차 — 게이트 판정을 JSON 에 싣는다(추가 필드만, 기존 계약 불변).

실측(2026-08-29): 사람용 보고서는 `gate_status()` 결론을 쓰는데 JSON 에는 그 값이
없어, JSON 만 읽는 포털이 `summary.blocked`(소스 기준·legacy)로 폴백했다 — 같은
검사에서 문서와 기계가 다른 답을 냈다.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from gvskb.gate import attach_gate, gate_status
from gvskb.scanner import scan_code, scan_path
from gvskb.schema import ScanReport


def test_summary_counts_unique_locations():
    rep = scan_code("exec(llm_response)\nos.system(cmd)\n", filename="app.py")
    s = rep.summary
    assert s.location_count == len({(f.location.file, f.location.line) for f in rep.findings})
    assert s.block_location_count <= s.location_count
    assert s.finding_count >= s.location_count   # 같은 줄에 GOV+KISA → 건수 ≥ 위치


def test_attach_gate_matches_gate_status():
    rep = scan_code('password = "hunter2plus9"', filename="app.py")
    attach_gate(rep)
    assert rep.gate == gate_status(rep)
    assert rep.gate["verdict"] in {"blocked", "conditional", "approved", "undetermined"}


def test_existing_fields_unchanged_and_gate_optional():
    """기존 소비자가 읽는 필드는 그대로, gate 는 없어도 파싱된다(구버전 JSON 호환)."""
    rep = scan_code("x = 1", filename="app.py")
    d = rep.model_dump(mode="json")
    for k in ("finding_count", "by_severity", "by_decision", "highest_severity", "blocked"):
        assert k in d["summary"]
    d.pop("gate", None)
    assert ScanReport.model_validate(d).gate is None


def test_cli_json_carries_gate(tmp_path: Path):
    (tmp_path / "app.py").write_text('password = "hunter2plus9"\n', encoding="utf-8")
    out = tmp_path / "r.json"
    subprocess.run(
        [sys.executable, "-m", "gvskb.cli", "scan", str(tmp_path), "--format", "json",
         "--output", str(out), "--fail-on", "never"],
        check=True, capture_output=True,
        env={**__import__("os").environ, "PYTHONPATH": "src", "PYTHONUTF8": "1"},
    )
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["gate"]["verdict"] == gate_status(ScanReport.model_validate(data))["verdict"]
    assert "location_count" in data["summary"]


def test_mcp_scan_code_returns_gate():
    from gvskb import server
    d = server.scan_code.fn("x = eval(user_input)", filename="app.py") if hasattr(server.scan_code, "fn") else server.scan_code("x = eval(user_input)", filename="app.py")
    assert d["gate"]["verdict"] in {"blocked", "conditional", "approved", "undetermined"}
    assert d["gate"]["blocked_source"] is True
