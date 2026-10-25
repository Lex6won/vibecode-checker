"""41차 D3 — 끝까지 e2e: 위험 구조 저장소 → CLI 종료코드 → JSON gate → 하네스·포털 표 매핑.

판정 표기 차이는 **설계**다(B6):
- 체커 CLI: 종료코드 1 = 조건부(소스 발견은 게이트를 막지 않는다)
- 하네스(.vibecode-harness/lib/checker-evidence.mjs): 0 이 아니면 `checker_status: "blocked"`(3 은 undetermined),
  `final_verdict` 는 언제나 `review_required` — 하네스는 승인하지 않는다
- 포털(src/scan-summary.mjs GATE_VERDICT_TO_DECISION): conditional → `needs_review`
같은 결과를 "개발 PC 에서는 막혔는데 포털에서는 검토"로 보는 것은 버그가 아니다.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
HOLDOUT = REPO / "eval_corpus" / "projects" / "j_agentic_2026"
PORTAL = REPO.parent / "vibecode-security-gate-portal" / "src" / "scan-summary.mjs"
HARNESS = REPO.parent / ".vibecode-harness" / "lib" / "checker-evidence.mjs"

#: 포털 계약 — 체커가 내는 verdict 와 포털 화면 판정. 새 verdict 값을 만들지 않는 이유(표 밖은 incomplete).
PORTAL_VERDICT_TO_DECISION = {"blocked": "blocked", "conditional": "needs_review",
                              "undetermined": "incomplete", "approved": "allow"}


def _run_cli(target: Path, out: Path, *extra: str) -> subprocess.CompletedProcess:
    env = dict(os.environ, GVSKB_MODE="offline", PYTHONPATH=str(REPO / "src"), GVSKB_TODAY="2026-10-25")
    return subprocess.run([sys.executable, "-m", "gvskb.cli", "scan", str(target), "--format", "json",
                           "--output", str(out), *extra], capture_output=True, text=True, encoding="utf-8",
                          errors="replace", env=env, cwd=str(REPO))


@pytest.mark.parametrize("root", ["t01_ide_task_chain", "t06_ci_workflows", "t09_cli_abuse"])
def test_risky_structure_exits_conditional_and_gate_says_so(tmp_path: Path, root: str) -> None:
    out = tmp_path / "r.json"
    proc = _run_cli(HOLDOUT / root, out)
    assert proc.returncode == 1, proc.stderr[-800:]
    data = json.loads(out.read_text(encoding="utf-8"))
    gate = data["gate"]
    assert gate["verdict"] == "conditional" and gate["blocked"] is False
    assert "source" in gate["conditional_criteria"]
    assert gate["blocked_source"] is True, "소스에 block 등급 발견이 있다는 **사실**은 남는다"
    assert PORTAL_VERDICT_TO_DECISION[gate["verdict"]] == "needs_review"


def test_fail_on_block_lets_conditional_pass(tmp_path: Path) -> None:
    proc = _run_cli(HOLDOUT / "t01_ide_task_chain", tmp_path / "r.json", "--fail-on", "block")
    assert proc.returncode == 0, proc.stderr[-800:]


def test_clean_twin_is_approved(tmp_path: Path) -> None:
    out = tmp_path / "r.json"
    proc = _run_cli(HOLDOUT / "n01_clean_ide", out)
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["gate"]["verdict"] == "approved" and proc.returncode == 0, data["gate"]["reason"]


@pytest.mark.skipif(not PORTAL.exists(), reason="포털 저장소가 옆에 없음(CI)")
def test_portal_mapping_table_matches_contract() -> None:
    text = PORTAL.read_text(encoding="utf-8")
    block = re.search(r"GATE_VERDICT_TO_DECISION\s*=\s*Object\.freeze\(\{(.*?)\}\)", text, re.S).group(1)
    table = dict(re.findall(r"(\w+):\s*\"(\w+)\"", block))
    assert table == PORTAL_VERDICT_TO_DECISION


@pytest.mark.skipif(not HARNESS.exists(), reason="하네스가 옆에 없음(CI)")
def test_harness_calls_nonzero_exit_blocked_by_design() -> None:
    text = HARNESS.read_text(encoding="utf-8")
    assert 'exitCode === 0 ? "review_required" : exitCode === 3 ? "undetermined" : "blocked"' in text
    assert 'final_verdict: "review_required"' in text
