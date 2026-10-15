"""36차 — 종료코드·MCP·패키지 미확정이 게이트 결론과 같은 말을 한다 (코덱스 독립 검증 2026-10-15 반영).

35차는 보고서·JSON·포털에는 "조건부·판정 불가"를 전달했지만 **CLI 종료코드와 MCP render_report** 는
예전 규칙(차단이 아니면 소스 발견 수만)을 그대로 써서, 취약 패키지만 있는 조건부·버전 미고정·필수 엔진 실패·
검사 0개가 전부 종료코드 0 이었다. 이 파일이 그 틈을 고정한다.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from gvskb.cli import EXIT_FINDINGS_BLOCK, EXIT_FINDINGS_WARN, EXIT_OK, EXIT_UNDETERMINED, _scan_exit_code
from gvskb.gate import FAIL_ON_CHOICES, gate_status, should_fail
from gvskb.report import render_markdown
from gvskb.scanner import scan_code
from gvskb.schema import EngineUnavailable, ScanReport


def _check(name: str, **kw) -> dict:
    base = {"name": name, "version": "1.0.0", "ecosystem": "pypi", "checked": True,
            "verdict": "checked_clean", "version_resolution": "pinned"}
    base.update(kw)
    return base


def _report(checks: list[dict] | None = None, code: str = "total = 1\n") -> ScanReport:
    r = scan_code(code, filename="a.py")
    if checks is not None:
        r.dependency_audit = {"audits": [{
            "ecosystem": "pypi", "manifest": "requirements.txt", "blocked": False,
            "parsed_count": len(checks), "checked_count": len(checks), "unchecked_count": 0,
            "truncated_count": 0, "checks": checks,
        }]}
    return r


_UNPINNED_CLEAN = _check("flask", version=None, resolved_version="3.1.0",
                         version_resolution="latest-assumed", requires_review=True)
_UNPINNED_CRITICAL = _check("torch", version=None, resolved_version="2.9.0", version_resolution="latest-assumed",
                            verdict="vulnerable", vulnerability_count=1, max_cve="CRITICAL",
                            advisories=[{"id": "GHSA-t", "severity": "CRITICAL"}])
_HIGH_ONLY = _check("hipkg", verdict="vulnerable", vulnerability_count=1, max_cve="HIGH",
                    advisories=[{"id": "GHSA-y", "severity": "HIGH"}])
_UNRESOLVED = _check("mystery", version=None, resolved_version=None, version_resolution="unresolved",
                     verdict="unknown", requires_review=True)


def _engine_failed() -> ScanReport:
    r = _report()
    r.engines.required = ["regex", "python-ast"]
    r.engines.failed = [EngineUnavailable(name="python-ast", reason="crash")]
    return r


def _empty() -> ScanReport:
    r = _report()
    r.scanned_files = []
    return r


# ---------------------------------------------------------------------------
# 종료코드 행렬 — (입력, warn, block, dependency, never)
# ---------------------------------------------------------------------------

_MATRIX = [
    ("clean", lambda: _report(), EXIT_OK, EXIT_OK, EXIT_OK, EXIT_OK),
    ("source-warn", lambda: _report(code="eval(llm_response)\n"), EXIT_FINDINGS_WARN, EXIT_OK, EXIT_OK, EXIT_OK),
    ("high-only", lambda: _report([_HIGH_ONLY]), EXIT_FINDINGS_WARN, EXIT_OK, EXIT_OK, EXIT_OK),
    ("unpinned-clean", lambda: _report([_UNPINNED_CLEAN]), EXIT_FINDINGS_WARN, EXIT_OK, EXIT_OK, EXIT_OK),
    ("unresolved", lambda: _report([_UNRESOLVED]), EXIT_FINDINGS_WARN, EXIT_OK, EXIT_OK, EXIT_OK),
    ("unpinned-critical", lambda: _report([_UNPINNED_CRITICAL]),
     EXIT_FINDINGS_BLOCK, EXIT_FINDINGS_BLOCK, EXIT_FINDINGS_BLOCK, EXIT_OK),
    ("engine-failed", _engine_failed, EXIT_UNDETERMINED, EXIT_UNDETERMINED, EXIT_OK, EXIT_OK),
    ("empty", _empty, EXIT_UNDETERMINED, EXIT_UNDETERMINED, EXIT_OK, EXIT_OK),
]


@pytest.mark.parametrize("name, make, warn, block, dep, never", _MATRIX, ids=[m[0] for m in _MATRIX])
def test_exit_code_matrix(name, make, warn, block, dep, never) -> None:
    r = make()
    assert _scan_exit_code(r, "warn") == warn
    assert _scan_exit_code(r, "block") == block
    assert _scan_exit_code(r, "dependency") == dep
    assert _scan_exit_code(r, "never") == never
    for policy in ("warn", "block", "dependency", "never"):
        assert should_fail(r, policy) == (_scan_exit_code(r, policy) != 0)


def test_exit_code_matches_gate_verdict_everywhere() -> None:
    """종료코드는 게이트 결론의 **번역**이다 — 조건부 1 · 차단 2 · 판정 불가 3."""
    for _, make, *_ in _MATRIX:
        r = make()
        g = gate_status(r)
        code = _scan_exit_code(r, "warn")
        expected = {"approved": 0, "conditional": 1, "blocked": 2, "undetermined": 3}[g["verdict"]]
        assert code == expected, (g["verdict"], code)


def test_fail_on_help_promises_match_code() -> None:
    assert "판정 불가는 3" in FAIL_ON_CHOICES["warn"]
    assert "판정 불가" in FAIL_ON_CHOICES["block"]
    assert "통과" in FAIL_ON_CHOICES["dependency"]


# ---------------------------------------------------------------------------
# 실제 프로세스 — 함수가 아니라 명령의 종료코드
# ---------------------------------------------------------------------------

def _run_cli(*args: str) -> int:
    env = {**os.environ, "GVSKB_UPDATE_CHECK": "off", "PYTHONIOENCODING": "utf-8"}
    src = str(Path(__file__).resolve().parent.parent / "src")
    env["PYTHONPATH"] = src + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run([sys.executable, "-m", "gvskb", *args], capture_output=True, env=env, timeout=120)
    return proc.returncode


def test_real_cli_empty_folder_exits_3_under_warn_and_block(tmp_path: Path) -> None:
    empty = tmp_path / "nothing"
    empty.mkdir()
    assert _run_cli("scan", str(empty), "--format", "json", "--output", str(tmp_path / "o1")) == EXIT_UNDETERMINED
    assert _run_cli("scan", str(empty), "--fail-on", "block", "--format", "json",
                    "--output", str(tmp_path / "o2")) == EXIT_UNDETERMINED
    assert _run_cli("scan", str(empty), "--fail-on", "never", "--format", "json",
                    "--output", str(tmp_path / "o3")) == EXIT_OK


def test_real_cli_clean_folder_exits_0(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("total = 1\n", encoding="utf-8")
    assert _run_cli("scan", str(tmp_path), "--format", "json", "--output", str(tmp_path / "o")) == EXIT_OK


# ---------------------------------------------------------------------------
# MCP render_report — 게이트 결론을 그대로 넘긴다
# ---------------------------------------------------------------------------

def test_mcp_render_report_carries_verdict_requires_action_and_complete() -> None:
    from gvskb.server import render_report

    out = render_report(_engine_failed().model_dump(mode="json"), format="markdown")
    assert out["blocked"] is False
    assert out["verdict"] == "undetermined" and out["requires_action"] is True and out["complete"] is False
    assert "필수 엔진 미가동" in out["coverage_gap"]
    out2 = render_report(_report([_UNPINNED_CLEAN]).model_dump(mode="json"), format="markdown")
    assert out2["verdict"] == "conditional" and out2["conditional_criteria"] == ["unpinned"]


# ---------------------------------------------------------------------------
# 가정 최신판이 취약한 경우 — 차단은 유지, 근거는 분리
# ---------------------------------------------------------------------------

def test_assumed_latest_critical_still_blocks_but_says_so() -> None:
    g = gate_status(_report([_UNPINNED_CRITICAL]))
    assert g["verdict"] == "blocked"
    reason = g["block_reasons"][0]
    assert reason["version"] is None and reason["resolved_version"] == "2.9.0"
    assert reason["version_resolution"] == "latest-assumed"
    assert reason["labels"] == ["CVSS CRITICAL 취약점(미고정 — 가정 최신판 2.9.0 기준)"]
    assert g["dependency_vulnerable_assumed"] == 1 and g["dependency_vulnerable"] == 1
    assert "설치 시점에 들어올 최신판" in g["reason"] and "고정(==)" in g["reason"]
    md = render_markdown(_report([_UNPINNED_CRITICAL]))
    assert "⚠ 개별 취약점 1건(가정 최신판 2.9.0 기준)" in md
    assert "고정(==)" in md.split("## 요약")[0]          # 해소 방안


def test_pinned_critical_keeps_plain_label() -> None:
    pinned = _check("torch", version="2.7.0", verdict="vulnerable", vulnerability_count=1, max_cve="CRITICAL",
                    advisories=[{"id": "GHSA-t", "severity": "CRITICAL"}])
    g = gate_status(_report([pinned]))
    assert g["block_reasons"][0]["labels"] == ["CVSS CRITICAL 취약점"]
    assert g["dependency_vulnerable_assumed"] == 0


# ---------------------------------------------------------------------------
# 버전 미확정(unresolved) — 역대 이력으로 차단하지 않고 검토로
# ---------------------------------------------------------------------------

def test_unresolved_is_conditional_with_unpinned_and_shown_as_undetermined() -> None:
    r = _report([_UNRESOLVED])
    g = gate_status(r)
    assert g["verdict"] == "conditional" and g["conditional_criteria"] == ["unpinned"]
    assert g["unpinned"][0]["version_resolution"] == "unresolved"
    md = render_markdown(r)
    assert "판정 불가(버전 미확정)" in md and "취약점 집계 안 함" in md
    assert "이상 없음(검사 시점)" not in md


# ---------------------------------------------------------------------------
# complete 경계 — 계약 방어
# ---------------------------------------------------------------------------

def test_explicit_coverage_incomplete_is_honoured_even_without_counters() -> None:
    r = _report()
    r.coverage.complete = False
    g = gate_status(r)
    assert g["complete"] is False and g["verdict"] == "undetermined"
    assert "사유 미기록" in g["coverage_gap"]


def test_required_engine_without_any_record_is_a_gap() -> None:
    r = _report()
    r.engines.required = ["regex", "python-ast"]
    r.engines.used = ["regex"]
    g = gate_status(r)
    assert g["complete"] is False and "python-ast(상태 미기록)" in g["coverage_gap"]


def test_optional_engine_without_record_is_not_a_gap() -> None:
    r = _report()
    r.engines.required = ["regex"]
    r.engines.used = ["regex"]                      # semgrep 은 어디에도 없지만 필수가 아니다
    assert gate_status(r)["complete"] is True


def test_empty_folder_is_complete_but_undetermined() -> None:
    """`complete` 하나로 통과를 정하면 안 된다 — 둘을 함께 읽어야 한다."""
    g = gate_status(_empty())
    assert g["complete"] is True and g["verdict"] == "undetermined" and g["requires_action"] is True
