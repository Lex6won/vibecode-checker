"""게이트 판정 — 소스와 의존성을 나누고, 답을 한 곳에서만 낸다.

## 이 파일이 막는 실측 결함

`ScanSummary.blocked` 은 **소스 발견만** 보고 정해진다(의존성 감사는 스캔이
끝난 뒤에 붙는다). 그런데 CLI 종료코드와 MCP `render_report` 가 그 값을 그대로
읽고 있었다. 결과:

    CRITICAL 취약 패키지 있음
      보고서 본문        → "배포 불가 — 차단 기준에 걸린 패키지가 있습니다"
      summary.blocked    → False
      MCP `blocked`      → False
      CLI --fail-on block → 종료코드 0 (통과)

**같은 문서가 사람에게는 막으라고 하고 기계에게는 통과라고 답했다.**
라운드 9에서 남의 하네스에서 찾아낸 *"게이트가 없는 필드를 읽음"* 이
우리 쪽에 그대로 있었다.

## 왜 나누는가

라운드 13의 판단 전환 — **"소스는 보조, 의존성은 게이트"**. 둘을 한 플래그로
묶으면 소스 오탐 하나 때문에 팀이 게이트를 통째로 끄고, 그러면 **오탐이 거의
없는 의존성 차단까지 함께 꺼진다.**
"""
from __future__ import annotations

import pytest

from gvskb.cli import _scan_exit_code
from gvskb.gate import gate_status, should_fail
from gvskb.scanner import scan_code

_SOURCE_BLOCK = "eval(llm_response)\n"        # GOV-LLM-OUTPUT-HANDLING-001 (block)
_CLEAN = "total = sum(x.price for x in items)\n"


def _dep_audit(*, blocked: bool = True, vuln: int = 1, unchecked: int = 0) -> dict:
    checks = [{"name": f"pkg{i}", "verdict": "vulnerable",
               "max_cve_severity": "CRITICAL", "vulnerability_count": 3}
              for i in range(vuln)]
    checks += [{"name": f"unk{i}", "verdict": "error"} for i in range(unchecked)]
    return {"audits": [{
        "blocked": blocked, "parsed_count": len(checks) or 1,
        "checked_count": len(checks), "unchecked_count": unchecked,
        "truncated_count": 0, "checks": checks,
    }]}


def _report(code: str = _CLEAN, *, filename: str = "a.py", dep: dict | None = None):
    r = scan_code(code, filename=filename)
    if dep is not None:
        r.dependency_audit = dep
    return r


# ---------------------------------------------------------------------------
# 핵심 결함 — 의존성 차단이 게이트에 닿는가
# ---------------------------------------------------------------------------

def test_dependency_block_reaches_the_gate() -> None:
    """`summary.blocked` 는 여전히 False 다(소스만 보므로) — 그런데도 게이트는
    막아야 한다. 이 둘이 갈리는 지점이 정확히 결함이 살던 자리다."""
    report = _report(dep=_dep_audit())
    assert report.summary.blocked is False, "전제가 바뀌었다면 이 테스트를 다시 써야 한다"

    status = gate_status(report)
    assert status["blocked"] is True
    assert status["blocked_dependency"] is True
    assert status["blocked_source"] is False


def test_cli_exit_code_fails_on_dependency_block() -> None:
    """예전에는 여기서 0 이 나왔다 — 보고서는 '배포 불가'인데 CI 는 초록불."""
    report = _report(dep=_dep_audit())
    assert _scan_exit_code(report, "block") != 0
    assert _scan_exit_code(report, "warn") != 0
    assert _scan_exit_code(report, "never") == 0


def test_mcp_render_report_exposes_split_gate() -> None:
    """하네스가 읽는 필드. `blocked` 만 고치고 분해값을 안 주면 연동 상대는
    여전히 '소스 오탐 때문에 막혔나 패키지 때문인가'를 알 수 없다."""
    from gvskb.server import render_report

    report = _report(dep=_dep_audit())
    out = render_report(report.model_dump(mode="json"), format="markdown")
    assert out["blocked"] is True
    assert out["blocked_dependency"] is True
    assert out["blocked_source"] is False
    assert "패키지" in out["gate_reason"]


# ---------------------------------------------------------------------------
# --fail-on dependency — "소스는 보조, 의존성은 게이트" 를 실제 스위치로
# ---------------------------------------------------------------------------

def test_fail_on_dependency_ignores_source_findings() -> None:
    """소스 룰은 추론이라 맥락을 탄다. 오탐 하나 때문에 게이트를 통째로 끄는
    대신, 의존성만 막는 선택지를 준다."""
    report = _report(_SOURCE_BLOCK, filename="a.js")
    assert gate_status(report)["blocked_source"] is True
    assert _scan_exit_code(report, "block") != 0
    assert _scan_exit_code(report, "dependency") == 0


def test_fail_on_dependency_still_fails_on_packages() -> None:
    """소스를 무시한다고 의존성까지 무시하면 그냥 게이트를 끈 것이다."""
    report = _report(dep=_dep_audit())
    assert _scan_exit_code(report, "dependency") != 0


def test_fail_on_dependency_passes_a_clean_project() -> None:
    assert _scan_exit_code(_report(dep=_dep_audit(blocked=False, vuln=0)), "dependency") == 0


# ---------------------------------------------------------------------------
# 기존 계약을 느슨하게 만들지 않았는가
# ---------------------------------------------------------------------------

def test_source_only_block_still_blocks() -> None:
    """의존성을 분리하면서 소스 차단이 새면 게이트를 연 것이다."""
    report = _report(_SOURCE_BLOCK, filename="a.js")
    status = gate_status(report)
    assert status["blocked"] is True and status["blocked_dependency"] is False
    assert _scan_exit_code(report, "block") != 0


def test_clean_project_is_not_blocked() -> None:
    status = gate_status(_report())
    assert status["blocked"] is False
    assert status["reason"] == "차단 없음."
    assert _scan_exit_code(_report(), "block") == 0


def test_suppressed_findings_do_not_block() -> None:
    """승인된 예외는 게이트를 통과시키되 발견은 남긴다 — 기존 계약."""
    report = _report(_SOURCE_BLOCK, filename="a.js")
    report.findings = [f.model_copy(update={"suppressed": True}) for f in report.findings]
    report.summary = report.summary.model_copy(update={"blocked": False})
    assert gate_status(report)["blocked_source"] is False


# ---------------------------------------------------------------------------
# 판정 불가를 '안전'으로 읽지 않게
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("code, filename", [(_CLEAN, "a.py"), (_SOURCE_BLOCK, "a.js")])
def test_unchecked_packages_are_named_in_the_reason(code: str, filename: str) -> None:
    """판정 불가는 안전이 아니다. 차단 사유 문장에서 그 사실이 사라지면,
    담당자는 '차단 없음'만 읽고 넘어간다."""
    report = _report(code, filename=filename,
                     dep=_dep_audit(blocked=False, vuln=0, unchecked=2))
    reason = gate_status(report)["reason"]
    assert "판정 불가" in reason and "안전" in reason, reason


def test_both_blocked_says_fixing_source_alone_is_not_enough() -> None:
    report = _report(_SOURCE_BLOCK, filename="a.js", dep=_dep_audit())
    status = gate_status(report)
    assert status["blocked_source"] and status["blocked_dependency"]
    assert "소스만 고치면" in status["reason"]


def test_should_fail_matches_exit_code_for_every_policy() -> None:
    """두 곳에서 정책을 따로 해석하면 언젠가 갈라진다 — 같은 답인지 고정한다."""
    cases = [
        _report(),
        _report(_SOURCE_BLOCK, filename="a.js"),
        _report(dep=_dep_audit()),
        _report(_SOURCE_BLOCK, filename="a.js", dep=_dep_audit()),
    ]
    for report in cases:
        for policy in ("never", "warn", "block", "dependency"):
            assert should_fail(report, policy) == (_scan_exit_code(report, policy) != 0), (
                policy, report.target)
