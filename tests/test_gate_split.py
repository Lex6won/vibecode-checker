"""게이트 판정 — 차단 / 조건부 승인 / 승인, 그리고 답은 한 곳에서만 낸다.

## 이 파일이 막는 실측 결함 ①

`ScanSummary.blocked` 은 **소스 발견만** 보고 정해진다(의존성 감사는 스캔이
끝난 뒤에 붙는다). 그런데 CLI 종료코드와 MCP `render_report` 가 그 값을 그대로
읽고 있었다. 결과:

    CRITICAL 취약 패키지 있음
      보고서 본문        → "배포 불가"
      summary.blocked    → False
      MCP `blocked`      → False
      CLI --fail-on block → 종료코드 0 (통과)

**같은 문서가 사람에게는 막으라고 하고 기계에게는 통과라고 답했다.**

## 이 파일이 막는 실측 결함 ② (2026-08-09 개정)

예전 기준은 **CVSS HIGH 하나라도 있으면 차단**이었다. 실측 4개 저장소가 전부
차단됐고 근거는 **100% `high` 하나** — 악성 0, KEV 0, CRITICAL 0. 가장 강한
신호 셋은 한 번도 발동한 적이 없는데 결과는 같았다.

    차단이 예외가 아니라 기본값이 되면, 그것은 더 이상 신호가 아니다.

게다가 `xlsx 0.18.5` 처럼 **수정본이 없는** 패키지가 막으면 담당자는 게이트를
만족시킬 방법이 없다. 만족시킬 수 없는 게이트는 우회되거나 꺼진다.

그래서 셋으로 나눴다 — 차단은 **악성 · 기관 거부 · 미존재 · CISA KEV ·
CVSS CRITICAL** 다섯뿐이고, 나머지는 전부 조건부 승인이다. 소스 발견도
조건부다(**소스는 보조, 의존성은 게이트**).
"""
from __future__ import annotations

import pytest

from gvskb.cli import _scan_exit_code
from gvskb.gate import gate_status, should_fail
from gvskb.scanner import scan_code

_SOURCE_BLOCK = "eval(llm_response)\n"        # GOV-LLM-OUTPUT-HANDLING-001 (block)
_CLEAN = "total = sum(x.price for x in items)\n"


def _pkg(name: str, **kw) -> dict:
    base = {"name": name, "version": "1.0.0", "ecosystem": "npm", "checked": True}
    base.update(kw)
    return base


def _audit(checks: list[dict], *, unchecked: int = 0, blocked: bool = False) -> dict:
    checks = list(checks) + [_pkg(f"unk{i}", verdict="error", checked=False)
                             for i in range(unchecked)]
    return {"audits": [{
        # 감사 자신의 `blocked` 는 **게이트가 읽지 않는다** — 게이트는 컴포넌트
        # 근거를 직접 본다. 이 값이 True 여도 근거가 없으면 차단되지 않아야 한다.
        "blocked": blocked, "parsed_count": len(checks) or 1,
        "checked_count": len(checks) - unchecked, "unchecked_count": unchecked,
        "truncated_count": 0, "checks": checks,
    }]}


#: 차단이어야 하는 다섯 가지.
_BLOCKING = {
    "악성 패키지": _pkg("evil", is_malicious_package=True, vulnerability_count=1),
    "기관 레지스트리 거부": _pkg("nope", verdict="registry_rejected", vulnerability_count=1),
    "레지스트리에 없는 이름": _pkg("ghost", verdict="not_found"),
    "CISA KEV 등재": _pkg("kevpkg", in_kev=True, vulnerability_count=1),
    "CVSS CRITICAL": _pkg("critpkg", vulnerability_count=1, max_cve="CRITICAL",
                          advisories=[{"id": "GHSA-x", "severity": "CRITICAL"}]),
}

#: 조건부여야 하는 것들.
_CONDITIONAL = {
    "CVSS HIGH": _pkg("hipkg", vulnerability_count=1, max_cve="HIGH",
                      advisories=[{"id": "GHSA-y", "severity": "HIGH"}]),
    "CVSS MEDIUM": _pkg("medpkg", vulnerability_count=1, max_cve="MEDIUM",
                        advisories=[{"id": "GHSA-z", "severity": "MEDIUM"}]),
    "쿨다운 보류": _pkg("newpkg", verdict="cooldown_hold"),
}


def _report(code: str = _CLEAN, *, filename: str = "a.py", dep: dict | None = None):
    r = scan_code(code, filename=filename)
    if dep is not None:
        r.dependency_audit = dep
    return r


# ---------------------------------------------------------------------------
# 결함 ① — 의존성 차단이 게이트에 닿는가
# ---------------------------------------------------------------------------

def test_dependency_block_reaches_the_gate() -> None:
    """`summary.blocked` 는 여전히 False 다(소스만 보므로) — 그런데도 게이트는
    막아야 한다. 이 둘이 갈리는 지점이 정확히 결함이 살던 자리다."""
    report = _report(dep=_audit([_BLOCKING["CVSS CRITICAL"]]))
    assert report.summary.blocked is False, "전제가 바뀌었다면 이 테스트를 다시 써야 한다"

    status = gate_status(report)
    assert status["verdict"] == "blocked"
    assert status["blocked"] is True
    assert status["blocked_dependency"] is True


def test_cli_exit_code_fails_on_dependency_block() -> None:
    """예전에는 여기서 0 이 나왔다 — 보고서는 '배포 불가'인데 CI 는 초록불."""
    report = _report(dep=_audit([_BLOCKING["악성 패키지"]]))
    assert _scan_exit_code(report, "block") != 0
    assert _scan_exit_code(report, "warn") != 0
    assert _scan_exit_code(report, "never") == 0


def test_mcp_render_report_exposes_the_verdict() -> None:
    """하네스가 읽는 필드. `blocked` 만 주고 판정을 안 주면 연동 상대는
    '차단인가 조건부인가'를 구분할 수 없다."""
    from gvskb.server import render_report

    report = _report(dep=_audit([_BLOCKING["CISA KEV 등재"]]))
    out = render_report(report.model_dump(mode="json"), format="markdown")
    assert out["blocked"] is True
    assert out["blocked_dependency"] is True
    assert "KEV" in out["gate_reason"]


# ---------------------------------------------------------------------------
# 결함 ② — 사다리: 차단은 다섯 가지뿐
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("label", sorted(_BLOCKING))
def test_only_these_five_block(label: str) -> None:
    status = gate_status(_report(dep=_audit([_BLOCKING[label]])))
    assert status["verdict"] == "blocked", label
    assert any(label.split()[0] in " ".join(r["labels"]) or r["criteria"]
               for r in status["block_reasons"])


@pytest.mark.parametrize("label", sorted(_CONDITIONAL))
def test_everything_else_is_conditional(label: str) -> None:
    """**만족시킬 수 없는 게이트는 우회된다.** HIGH·MEDIUM·쿨다운은 사람이 판단한다."""
    status = gate_status(_report(dep=_audit([_CONDITIONAL[label]])))
    assert status["verdict"] == "conditional", label
    assert status["blocked"] is False
    assert status["requires_action"] is True, "조건부는 '할 일 없음'이 아니다"


def test_audit_self_declared_block_does_not_bypass_the_criteria() -> None:
    """감사가 `blocked: True` 라고 해도 **근거가 없으면 차단하지 않는다.**

    예전에는 이 플래그 하나를 그대로 읽어 HIGH 만으로도 막았다. 판정 기준은
    게이트가 컴포넌트 근거에서 직접 세운다.
    """
    status = gate_status(_report(dep=_audit([_CONDITIONAL["CVSS HIGH"]], blocked=True)))
    assert status["verdict"] == "conditional"


def test_block_reasons_name_the_package_and_the_criterion() -> None:
    """*"차단 기준에 걸린 패키지가 있습니다"* 만으로는 무엇을 고칠지 알 수 없다."""
    status = gate_status(_report(dep=_audit([
        _pkg("protobufjs", version="7.5.4", vulnerability_count=1, max_cve="CRITICAL",
             recommended_version="7.5.6",
             advisories=[{"id": "GHSA-x", "severity": "CRITICAL"}]),
    ])))
    (reason,) = status["block_reasons"]
    assert reason["package"] == "protobufjs" and reason["version"] == "7.5.4"
    assert reason["recommended_version"] == "7.5.6"
    assert "CRITICAL" in " ".join(reason["labels"])
    assert "protobufjs" in status["reason"]


# ---------------------------------------------------------------------------
# 소스는 보조 — 막지 않되, 노출은 앞으로 끌어낸다
# ---------------------------------------------------------------------------

def test_source_findings_do_not_block() -> None:
    """의존성 차단을 좁히면서 소스를 그대로 두면 원칙이 뒤집힌다 — 오탐이 적은
    쪽은 거의 안 막고 틀릴 수 있는 쪽이 막게 된다."""
    report = _report(_SOURCE_BLOCK, filename="a.js")
    status = gate_status(report)
    assert status["verdict"] == "conditional"
    assert status["blocked"] is False
    assert status["blocked_source"] is True, "사실 자체는 남겨야 한다(소비자 정책용)"
    assert _scan_exit_code(report, "block") == 0
    assert _scan_exit_code(report, "warn") != 0, "기본값은 여전히 CI 를 세운다"


def test_secret_exposure_is_pulled_to_the_front() -> None:
    """조건부라고 조용히 넘어가면 안 되는 것이 있다.

    노출된 키는 코드에서 지우는 것만으로 끝나지 않는다 — Git 이력에 남으므로
    **반드시 재발급**해야 한다.
    """
    report = _report('API_KEY = "sk-proj-Ab3xK9mQ2pR7sT1uV5wY8zC4dE6f"\n', filename="a.py")
    status = gate_status(report)
    assert status["verdict"] == "conditional"
    assert status["exposure"]["secret"] >= 1
    assert "재발급" in status["reason"]


def test_pii_exposure_says_what_to_do() -> None:
    report = _report('rrn = "900101-1234567"\n', filename="a.py")
    status = gate_status(report)
    assert status["exposure"]["pii"] >= 1
    assert "개인정보" in status["reason"]


def test_both_source_and_package_says_fixing_source_alone_is_not_enough() -> None:
    report = _report(_SOURCE_BLOCK, filename="a.js",
                     dep=_audit([_BLOCKING["CVSS CRITICAL"]]))
    status = gate_status(report)
    assert status["verdict"] == "blocked"
    assert "소스만 고치면" in status["reason"]


# ---------------------------------------------------------------------------
# --fail-on — "소스는 보조, 의존성은 게이트" 를 실제 스위치로
# ---------------------------------------------------------------------------

def test_fail_on_dependency_ignores_source_findings() -> None:
    report = _report(_SOURCE_BLOCK, filename="a.js")
    assert _scan_exit_code(report, "dependency") == 0


def test_fail_on_dependency_still_fails_on_packages() -> None:
    """소스를 무시한다고 의존성까지 무시하면 그냥 게이트를 끈 것이다."""
    report = _report(dep=_audit([_BLOCKING["악성 패키지"]]))
    assert _scan_exit_code(report, "dependency") != 0


def test_fail_on_dependency_passes_a_clean_project() -> None:
    assert _scan_exit_code(_report(dep=_audit([])), "dependency") == 0


# ---------------------------------------------------------------------------
# 느슨해지지 않았는가
# ---------------------------------------------------------------------------

def test_clean_project_is_approved() -> None:
    status = gate_status(_report())
    assert status["verdict"] == "approved"
    assert status["requires_action"] is False
    assert _scan_exit_code(_report(), "block") == 0


def test_suppressed_findings_do_not_block() -> None:
    """승인된 예외는 게이트를 통과시키되 발견은 남긴다 — 기존 계약."""
    report = _report(_SOURCE_BLOCK, filename="a.js")
    report.findings = [f.model_copy(update={"suppressed": True}) for f in report.findings]
    report.summary = report.summary.model_copy(update={"blocked": False})
    assert gate_status(report)["blocked_source"] is False


def test_requires_action_preserves_the_old_blocked_meaning() -> None:
    """`blocked` 의 뜻이 좁아졌다. 예전 뜻("할 일이 남았는가")을 읽던 소비자가
    **조용히 느슨해지지 않도록** 옮겨 담을 자리를 둔다."""
    for dep in (_audit([_CONDITIONAL["CVSS HIGH"]]), _audit([_BLOCKING["악성 패키지"]])):
        assert gate_status(_report(dep=dep))["requires_action"] is True
    assert gate_status(_report())["requires_action"] is False


@pytest.mark.parametrize("code, filename", [(_CLEAN, "a.py"), (_SOURCE_BLOCK, "a.js")])
def test_unchecked_packages_are_named_in_the_reason(code: str, filename: str) -> None:
    """판정 불가는 안전이 아니다. 그 사실이 문장에서 사라지면 담당자는
    '차단 없음'만 읽고 넘어간다."""
    report = _report(code, filename=filename, dep=_audit([], unchecked=2))
    reason = gate_status(report)["reason"]
    assert "판정 불가" in reason and "안전" in reason, reason


def test_should_fail_matches_exit_code_for_every_policy() -> None:
    """두 곳에서 정책을 따로 해석하면 언젠가 갈라진다 — 같은 답인지 고정한다."""
    cases = [
        _report(),
        _report(_SOURCE_BLOCK, filename="a.js"),
        _report(dep=_audit([_BLOCKING["CVSS CRITICAL"]])),
        _report(dep=_audit([_CONDITIONAL["CVSS HIGH"]])),
        _report(_SOURCE_BLOCK, filename="a.js", dep=_audit([_BLOCKING["악성 패키지"]])),
    ]
    for report in cases:
        for policy in ("never", "warn", "block", "dependency"):
            assert should_fail(report, policy) == (_scan_exit_code(report, policy) != 0), (
                policy, report.target)
