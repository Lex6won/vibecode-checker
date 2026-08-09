"""판정 사다리와 본문 문구가 어긋나지 않는가 — 라운드 23.

**어떻게 드러났나(실측 2026-08-09)**: `amnotyoung/koica-reg-mcp` 를 검사한
보고서가 한 문서 안에서 두 말을 했다.

    | 15행 | 차단 사유는 없습니다 … (조건부 승인)        |
    | 68행 | 소스 코드만 고치면 **배포 차단이 풀리지 않습니다** |

라운드 22 에서 '차단'의 뜻을 다섯 가지로 좁힐 때 `gate.py` 만 고치고 본문
문구를 두고 온 결과다. 판정을 세 군데서 따로 계산하고 있었다 —

    1. `gate_status`            (새 기준, 유일한 권위)
    2. `summary.blocked` / `by_decision["block"]`  (발견 단위 등급, 배포 판정 아님)
    3. 의존성 감사의 `blocked` 플래그              (사다리 이전 기준)

여기 테스트는 **배포 결과를 말하는 문장은 1번만 따른다**는 것을 고정한다.
"""
from __future__ import annotations

import re

import pytest

from gvskb.gate import gate_status
from gvskb.report import (
    _ACTION_LEAD_BLOCK,
    _ACTION_LEAD_MUST,
    _ACTION_LEAD_WARN,
    _action_lead,
    _dep_also_note,
    _dep_prompt_warn,
    _md_bold_to_html,
    render_html,
    render_markdown,
)
from gvskb.schema import (
    CodeLocation,
    Decision,
    Finding,
    ScanReport,
    ScanSummary,
    Severity,
)


def _dep(max_cve: str, *, blocked: bool = True, name: str = "pkg") -> dict:
    """의존성 감사 한 벌. `blocked=True` 는 **감사의 옛 플래그** — 게이트가
    이걸 그대로 따라가면 안 된다는 것이 이 테스트의 요점이다."""
    return {
        "audits": [{
            "ecosystem": "pypi",
            "manifest": "requirements.txt",
            "parsed_count": 1,
            "checked_count": 1,
            "unchecked_count": 0,
            "blocked": blocked,
            "verdict": "blocked" if blocked else "ok",
            "checks": [{
                "name": name, "version": "1.0", "checked": True,
                "is_malicious_package": False, "vulnerability_count": 1,
                "verdict": "vulnerable", "max_cve": max_cve, "in_kev": False,
            }],
        }],
    }


def _finding(decision: Decision, severity: Severity) -> Finding:
    return Finding(
        id=f"R-X:app.py:1:{decision.value}",
        rule_id="R-X",
        title="하드코딩된 자격증명",
        plain_title="하드코딩된 자격증명",
        severity=severity,
        decision=decision,
        category="secret-scanning",
        location=CodeLocation(file="app.py", line=1),
        evidence="api_key = '[마스킹]'",
        why_it_matters="키가 코드에 남으면 저장소를 읽는 누구나 쓸 수 있습니다.",
        safe_fix="환경변수·비밀관리로 옮기고 값을 재발급하세요.",
    )


def _report(*findings: Finding, deps: dict | None = None) -> ScanReport:
    by_dec: dict[str, int] = {}
    by_sev: dict[str, int] = {}
    for f in findings:
        by_dec[f.decision.value] = by_dec.get(f.decision.value, 0) + 1
        by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
    top = max((f.severity for f in findings), key=lambda s: list(Severity).index(s), default=None)
    rep = ScanReport(
        target="fixture",
        summary=ScanSummary(
            finding_count=len(findings),
            by_severity=by_sev,
            by_decision=by_dec,
            highest_severity=top,
        ),
        findings=list(findings),
        scanned_files=["app.py"],
    )
    if deps is not None:
        rep.dependency_audit = deps
    return rep


# ---------------------------------------------------------------------------
# ① 조건부 승인 보고서는 "차단"을 주장하지 않는다
# ---------------------------------------------------------------------------

# 배포 결과를 단정하는 표현들. 발견 하나하나의 등급 표시("치명·차단",
# "차단(block): 1건")는 다른 개념이라 여기 넣지 않는다.
_BLOCK_CLAIMS = (
    "배포 차단이 풀리지 않습니다",
    "패키지 블록을 빠뜨리지 마세요",
    "배포가 차단됩니다",
    "지금 이대로 올리거나 배포하면 안 됩니다",
    "차단 권고",
    "[차단] 취약",
)


@pytest.mark.parametrize(
    "name,report",
    [
        ("소스 차단등급만", _report(_finding(Decision.block, Severity.critical))),
        ("소스 경고만", _report(_finding(Decision.warn, Severity.medium))),
        ("HIGH 패키지", _report(deps=_dep("HIGH"))),
        ("소스+HIGH패키지", _report(_finding(Decision.block, Severity.critical),
                                deps=_dep("HIGH"))),
        ("MEDIUM 패키지", _report(deps=_dep("MEDIUM"))),
    ],
)
def test_conditional_report_never_claims_deployment_is_blocked(
    name: str, report: ScanReport
) -> None:
    assert gate_status(report)["verdict"] == "conditional", name
    for fmt, doc in (("MD", render_markdown(report)), ("HTML", render_html(report))):
        for claim in _BLOCK_CLAIMS:
            assert claim not in doc, f"{name}/{fmt}: 조건부 승인인데 '{claim}' 라고 말한다"


# ---------------------------------------------------------------------------
# ② 진짜 차단이면 반대로 **반드시** 말한다 — 완화가 침묵이 되면 안 된다
# ---------------------------------------------------------------------------


def test_blocked_report_still_says_it_plainly() -> None:
    report = _report(_finding(Decision.block, Severity.critical), deps=_dep("CRITICAL"))
    assert gate_status(report)["verdict"] == "blocked"
    for doc in (render_markdown(report), render_html(report)):
        assert "배포 차단이 풀리지 않습니다" in doc
        assert "패키지 블록을 빠뜨리지 마세요" in doc
        assert "지금 이대로 올리거나 배포하면 안 됩니다" in doc


def test_dep_sentences_switch_on_gate_not_on_audit_flag() -> None:
    """의존성 감사가 `blocked=True` 라고 우겨도 게이트가 아니면 따르지 않는다."""
    high = _report(deps=_dep("HIGH", blocked=True))
    crit = _report(deps=_dep("CRITICAL", blocked=True))
    assert "조치가 끝나지 않습니다" in _dep_also_note(high)
    assert "배포 차단이 풀리지 않습니다" in _dep_also_note(crit)
    assert "패키지를 빠뜨리지 마세요" in _dep_prompt_warn(high)
    assert "패키지 블록을 빠뜨리지 마세요" in _dep_prompt_warn(crit)


# ---------------------------------------------------------------------------
# ③ 차단 등급 발견은 조건부에서도 약해지지 않는다 — 완화는 삭제가 아니다
# ---------------------------------------------------------------------------


def test_block_grade_finding_still_gets_a_stronger_lead_than_plain_warning() -> None:
    must = _report(_finding(Decision.block, Severity.critical))
    warn = _report(_finding(Decision.warn, Severity.medium))
    assert _action_lead(must) == _ACTION_LEAD_MUST
    assert _action_lead(warn) == _ACTION_LEAD_WARN
    assert _action_lead(_report(_finding(Decision.block, Severity.critical),
                                deps=_dep("CRITICAL"))) == _ACTION_LEAD_BLOCK
    # 셋이 서로 다른 말을 해야 구분이 의미가 있다.
    assert len({_ACTION_LEAD_BLOCK, _ACTION_LEAD_MUST, _ACTION_LEAD_WARN}) == 3


# ---------------------------------------------------------------------------
# ④ 리드 문구에 마크업을 넣지 않는다 — 내가 고치면서 만든 결함의 회귀 테스트
# ---------------------------------------------------------------------------


def test_action_leads_carry_no_markdown_markup() -> None:
    """`**` 를 넣었더니 MD 는 굵게가 중첩돼 깨지고 HTML 은 별표가 그대로 나왔다.

    MD 호출부가 `**{lead}**` 로 감싸고 HTML 호출부는 `_esc` 로 내보내므로,
    문구 자체에는 마크업이 없어야 한다.
    """
    for lead in (_ACTION_LEAD_BLOCK, _ACTION_LEAD_MUST, _ACTION_LEAD_WARN):
        assert "**" not in lead, lead


def test_rendered_documents_do_not_leak_raw_asterisks_into_html() -> None:
    for report in (
        _report(_finding(Decision.block, Severity.critical)),
        _report(_finding(Decision.warn, Severity.medium), deps=_dep("HIGH")),
        _report(_finding(Decision.block, Severity.critical), deps=_dep("CRITICAL")),
    ):
        html_doc = render_html(report)
        for div in re.findall(r'<div class="(?:lead|depwarn)">(.*?)</div>', html_doc, re.S):
            assert "**" not in div, f"HTML 에 마크다운 별표가 그대로 나왔다: {div[:120]}"
        md_doc = render_markdown(report)
        assert "****" not in md_doc


def test_md_bold_to_html_converts_and_escapes() -> None:
    out = _md_bold_to_html("**위험** <script>")
    assert out == "<b>위험</b> &lt;script&gt;"
