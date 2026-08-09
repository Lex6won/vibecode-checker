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

import ast
import re
from pathlib import Path

import pytest

import gvskb.report
from gvskb.gate import gate_status
from gvskb.report import (
    _ACTION_LEAD_BLOCK,
    _ACTION_LEAD_MUST,
    _ACTION_LEAD_WARN,
    _action_lead,
    _action_order,
    _dep_also_note,
    _dep_prompt_warn,
    _md_inline_to_html,
    render_html,
    render_markdown,
)
from gvskb.scanner import scan_path
from gvskb.schema import (
    CodeLocation,
    Decision,
    Finding,
    ScanReport,
    ScanSummary,
    Severity,
    SkippedFile,
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
        # 제외 사유는 스캐너가 만든 문장이고 **백틱 표기를 담고 있다**. 픽스처에
        # 이걸 안 넣었더니 화면 훑기가 그 자리를 지나쳐, 실제 보고서에서 백틱
        # 4개가 그대로 나온 뒤에야 알았다 — 픽스처가 얇으면 스윕도 얇다.
        skipped_files=[
            SkippedFile(
                path="requirements.txt",
                reason="의존성 매니페스트 — 취약점은 `gvskb check-package` 또는 "
                       "MCP `scan_dependencies`로 검사하세요",
            ),
            SkippedFile(path="README.md", reason="검사 대상 확장자 아님(.md) — 검사되지 않았습니다"),
        ],
    )
    if deps is not None:
        rep.dependency_audit = deps
    return rep


# ---------------------------------------------------------------------------
# ① 조건부 승인 보고서는 "차단"을 주장하지 않는다
# ---------------------------------------------------------------------------

# 배포 결과를 단정하는 표현들.
#
# 목록을 두 번 늘렸다. 처음엔 그때 고친 문장만 담았는데, 죽은 함수
# `_hero_line` 이 "지금 이대로 배포하면 안 됩니다 — 치명·차단 위험 N건" 을
# 들고 있는 것을 스윕이 지나쳤다. **방금 고친 자리만 담은 목록은 다음 자리를
# 못 잡는다** — 배포를 단정하는 어법 자체를 넣는다.
_BLOCK_CLAIMS = (
    "배포 차단이 풀리지 않습니다",
    "패키지 블록을 빠뜨리지 마세요",
    "배포가 차단됩니다",
    "지금 이대로 올리거나 배포하면 안 됩니다",
    "지금 이대로 배포하면 안 됩니다",
    "차단 권고",
    "[차단] 취약",
    "배포 미승인",
    "배포 불가",
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
# ②-2 발견 등급은 '차단'이라 부르지 않는다 — 배포 판정과 말이 겹쳤다
# ---------------------------------------------------------------------------


def test_finding_grade_is_labelled_required_action_not_blocked() -> None:
    """요약의 "차단(block): 1건" 이 "조건부 승인" 옆에 찍혀 있었다.

    담당자는 막힌 건지 아닌지 알 수 없다. 사람이 읽는 이름표만 바꾸고
    기계 값(`decision: "block"`)은 그대로 둔다.
    """
    report = _report(_finding(Decision.block, Severity.critical))
    assert gate_status(report)["verdict"] == "conditional"
    for fmt, doc in (("MD", render_markdown(report)), ("HTML", render_html(report))):
        assert "필수 조치" in doc, fmt
        assert "차단(block)" not in doc, f"{fmt}: 옛 이름표가 남아 있다"
        assert "치명·차단" not in doc, f"{fmt}: 발견 뱃지가 아직 '차단' 이라고 한다"
        assert "치명/차단" not in doc, f"{fmt}: 수정 프롬프트 머리가 아직 '차단' 이다"
        # 처리 순서 안내도 같은 이름표를 써야 한다 — 한 문서 안에서 같은 것을
        # 두 이름으로 부르면, 읽는 사람은 서로 다른 것으로 읽는다.
        assert "순서(차단" not in doc, f"{fmt}: LLM 처리 순서가 아직 '차단' 이라고 한다"
    # 기계 계약은 건드리지 않는다 — 하네스·레지스트리가 읽는 값이다.
    assert report.findings[0].decision.value == "block"
    assert report.summary.by_decision["block"] == 1


def test_machine_fields_still_say_block(tmp_path) -> None:
    """SARIF·JSON 은 사람 이름표를 따라가지 않는다."""
    (tmp_path / "app.py").write_text('exec(input())\n', encoding="utf-8")
    rep = scan_path(str(tmp_path))
    dumped = rep.model_dump(mode="json")
    assert set(dumped["summary"]["by_decision"]) <= {"block", "warn", "allow"}
    for f in dumped["findings"]:
        assert f["decision"] in {"block", "warn", "allow"}


# ---------------------------------------------------------------------------
# ③ 필수 조치 등급 발견은 조건부에서도 약해지지 않는다 — 완화는 삭제가 아니다
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
    # 내용까지 본다. `== _ACTION_LEAD_MUST` 는 상수를 통째로 바꿔도 통과하고,
    # "문서에 '필수 조치' 가 있는가" 는 요약 줄·단 이름표에 가려 통과한다
    # (변이 검사에서 실제로 둘 다 빠져나갔다).
    assert "필수 조치" in _ACTION_LEAD_MUST
    assert "사유 기록으로 넘길 수 없" in _ACTION_LEAD_MUST


def test_action_order_top_tier_is_named_required_action() -> None:
    """단 이름표도 같은 이름을 쓴다 — 문서 전체 검색으로는 가려진다."""
    tiers = _action_order([_finding(Decision.block, Severity.critical),
                           _finding(Decision.warn, Severity.low)])
    top = tiers[0]
    assert top["label"] == "지금 막아야 하는 것"
    assert "필수 조치" in top["hint"], top["hint"]
    assert "차단" not in top["hint"], top["hint"]


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


# 복사용 프롬프트는 **AI 도구에 그대로 붙여넣는 평문**이라 마크다운이 의도된
# 것이다. 그 블록만 걷어내고 나머지 화면 텍스트를 전부 훑는다 — 처음엔
# `lead`·`depwarn` 두 클래스만 봤다가, 정작 가장 중요한 **판정 상자의 해소
# 방안**에 `` `mcp 1.8` → **1.28.1 이상** `` 이 그대로 나와 있는 것을 놓쳤다.
_COPY_BLOCKS = re.compile(
    r'data-copy="[^"]*"|<pre[^>]*>.*?</pre>|<div class="fixprompt">.*?</div>', re.S
)


def _visible_html(doc: str) -> str:
    return _COPY_BLOCKS.sub("", doc)


@pytest.mark.parametrize(
    "name,report",
    [
        ("소스만", _report(_finding(Decision.block, Severity.critical))),
        ("HIGH패키지", _report(_finding(Decision.warn, Severity.medium), deps=_dep("HIGH"))),
        ("차단", _report(_finding(Decision.block, Severity.critical), deps=_dep("CRITICAL"))),
    ],
)
def test_rendered_html_never_shows_raw_markdown(name: str, report: ScanReport) -> None:
    """화면에 별표·백틱이 그대로 나오면 안 된다 — 문서 전체를 훑는다."""
    visible = _visible_html(render_html(report))
    assert "**" not in visible, f"{name}: HTML 에 별표가 그대로 나왔다"
    assert "`" not in visible, f"{name}: HTML 에 백틱이 그대로 나왔다"
    assert "****" not in render_markdown(report)


def test_real_scan_report_shows_no_raw_markdown(tmp_path) -> None:
    """합성 픽스처가 아니라 **실제 스캔 결과**를 훑는다.

    픽스처는 렌더 경로를 다 지나가지 않는다 — 제외 파일 표를 안 만들어서
    백틱 누출을 놓쳤다. 진짜 스캔은 우리가 예상하지 못한 문장까지 만든다.
    """
    (tmp_path / "app.py").write_text(
        'API_KEY = "sk-live-abcdef0123456789abcdef"\n'
        "import sqlite3\n"
        'conn = sqlite3.connect("x.db")\n',
        encoding="utf-8",
    )
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("# 문서\n", encoding="utf-8")

    report = scan_path(str(tmp_path))
    assert report.skipped_files, "제외 파일이 0개면 이 스윕은 그 표를 안 본다"
    visible = _visible_html(render_html(report))
    assert "**" not in visible
    assert "`" not in visible


def test_the_sweep_actually_inspects_something() -> None:
    """복사 블록을 걷어내고도 볼 것이 남아 있는가 — 빈 문자열을 훑고 '이상
    없음'을 내는 것이 가장 나쁜 통과다."""
    visible = _visible_html(render_html(
        _report(_finding(Decision.block, Severity.critical), deps=_dep("CRITICAL"))
    ))
    assert len(visible) > 3000
    assert "배포 미승인" in visible          # 판정 상자가 훑기 대상에 들어 있다
    assert "해소 방안" in visible


# ---------------------------------------------------------------------------
# ⑤ 리포트는 배포 판정을 **스스로 계산하지 않는다** — 구조로 못 박는다
# ---------------------------------------------------------------------------


def test_report_module_never_reads_summary_blocked() -> None:
    """`report.py` 안에서 `.blocked` 를 읽는 곳이 하나도 없어야 한다.

    같은 결함을 세 번 만났다 — `_verdict_line`·`_verdict_css_color`·`_hero_line`
    이 전부 `summary.blocked or block_count` 로 배포 판정을 **다시 계산**하고
    있었다. 셋 다 죽은 코드였지만, 죽은 코드는 되살아난다.

    출력만 훑는 테스트로는 못 잡는다(불리지 않으니 화면에 안 나온다). 그래서
    **소스 구조**를 본다: 판정은 `gate_status(report)["blocked"]` 로만 얻는다.
    """
    src = Path(gvskb.report.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    hits = [
        f"line {n.lineno}: ....{n.attr}"
        for n in ast.walk(tree)
        if isinstance(n, ast.Attribute) and n.attr == "blocked"
    ]
    assert not hits, (
        "report.py 가 배포 판정을 다시 계산하고 있다 — gate_status 에 물어야 한다:\n"
        + "\n".join(hits)
    )


def test_md_inline_to_html_converts_and_escapes() -> None:
    out = _md_inline_to_html("**위험** <script>")
    assert out == "<b>위험</b> &lt;script&gt;"
