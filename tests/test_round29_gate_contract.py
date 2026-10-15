"""35차 — 게이트 계약 보강 (가이드북 별도검토 2026-10-15 반영).

실측으로 확인한 결함 세 가지를 막는다.

① 미고정 패키지가 게이트·보고서에서 사라졌다. 34차가 "최신판 기준 조회"로 역대 취약점 차단 오탐을
   없앴는데, 최신판이 깨끗하면 게이트는 '승인', 보고서는 '이상 없음'이었다 — 최신판 조회는 설치본이
   안전하다는 근거가 아니다.
② 필수 엔진이 죽어도 게이트가 승인했다. python-ast 가 중단된 Python 프로젝트가 regex 만 돌고 '승인'.
③ 판정 불가(undetermined)에서 `requires_action=False` — 이 값만 읽는 소비자가 '조치 불필요'로 읽는다.

그리고 사람이 읽는 보고서에 검사한 소스의 신원(커밋·내용 지문)과 "기술 판정 ≠ 기관 승인" 문장을 싣는다.
"""
from __future__ import annotations

from pathlib import Path

from gvskb.gate import CONDITIONAL_CRITERIA, gate_status
from gvskb.report import render_html, render_markdown
from gvskb.scanner import scan_code, scan_path
from gvskb.schema import EngineUnavailable, ScanReport, SourceSnapshot


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


# ---------------------------------------------------------------------------
# ① 미고정 패키지
# ---------------------------------------------------------------------------

def test_unpinned_clean_latest_is_conditional_not_approved() -> None:
    g = gate_status(_report([_UNPINNED_CLEAN]))
    assert g["verdict"] == "conditional"
    assert g["conditional_criteria"] == ["unpinned"]
    assert g["unpinned"] == [{"name": "flask", "resolved_version": "3.1.0",
                              "version_resolution": "latest-assumed"}]
    assert g["requires_action"] is True
    assert "버전 미고정 1종" in g["reason"] and "최신판 기준" in g["reason"]


def test_pinned_clean_stays_approved() -> None:
    g = gate_status(_report([_check("flask", version="3.1.0")]))
    assert g["verdict"] == "approved" and g["unpinned"] == []


def test_unpinned_vulnerable_latest_keeps_vulnerable_and_adds_unpinned() -> None:
    vuln = _check("torch", version=None, resolved_version="2.7.0", version_resolution="latest-assumed",
                  verdict="vulnerable", vulnerability_count=2, max_cve="HIGH",
                  advisories=[{"id": "GHSA-x", "severity": "HIGH"}])
    g = gate_status(_report([vuln]))
    assert g["verdict"] == "conditional"
    assert "vulnerable" in g["conditional_criteria"] and "unpinned" in g["conditional_criteria"]


def test_unpinned_criterion_has_a_label() -> None:
    """사전에 이름만 올리고 아무도 계산하지 않는 '죽은 기준'을 막는다 — 반대 방향도 같다."""
    assert "unpinned" in CONDITIONAL_CRITERIA and "coverage" in CONDITIONAL_CRITERIA


def test_report_shows_unpinned_in_table_remedy_and_criteria() -> None:
    md = render_markdown(_report([_UNPINNED_CLEAN]))
    head = md.split("## 상세 검토 결과")[0]
    assert "조건부 승인" in head
    assert "버전 미고정" in head                      # 해소 방안
    assert "최신판 3.1.0 기준" in md                   # 패키지 표 비고
    assert "⚠ 미고정(최신판 기준 이상 없음)" in md     # 판정 칸 — 비고만 있으면 초록 옆에서 읽히지 않는다
    assert "이상 없음(검사 시점)" not in md
    assert "버전 미고정 · 검사 범위 결손" in head       # 판정 기준표


# ---------------------------------------------------------------------------
# ② 필수 엔진 미가동
# ---------------------------------------------------------------------------

def _engine_down(report: ScanReport, name: str = "python-ast", *, where: str = "failed") -> ScanReport:
    report.engines.required = ["regex", "python-ast"]
    setattr(report.engines, where, [EngineUnavailable(name=name, reason="테스트용 중단")])
    return report


def test_required_engine_failure_without_findings_is_undetermined() -> None:
    g = gate_status(_engine_down(_report()))
    assert g["verdict"] == "undetermined"
    assert g["complete"] is False
    assert g["requires_action"] is True
    assert "필수 엔진 미가동" in g["coverage_gap"] and "python-ast" in g["coverage_gap"]
    assert "gvskb doctor" in g["reason"]


def test_required_engine_unavailable_counts_too() -> None:
    g = gate_status(_engine_down(_report(), where="unavailable"))
    assert g["verdict"] == "undetermined" and g["complete"] is False


def test_required_engine_failure_with_finding_is_conditional_with_coverage() -> None:
    """경고 하나 때문에 검사 불완전이 덜 엄격해 보이면 안 된다 — 사유·complete·requires_action 이 남는다."""
    r = _engine_down(_report(code="eval(llm_response)\n"))
    g = gate_status(r)
    assert g["verdict"] == "conditional"
    assert "coverage" in g["conditional_criteria"]
    assert g["complete"] is False and g["requires_action"] is True
    assert "필수 엔진이 돌지 않아" in g["reason"]


def test_optional_engine_absence_does_not_change_verdict() -> None:
    r = _report()
    r.engines.required = ["regex", "python-ast"]
    r.engines.unavailable = [EngineUnavailable(name="semgrep", reason="Windows 미지원")]
    g = gate_status(r)
    assert g["verdict"] == "approved" and g["complete"] is True


def test_complete_is_true_on_a_clean_full_scan() -> None:
    g = gate_status(_report())
    assert g["complete"] is True and g["coverage_gap"] == ""


# ---------------------------------------------------------------------------
# ③ 판정 불가 = 할 일이 남았다
# ---------------------------------------------------------------------------

def test_undetermined_requires_action() -> None:
    r = _report()
    r.scanned_files = []
    g = gate_status(r)
    assert g["verdict"] == "undetermined" and g["requires_action"] is True


# ---------------------------------------------------------------------------
# 보고서 — 소스 신원 · 기술 판정 문장
# ---------------------------------------------------------------------------

def test_report_states_it_is_a_technical_verdict_not_an_approval() -> None:
    r = _report()
    md = render_markdown(r)
    html = render_html(r)
    assert "기술 판정" in md.split("## 요약")[0]
    assert "기관 보안담당자의 사용 승인" in md
    assert 'class="vnote"' in html and "기술 판정" in html


def test_report_header_shows_source_identity(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    r = scan_path(str(tmp_path))
    assert r.source_snapshot is not None and r.source_snapshot.content_tree_hash
    md = render_markdown(r)
    row = next(line for line in md.splitlines() if "검사한 소스" in line)
    assert r.source_snapshot.content_tree_hash[:12] in row
    assert "1개 파일" in row
    assert "커밋" not in row            # git 저장소가 아니면 커밋을 지어내지 않는다


def test_source_identity_mentions_dirty_tree() -> None:
    r = _report()
    r.source_snapshot = SourceSnapshot(commit="abcdef0123456789", dirty=True,
                                       content_tree_hash="f" * 64, file_count=3)
    md = render_markdown(r)
    row = next(line for line in md.splitlines() if "검사한 소스" in line)
    assert "커밋 abcdef012345" in row and "미커밋 변경 있음" in row and "ffffffffffff…" in row


def test_content_hash_changes_with_one_byte(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    h1 = scan_path(str(tmp_path)).source_snapshot.content_tree_hash
    (tmp_path / "a.py").write_text("x = 2\n", encoding="utf-8")
    h2 = scan_path(str(tmp_path)).source_snapshot.content_tree_hash
    assert h1 != h2
