"""render_markdown: 한국어 리포트 출력 동작 확인."""
from __future__ import annotations

from pathlib import Path

from gvskb.report import render_html, render_markdown
from gvskb.schema import (
    CodeLocation,
    Decision,
    Finding,
    ScanReport,
    ScanSummary,
    Severity,
    SkippedFile,
)
from gvskb.scanner import scan_code, scan_path


def test_render_markdown_includes_required_sections() -> None:
    report = scan_code(
        "name = input('name')\n"
        "cursor.execute(f\"SELECT * FROM complaints WHERE name = '{name}'\")\n",
        filename="app.py",
        language="python",
    )
    md = render_markdown(report)

    assert "# 코드 보안 검사 결과" in md
    assert "## 요약" in md
    # Layer 2 — 상세 검토 결과(분야별) 에 발견 상세가 들어간다
    assert "## 상세 검토 결과" in md
    assert "보안 분야 개요" in md
    assert "왜 위험한가" in md and "안전한 수정 방향" in md
    assert "자동 보안 보조 검토" in md  # 면책 문구(제목 없이 요약부)
    assert "GOV-SQL-INJECTION-001" in md
    assert "app.py" in md
    # severity label rendered in Korean
    assert "치명" in md or "높음" in md


def test_render_markdown_empty_findings_clean_message() -> None:
    report = scan_code('print("hello")\n', filename="hello.py", language="python")
    md = render_markdown(report)

    assert "## 파일별 발견 사항" not in md
    assert "발견된 위험이 없습니다" in md
    assert "자동 보안 보조 검토" in md  # 면책 문구는 제목 없이 유지


def test_render_markdown_redacts_evidence(tmp_path: Path) -> None:
    f = tmp_path / "settings.py"
    f.write_text(
        'OPENAI_API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz"\n',
        encoding="utf-8",
    )
    report = scan_path(tmp_path)
    md = render_markdown(report)
    assert "abcdefghijklmnopqrstuvwxyz" not in md
    assert "REDACTED" in md or "***" in md


# ---------------------------------------------------------------------------
# B-3 report quality additions — verdict line, reproduce, revalidation,
# guideline grouping
# ---------------------------------------------------------------------------


def _report_with_findings():
    return scan_code(
        "import hashlib\n"
        "name = input('name')\n"
        "cursor.execute(f\"SELECT * FROM t WHERE name = '{name}'\")\n"
        "hashlib.md5(b'x').hexdigest()\n",
        filename="app.py",
        language="python",
    )


def test_render_markdown_includes_one_line_verdict() -> None:
    md = render_markdown(_report_with_findings())
    assert "## 결론" in md
    head = md.split("## 요약")[0]
    # 한 줄 결론은 승인/미승인 박스 + 배포 판정으로 표현된다(차단권고 줄은 제거됨).
    assert "배포 판정" in head
    assert (
        "배포 미승인" in head
        or "배포 보류" in head
        or "배포 승인 가능" in head
    )


def test_render_markdown_empty_findings_verdict_is_clean() -> None:
    report = scan_code('print("hi")\n', filename="hi.py", language="python")
    md = render_markdown(report)
    assert "배포 승인 가능" in md.split("## 상세 검토 결과")[0]


def test_render_markdown_includes_reproduce_section() -> None:
    md = render_markdown(
        _report_with_findings(),
        reproduce_command="gvskb scan app.py --profile public-default-strict",
    )
    assert "## 재현 절차" in md
    assert "gvskb scan app.py --profile public-default-strict" in md


def test_render_markdown_reproduce_falls_back_when_no_command() -> None:
    md = render_markdown(_report_with_findings())
    assert "## 재현 절차" in md
    assert "gvskb" in md


def test_render_markdown_includes_revalidation_guidance() -> None:
    md = render_markdown(_report_with_findings())
    assert "## 수정 후 다시 검증" in md
    assert "scan_code" in md
    assert "gvskb scan" in md


def test_render_markdown_groups_findings_by_guideline_source() -> None:
    md = render_markdown(_report_with_findings())
    assert "## 가이드라인별 분포" in md


# ---------------------------------------------------------------------------
# HTML 리포트 — 카드 강조형, 자체 포함 단일 파일
# ---------------------------------------------------------------------------


def test_render_html_is_self_contained_document() -> None:
    html = render_html(_report_with_findings())
    assert html.startswith("<!DOCTYPE html>")
    assert '<html lang="ko">' in html
    assert "</body></html>" in html
    # CSS 내장(외부 stylesheet 없음)
    assert "<style>" in html
    # 자체 포함의 진짜 기준: 외부 리소스를 '불러오는' 요소가 없어야 한다.
    # (출처 URL이 본문에 텍스트로 인용되는 것은 허용 — 아무것도 로딩하지 않음.
    #  동적 코드의 < 는 모두 이스케이프되므로 <img 등은 &lt;img 로만 나타난다.)
    lower = html.lower()
    # 복사 버튼용 인라인 <script>는 외부 로딩이 아니므로 허용. 외부 리소스를
    # '불러오는' 태그만 금지한다.
    assert "<script src" not in lower
    for tag in ("<iframe", "<link", "<img", "<object", "<embed"):
        assert tag not in lower, f"외부 로딩 가능 태그 발견: {tag}"
    assert "@import" not in lower
    assert "url(http" not in lower


def test_render_html_includes_findings_and_safe_fix() -> None:
    html = render_html(_report_with_findings())
    assert 'class="card"' in html
    assert "왜 위험한가" in html
    assert "안전한 수정 방향" in html
    assert "app.py" in html
    assert "자동 보안 보조 검토" in html  # 면책 문구(제목 없이)


def test_render_html_escapes_dynamic_content() -> None:
    # 코드에 HTML 메타문자가 있어도 레이아웃을 깨거나 주입되지 않도록 이스케이프.
    report = scan_code(
        'el.innerHTML = "<img src=x onerror=alert(1)>"\n',
        filename="x.js",
        language="javascript",
    )
    html = render_html(report)
    assert "<img src=x onerror=alert(1)>" not in html
    assert "&lt;img" in html or "onerror" not in html


def test_render_html_empty_findings_clean_banner() -> None:
    report = scan_code('print("hi")\n', filename="hi.py", language="python")
    html = render_html(report)
    assert "배포 승인 가능" in html
    assert html.startswith("<!DOCTYPE html>")


def test_render_html_reference_urls_are_text_not_loaded() -> None:
    # 출처 URL은 본문에 '텍스트'로 인용되어야 한다 — 그러나 어떤 리소스도
    # 외부에서 불러오지 않는다(로딩 태그 없음).
    finding = Finding(
        id="f1",
        rule_id="GOV-TEST-001",
        title="test",
        plain_title="테스트 위험",
        severity=Severity.high,
        decision=Decision.block,
        category="test",
        location=CodeLocation(file="a.py", line=1),
        why_it_matters="설명",
        references=["https://docs.python.org/3/library/secrets.html"],
    )
    report = ScanReport(
        target="a.py",
        summary=ScanSummary(
            finding_count=1,
            by_severity={"high": 1},
            by_decision={"block": 1},
            highest_severity=Severity.high,
            blocked=True,
        ),
        findings=[finding],
    )
    html = render_html(report)
    assert "docs.python.org/3/library/secrets.html" in html  # 텍스트로 인용됨
    lower = html.lower()
    for tag in ("<script src", "<link", "<img", "<iframe"):
        assert tag not in lower


# ---------------------------------------------------------------------------
# 리포트 재설계 — 1페이지 요약 + 파일별 접기 + 수정 프롬프트
# ---------------------------------------------------------------------------


def _multi_finding_report():
    # 같은 룰(SQL 인젝션)이 한 파일에서 두 줄에 걸리도록 → 중복제거 시연.
    return scan_code(
        "q = input('q')\n"
        "cursor.execute(f\"SELECT * FROM a WHERE x = '{q}'\")\n"
        "cursor.execute(f\"SELECT * FROM b WHERE y = '{q}'\")\n",
        filename="views.py",
        language="python",
    )


def test_render_html_has_two_layer_sections() -> None:
    html = render_html(_report_with_findings())
    for section in (
        "한눈에 보기",          # Layer 1 — 공무원 요약
        "가장 먼저 할 일",       # Layer 1 — Top 3
        "상세 검토 결과",      # Layer 2 헤더
        "보안 분야 개요",        # Layer 2 — 분야 한눈에
        "수정 프롬프트",
    ):
        assert section in html, f"누락된 섹션: {section}"
    # 스탯 카드 + 분야별 접기(details)
    assert "검사한 파일" in html
    assert 'class="stat"' in html
    assert "<details" in html  # 순수 CSS 접기(분야별 상세)
    # 옛 파일별 구조는 제거됐다
    assert "파일별 상세" not in html
    assert 'href="#file-0"' not in html


def test_render_html_uses_pure_css_details_no_js() -> None:
    html = render_html(_report_with_findings())
    assert "<details" in html and "<summary" in html
    # 접기 동작에 외부/인라인 JS 를 쓰지 않는다(자체포함 원칙 유지).
    assert "<script src" not in html.lower()  # 외부 스크립트 로딩 없음(자체완결)
    assert "onclick" not in html.lower()  # 인라인 핸들러 대신 이벤트 위임 사용


def test_render_html_dedupes_same_rule_with_line_list() -> None:
    html = render_html(_multi_finding_report())
    # 같은 룰은 카드 한 장 + 위치목록(line a, b)로 합쳐진다.
    assert html.count("GOV-SQL-INJECTION-001") >= 1
    assert "2건" in html or "line 2, 3" in html


def test_render_html_shows_build_artifact_note() -> None:
    report = _report_with_findings()
    report.skipped_files.append(
        SkippedFile(path="public/assets/", reason="빌드 산출물(압축/번들) — 원본 소스 아님")
    )
    html = render_html(report)
    assert "빌드 산출물" in html


def test_render_markdown_has_domain_sections_and_prompts() -> None:
    md = render_markdown(_report_with_findings())
    assert "## 상세 검토 결과" in md
    assert "### 보안 분야 개요" in md
    assert "## 가장 먼저 할 일" in md
    assert "## 수정 프롬프트" in md
    # 발견 상세(왜 위험·대응방안)는 분야별 카드에 보존된다
    assert "왜 위험한가" in md and "안전한 수정 방향" in md


def test_render_markdown_dedupes_same_rule_into_one_block() -> None:
    md = render_markdown(_multi_finding_report())
    # 같은 룰은 한 번만 설명되고 위치는 목록으로 합쳐진다("2건").
    head = md.split("## 수정 프롬프트")[0]
    assert "상세 검토 결과" in head
    assert "주입" in head  # SQL 두 건이 '주입' 분야로 묶인다
    assert "2건" in md


# ---------------------------------------------------------------------------
# 초보자용 "다음 할 일" 행동 안내 — 결과 받고 무엇을 할지 바로 알려준다
# ---------------------------------------------------------------------------


def test_render_html_has_beginner_action_box() -> None:
    html = render_html(_report_with_findings())
    assert "조치 가이드" in html  # 3단계 조치 박스 제목
    assert 'class="actionbox"' in html
    # 자기가 쓰던 AI 도구에 그대로 말하는 흐름 + 키 노출 코드외 조치 경고
    assert "안전하게 고쳐줘" in html
    assert "다시 검사" in html
    assert "새로 발급" in html
    # 수정 프롬프트 섹션도 '가장 쉬운 방법'을 맨 앞에서 안내
    assert "가장 쉬운 방법" in html


def test_render_markdown_has_beginner_action_box() -> None:
    md = render_markdown(_report_with_findings())
    # Layer 1(공무원) — 상세 검토 결과(Layer 2)보다 위에 위치
    head = md.split("## 상세 검토 결과")[0]
    assert "조치 가이드" in head
    assert "안전하게 고쳐줘" in head
    assert "새로 발급" in head


def test_action_box_absent_when_no_findings() -> None:
    clean = scan_code('print("hi")\n', filename="hi.py", language="python")
    assert "조치 가이드" not in render_html(clean)
    assert "조치 가이드" not in render_markdown(clean)


# ---------------------------------------------------------------------------
# ① 검토 범위·한계 고지 — 보안팀 제출 문서로서 도구의 한계를 정직하게 밝힌다
# ---------------------------------------------------------------------------


def test_scope_and_limit_section_in_md_and_html() -> None:
    report = _report_with_findings()
    md = render_markdown(report)
    html = render_html(report)
    for out in (md, html):
        assert "검토 범위 및 한계" in out
        # 핵심 문구: 발견 0건 ≠ 안전, 공식 보안성 검토 대체 불가
        assert "발견 0건이" in out
        assert "보안성 검토를 대체하지 않습니다" in out
        assert "scan_dependencies" in out
    # 상단부(부록 아님): 상세 검토 결과(Layer 2) 헤더보다 앞에 위치
    # (Top 3 안내가 헤더를 '참조'하므로 헤더 형태로 정확히 비교한다)
    assert md.index("검토 범위 및 한계") < md.index("## 상세 검토 결과")
    assert html.index("검토 범위 및 한계") < html.index("<h2>상세 검토 결과")


def test_scope_section_present_even_when_clean() -> None:
    clean = scan_code('print("hi")\n', filename="hi.py", language="python")
    # 발견 0건일수록 한계 고지가 더 중요하다 — 항상 표시.
    assert "발견 0건이" in render_markdown(clean)
    assert "발견 0건이" in render_html(clean)


def test_scope_section_counts_scanned_and_skipped() -> None:
    report = _report_with_findings()
    report.skipped_files.append(
        SkippedFile(path="requirements.txt", reason="의존성 매니페스트 — 별도 검사 필요")
    )
    md = render_markdown(report)
    html = render_html(report)
    for out in (md, html):
        assert "검토 범위" in out
        assert "검사 제외" in out
        assert ".py" in out  # 확장자 분포


# ---------------------------------------------------------------------------
# ② 실행 모드·기준일 배너 + 인쇄 PDF 상세 복구
# ---------------------------------------------------------------------------


def test_scan_mode_banner_absent_by_default() -> None:
    report = _report_with_findings()
    assert report.scan_mode is None
    assert "오프라인(망분리)" not in render_markdown(report)
    assert "오프라인(망분리)" not in render_html(report)


def test_scan_mode_offline_banner_with_freshness() -> None:
    report = _report_with_findings()
    report.scan_mode = "offline"
    report.intel_freshness = {"advisory_db": "2026-06-01"}
    md = render_markdown(report)
    html = render_html(report)
    for out in (md, html):
        assert "오프라인(망분리)" in out
        assert "2026-06-01" in out
        assert "안전" in out  # "미갱신 항목을 '안전'으로 간주하지 마세요"


def test_scan_report_new_fields_optional_backcompat() -> None:
    # 구버전 JSON(신규 필드 없음)도 그대로 파싱된다 — render_report MCP 역호환.
    r = _report_with_findings()
    data = r.model_dump(mode="json", exclude={"scan_mode", "intel_freshness"})
    parsed = ScanReport.model_validate(data)
    assert parsed.scan_mode is None
    assert parsed.intel_freshness is None
    # 렌더도 문제없이 동작
    assert "# 코드 보안 검사 결과" in render_markdown(parsed)


def test_print_css_forces_details_content_visible() -> None:
    # 최신 Chromium/Edge 인쇄에서 닫힌 <details> 상세가 누락되는 버그 방지 —
    # @media print 에 ::details-content 강제 펼침 규칙이 있어야 한다.
    html = render_html(_report_with_findings())
    assert "details::details-content" in html
    compact = html.replace(" ", "")
    assert "content-visibility:visible!important" in compact
    assert "@media print" in html


# ---------------------------------------------------------------------------
# ③ 개인정보·비밀값 요약 + 같은 줄 다중 지적(표시 계층 dedupe)
# ---------------------------------------------------------------------------


def test_pii_summary_section_when_secret_found(tmp_path: Path) -> None:
    f = tmp_path / "config.py"
    f.write_text(
        'OPENAI_API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz123456"\n',
        encoding="utf-8",
    )
    report = scan_path(tmp_path)
    md = render_markdown(report)
    html = render_html(report)
    for out in (md, html):
        assert "개인정보·비밀값 주의" in out  # 분야 상세 뒤의 콜아웃
        assert "재발급" in out  # 코드 삭제만으로 부족 — 재발급 안내


def test_pii_summary_absent_when_no_pii_findings() -> None:
    # SQL 인젝션만 있는 리포트 — 개인정보·비밀값 콜아웃은 나오지 않는다.
    report = scan_code(
        "q = input('q')\n"
        "cursor.execute(f\"SELECT * FROM t WHERE x = '{q}'\")\n",
        filename="db.py",
        language="python",
    )
    assert report.findings  # 전제: SQLi 발견 존재
    assert "개인정보·비밀값 주의" not in render_markdown(report)
    assert "개인정보·비밀값 요약" not in render_html(report)


def _same_line_two_rules_report() -> ScanReport:
    """같은 (파일, 줄)에 서로 다른 두 룰이 걸린 리포트(표시 dedupe 검증용)."""
    common = dict(
        title="t",
        severity=Severity.critical,
        decision=Decision.block,
        location=CodeLocation(file="app.py", line=9),
        why_it_matters="설명",
    )
    f1 = Finding(
        id="f1", rule_id="GOV-SECRET-APIKEY-001", plain_title="하드코딩된 API 키",
        category="secret-scanning", **common,
    )
    f2 = Finding(
        id="f2", rule_id="KISA-PY-SEC-06", plain_title="하드코딩된 비밀번호",
        category="secret-scanning", **common,
    )
    return ScanReport(
        target="app.py",
        summary=ScanSummary(
            finding_count=2,
            by_severity={"critical": 2},
            by_decision={"block": 2},
            highest_severity=Severity.critical,
            blocked=True,
        ),
        findings=[f1, f2],
        scanned_files=["app.py"],
    )


def test_summary_shows_finding_count_and_unique_locations() -> None:
    report = _same_line_two_rules_report()
    md = render_markdown(report)
    html = render_html(report)
    # 발견 2건 · 고유 위치 1곳 — 두 수치를 함께 표기해 이중 계상 오해 방지.
    assert "고유 위치" in md and "1곳" in md
    assert "고유 위치" in html and "1곳" in html


def test_same_line_multi_rule_grouped_in_display() -> None:
    report = _same_line_two_rules_report()
    md = render_markdown(report)
    html = render_html(report)
    for out in (md, html):
        assert "같은 줄 다중 지적" in out
        assert "관련 룰 2개" in out
        assert "GOV-SECRET-APIKEY-001" in out
        assert "KISA-PY-SEC-06" in out


def test_no_multi_rule_note_when_lines_unique() -> None:
    # 서로 다른 줄이면 다중 지적 안내가 나오지 않는다.
    report = _multi_finding_report()  # 같은 룰이 2, 3번째 줄 — 위치는 전부 고유
    assert "같은 줄 다중 지적" not in render_markdown(report)
    assert "같은 줄 다중 지적" not in render_html(report)


# ---------------------------------------------------------------------------
# ④ 배포 판정 + 잔여위험 + 결재 헤더/서명란
# ---------------------------------------------------------------------------


def test_deploy_verdict_block_when_block_findings() -> None:
    report = _report_with_findings()  # SQLi → block 포함
    md = render_markdown(report)
    html = render_html(report)
    for out in (md, html):
        assert "배포 판정" in out
        assert "배포 불가" in out
        assert "잔여 위험" in out


def test_deploy_verdict_clean_references_limits() -> None:
    clean = scan_code('print("hi")\n', filename="hi.py", language="python")
    md = render_markdown(clean)
    html = render_html(clean)
    for out in (md, html):
        assert "심각 위험 미발견" in out
        assert "잔여 위험" in out
        assert "검토 범위 및 한계" in out  # 판정문이 한계 고지를 참조


def test_deploy_verdict_undecidable_when_nothing_scanned() -> None:
    report = ScanReport(
        target="empty",
        summary=ScanSummary(finding_count=0, by_severity={}, by_decision={}),
        findings=[],
        scanned_files=[],
    )
    assert "판정 불가" in render_markdown(report)
    assert "판정 불가" in render_html(report)


def test_no_approval_artifacts_in_report() -> None:
    # 리포트는 공문 '붙임'으로 제출된다 — 결재는 상위 공문이 담당하므로
    # 리포트 자체에 결재 헤더·서명란이 있어서는 안 된다.
    report = _report_with_findings()
    md = render_markdown(report)
    html = render_html(report)
    for out in (md, html):
        assert "승인자" not in out
        assert "▢" not in out
        assert "## 결재" not in out


def test_render_call_backcompat() -> None:
    # 기존 호출부(cli.py·server.py)와 동일한 호출 방식이 그대로 동작한다.
    report = _report_with_findings()
    assert render_markdown(report, reproduce_command="gvskb scan app.py")
    assert render_html(report, reproduce_command="gvskb scan app.py")


# ---------------------------------------------------------------------------
# 의존성(패키지) 취약점 검사 — dependency_audit 병합 렌더
# ---------------------------------------------------------------------------


def _audit_with_vulns() -> dict:
    return {
        "audits": [{
            "ecosystem": "pypi", "manifest": "requirements.txt",
            "parsed_count": 2, "checked_count": 2, "unchecked_count": 0,
            "blocked": False, "requires_review": True, "verdict": "review_required",
            "checks": [
                {"name": "flask", "version": "0.12.2", "checked": True,
                 "is_malicious_package": False, "vulnerability_count": 7},
                {"name": "openai", "version": None, "checked": True,
                 "is_malicious_package": False, "vulnerability_count": 0},
            ],
        }],
    }


def test_dependency_audit_section_rendered_when_present() -> None:
    report = _report_with_findings()
    report.dependency_audit = _audit_with_vulns()
    md = render_markdown(report)
    html = render_html(report)
    for out in (md, html):
        assert "의존성(패키지) 취약점 검사" in out
        assert "flask" in out and "0.12.2" in out
        assert "취약점 7건" in out
    # 배너가 "별도 필요"가 아니라 결과 요약으로 대체된다
    assert "의존성 검사 별도 필요" not in md


def test_dependency_audit_absent_by_default() -> None:
    report = _report_with_findings()
    assert report.dependency_audit is None
    md = render_markdown(report)
    assert "의존성(패키지) 취약점 검사" not in md


def test_dependency_audit_unchecked_flagged_not_safe() -> None:
    report = _report_with_findings()
    report.dependency_audit = {
        "audits": [{
            "ecosystem": "pypi", "manifest": "requirements.txt",
            "parsed_count": 1, "checked_count": 0, "unchecked_count": 1,
            "blocked": False, "requires_review": True, "verdict": "review_required",
            "checks": [{"name": "requests", "version": "2.19.1", "checked": False}],
        }],
    }
    md = render_markdown(report)
    html = render_html(report)
    for out in (md, html):
        assert "판정 불가" in out
        assert "안전'이 아닙니다" in out or "안전'으로" in out


def test_dependency_audit_unparsed_lockfile_note() -> None:
    report = _report_with_findings()
    report.dependency_audit = {
        "ecosystem": "npm", "manifest": "yarn.lock", "verdict": "unparsed",
        "parsed_count": 0, "checked_count": 0, "unchecked_count": 0,
        "blocked": False, "requires_review": True, "checks": [],
        "note": "락파일 형식(yarn.lock)은 이 도구가 파싱하지 못합니다.",
    }
    md = render_markdown(report)
    assert "unparsed" in md
    assert "파싱 0건은 '안전'이 아닙니다" in md


# ---------------------------------------------------------------------------
# SARIF 2.1.0 — CI·보안도구 연동 출력
# ---------------------------------------------------------------------------


def test_render_sarif_minimal_valid_shape() -> None:
    from gvskb.report import render_sarif

    report = _report_with_findings()
    sarif = render_sarif(report)
    assert sarif["version"] == "2.1.0"
    assert "sarif-2.1.0" in sarif["$schema"]
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "vibecode-checker"
    rules = run["tool"]["driver"]["rules"]
    results = run["results"]
    assert results and rules
    # 모든 result의 ruleId/ruleIndex가 rules와 일치해야 한다
    ids = [r["id"] for r in rules]
    for res in results:
        assert res["ruleId"] == ids[res["ruleIndex"]]
        assert res["level"] in ("error", "warning", "note")
        loc = res["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"]
        assert loc["region"]["startLine"] >= 1


def test_render_sarif_block_maps_to_error_and_evidence_masked() -> None:
    import json

    from gvskb.report import render_sarif

    report = scan_code(
        'DB_PASSWORD = "SuperSecretValue123"\n', filename="a.py", language="python"
    )
    sarif = render_sarif(report)
    blob = json.dumps(sarif, ensure_ascii=False)
    assert '"level": "error"' in blob or any(
        r["level"] == "error" for r in sarif["runs"][0]["results"]
    )
    assert "SuperSecretValue123" not in blob  # SARIF에도 원문 비밀값 없음


def test_render_sarif_empty_findings_ok() -> None:
    from gvskb.report import render_sarif

    report = scan_code('print("hi")\n', filename="hi.py", language="python")
    sarif = render_sarif(report)
    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["properties"]["scanned_files"] == 1


# ---------------------------------------------------------------------------
# 보안 분야 분류 — 발견을 보안팀이 아는 '분야'로 묶어 두괄식 검토를 돕는다
# ---------------------------------------------------------------------------


def _domain_label(code: str, filename: str = "app.py", language: str = "python") -> set[str]:
    from gvskb.report import _security_domain
    from gvskb.scanner import scan_code

    r = scan_code(code, filename=filename, language=language)
    return {_security_domain(f)[1] for f in r.findings}


def test_domain_classifier_maps_sql_to_injection() -> None:
    labels = _domain_label(
        "q = input('q')\ncursor.execute(f\"SELECT * FROM t WHERE n='{q}'\")\n"
    )
    assert any("주입" in x for x in labels)


def test_domain_classifier_maps_secret_to_secret_domain() -> None:
    labels = _domain_label('DB_PASSWORD = "SuperSecretValue123"\n')
    assert any("비밀값" in x for x in labels)


def test_domain_classifier_maps_innerhtml_to_web() -> None:
    labels = _domain_label(
        'const h = "<p>"+c+"</p>";\ndocument.getElementById("b").innerHTML = h;\n',
        filename="ui.js", language="javascript",
    )
    assert any("웹" in x for x in labels)


def test_domain_classifier_maps_flask_debug_to_misconfig() -> None:
    labels = _domain_label('app.run(host="0.0.0.0", debug=True)\n')
    assert any("설정" in x for x in labels)


def test_group_by_domain_orders_and_counts() -> None:
    from gvskb.report import _group_by_domain
    from gvskb.scanner import scan_path
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "app.py"
        p.write_text(
            'DB_PASSWORD = "SuperSecretValue123"\n'
            "q = input('q')\n"
            'os.system("ls " + q)\n',
            encoding="utf-8",
        )
        report = scan_path(d)
    domains = _group_by_domain(report.findings)
    assert domains, "분야가 하나 이상 있어야 한다"
    # 정렬 순서(개인정보<비밀값<주입…)를 지킨다
    orders = [dm["order"] for dm in domains]
    assert orders == sorted(orders)
    # 각 분야 dict 필수 키
    for dm in domains:
        assert {"order", "label", "findings", "count", "files", "max_severity"} <= set(dm)
        assert dm["count"] == len(dm["findings"])


def test_domain_section_expandable_shows_location_and_fix() -> None:
    # 분야를 펼치면 위치·왜위험·대응방안이 보여야 한다(보안팀 세부 확인).
    report = _report_with_findings()
    html = render_html(report)
    # 분야 details 안에 발견 카드의 핵심 3요소
    assert "<details" in html
    assert "위치" in html or "line" in html
    assert "왜 위험한가" in html
    assert "안전한 수정 방향" in html


# ---------------------------------------------------------------------------
# 수정 프롬프트 복사 버튼 — '가장 쉬운 방법' 강조 + 인라인(외부 로딩 없음)
# ---------------------------------------------------------------------------


def test_fix_prompt_has_copy_buttons() -> None:
    html = render_html(_report_with_findings())
    # '가장 쉬운 방법' 강조 박스 + 복사 버튼
    assert 'class="easyfix"' in html
    assert "가장 쉬운 방법" in html
    # 유형별 프롬프트마다 복사 버튼(data-copy)
    assert html.count('class="copybtn"') >= 2
    assert "data-copy=" in html
    # 복사 동작은 인라인 스크립트로만(외부 로딩 없음)
    assert "<script>" in html
    assert "<script src" not in html.lower()
    assert "navigator.clipboard" in html


def test_copy_button_text_is_escaped() -> None:
    # data-copy 에 들어가는 프롬프트 텍스트도 이스케이프돼야 한다(속성 주입 방지).
    report = scan_code(
        'el.innerHTML = "<img src=x onerror=alert(1)>"\n',
        filename="x.js", language="javascript",
    )
    html = render_html(report)
    assert 'onerror=alert(1)>"' not in html  # 원문 그대로 삽입 금지
    assert "&lt;img" in html or "&quot;" in html
