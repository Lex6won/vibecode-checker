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
    assert "## 파일별 발견 사항" in md
    assert "## 면책" in md
    assert "GOV-SQL-INJECTION-001" in md
    assert "app.py" in md
    # severity label rendered in Korean
    assert "치명" in md or "높음" in md


def test_render_markdown_empty_findings_clean_message() -> None:
    report = scan_code('print("hello")\n', filename="hello.py", language="python")
    md = render_markdown(report)

    assert "## 파일별 발견 사항" not in md
    assert "발견된 위험이 없습니다" in md
    assert "## 면책" in md


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
    assert "차단 권고" in head or "수정 권고" in head or "위험 없음" in head


def test_render_markdown_empty_findings_verdict_is_clean() -> None:
    report = scan_code('print("hi")\n', filename="hi.py", language="python")
    md = render_markdown(report)
    head = md.split("## 면책")[0]
    assert "위험 없음" in head


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
    for tag in ("<script", "<iframe", "<link", "<img", "<object", "<embed"):
        assert tag not in lower, f"외부 로딩 가능 태그 발견: {tag}"
    assert "@import" not in lower
    assert "url(http" not in lower


def test_render_html_includes_findings_and_safe_fix() -> None:
    html = render_html(_report_with_findings())
    assert 'class="card"' in html
    assert "왜 위험한가" in html
    assert "안전한 수정 방향" in html
    assert "app.py" in html
    assert "면책" in html


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
    assert "위험 없음" in html
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
    for tag in ("<script", "<link", "<img", "<iframe"):
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


def test_render_html_has_one_page_summary_sections() -> None:
    html = render_html(_report_with_findings())
    for section in (
        "한눈에 보기",
        "위험 유형",
        "파일별 위험 요약",
        "가장 먼저 할 일",
        "파일별 상세",
        "수정 프롬프트",
    ):
        assert section in html, f"누락된 1페이지 요약 섹션: {section}"
    # 스탯 카드 4종 + 파일 상세로 점프하는 앵커
    assert "검사한 파일" in html
    assert 'class="stat"' in html
    assert 'href="#file-0"' in html
    assert "<details" in html  # 순수 CSS 접기


def test_render_html_uses_pure_css_details_no_js() -> None:
    html = render_html(_report_with_findings())
    assert "<details" in html and "<summary" in html
    # 접기 동작에 외부/인라인 JS 를 쓰지 않는다(자체포함 원칙 유지).
    assert "<script" not in html.lower()
    assert "onclick" not in html.lower()


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


def test_render_markdown_has_type_and_file_summary_and_prompts() -> None:
    md = render_markdown(_report_with_findings())
    assert "## 위험 유형" in md
    assert "## 파일별 위험 요약" in md
    assert "## 가장 먼저 할 일" in md
    assert "## 수정 프롬프트" in md
    assert "## 파일별 발견 사항" in md  # 세부 헤더 보존


def test_render_markdown_dedupes_same_rule_into_one_block() -> None:
    md = render_markdown(_multi_finding_report())
    # 같은 룰은 한 번만 설명되고 위치는 목록으로 합쳐진다("2건").
    head = md.split("## 수정 프롬프트")[0]
    assert "## 파일별 발견 사항" in head
    assert "2건" in md


# ---------------------------------------------------------------------------
# 초보자용 "다음 할 일" 행동 안내 — 결과 받고 무엇을 할지 바로 알려준다
# ---------------------------------------------------------------------------


def test_render_html_has_beginner_action_box() -> None:
    html = render_html(_report_with_findings())
    assert "다음 3단계만 하세요" in html
    assert 'class="actionbox"' in html
    # 자기가 쓰던 AI 도구에 그대로 말하는 흐름 + 키 노출 코드외 조치 경고
    assert "안전하게 고쳐줘" in html
    assert "다시 검사" in html
    assert "새로 발급" in html
    # 수정 프롬프트 섹션도 '가장 쉬운 방법'을 맨 앞에서 안내
    assert "가장 쉬운 방법" in html


def test_render_markdown_has_beginner_action_box() -> None:
    md = render_markdown(_report_with_findings())
    head = md.split("## 요약")[0]  # 결론 직후, 요약보다 위에 위치
    assert "다음 3단계만 하세요" in head
    assert "안전하게 고쳐줘" in head
    assert "새로 발급" in head


def test_action_box_absent_when_no_findings() -> None:
    clean = scan_code('print("hi")\n', filename="hi.py", language="python")
    assert "다음 3단계" not in render_html(clean)
    assert "다음 3단계" not in render_markdown(clean)


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
    # 상단부(부록 아님): 파일별 상세보다 앞에 위치
    assert md.index("검토 범위 및 한계") < md.index("## 파일별 발견 사항")
    assert html.index("검토 범위 및 한계") < html.index("파일별 상세")


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
        assert "개인정보·비밀값 요약" in out
        assert "재발급" in out  # 코드 삭제만으로 부족 — 재발급 안내


def test_pii_summary_absent_when_no_pii_findings() -> None:
    # SQL 인젝션만 있는 리포트 — 개인정보·비밀값 섹션은 나오지 않는다.
    report = scan_code(
        "q = input('q')\n"
        "cursor.execute(f\"SELECT * FROM t WHERE x = '{q}'\")\n",
        filename="db.py",
        language="python",
    )
    assert report.findings  # 전제: SQLi 발견 존재
    assert "개인정보·비밀값 요약" not in render_markdown(report)
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


def test_approval_header_and_signature_when_params_given() -> None:
    report = _report_with_findings()
    md = render_markdown(
        report, agency="경기도", department="AI국", author="원준석",
        doc_no="제2026-42호", reviewer="김보안",
    )
    for token in ("경기도", "AI국", "원준석", "제2026-42호", "김보안"):
        assert token in md
    assert "## 결재" in md
    assert "검토자" in md and "승인자" in md and "▢" in md
    html = render_html(
        report, agency="경기도", department="AI국", author="원준석",
        doc_no="제2026-42호", reviewer="김보안",
    )
    for token in ("경기도", "AI국", "원준석", "제2026-42호", "김보안"):
        assert token in html
    assert "승인자" in html and "▢" in html


def test_approval_params_are_escaped_in_html() -> None:
    html = render_html(_report_with_findings(), agency='<img src=x onerror=1>')
    assert "<img" not in html.lower()
    assert "&lt;img" in html


def test_no_approval_artifacts_without_params() -> None:
    # 파라미터 미지정 시 기존과 동일 렌더 — 결재 헤더·서명란 없음(하위호환).
    report = _report_with_findings()
    md = render_markdown(report)
    html = render_html(report)
    for out in (md, html):
        assert "승인자" not in out
        assert "▢" not in out


def test_render_signatures_backcompat_positional_free() -> None:
    # 기존 호출부(cli.py·server.py)와 동일한 호출 방식이 그대로 동작한다.
    report = _report_with_findings()
    assert render_markdown(report, reproduce_command="gvskb scan app.py")
    assert render_html(report, reproduce_command="gvskb scan app.py")
