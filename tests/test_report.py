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
