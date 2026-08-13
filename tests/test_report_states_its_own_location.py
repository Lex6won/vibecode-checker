"""보고서는 **자기가 어디 저장됐는지** 말해야 한다.

실사용 지적(2026-08-09):

> *"항상 정확한 파일 위치를 알려줘. 사용자들에게 마찬가지야. 최종 점검 후에는
> 파일위치 풀 경로를 제공해줘야해 사용자들은 몰라. 기억을 못해."*

저장 경로는 CLI 의 stderr 한 줄과 MCP 응답의 `saved` 필드로만 나갔다. 그 줄을
놓치거나, 나중에 파일만 전달받거나, 며칠 뒤 다시 찾는 사람은 **원본이 어디
있는지 알 방법이 없었다.** 결재로 올라가고 감사에 인용되는 문서가 자기 출처를
말하지 않고 있었다.
"""

from __future__ import annotations

from pathlib import Path

from gvskb.report import render_html, render_markdown
from gvskb.scanner import scan_code

_PATH = r"C:\기관\사업\.check-reports\2026-08-09_1716_보안점검.md"


def _report():
    return scan_code("eval(user_input)", filename="a.py")


def test_markdown_carries_its_own_path() -> None:
    md = render_markdown(_report(), saved_path=_PATH)
    assert "이 보고서 위치" in md
    assert _PATH in md


def test_html_carries_its_own_path() -> None:
    html_doc = render_html(_report(), saved_path=_PATH)
    assert "이 보고서 위치" in html_doc
    assert "2026-08-09_1716_보안점검.md" in html_doc


def test_no_path_row_when_not_saved() -> None:
    """화면으로만 흘려보낼 때는 저장 경로가 없다 — 없는 것을 있다고 적지 않는다."""
    assert "이 보고서 위치" not in render_markdown(_report())
    assert "이 보고서 위치" not in render_html(_report())


def test_cli_writes_the_real_path_into_the_file(tmp_path: Path) -> None:
    """서명만 맞추고 호출부를 안 고치는 실수를 잡는다 — 실제 파일 내용을 읽는다."""
    import argparse

    from gvskb.cli import _emit_doc_report

    src = tmp_path / "app.py"
    src.write_text("eval(user_input)\n", encoding="utf-8")
    out = tmp_path / ".check-reports" / "보안점검"

    _emit_doc_report(
        scan_code(src.read_text(encoding="utf-8"), filename=str(src)),
        fmt="markdown", output=str(out), reproduce_command=None,
    )
    md_path = out.with_suffix(".md")
    body = md_path.read_text(encoding="utf-8")
    assert str(md_path) in body, "문서가 자기 경로를 담고 있지 않다"
    # HTML 도 같은 경로(마크다운 원본)를 가리켜야 한다 — 둘은 한 쌍이다.
    assert str(md_path) in out.with_suffix(".html").read_text(encoding="utf-8")
    assert isinstance(argparse.Namespace(), argparse.Namespace)  # import 고정


def test_mcp_save_report_writes_the_path_into_the_file(tmp_path: Path) -> None:
    from gvskb import server

    fn = getattr(server.save_report, "fn", server.save_report)
    report = scan_code("eval(user_input)", filename=str(tmp_path / "a.py"))
    result = fn(report=report.model_dump(mode="json"), output_dir=str(tmp_path / "out"))

    assert "saved" in result, result
    md_path = result["saved"]["markdown"]
    assert md_path in Path(md_path).read_text(encoding="utf-8")
    assert md_path in Path(result["saved"]["html"]).read_text(encoding="utf-8")
