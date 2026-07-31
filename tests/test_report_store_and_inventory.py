"""보고서 저장 규약 + 외부 연결 분류 + 제외 사유 표시 — 회귀 방지.

실측 문제 기반:
1. 보고서가 어디에도 저장되지 않아 결재 첨부용 파일이 남지 않던 문제
2. 외부 호스트가 전부 '기타'로 뭉뚱그려져 성격을 알 수 없던 문제
3. 제외 파일 148건이 한 줄로 뭉개지거나 확장자마다 그룹이 쪼개지던 문제
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest

from gvskb.report import render_html, render_markdown
from gvskb.report_store import (
    REPORT_DIR_NAME,
    ensure_writable,
    report_dir_for,
    resolve_report_path,
)
from gvskb.scanners.external_surface import _lookup_host
from gvskb.schema import ExternalConnection, ScanReport, ScanSummary, SkippedFile


def _empty_report(**kw) -> ScanReport:
    base = dict(
        target="proj",
        summary=ScanSummary(finding_count=0, by_severity={}, by_decision={}),
        findings=[],
    )
    base.update(kw)
    return ScanReport(**base)


# ---------------------------------------------------------------------------
# 1. 보고서 저장 규약
# ---------------------------------------------------------------------------


def test_report_dir_is_next_to_project(tmp_path: Path, monkeypatch) -> None:
    """기본 위치는 <프로젝트>/.check-reports — 공무원이 찾을 수 있는 곳."""
    monkeypatch.delenv("GVSKB_REPORT_DIR", raising=False)
    assert report_dir_for(tmp_path) == tmp_path / REPORT_DIR_NAME


def test_report_dir_for_single_file_uses_parent(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("GVSKB_REPORT_DIR", raising=False)
    f = tmp_path / "app.py"
    f.write_text("x = 1\n", encoding="utf-8")
    assert report_dir_for(f) == tmp_path / REPORT_DIR_NAME


def test_env_override_wins(tmp_path: Path, monkeypatch) -> None:
    """기관 공용 폴더 지정 — 보안담당자가 이력을 한곳에서 본다."""
    shared = tmp_path / "공용"
    monkeypatch.setenv("GVSKB_REPORT_DIR", str(shared))
    assert report_dir_for(tmp_path / "any") == shared


def test_filename_has_date_and_time(tmp_path: Path, monkeypatch) -> None:
    """조치 전/후 비교가 필요하므로 이력이 덮어써지면 안 된다."""
    monkeypatch.delenv("GVSKB_REPORT_DIR", raising=False)
    now = datetime(2026, 7, 31, 15, 30)
    p = resolve_report_path(tmp_path, now=now)
    assert p.name == "2026-07-31_1530_보안점검"
    assert p.parent.name == REPORT_DIR_NAME


def test_explicit_output_is_respected(tmp_path: Path, monkeypatch) -> None:
    """사용자가 -o 로 준 경로는 규약보다 우선한다."""
    monkeypatch.setenv("GVSKB_REPORT_DIR", str(tmp_path / "무시됨"))
    p = resolve_report_path(tmp_path, explicit=str(tmp_path / "내보고서"))
    assert p == tmp_path / "내보고서"


def test_ensure_writable_creates_dir(tmp_path: Path) -> None:
    base = tmp_path / REPORT_DIR_NAME / "2026-07-31_1530_보안점검"
    got, note = ensure_writable(base)
    assert got == base
    assert note is None
    assert base.parent.is_dir()


def test_cli_saves_without_output_flag(tmp_path: Path, monkeypatch) -> None:
    """-o 없이도 규약 위치에 저장돼야 한다(예전에는 화면으로 흘려보내 사라졌다)."""
    monkeypatch.delenv("GVSKB_REPORT_DIR", raising=False)
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    from gvskb.cli import main

    rc = main(["scan", str(tmp_path), "--fail-on", "never"])
    assert rc == 0
    saved = list((tmp_path / REPORT_DIR_NAME).glob("*_보안점검.html"))
    assert saved, "기본 저장이 되지 않았다"
    assert (tmp_path / REPORT_DIR_NAME / saved[0].name).with_suffix(".md").exists()


def test_cli_stdout_flag_skips_saving(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.delenv("GVSKB_REPORT_DIR", raising=False)
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    from gvskb.cli import main

    main(["scan", str(tmp_path), "--stdout", "--fail-on", "never"])
    assert not (tmp_path / REPORT_DIR_NAME).exists()
    assert capsys.readouterr().out.strip(), "화면 출력이 비었다"


def test_mcp_save_report_writes_three_formats(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("GVSKB_REPORT_DIR", str(tmp_path / "out"))
    from gvskb.server import save_report

    result = save_report(report=_empty_report().model_dump(mode="json"))
    assert set(result["saved"]) == {"markdown", "html", "json"}
    for path in result["saved"].values():
        assert Path(path).is_file()


def test_mcp_save_report_rejects_bad_input() -> None:
    from gvskb.server import save_report

    assert "error" in save_report(report={"not": "a report"})


def test_render_report_saves_by_default(tmp_path: Path, monkeypatch) -> None:
    """실측 문제: 에이전트가 render_report 의 문자열을 받아 **자기 방식으로**
    저장해 규약 밖 위치·이름의 보고서가 생겼다(Codex·Claude·Cursor 공통).
    지시문에 기대지 않고 도구가 직접 저장해야 규약이 지켜진다."""
    monkeypatch.setenv("GVSKB_REPORT_DIR", str(tmp_path / "out"))
    from gvskb.server import render_report

    out = render_report(report=_empty_report().model_dump(mode="json"), format="both")
    assert "saved" in out, "render_report 가 저장하지 않았다"
    for path in out["saved"].values():
        assert Path(path).is_file()
    # 에이전트가 다시 저장하지 않도록 반환값이 분명히 말해야 한다.
    assert "다시 저장하지 마세요" in out["note"]


def test_render_report_save_false_returns_content_only(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("GVSKB_REPORT_DIR", str(tmp_path / "out"))
    from gvskb.server import render_report

    out = render_report(report=_empty_report().model_dump(mode="json"), save=False)
    assert "saved" not in out
    assert out["content"]
    assert not (tmp_path / "out").exists()


def test_render_report_description_warns_against_double_save() -> None:
    """도구 설명(에이전트가 실제로 읽는 것)에 규약이 들어 있어야 한다 —
    MCP instructions 만으로는 클라이언트에 따라 무시된다."""
    from gvskb.server import render_report

    doc = render_report.__doc__ or ""
    assert "다시 저장하지 마세요" in doc
    assert ".check-reports" in doc


def test_report_dir_is_excluded_from_scanning() -> None:
    """보고서 폴더는 스캔 제외 목록에 있어야 한다 — 두 상수가 어긋나면 자기 참조가 난다."""
    from gvskb.scanner import DEFAULT_EXCLUDE_DIRS

    assert REPORT_DIR_NAME in DEFAULT_EXCLUDE_DIRS


def test_saved_report_is_not_rescanned(tmp_path: Path, monkeypatch) -> None:
    """실측 결함: 저장한 보고서에 인용된 증거(PEM 헤더)를 재검사에서 새 위험으로
    잡아 발견이 계속 증식했다."""
    monkeypatch.delenv("GVSKB_REPORT_DIR", raising=False)
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    reports = tmp_path / REPORT_DIR_NAME
    reports.mkdir()
    (reports / "old.md").write_text(
        "증거: -----BEGIN PRIVATE KEY-----\n", encoding="utf-8"
    )
    from gvskb.scanner import scan_path

    report = scan_path(tmp_path)
    assert not [f for f in report.findings if REPORT_DIR_NAME in f.location.file]
    assert not [s for s in report.scanned_files if REPORT_DIR_NAME in s]


# ---------------------------------------------------------------------------
# 2. 외부 연결 분류
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("host,expected_cat", [
    ("acme-v02.api.letsencrypt.org", "infra"),
    ("api.ipify.org", "infra"),
    ("cdn.jsdelivr.net", "cdn"),
    ("fonts.googleapis.com", "cdn"),
    ("apis.data.go.kr", "gov-api"),
    ("dapi.kakao.com", "platform"),
    ("api.openai.com", "ai"),
])
def test_known_hosts_are_classified(host: str, expected_cat: str) -> None:
    """실측에서 전부 '기타'로 떨어지던 호스트들이 제 성격으로 분류돼야 한다."""
    cat, _summary, _region, _oper = _lookup_host(host)
    assert cat == expected_cat


@pytest.mark.parametrize("host,expected_cat", [
    ("cdn.mycompany.io", "cdn"),          # 접미사 추정
    ("static.example.com", "cdn"),
    ("api.unknown-service.com", "api"),
    ("someservice.go.kr", "gov-api"),
])
def test_heuristic_fallback_classifies(host: str, expected_cat: str) -> None:
    cat, summary, region, oper = _lookup_host(host)
    assert cat == expected_cat
    assert "추정" in summary          # 근거가 약함을 문구로 명시
    assert region is None and oper is None   # 추정은 국가·주체를 단정하지 않는다


def test_truly_unknown_host_is_unclassified() -> None:
    cat, summary, _r, _o = _lookup_host("totally.random.host")
    assert cat == "unclassified"
    assert "확인 필요" in summary


def test_unclassified_label_is_not_기타() -> None:
    """'기타'는 카테고리가 아니라 '분류 안 됨'이었다 — 정직하게 표기한다."""
    from gvskb.report import _cat_ko

    assert _cat_ko("unclassified") == "미분류"
    assert _cat_ko("infra") == "인프라"
    assert _cat_ko("gov-api") == "공공 API"


def test_ipify_summary_warns_about_ip_exposure() -> None:
    _c, summary, _r, _o = _lookup_host("api.ipify.org")
    assert "공인 IP" in summary


# ---------------------------------------------------------------------------
# 3. 표 가독성 — 모델 컬럼 통합
# ---------------------------------------------------------------------------


def _report_with_api(model: str | None = None) -> ScanReport:
    return _empty_report(external_surface=[ExternalConnection(
        kind="api", target="api.openai.com", category="ai",
        data_summary="프롬프트 텍스트", region="국외", operator="OpenAI(미국)",
        location="app.py:10", model=model,
    )])


def test_markdown_table_has_no_model_column() -> None:
    md = render_markdown(_report_with_api())
    assert "| 대상(호스트) | 종류 | 위치 | 이용 정보 | 국외이전(운영주체) | 검토 |" in md


def test_model_is_merged_into_info_column() -> None:
    md = render_markdown(_report_with_api(model="gpt-4o"))
    assert "모델 gpt-4o" in md


def test_html_table_declares_column_widths() -> None:
    """자동 배분은 긴 경로가 공간을 먹고 '이용 정보'를 찌그러뜨린다."""
    html = render_html(_report_with_api())
    assert "<colgroup>" in html
    assert "extbl" in html


# ---------------------------------------------------------------------------
# 4. 제외 사유 분류
# ---------------------------------------------------------------------------


def test_skip_breakdown_groups_by_reason() -> None:
    report = _empty_report(skipped_files=[
        SkippedFile(path=f"a{i}.pdf", reason="검사 대상 확장자 아님(.pdf) — 검사되지 않았습니다")
        for i in range(3)
    ] + [
        SkippedFile(path="b.png", reason="검사 대상 확장자 아님(.png) — 검사되지 않았습니다"),
        SkippedFile(path="c.min.js", reason="빌드 산출물(압축/번들) — 원본 아님"),
        SkippedFile(path="big.py", reason="too large (999999 bytes)"),
    ])
    md = render_markdown(report)
    # 확장자마다 그룹이 쪼개지지 않고 하나로 합쳐져야 한다(.pdf 3 + .png 1 = 4).
    assert "검사 대상 확장자 아님 4" in md
    assert "검사 제외: **6건**" in md


def test_skip_breakdown_warns_not_scanned_means_not_safe() -> None:
    report = _empty_report(skipped_files=[
        SkippedFile(path="key.pdf", reason="검사 대상 확장자 아님(.pdf) — 검사되지 않았습니다"),
    ])
    md = render_markdown(report)
    assert "검사되지 않았다는 뜻" in md


def test_skip_breakdown_warns_on_max_files() -> None:
    report = _empty_report(skipped_files=[
        SkippedFile(path="root", reason="max_files=500 reached"),
    ])
    md = render_markdown(report)
    assert "일부만 검사" in md


def test_no_skip_section_when_nothing_skipped() -> None:
    assert "검사 제외:" not in render_markdown(_empty_report())
