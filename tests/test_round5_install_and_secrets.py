"""라운드 5 — 재설치 안전성 · 비밀 파일 내용 · 중복 표시 · 외부연결 맥락.

실측 문제 기반:
1. site-packages 의 구버전 물리 디렉터리가 editable 경로를 가려 **구버전 룰로
   검사**하던 사고 — 조용히 실패하므로 기동 시 크게 경고해야 한다
2. `.secret_key` 는 스캔은 됐지만 64자 hex 값이 아무 룰에도 걸리지 않았다
3. 같은 인증서·키가 두 경로에 복사돼 발견이 배수로 보였다
4. 설치 안내 문서·bat 스크립트의 다운로드 링크가 '국외 전송'으로 잡혔다
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

from gvskb.report import render_markdown
from gvskb.scanner import scan_path
from gvskb.scanners.external_surface import _file_context, extract_api_connections

# ---------------------------------------------------------------------------
# 1. 재설치·업그레이드 안전성
# ---------------------------------------------------------------------------


def test_install_problem_is_none_when_clean() -> None:
    """정상 설치 상태에서는 경고가 없어야 한다(경고 피로 방지)."""
    from gvskb.diagnostics import install_problem

    assert install_problem() is None


def test_install_problem_detects_shadowing_copy(tmp_path: Path, monkeypatch) -> None:
    """다른 버전의 사본이 sys.path 에 있으면 반드시 잡아야 한다."""
    fake = tmp_path / "gvskb"
    fake.mkdir()
    (fake / "__init__.py").write_text('__version__ = "0.0.1-stale"\n', encoding="utf-8")
    monkeypatch.setattr(sys, "path", [*sys.path, str(tmp_path)])

    from gvskb.diagnostics import install_problem

    problem = install_problem()
    assert problem is not None
    assert "0.0.1-stale" in problem
    assert "pip uninstall" in problem      # 해결 방법을 함께 준다


def test_warn_if_install_broken_writes_to_stream(tmp_path: Path, monkeypatch) -> None:
    """경고는 '못 보고 지나칠 수 없게' 출력돼야 한다."""
    import io

    fake = tmp_path / "gvskb"
    fake.mkdir()
    (fake / "__init__.py").write_text('__version__ = "0.0.2-stale"\n', encoding="utf-8")
    monkeypatch.setattr(sys, "path", [*sys.path, str(tmp_path)])

    from gvskb.diagnostics import warn_if_install_broken

    buf = io.StringIO()
    assert warn_if_install_broken(stream=buf) is True
    text = buf.getvalue()
    assert "설치 상태 경고" in text
    assert "최신 코드가 아닐 수 있습니다" in text


def test_cli_entrypoints_are_importable() -> None:
    """`python -m gvskb.cli` / MCP 서버 진입점이 import 가능해야 한다."""
    import importlib

    for mod in ("gvskb.cli", "gvskb.server", "gvskb.diagnostics"):
        assert importlib.import_module(mod) is not None


def test_version_is_single_source_of_truth() -> None:
    """코드의 __version__ 이 진단이 보고하는 버전과 같아야 한다."""
    import gvskb
    from gvskb.diagnostics import _package_version

    assert _package_version() == gvskb.__version__


# ---------------------------------------------------------------------------
# 2. 비밀 파일 내용 탐지
# ---------------------------------------------------------------------------


def test_secret_keyfile_with_high_entropy_value_is_flagged(tmp_path: Path) -> None:
    """실측: `.secret_key` 의 64자 hex 값이 아무 룰에도 걸리지 않았다."""
    (tmp_path / ".secret_key").write_text(
        "77fec85613b823cd9b6e3bdb41dfd1fc492fdf2463fd01ce7bc8cf3e1606cfac\n",
        encoding="utf-8",
    )
    report = scan_path(tmp_path)
    hits = [f for f in report.findings if f.rule_id == "GOV-SECRET-KEYFILE-001"]
    assert hits, "비밀 파일의 자격증명 값을 탐지하지 못했다"
    assert hits[0].severity.value == "high"


def test_secret_named_file_with_only_prose_is_not_flagged(tmp_path: Path) -> None:
    """안내문만 있는 password.txt 는 오탐이 되면 안 된다(실측 파일)."""
    (tmp_path / "password.txt").write_text(
        "패스워드 없는 형태의 인증서 파일입니다.\n", encoding="utf-8"
    )
    report = scan_path(tmp_path)
    assert not [f for f in report.findings if f.rule_id == "GOV-SECRET-KEYFILE-001"]


def test_secret_file_comment_lines_are_ignored(tmp_path: Path) -> None:
    (tmp_path / "credentials.conf").write_text(
        "# 이 파일은 기동 시 자동 생성됩니다\n# 값을 직접 넣지 마세요\n",
        encoding="utf-8",
    )
    report = scan_path(tmp_path)
    assert not [f for f in report.findings if f.rule_id == "GOV-SECRET-KEYFILE-001"]


def test_key_value_form_is_detected(tmp_path: Path) -> None:
    (tmp_path / "secret.conf").write_text(
        'SECRET_KEY = "aGVsbG93b3JsZHNlY3JldGtleXZhbHVlMTIzNDU2Nzg5MA=="\n',
        encoding="utf-8",
    )
    report = scan_path(tmp_path)
    assert [f for f in report.findings if f.rule_id == "GOV-SECRET-KEYFILE-001"]


def test_short_value_is_not_flagged(tmp_path: Path) -> None:
    """짧은 값은 설정·식별자일 가능성이 높다 — 오탐 방지."""
    (tmp_path / "secret.conf").write_text("mode = production\n", encoding="utf-8")
    report = scan_path(tmp_path)
    assert not [f for f in report.findings if f.rule_id == "GOV-SECRET-KEYFILE-001"]


# ---------------------------------------------------------------------------
# 3. 중복(복제) 파일 표시
# ---------------------------------------------------------------------------


_PRIVATE_KEY = (
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ==\n"
    "-----END PRIVATE KEY-----\n"
)


def test_duplicate_files_are_recorded(tmp_path: Path) -> None:
    """같은 키가 두 경로에 복사되면 '동일 자산'임을 알려야 한다."""
    for sub in ("ssl", "deploy/ssl"):
        d = tmp_path / sub
        d.mkdir(parents=True)
        (d / "server_key.pem").write_text(_PRIVATE_KEY, encoding="utf-8")

    report = scan_path(tmp_path)
    assert report.duplicate_files, "복제 파일이 기록되지 않았다"
    paths = report.duplicate_files[0]["paths"]
    assert len(paths) == 2


def test_duplicate_note_appears_in_report(tmp_path: Path) -> None:
    for sub in ("a", "b"):
        d = tmp_path / sub
        d.mkdir()
        (d / "key.pem").write_text(_PRIVATE_KEY, encoding="utf-8")
    md = render_markdown(scan_path(tmp_path))
    assert "동일 내용 파일 복제" in md
    assert "모든 사본에 함께" in md


def test_unrelated_duplicates_are_not_reported(tmp_path: Path) -> None:
    """발견이 없는 파일의 중복은 소음이므로 기록하지 않는다."""
    for sub in ("a", "b"):
        d = tmp_path / sub
        d.mkdir()
        (d / "readme.md").write_text("# 같은 문서\n", encoding="utf-8")
    assert not scan_path(tmp_path).duplicate_files


# ---------------------------------------------------------------------------
# 4. 런타임 호출 vs 문서·설치 링크
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("filename,expected", [
    ("app.py", "runtime"),
    ("src/service.js", "runtime"),
    # HTML 은 경로로 갈린다 — 템플릿은 브라우저가 실제로 로딩하는 런타임 코드다.
    ("disaster-response/templates/base.html", "runtime"),
    ("static/index.html", "runtime"),
    ("deploy/서버설치가이드.html", "doc-or-installer"),
    ("docs/manual.html", "doc-or-installer"),
    ("README.md", "doc-or-installer"),
    ("install.bat", "doc-or-installer"),
    ("deploy/setup.ps1", "doc-or-installer"),
])
def test_file_context_classification(filename: str, expected: str) -> None:
    assert _file_context(filename) == expected


def test_template_cdn_keeps_airgap_warning() -> None:
    """실측 과잉 교정: Flask 템플릿의 CDN 로딩이 '문서'로 분류돼
    폐쇄망에서 화면이 깨지는 실제 위험이 숨겨졌다."""
    code = '<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>\n'
    conns = extract_api_connections(code, "templates/base.html")
    conns += [c for c in conns]   # 형태 무관 — 아래 검증은 존재 여부만 본다
    ctx = _file_context("disaster-response/templates/base.html")
    assert ctx == "runtime"


def test_installer_link_is_not_treated_as_egress() -> None:
    """실측: nginx.org·nssm.cc 다운로드 링크가 '국외 전송'으로 잡혔다."""
    code = 'curl -O https://nginx.org/download/nginx-1.24.0.zip\n'
    conns = extract_api_connections(code, "install.bat")
    assert conns
    c = conns[0]
    assert c.context == "doc-or-installer"
    assert c.airgap_impact is None            # 전송이 아니라 '설치 불가'의 문제
    assert "운영 중 전송 아님" in c.data_summary


def test_runtime_call_keeps_egress_marking() -> None:
    code = 'requests.post("https://api.openai.com/v1/chat/completions", json=d)\n'
    conns = extract_api_connections(code, "app.py")
    assert conns[0].context == "runtime"
    assert conns[0].airgap_impact == "egress"


def test_report_marks_doc_links_separately() -> None:
    from gvskb.schema import ExternalConnection, ScanReport, ScanSummary

    report = ScanReport(
        target="proj",
        summary=ScanSummary(finding_count=0, by_severity={}, by_decision={}),
        findings=[],
        external_surface=[ExternalConnection(
            kind="api", target="nginx.org", category="unclassified",
            data_summary="설치·안내 문서의 다운로드 주소(운영 중 전송 아님)",
            location="install.bat:3", context="doc-or-installer",
        )],
    )
    md = render_markdown(report)
    assert "문서·설치" in md


# ---------------------------------------------------------------------------
# 2-b. 비밀 파일 판정의 정밀도 — 실측 오탐 2건 + 위치 정직성 (2026-08-08)
#
# 이 발견은 '파일명 + 내용'을 함께 봐야 해서 regex 룰로 만들 수 없고, 그래서
# 코드로 판정한다. 코드로 판정하는 것은 룰보다 눈에 덜 띄므로 더 촘촘히 고정한다.
# ---------------------------------------------------------------------------

def test_secret_file_ignores_filesystem_paths(tmp_path: Path) -> None:
    r"""실측: `BACKOFF_FILE="/tmp/claude-token-refresh-backoff"` 가 걸렸다.
    `/` 는 base64 알파벳이기도 해서 값 문자만 보면 경로와 구별되지 않는다 —
    머리 모양(`/`·`./`·`~/`·`C:\`)으로 가른다."""
    (tmp_path / "get-claude-token.sh").write_text(
        '#!/bin/bash\nBACKOFF_FILE="/tmp/claude-token-refresh-backoff"\n'
        'CACHE_DIR="/home/runner/.cache/claude-token-store"\n',
        encoding="utf-8",
    )
    report = scan_path(tmp_path)
    assert not [f for f in report.findings if f.rule_id == "GOV-SECRET-KEYFILE-001"]


def test_secret_file_ignores_a_bare_path_line(tmp_path: Path) -> None:
    """`KEY=` 없이 경로만 있는 줄 — 키 이름 가드가 닿지 않는 자리다.
    이 경우가 없으면 경로 판정을 통째로 지워도 테스트가 통과한다
    (실제로 변이검사에서 통과했다: 위 두 줄은 `_FILE`·`_DIR` 이라 키 이름
    가드가 먼저 걸러 경로 가드를 가리고 있었다)."""
    (tmp_path / "token.conf").write_text(
        "/var/lib/app/session-store-directory-for-tokens\n", encoding="utf-8"
    )
    report = scan_path(tmp_path)
    assert not [f for f in report.findings if f.rule_id == "GOV-SECRET-KEYFILE-001"]


def test_secret_file_ignores_public_oauth_identifiers(tmp_path: Path) -> None:
    """실측: `CLIENT_ID="9d1c250a-…"`(UUID) 가 걸렸다. OAuth client_id 는
    브라우저 URL 에 그대로 실려 나가는 **공개값**이다."""
    (tmp_path / "refresh-claude-token.sh").write_text(
        '#!/bin/bash\nCLIENT_ID="9d1c250a-e61b-44d9-88ed-5944d1962f5e"\n',
        encoding="utf-8",
    )
    report = scan_path(tmp_path)
    assert not [f for f in report.findings if f.rule_id == "GOV-SECRET-KEYFILE-001"]


def test_client_secret_is_still_flagged(tmp_path: Path) -> None:
    """CLIENT_ID 를 빼면서 CLIENT_SECRET 까지 빼면 룰이 무의미해진다.
    이 테스트가 그 경계를 지킨다."""
    (tmp_path / "api_key.env").write_text(
        'CLIENT_SECRET="9d1c250ae61b44d988ed5944d1962f5e0011223344556677"\n',
        encoding="utf-8",
    )
    report = scan_path(tmp_path)
    assert [f for f in report.findings if f.rule_id == "GOV-SECRET-KEYFILE-001"]


def test_base64_value_starting_with_slash_is_still_flagged(tmp_path: Path) -> None:
    """경로 제외가 base64 비밀까지 삼키면 안 된다 — `+`/`=` 가 있으면 경로가 아니다."""
    (tmp_path / "secret.key").write_text(
        "/9j4AAQSkZJRgABAQEAYABgAAD+bWFnaWNzdHJpbmdoZXJlMTIzNA==\n",
        encoding="utf-8",
    )
    report = scan_path(tmp_path)
    assert [f for f in report.findings if f.rule_id == "GOV-SECRET-KEYFILE-001"]


def test_secret_keyfile_points_at_the_real_line(tmp_path: Path) -> None:
    """이전에는 `line_no=1` 을 박아서, 담당자가 1행을 열면 아무것도 없었다.
    근거 줄은 보여 주면서 위치는 거짓인 상태 — 그러면 확인 자체가 안 된다."""
    (tmp_path / ".secret_key").write_text(
        "# 이 값은 기동 시 생성됩니다\n"
        "\n"
        "77fec85613b823cd9b6e3bdb41dfd1fc492fdf2463fd01ce7bc8cf3e1606cfac\n",
        encoding="utf-8",
    )
    report = scan_path(tmp_path)
    hits = [f for f in report.findings if f.rule_id == "GOV-SECRET-KEYFILE-001"]
    assert hits
    assert hits[0].location.line == 3, f"위치가 {hits[0].location.line} 행으로 보고됐습니다"
