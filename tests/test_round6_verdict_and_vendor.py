"""라운드 6 — 상용툴(코드 스패로우) 대조에서 도출된 결함 2종의 회귀 테스트.

개선 1: 결론(배포 판정) 박스가 의존성 감사 결과를 무시해 **패키지가 차단 판정이어도
        "배포 승인 가능"(초록)** 이 나오던 결함. 같은 문서가 스스로 모순됐다.
개선 2: ``.min.`` 파일명만으로 벤더 라이브러리를 '빌드 산출물'로 조용히 제외해,
        실제 취약 컴포넌트(xlsx 0.18.5 / CVE-2023-30533)를 아무도 보지 않던 결함.
"""

from __future__ import annotations

from gvskb.report import render_html, render_markdown
from gvskb.schema import ScanReport, ScanSummary

# ---------------------------------------------------------------------------
# 개선 1 — 결론 박스가 의존성을 함께 본다
# ---------------------------------------------------------------------------


def _clean_source_report() -> ScanReport:
    """소스 발견 0건 · 파일은 실제로 검사됨 — 그 자체로는 초록불 대상."""
    return ScanReport(
        target="fixture",
        summary=ScanSummary(finding_count=0, by_severity={}, by_decision={}),
        findings=[],
        scanned_files=["hello.py"],
    )


def _audit(**over) -> dict:
    """의존성 감사 1건 픽스처 — 기본은 '전부 이상 없음'."""
    check = {
        "name": "openpyxl", "version": "3.1.5", "checked": True,
        "is_malicious_package": False, "vulnerability_count": 0,
        "verdict": "checked_clean",
    }
    check.update(over.pop("check", {}))
    audit = {
        "ecosystem": "pypi", "manifest": "requirements.txt",
        "parsed_count": 1, "checked_count": 1, "unchecked_count": 0,
        "blocked": False, "verdict": "ok", "checks": [check],
    }
    audit.update(over)
    return {"audits": [audit]}


def test_blocked_package_forbids_green_verdict() -> None:
    """차단 판정 패키지가 있으면 소스가 깨끗해도 '배포 승인 가능'이 될 수 없다."""
    report = _clean_source_report()
    report.dependency_audit = _audit(
        blocked=True, verdict="blocked",
        check={"vulnerability_count": 26, "name": "pillow", "version": "12.2.0"},
    )
    for out in (render_markdown(report), render_html(report)):
        assert "배포 승인 가능" not in out
        assert "배포 미승인" in out
        assert "취약·악성 패키지 1건" in out


def test_vulnerable_package_without_block_forbids_green_verdict() -> None:
    """차단까지는 아니어도 취약 패키지가 있으면 초록이 아니라 '보류'다."""
    report = _clean_source_report()
    report.dependency_audit = _audit(
        check={"vulnerability_count": 3, "name": "requests", "version": "2.0.0"},
    )
    md = render_markdown(report)
    assert "배포 승인 가능" not in md
    assert "배포 보류" in md


def test_undetermined_packages_forbid_green_verdict() -> None:
    """판정 불가는 '안전'이 아니다 — 오프라인·API 실패 회차가 초록으로 나가면 안 된다."""
    report = _clean_source_report()
    report.dependency_audit = _audit(
        checked_count=0, unchecked_count=1, verdict="review_required",
        check={"checked": False, "verdict": "unchecked"},
    )
    md = render_markdown(report)
    assert "배포 승인 가능" not in md
    assert "판정 불가 1건" in md


def test_clean_packages_keep_green_verdict() -> None:
    """과잉 교정 방지 — 의존성이 전부 '이상 없음'이면 초록불을 유지한다."""
    report = _clean_source_report()
    report.dependency_audit = _audit()
    md = render_markdown(report)
    assert "배포 승인 가능" in md
    assert "심각 위험 미발견" in md


def test_verdict_without_dependency_audit_is_unchanged() -> None:
    """의존성 감사가 아예 없으면 기존 동작 그대로(회귀 방지)."""
    report = _clean_source_report()
    assert report.dependency_audit is None
    assert "배포 승인 가능" in render_markdown(report)


# ---------------------------------------------------------------------------
# 개선 2 — 벤더 번들(*.min.js)을 조용히 제외하지 않고 컴포넌트로 식별한다
# ---------------------------------------------------------------------------

# 실측 축약: xlsx.full.min.js 는 선두 배너에 버전이 없고, 라이브러리 자기 버전은
# 파일 중간의 `var XLSX={};function make_xlsx_lib(e){e.version="0.18.5"` 에 있다.
# 같은 파일에 번들된 하위 라이브러리(SSF 1.2.0 · CFB 1.2.1)도 `.version=` 을 쓰므로,
# **이름 토큰이 인접한 대입만** 골라야 0.18.5 가 나온다.
_XLSX_LIKE = (
    '/*! xlsx.js (C) 2013-present SheetJS -- http://sheetjs.com */\n'
    'var cptable={version:"1.15.0"};'
    + "var pad=1;" * 40
    + 'var Ye=function(){var e={};e.version="1.2.0";return e}();'
    + "var q=2;" * 40
    + 'var XLSX={};function make_xlsx_lib(e){e.version="0.18.5";'
)


def test_vendor_bundle_picks_library_own_version_not_bundled_sublibrary() -> None:
    """번들 안에 여러 `.version=` 이 있어도 파일명이 가리키는 컴포넌트의 것을 고른다."""
    from gvskb.tools.vendor_bundle import identify_vendor_bundle

    vb = identify_vendor_bundle("static/xlsx.full.min.js", _XLSX_LIKE)
    assert (vb.name, vb.version) == ("xlsx", "0.18.5")


def test_vendor_bundle_version_unknown_is_not_guessed() -> None:
    """버전 근거가 없으면 추측하지 않는다 — None 으로 두고 호출측이 판정 불가 처리."""
    from gvskb.tools.vendor_bundle import identify_vendor_bundle

    vb = identify_vendor_bundle("static/qrcode.min.js", "var QRCode;!function(){}();")
    assert vb.name == "qrcode"
    assert vb.version is None


def test_vendor_bundle_reads_version_from_filename_and_banner() -> None:
    from gvskb.tools.vendor_bundle import identify_vendor_bundle

    a = identify_vendor_bundle("jquery-3.6.0.min.js", "x")
    assert (a.name, a.version) == ("jquery", "3.6.0")
    b = identify_vendor_bundle("bootstrap.bundle.min.js", "/*! Bootstrap v5.3.2 */")
    assert (b.name, b.version) == ("bootstrap", "5.3.2")


def test_vendor_bundle_is_recorded_not_silently_dropped(tmp_path) -> None:
    """`*.min.js` 는 소스 검사에서 빠지되 **컴포넌트 후보로는 남아야** 한다."""
    from gvskb.scanner import VENDOR_BUNDLE_SKIP_REASON, scan_path

    static = tmp_path / "static"
    static.mkdir()
    (static / "xlsx.full.min.js").write_text(_XLSX_LIKE, encoding="utf-8")
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")

    report = scan_path(tmp_path)

    assert not any("xlsx" in f for f in report.scanned_files)   # 소스 룰 검사는 계속 제외
    assert [(b["name"], b["version"]) for b in report.vendor_bundles] == [("xlsx", "0.18.5")]
    reasons = {s.reason for s in report.skipped_files if "xlsx" in s.path}
    assert reasons == {VENDOR_BUNDLE_SKIP_REASON}


def test_unknown_version_bundle_is_audited_as_undetermined() -> None:
    """버전 미상 번들은 조회하지 않되 '판정 불가'로 감사에 남아야 한다.

    네트워크를 타지 않는 경로만 검증한다(식별된 컴포넌트가 없으면 OSV 조회 없음).
    """
    import asyncio

    from gvskb.tools.vendor_bundle import audit_vendor_bundles

    audit = asyncio.run(audit_vendor_bundles([
        {"path": "static/qrcode.min.js", "name": "qrcode", "version": None,
         "evidence": "버전 표기를 찾지 못함", "ecosystem": "npm"},
    ]))

    assert audit["unchecked_count"] == 1
    assert audit["requires_review"] is True
    assert audit["source"] == "vendor-bundle"
    (check,) = audit["checks"]
    assert check["name"] == "qrcode"
    assert check["checked"] is False
    assert check["vendor_bundle_path"] == "static/qrcode.min.js"


def test_undetermined_vendor_bundle_blocks_green_verdict() -> None:
    """개선1 + 개선2 합류 — 버전 미상 벤더 번들만 있어도 초록불이 되면 안 된다."""
    import asyncio

    from gvskb.tools.vendor_bundle import audit_vendor_bundles

    report = _clean_source_report()
    audit = asyncio.run(audit_vendor_bundles([
        {"path": "static/qrcode.min.js", "name": "qrcode", "version": None,
         "evidence": "버전 표기를 찾지 못함", "ecosystem": "npm"},
    ]))
    report.dependency_audit = {"audits": [audit]}

    md = render_markdown(report)
    assert "배포 승인 가능" not in md
    assert "판정 불가 1건" in md


def test_mcp_exposes_vendor_bundle_scan_tool() -> None:
    """MCP(IDE) 경로에서도 벤더 번들 검사가 노출돼야 한다 — 없으면 조용한 초록불."""
    import asyncio

    from gvskb.server import mcp

    names = {t.name for t in asyncio.run(mcp.list_tools())}
    assert "scan_vendor_bundles" in names


def test_hashed_build_artifact_stays_a_build_artifact(tmp_path) -> None:
    """과잉 교정 방지 — 콘텐츠 해시가 박힌 진짜 빌드 산출물은 벤더 번들이 아니다."""
    from gvskb.scanner import BUILD_ARTIFACT_SKIP_REASON, scan_path

    (tmp_path / "app-3f9a2c1b.js").write_text("var a=1;\n", encoding="utf-8")
    report = scan_path(tmp_path)

    assert report.vendor_bundles == []
    assert any(s.reason == BUILD_ARTIFACT_SKIP_REASON for s in report.skipped_files)
