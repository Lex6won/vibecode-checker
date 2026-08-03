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


# ---------------------------------------------------------------------------
# 개선 3 — 동일 컴포넌트를 매니페스트·설치본 양쪽에서 두 번 세지 않는다
# ---------------------------------------------------------------------------


def _audit_pair(v_manifest: str, v_installed: str, name: str = "pillow") -> dict:
    """같은 패키지를 매니페스트와 설치본 양쪽에서 본 상황."""
    def _one(version: str, manifest: str, source: str | None) -> dict:
        a = {
            "ecosystem": "pypi", "manifest": manifest,
            "parsed_count": 1, "checked_count": 1, "unchecked_count": 0,
            "blocked": False, "verdict": "ok",
            "checks": [{
                "name": name, "version": version, "checked": True,
                "is_malicious_package": False, "vulnerability_count": 26,
            }],
        }
        if source:
            a["source"] = source
        return a

    return {"audits": [
        _one(v_manifest, "requirements.txt", None),
        _one(v_installed, "<설치된 패키지: pypi>", "installed-inventory"),
    ]}


def test_same_component_counted_once_with_both_sources() -> None:
    """조치 단위(업그레이드할 패키지)와 알림 단위가 같아야 한다 — 원칙 6."""
    report = _clean_source_report()
    report.dependency_audit = _audit_pair("12.2.0", "12.2.0")

    md = render_markdown(report)
    assert "취약 패키지: **1건**" in md
    assert "고유 1종" in md
    # 출처는 버리지 않는다 — 조치는 모든 사본에 함께 적용해야 한다.
    assert "requirements.txt · 설치본" in md


def test_different_versions_stay_separate_components() -> None:
    """과잉 병합 방지 — 버전이 다르면 서로 다른 조치 대상이다."""
    report = _clean_source_report()
    report.dependency_audit = _audit_pair("12.2.0", "12.3.0")

    md = render_markdown(report)
    assert "취약 패키지: **2건**" in md
    assert "고유 2종" in md


def test_pep503_name_variants_merge() -> None:
    """`et_xmlfile` 과 `et-xmlfile` 은 같은 패키지다(PEP 503 정규화)."""
    from gvskb.report import _dep_audits, _dep_merged_components

    report = _clean_source_report()
    report.dependency_audit = _audit_pair("2.0.0", "2.0.0", name="et_xmlfile")
    report.dependency_audit["audits"][1]["checks"][0]["name"] = "et-xmlfile"

    assert len(_dep_merged_components(_dep_audits(report))) == 1


# ---------------------------------------------------------------------------
# 개선 4 — 파일명에 `.min.` 이 없어도 내용이 미니파이드면 벤더 식별을 시도한다
# ---------------------------------------------------------------------------


def test_content_minified_js_is_identified_as_component(tmp_path) -> None:
    """`vendor/lib.js` 처럼 이름은 평범한데 미니파이드인 라이브러리도 잡아야 한다."""
    from gvskb.scanner import VENDOR_BUNDLE_SKIP_REASON, scan_path

    static = tmp_path / "static"
    static.mkdir()
    (static / "moment.js").write_text(
        "/*! moment.js v2.29.4 */\n" + "var a=1;" * 400, encoding="utf-8",
    )

    report = scan_path(tmp_path)

    found = {(b["name"], b["version"], b["detected_by"]) for b in report.vendor_bundles}
    assert found == {("moment", "2.29.4", "content")}
    assert any(s.reason == VENDOR_BUNDLE_SKIP_REASON for s in report.skipped_files)


def test_unidentified_self_bundle_does_not_raise_alarm(tmp_path) -> None:
    """과잉 교정 방지 — 자체 번들(식별 불가·이름 신호 없음)이 매번 노란불을 켜면 안 된다.

    제외 목록에는 남지만 '판정 불가'로 올리지는 않는다. 안 그러면 자체 번들을 둔
    프로젝트는 영구히 초록불을 못 받고, 그 피로가 진짜 경고까지 묻는다(원칙 6).
    """
    import asyncio

    from gvskb.scanner import scan_path
    from gvskb.tools.vendor_bundle import audit_vendor_bundles

    static = tmp_path / "static"
    static.mkdir()
    (static / "app.js").write_text("var x=1;" * 400, encoding="utf-8")

    report = scan_path(tmp_path)
    assert [b["detected_by"] for b in report.vendor_bundles] == ["content"]

    audit = asyncio.run(audit_vendor_bundles(report.vendor_bundles))
    assert audit["unchecked_count"] == 0
    assert audit["checks"] == []


def test_named_min_js_without_version_still_escalates(tmp_path) -> None:
    """반대로 `.min.js` 는 작성자가 배포본 라이브러리를 넣었다는 명시적 신호다 —
    버전을 몰라도 '판정 불가'로 남겨야 한다(조용히 사라지면 안 됨)."""
    import asyncio

    from gvskb.scanner import scan_path
    from gvskb.tools.vendor_bundle import audit_vendor_bundles

    static = tmp_path / "static"
    static.mkdir()
    (static / "qrcode.min.js").write_text("var QRCode;!function(){}();", encoding="utf-8")

    report = scan_path(tmp_path)
    assert [b["detected_by"] for b in report.vendor_bundles] == ["name"]

    audit = asyncio.run(audit_vendor_bundles(report.vendor_bundles))
    assert audit["unchecked_count"] == 1


def test_minified_non_js_stays_a_build_artifact(tmp_path) -> None:
    """미니파이드라도 `.js` 계열이 아니면 벤더 컴포넌트가 아니다."""
    from gvskb.scanner import BUILD_ARTIFACT_SKIP_REASON, scan_path

    (tmp_path / "page.html").write_text("<div>" + "x" * 3000 + "</div>", encoding="utf-8")
    report = scan_path(tmp_path)

    assert report.vendor_bundles == []
    assert any(s.reason == BUILD_ARTIFACT_SKIP_REASON for s in report.skipped_files)


# ---------------------------------------------------------------------------
# 개선 5 (C1) — 적용되지 않은 프로파일을 적용된 것처럼 적지 않는다
# ---------------------------------------------------------------------------


def test_unknown_profile_is_reported_not_silently_substituted() -> None:
    """요청한 프로파일이 없으면 리포트가 그 사실을 말해야 한다.

    실측(하네스 연동): MCP `scan_path(profile="dev-quick")` 이 정책 파일을 못 찾아
    아무 필터도 걸리지 않았는데 머리표에는 `dev-quick` 으로 판정했다고 찍혔다.
    CLI 는 경고 후 기본값으로 바꿔 정직했지만 API·MCP 경로에는 그 처리가 없었다.
    """
    from gvskb.scanner import scan_code

    report = scan_code("x = 1\n", filename="a.py", profile="dev-quick")

    assert report.profile == "public-default-strict"      # 실제 적용된 것
    fb = report.profile_fallback
    assert fb is not None
    assert fb["requested"] == "dev-quick"
    assert fb["applied"] == "public-default-strict"
    assert "public-default-strict" in fb["available"]

    md = render_markdown(report)
    assert "dev-quick" in md and "찾지 못해 대체" in md


def test_known_profile_has_no_fallback_noise() -> None:
    """과잉 교정 방지 — 정상 프로파일에는 대체 안내가 붙지 않는다."""
    from gvskb.scanner import scan_code

    report = scan_code("x = 1\n", filename="a.py", profile="public-default-strict")
    assert report.profile_fallback is None
    assert "찾지 못해 대체" not in render_markdown(report)


# ---------------------------------------------------------------------------
# 개선 6 (C3) — 파일명으로 추정한 컴포넌트를 레지스트리로 검증한다
# ---------------------------------------------------------------------------


def test_banner_name_beats_filename_for_chartjs() -> None:
    """`chart.min.js` 의 실체는 Chart.js(npm `chart.js`)다 — npm `chart` 가 아니다.

    파일명만 믿으면 전혀 다른 패키지(최신 0.1.2)를 조회해 '이상 없음'이 나온다.
    """
    from gvskb.tools.vendor_bundle import identify_vendor_bundle

    vb = identify_vendor_bundle(
        "static/chart.min.js", "/*! Chart.js v3.9.1 | (c) Chart.js Contributors */\nvar x=1;"
    )
    assert vb.version == "3.9.1"
    assert vb.name_candidates[0] == "chart.js"      # 배너 이름이 파일명보다 앞선다
    assert "chart" in vb.name_candidates


def test_unresolvable_component_is_not_reported_clean() -> None:
    """레지스트리에 없는 조합은 '이상 없음'이 아니라 판정 불가다.

    네트워크를 타지 않도록 오프라인 경로가 아닌 '후보 없음'을 직접 검증한다.
    """
    import asyncio

    from gvskb.tools import vendor_bundle as vb_mod

    async def _no_match(candidates, version, *, timeout=10.0):
        return None, "no_match"

    orig = vb_mod.resolve_npm_component
    vb_mod.resolve_npm_component = _no_match
    try:
        audit = asyncio.run(vb_mod.audit_vendor_bundles([{
            "path": "static/mylib.min.js", "name": "mylib", "version": "9.9.9",
            "evidence": "파일명에 버전 표기", "ecosystem": "npm",
            "detected_by": "name", "name_candidates": ["mylib"],
        }]))
    finally:
        vb_mod.resolve_npm_component = orig

    (check,) = audit["checks"]
    assert check["verdict"] == "unchecked"
    assert check["checked"] is False
    assert audit["unchecked_count"] == 1
    assert "다른 라이브러리일 수 있어" in check["note"]


def test_unverified_identity_is_flagged_for_review() -> None:
    """오프라인 등으로 확인하지 못했으면 '확인함'으로 두지 않는다."""
    import asyncio

    from gvskb.tools import vendor_bundle as vb_mod

    async def _unverified(candidates, version, *, timeout=10.0):
        return candidates[0], "unverified"

    async def _fake_audit(text, **kw):
        return {"ecosystem": "npm", "verdict": "ok", "parsed_count": 1,
                "checked_count": 1, "unchecked_count": 0, "blocked": False,
                "checks": [{"name": "mylib", "version": "1.0.0", "checked": True,
                            "is_malicious_package": False, "vulnerability_count": 0}]}

    orig_r, orig_a = vb_mod.resolve_npm_component, None
    vb_mod.resolve_npm_component = _unverified
    import gvskb.tools.check_package as cp
    orig_a, cp.audit_manifest = cp.audit_manifest, _fake_audit
    try:
        audit = asyncio.run(vb_mod.audit_vendor_bundles([{
            "path": "static/mylib.min.js", "name": "mylib", "version": "1.0.0",
            "evidence": "파일명에 버전 표기", "ecosystem": "npm",
            "detected_by": "name", "name_candidates": ["mylib"],
        }]))
    finally:
        vb_mod.resolve_npm_component = orig_r
        cp.audit_manifest = orig_a

    (check,) = audit["checks"]
    assert check["requires_review"] is True
    assert "'안전' 아님" in check["note"]


def test_hashed_build_artifact_stays_a_build_artifact(tmp_path) -> None:
    """과잉 교정 방지 — 콘텐츠 해시가 박힌 진짜 빌드 산출물은 벤더 번들이 아니다."""
    from gvskb.scanner import BUILD_ARTIFACT_SKIP_REASON, scan_path

    (tmp_path / "app-3f9a2c1b.js").write_text("var a=1;\n", encoding="utf-8")
    report = scan_path(tmp_path)

    assert report.vendor_bundles == []
    assert any(s.reason == BUILD_ARTIFACT_SKIP_REASON for s in report.skipped_files)
