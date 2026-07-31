"""라운드 2 개선(1~7번)의 회귀 방지 — 실측 결함 기반.

각 테스트는 **실제 공공 프로젝트 점검에서 확인된 결함**을 고정한다:
1. BOM 파일에서 AST 정밀 엔진이 조용히 꺼지던 문제
2. 개인키(.pem)가 확장자 목록에 없어 검사조차 되지 않던 문제
3. 검사 대상이 아닌 파일이 skipped_files 에도 남지 않던 문제(침묵)
4. 구버전 설치본이 현재 소스를 가리는 상황을 진단하지 못하던 문제
5. 설치 흔적(.venv·휠) 패키지를 SCA 범위에서 놓치던 문제
6. 라이선스를 수집하고도 리포트에 노출하지 않던 문제
7. 판정 근거 강도가 없어 '치명 8건'이 전부 패턴 일치여도 알 수 없던 문제
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from gvskb.scanner import scan_code, scan_path

# ---------------------------------------------------------------------------
# 1. BOM — AST 우회 방지
# ---------------------------------------------------------------------------

_SQLI_SRC = (
    "import sqlite3\n"
    "name = request.args.get('name')\n"
    "cur.execute(f\"SELECT * FROM t WHERE n = '{name}'\")\n"
)


def test_bom_file_still_gets_ast_analysis(tmp_path: Path) -> None:
    """BOM 이 붙어도 AST 엔진이 동작해야 한다(engine=python-ast)."""
    p = tmp_path / "app.py"
    p.write_bytes(b"\xef\xbb\xbf" + _SQLI_SRC.encode("utf-8"))
    report = scan_path(p)
    sqli = [f for f in report.findings if f.rule_id == "GOV-SQL-INJECTION-001"]
    assert sqli, "BOM 파일에서 SQL 삽입을 놓쳤다 — AST 가 꺼진 것"
    assert any(f.engine == "python-ast" for f in sqli), "regex 로만 검사됨(AST 우회)"


def test_bom_file_constant_sql_is_not_flagged(tmp_path: Path) -> None:
    """BOM 파일에서도 상수 기반 DDL 은 오탐이 나오면 안 된다."""
    src = (
        "for col, dfn in [('a', 'TEXT'), ('b', 'INTEGER')]:\n"
        "    c.execute(f'ALTER TABLE t ADD COLUMN {col} {dfn}')\n"
    )
    p = tmp_path / "mig.py"
    p.write_bytes(b"\xef\xbb\xbf" + src.encode("utf-8"))
    report = scan_path(p)
    assert not [f for f in report.findings if "SQL" in f.rule_id]


# ---------------------------------------------------------------------------
# 2. 비밀·인증서 파일 탐지
# ---------------------------------------------------------------------------

_PRIVATE_KEY = (
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ==\n"
    "-----END PRIVATE KEY-----\n"
)
_CERT = (
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQ==\n"
    "-----END CERTIFICATE-----\n"
)


def test_private_key_pem_is_detected_and_blocked(tmp_path: Path) -> None:
    """실측 결함: ssl/*_key.pem 이 스캔 대상이 아니라 통째로 무시됐다."""
    (tmp_path / "server_key.pem").write_text(_PRIVATE_KEY, encoding="utf-8")
    report = scan_path(tmp_path)
    keys = [f for f in report.findings if f.rule_id == "GOV-SECRET-PRIVATEKEY-001"]
    assert keys, "개인키 파일을 탐지하지 못했다"
    assert keys[0].severity.value == "critical"
    assert report.summary.blocked is True


def test_certificate_is_low_not_critical(tmp_path: Path) -> None:
    """인증서는 **공개 자재** — 개인키와 같은 치명으로 올리면 과잉 경보다."""
    (tmp_path / "server_crt.pem").write_text(_CERT, encoding="utf-8")
    report = scan_path(tmp_path)
    certs = [f for f in report.findings if f.rule_id == "GOV-CERT-IN-SOURCE-001"]
    assert certs, "인증서 파일을 탐지하지 못했다"
    assert certs[0].severity.value == "low"
    assert report.summary.blocked is False


def test_password_txt_is_scanned_by_filename(tmp_path: Path) -> None:
    """`.txt` 는 스캔 대상이 아니지만 **이름이 password** 면 검사한다."""
    (tmp_path / "password.txt").write_text("api_key = 'sk-abcdefghijklmnop'\n", encoding="utf-8")
    report = scan_path(tmp_path)
    assert "password.txt" in [Path(s).name for s in report.scanned_files]


def test_ordinary_txt_is_not_scanned_but_recorded(tmp_path: Path) -> None:
    """일반 .txt 는 검사하지 않되 **기록은 남긴다**(노이즈 억제 + 침묵 방지)."""
    (tmp_path / "readme.txt").write_text("hello\n", encoding="utf-8")
    report = scan_path(tmp_path)
    assert not report.scanned_files
    assert any("readme.txt" in s.path for s in report.skipped_files)


# ---------------------------------------------------------------------------
# 3. 침묵 제거 — 미검사 파일 기록
# ---------------------------------------------------------------------------


def test_unscanned_extension_is_recorded_with_reason(tmp_path: Path) -> None:
    """실측 결함: 대상 외 확장자 파일이 스캔·제외 어디에도 없이 사라졌다."""
    (tmp_path / "manual.pdf").write_text("dummy", encoding="utf-8")
    report = scan_path(tmp_path)
    hit = [s for s in report.skipped_files if "manual.pdf" in s.path]
    assert hit, "미검사 파일이 기록되지 않았다 — '안 봤음'이 '깨끗함'으로 보인다"
    assert "검사되지 않았습니다" in hit[0].reason


# ---------------------------------------------------------------------------
# 4. 설치본 정합성
# ---------------------------------------------------------------------------


def test_install_consistency_checks_exist() -> None:
    from gvskb.diagnostics import check_install_consistency

    names = {c["name"] for c in check_install_consistency()}
    assert "Install consistency" in names
    assert "Import: gvskb.cli" in names
    assert "Import: gvskb.server" in names


def test_shadowing_copy_detection_reports_versions(tmp_path: Path, monkeypatch) -> None:
    """sys.path 에 다른 버전의 gvskb 사본이 있으면 경고해야 한다."""
    import sys

    fake = tmp_path / "gvskb"
    fake.mkdir()
    (fake / "__init__.py").write_text('__version__ = "0.0.1-old"\n', encoding="utf-8")
    monkeypatch.setattr(sys, "path", [*sys.path, str(tmp_path)])

    from gvskb.diagnostics import check_install_consistency

    shadow = [c for c in check_install_consistency() if c["name"] == "Shadowing copies"]
    assert shadow, "가리는 사본을 감지하지 못했다"
    assert shadow[0]["status"] == "warn"
    assert "0.0.1-old" in shadow[0]["note"]


# ---------------------------------------------------------------------------
# 5. 설치 흔적 SCA 범위
# ---------------------------------------------------------------------------


def test_collect_installed_packages_reads_dist_info(tmp_path: Path) -> None:
    d = tmp_path / ".venv" / "Lib" / "site-packages" / "flask-3.1.3.dist-info"
    d.mkdir(parents=True)
    (d / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: Flask\nVersion: 3.1.3\nLicense: BSD-3-Clause\n\n본문\n",
        encoding="utf-8",
    )
    from gvskb.tools.installed_packages import collect_installed_packages

    inv = collect_installed_packages(tmp_path)
    assert inv["stats"]["metadata"] == 1
    assert inv["pypi"][0]["name"] == "Flask"
    assert inv["pypi"][0]["license"] == "BSD-3-Clause"


def test_wheel_and_dist_info_are_deduped(tmp_path: Path) -> None:
    """dist-info(et_xmlfile)와 휠(et-xmlfile)이 같은 패키지로 합쳐져야 한다."""
    d = tmp_path / "et_xmlfile-2.0.0.dist-info"
    d.mkdir(parents=True)
    (d / "METADATA").write_text("Name: et_xmlfile\nVersion: 2.0.0\n\n", encoding="utf-8")
    (tmp_path / "et_xmlfile-2.0.0-py3-none-any.whl").write_text("x", encoding="utf-8")

    from gvskb.tools.installed_packages import collect_installed_packages

    inv = collect_installed_packages(tmp_path)
    assert inv["stats"]["pypi_total"] == 1, "같은 패키지가 중복 집계됐다"


def test_node_modules_package_json(tmp_path: Path) -> None:
    d = tmp_path / "node_modules" / "lodash"
    d.mkdir(parents=True)
    (d / "package.json").write_text(
        json.dumps({"name": "lodash", "version": "4.17.21", "license": "MIT"}),
        encoding="utf-8",
    )
    from gvskb.tools.installed_packages import collect_installed_packages

    inv = collect_installed_packages(tmp_path)
    assert inv["npm"][0]["name"] == "lodash"
    assert inv["npm"][0]["license"] == "MIT"


def test_to_requirements_text_roundtrip() -> None:
    from gvskb.tools.installed_packages import to_requirements_text

    text = to_requirements_text([{"name": "Flask", "version": "3.1.3"}, {"name": "x", "version": None}])
    assert "Flask==3.1.3" in text
    assert "x" in text


# ---------------------------------------------------------------------------
# 6. 라이선스 리포트 노출
# ---------------------------------------------------------------------------


def test_report_shows_license_column() -> None:
    from gvskb.report import render_markdown
    from gvskb.schema import ScanReport, ScanSummary

    report = ScanReport(
        target="proj",
        summary=ScanSummary(finding_count=0, by_severity={}, by_decision={}),
        findings=[],
        dependency_audit={
            "ecosystem": "pypi", "verdict": "ok", "parsed_count": 1,
            "checked_count": 1, "unchecked_count": 0, "blocked": False,
            "checks": [{
                "name": "flask", "version": "3.1.3", "checked": True,
                "registry_metadata": {"license": "BSD-3-Clause"},
                "license_verdict": "allowed",
            }],
        },
    )
    md = render_markdown(report)
    assert "라이선스" in md
    assert "BSD-3-Clause" in md


def test_report_marks_review_required_license() -> None:
    from gvskb.report import render_markdown
    from gvskb.schema import ScanReport, ScanSummary

    report = ScanReport(
        target="proj",
        summary=ScanSummary(finding_count=0, by_severity={}, by_decision={}),
        findings=[],
        dependency_audit={
            "ecosystem": "pypi", "verdict": "review_required", "parsed_count": 1,
            "checked_count": 1, "unchecked_count": 0, "blocked": False,
            "checks": [{
                "name": "somepkg", "version": "1.0", "checked": True,
                "registry_metadata": {"license": "AGPL-3.0"},
                "license_verdict": "review_required",
            }],
        },
    )
    md = render_markdown(report)
    assert "⚠ AGPL-3.0" in md


# ---------------------------------------------------------------------------
# 7. 판정 근거 강도(confidence)
# ---------------------------------------------------------------------------


def test_regex_findings_are_pattern_only() -> None:
    """regex 는 값의 출처를 모르므로 항상 pattern-only 여야 한다."""
    report = scan_code("DB_HOST = '192.168.10.25'\n", filename="conf.py")
    net = [f for f in report.findings if f.rule_id == "GOV-INTERNAL-NET-001"]
    assert net and net[0].confidence == "pattern-only"


def test_ast_sql_taint_is_confirmed() -> None:
    """테인트를 실제로 추적한 SQL 삽입은 confirmed 여야 한다."""
    report = scan_code(_SQLI_SRC, filename="t.py")
    sqli = [f for f in report.findings if f.rule_id == "GOV-SQL-INJECTION-001"]
    assert sqli and sqli[0].confidence == "confirmed"


def test_ddl_rule_is_likely_not_confirmed() -> None:
    """DDL 은 조립 사실만 확인 — 값의 출처는 사람이 봐야 하므로 likely."""
    src = "col = request.args['col']\ncur.execute(f'ALTER TABLE t ADD COLUMN {col} TEXT')\n"
    report = scan_code(src, filename="t.py")
    ddl = [f for f in report.findings if f.rule_id == "GOV-SQL-DDL-DYNAMIC-001"]
    assert ddl and ddl[0].confidence == "likely"


def test_report_shows_confidence_summary_and_detail() -> None:
    from gvskb.report import render_markdown

    report = scan_code("DB_HOST = '192.168.10.25'\n", filename="conf.py")
    md = render_markdown(report)
    assert "판정 근거" in md
    assert "패턴 일치만" in md


@pytest.mark.parametrize("value,expected", [
    ("confirmed", "확인됨"),
    ("likely", "유력함"),
    ("pattern-only", "패턴 일치만"),
    (None, "패턴 일치"),
])
def test_confidence_labels(value, expected) -> None:
    from gvskb.report import _confidence_label

    assert expected in _confidence_label(value)
