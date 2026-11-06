"""이메일 · 문서(.md) 검사 · 기관 표준 밖의 실행 형태."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from gvskb.gate import gate_status
from gvskb.scanner import scan_code, scan_path
from gvskb.scanners.regex_scanner import redact_evidence

EMAIL = "GOV-PII-EMAIL-001"
PHONE = "GOV-PII-PHONE-001"


def _rules(report) -> set[str]:
    return {f.rule_id for f in report.findings if not f.suppressed}


def _project(tmp_path: Path, files: dict[str, str]):
    for rel, text in files.items():
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    return scan_path(str(tmp_path))


@pytest.mark.parametrize("filename,code", [
    ("a.py", 'OWNER = "kim.minsu@somecompany.co.kr"\n'),
    ("a.js", 'const owner = "kim.minsu@somecompany.co.kr";\n'),
    ("a.ts", 'const owner: string = "kim.minsu@somecompany.co.kr";\n'),
    ("a.yaml", 'owner: kim.minsu@somecompany.co.kr\n'),
])
def test_real_email_is_found_in_code(filename: str, code: str) -> None:
    assert EMAIL in _rules(scan_code(code, filename=filename))


@pytest.mark.parametrize("code", [
    'x = "name@example.com"\n', 'x = "git@github.com:org/repo.git"\n', 'x = "noreply@anthropic.com"\n',
    'x = "postgres://u:p@db.somecorp.com/app"\n', 'x = "vue@2.6.14.js"\n', 'x = "@types/node"\n',
    'x = "pkg@1.0.0"\n', 'y = "\\n@app.route"\n', 'z = "a@b.tool"\n',
])
def test_not_an_email(code: str) -> None:
    assert EMAIL not in _rules(scan_code(code, filename="a.py"))


def test_email_is_masked_in_evidence() -> None:
    assert "kim.minsu" not in redact_evidence('x = "kim.minsu@somecompany.co.kr"')
    assert "@somecompany.co.kr" in redact_evidence('x = "kim.minsu@somecompany.co.kr"')


@pytest.mark.parametrize("value", ["010-3825-7193", "010 3825 7193", "01038257193", "010.3825.7193"])
def test_mobile_number_is_found(value: str) -> None:
    assert PHONE in _rules(scan_code(f'PHONE = "{value}"\n', filename="a.py"))


def test_markdown_reports_pii_and_secrets(tmp_path: Path) -> None:
    report = _project(tmp_path, {"notes.md": "담당: kim.minsu@somecompany.co.kr / 010-3825-7193\n\nkey: AKIAIOSFODNN7ABCDEFG\n"})
    assert "notes.md" in report.scanned_files
    rules = _rules(report)
    assert EMAIL in rules and PHONE in rules
    assert any(f.category == "secret-scanning" for f in report.findings), rules


def test_markdown_does_not_run_code_rules(tmp_path: Path) -> None:
    report = _project(tmp_path, {"guide.md": "```python\neval(input())\nos.system(cmd)\nquery = \"SELECT * FROM t WHERE a=\" + b\n```\n"})
    assert "guide.md" in report.scanned_files
    assert not report.findings, _rules(report)


def test_markdown_finding_reaches_the_form(tmp_path: Path) -> None:
    from gvskb.form_v12 import form_v12_table

    report = _project(tmp_path, {"a.py": "x = 1\n", "notes.md": "연락처 kim.minsu@somecompany.co.kr\n"})
    row = next(r for r in form_v12_table(report)["items"] if r["key"] == "pii")
    assert row["result"] != "적합"


@pytest.mark.parametrize("files,label", [
    ({"package.json": json.dumps({"name": "a", "devDependencies": {"electron": "41.0.0"}})}, "Electron 앱"),
    ({"electron-builder.yml": "appId: a\n"}, "Electron 앱"),
    ({"manifest.json": json.dumps({"manifest_version": 3, "name": "a", "permissions": []})}, "브라우저 확장"),
    ({"package.json": json.dumps({"name": "a", "engines": {"vscode": "^1.90.0"}})}, "VS Code 확장"),
    ({"apps/desktop/package.json": json.dumps({"name": "a", "dependencies": {"electron": "41.0.0"}})}, "Electron 앱"),
])
def test_unsupported_platform_is_not_approved(files: dict[str, str], label: str, tmp_path: Path) -> None:
    report = _project(tmp_path, {"a.js": "const x = 1;\n", **files})
    gate = gate_status(report)
    assert gate["verdict"] == "blocked" and gate["blocked_dependency"] is False
    row = next(r for r in gate["block_reasons"] if r["package"] == label)
    assert row["criteria"] == ["unsupported_platform"] and row["files"]
    assert "승인할 수 없습니다" in gate["reason"] and "교체" in gate["reason"] and "CDN" in gate["reason"]


@pytest.mark.parametrize("files", [
    {"package.json": json.dumps({"name": "a", "dependencies": {"express": "5.0.0"}})},
    {"manifest.json": json.dumps({"name": "pwa", "short_name": "p", "icons": []})},   # 웹앱 매니페스트
    {"tests/fixtures/package.json": json.dumps({"name": "a", "dependencies": {"electron": "41.0.0"}})},
    {"examples/ext/manifest.json": json.dumps({"manifest_version": 3, "permissions": []})},
])
def test_standard_web_project_is_not_flagged(files: dict[str, str], tmp_path: Path) -> None:
    report = _project(tmp_path, {"a.js": "const x = 1;\n", **files})
    assert not report.unsupported_platforms
    assert not any("unsupported_platform" in r["criteria"] for r in gate_status(report)["block_reasons"])


def test_platform_action_reaches_the_report(tmp_path: Path) -> None:
    from gvskb.gate import attach_gate
    from gvskb.report import render_markdown

    report = _project(tmp_path, {"a.js": "const x = 1;\n", "package.json": json.dumps({"name": "a", "dependencies": {"electron": "41.0.0"}})})
    attach_gate(report)
    text = render_markdown(report)
    assert "기관 표준 밖" in text and "웹서비스와 기본 패키지로 교체" in text
