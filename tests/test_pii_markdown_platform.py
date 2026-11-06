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


ELECTRON = {"name": "a", "devDependencies": {"electron": "41.0.0", "electron-builder": "26.0.0", "typescript": "5.0.0"}}
CHROME = {"manifest_version": 3, "name": "a", "permissions": []}
VSCODE = {"name": "a", "engines": {"vscode": "^1.90.0"}, "devDependencies": {"@types/vscode": "1.90.0"}}


@pytest.mark.parametrize("files,label,package", [
    ({"package.json": json.dumps({**ELECTRON, "dependencies": {"axios": "1.7.9"}})}, "Electron 앱", "axios"),
    ({"apps/desktop/package.json": json.dumps({**ELECTRON, "dependencies": {"sqlite3": "5.0.0"}})}, "Electron 앱", "sqlite3"),
    ({"manifest.json": json.dumps(CHROME), "package.json": json.dumps({"name": "a", "dependencies": {"lodash": "4.17.21"}})}, "브라우저 확장", "lodash"),
    ({"package.json": json.dumps({**VSCODE, "dependencies": {"got": "14.0.0"}})}, "VS Code 확장", "got"),
])
def test_platform_with_non_base_package_is_blocked_and_says_what(files: dict[str, str], label: str, package: str, tmp_path: Path) -> None:
    gate = gate_status(_project(tmp_path, {"a.js": "const x = 1;\n", **files}))
    assert gate["verdict"] == "blocked" and gate["blocked_dependency"] is False
    row = next(r for r in gate["block_reasons"] if r["package"] == label)
    assert row["criteria"] == ["unsupported_platform"] and row["files"] and row["packages"] == [package]
    for word in (package, "승인할 수 없습니다", "교체", "CDN", "안전 목록"):
        assert word in gate["reason"], word


@pytest.mark.parametrize("files", [
    {"package.json": json.dumps(ELECTRON)},                   # 런타임·개발 도구뿐
    {"electron-builder.yml": "appId: a\n"},
    {"manifest.json": json.dumps(CHROME)},                    # 패키지 없는 확장
    {"package.json": json.dumps(VSCODE)},
])
def test_platform_with_base_packages_only_is_not_blocked(files: dict[str, str], tmp_path: Path) -> None:
    report = _project(tmp_path, {"a.js": "const x = 1;\n", **files})
    assert report.unsupported_platforms, "형태는 알아본다"
    assert not any("unsupported_platform" in r["criteria"] for r in gate_status(report)["block_reasons"])


def test_platform_loading_external_cdn_is_blocked(tmp_path: Path) -> None:
    report = _project(tmp_path, {
        "manifest.json": json.dumps(CHROME),
        "popup.js": 'const s = document.createElement("script"); s.src = "https://cdn.jsdelivr.net/npm/vue@3/dist/vue.js"; document.head.append(s);\n',
    })
    gate = gate_status(report)
    row = next(r for r in gate["block_reasons"] if r["package"] == "브라우저 확장")
    assert "cdn.jsdelivr.net" in row["cdn"] and "cdn.jsdelivr.net" in gate["reason"]


def test_web_project_using_cdn_is_not_this_rule(tmp_path: Path) -> None:
    report = _project(tmp_path, {"app.js": 'fetch("https://cdn.jsdelivr.net/npm/vue@3/dist/vue.js");\n', "package.json": json.dumps({"name": "a", "dependencies": {"express": "5.0.0"}})})
    assert not any("unsupported_platform" in r["criteria"] for r in gate_status(report)["block_reasons"])


def test_approved_package_counts_as_base(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    listed = tmp_path / "approved.json"
    listed.write_text('{"packages":[{"ecosystem":"npm","name":"axios"}]}', encoding="utf-8")
    monkeypatch.setenv("GVSKB_APPROVED_PACKAGES", str(listed))
    project = tmp_path / "p"
    report = _project(project, {"a.js": "const x = 1;\n", "package.json": json.dumps({**ELECTRON, "dependencies": {"axios": "1.7.9"}})})
    assert not any("unsupported_platform" in r["criteria"] for r in gate_status(report)["block_reasons"])
    listed.write_text('{"packages":[]}', encoding="utf-8")
    assert any("unsupported_platform" in r["criteria"] for r in gate_status(report)["block_reasons"])


@pytest.mark.parametrize("files", [
    {"package.json": json.dumps({"name": "a", "dependencies": {"express": "5.0.0"}})},
    {"manifest.json": json.dumps({"name": "pwa", "short_name": "p", "icons": []})},   # 웹앱 매니페스트
    {"tests/fixtures/package.json": json.dumps({"name": "a", "dependencies": {"electron": "41.0.0", "axios": "1.0.0"}})},
    {"examples/ext/manifest.json": json.dumps(CHROME)},
])
def test_standard_web_project_is_not_flagged(files: dict[str, str], tmp_path: Path) -> None:
    report = _project(tmp_path, {"a.js": "const x = 1;\n", **files})
    assert not report.unsupported_platforms


def test_platform_action_reaches_the_report(tmp_path: Path) -> None:
    from gvskb.gate import attach_gate
    from gvskb.report import render_markdown

    report = _project(tmp_path, {"a.js": "const x = 1;\n", "package.json": json.dumps({**ELECTRON, "dependencies": {"axios": "1.7.9"}})})
    attach_gate(report)
    text = render_markdown(report)
    assert "기본 패키지" in text and "안전 목록으로 지정한 패키지로 교체" in text
