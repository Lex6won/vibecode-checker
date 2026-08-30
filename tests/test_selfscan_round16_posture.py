"""16차 — 경로 성격별 집계(A-3)와 보안 자세 관찰(D4·E). 둘 다 판정을 바꾸지 않는다.

A-3: "차단 13건"이 실제로는 "운영 0 + 시험 13"임을 요약에서 바로 알게 — 감등은 거부, 분리는 수용.
E: 웹 서버 진입점은 있는데 CSP·X-Frame-Options·쿠키 보호 속성 흔적이 저장소 어디에도 없으면
   **정보** 항목. 게이트·건수와 무관.
"""
from __future__ import annotations

import json
from pathlib import Path

from gvskb.report import render_html, render_markdown
from gvskb.scanner import path_class, scan_path
from gvskb.schema import ScanReport


# ── A-3 경로 성격 ──
def test_path_class_buckets():
    assert path_class("src/app.py") == "runtime"
    assert path_class("tests/test_app.py") == "test"
    assert path_class("fixtures/checker-negative-fixture/app/main.py") == "sample"
    assert path_class("examples/demo.js") == "sample"
    assert path_class("app/fixtures.py") == "runtime", "파일명이 아니라 디렉터리 세그먼트로 본다"


def test_summary_splits_block_counts_by_path_class_without_changing_verdict(tmp_path: Path):
    (tmp_path / "app.py").write_text("exec(user_input)\n", encoding="utf-8")
    (tmp_path / "fixtures").mkdir()
    (tmp_path / "fixtures" / "bad.py").write_text("exec(user_input)\n", encoding="utf-8")
    rep = scan_path(str(tmp_path))
    bp = rep.summary.by_path_class
    assert bp["runtime"]["block"] == 1 and bp["sample"]["block"] == 1
    assert rep.summary.by_decision["block"] == 2, "판정·건수는 그대로다"
    md = render_markdown(rep)
    assert "시험·예제 1" in md and "판정은 동일" in md


def test_summary_suffix_absent_when_only_runtime(tmp_path: Path):
    (tmp_path / "app.py").write_text("exec(user_input)\n", encoding="utf-8")
    md = render_markdown(scan_path(str(tmp_path)))
    assert "경로 성격별" not in md


# ── E 보안 자세 관찰 ──
def _express(tmp_path: Path, extra: str = "", where: str = "server.js") -> Path:
    (tmp_path / where).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / where).write_text(
        'const express = require("express");\nconst app = express();\n' + extra + "app.listen(3000);\n",
        encoding="utf-8")
    return tmp_path


def test_express_without_headers_gets_info_note_not_finding(tmp_path: Path):
    rep = scan_path(str(_express(tmp_path)))
    ids = [n["id"] for n in rep.posture_notes]
    assert "POSTURE-HEADERS-001" in ids
    assert not rep.findings and rep.summary.blocked is False
    md, html = render_markdown(rep), render_html(rep)
    assert "보안 자세 관찰" in md and "보안 자세 관찰" in html and "X-Frame-Options" in md


def test_helmet_anywhere_silences_header_note(tmp_path: Path):
    _express(tmp_path)
    (tmp_path / "security.js").write_text('app.use(helmet());\n', encoding="utf-8")
    assert not [n for n in scan_path(str(tmp_path)).posture_notes if n["id"] == "POSTURE-HEADERS-001"]


def test_no_web_entry_means_no_note(tmp_path: Path):
    (tmp_path / "lib.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    assert scan_path(str(tmp_path)).posture_notes == []


def test_entry_in_fixture_path_is_not_an_entry(tmp_path: Path):
    _express(tmp_path, where="fixtures/sample/server.js")
    assert scan_path(str(tmp_path)).posture_notes == []


def test_cookie_without_guards_gets_note_and_guards_silence_it(tmp_path: Path):
    rep = scan_path(str(_express(tmp_path, 'res.cookie("sid", sid);\n')))
    assert any(n["id"] == "POSTURE-COOKIE-001" for n in rep.posture_notes)
    rep2 = scan_path(str(_express(tmp_path, 'res.cookie("sid", sid, { httpOnly: true, secure: true, sameSite: "lax" });\n')))
    assert not any(n["id"] == "POSTURE-COOKIE-001" for n in rep2.posture_notes)


def test_posture_notes_survive_json_and_legacy_json_loads(tmp_path: Path):
    rep = scan_path(str(_express(tmp_path)))
    data = json.loads(rep.model_dump_json())
    assert data["posture_notes"]
    data.pop("posture_notes")
    data["summary"].pop("by_path_class", None)
    assert ScanReport.model_validate(data)


NL = chr(10)


def test_evidence_is_scoped_to_project_root_not_repo(tmp_path: Path):
    """포털 실측: 동봉된 골든 템플릿이 helmet 을 써서 정작 앱의 공백이 가려졌다."""
    _express(tmp_path, where="src/server.js")
    (tmp_path / "package.json").write_text('{"name":"portal"}', encoding="utf-8")
    tpl = tmp_path / "shared" / "golden-templates" / "gg-node-api"
    (tpl / "src").mkdir(parents=True)
    (tpl / "package.json").write_text('{"name":"tpl","dependencies":{"helmet":"^7"}}', encoding="utf-8")
    (tpl / "src" / "server.js").write_text(
        'const express = require("express");' + NL + 'const app = express();' + NL
        + 'app.use(helmet());' + NL + 'app.listen(3000);' + NL,
        encoding="utf-8")
    notes = scan_path(str(tmp_path)).posture_notes
    projects = {n["project"] for n in notes if n["id"] == "POSTURE-HEADERS-001"}
    assert "(저장소 루트)" in projects, "앱 자신은 헤더 흔적이 없다"
    assert not any("golden-templates" in p for p in projects), "템플릿은 helmet 이 있다"


def test_nosniff_alone_is_not_header_evidence(tmp_path: Path):
    rep = scan_path(str(_express(tmp_path, 'res.setHeader("X-Content-Type-Options", "nosniff");' + NL)))
    assert any(n["id"] == "POSTURE-HEADERS-001" for n in rep.posture_notes)


def test_design_doc_mentioning_csp_is_not_evidence(tmp_path: Path):
    _express(tmp_path)
    (tmp_path / "docs.md").write_text("# TODO" + NL + "Content-Security-Policy 를 넣을 것" + NL, encoding="utf-8")
    assert any(n["id"] == "POSTURE-HEADERS-001" for n in scan_path(str(tmp_path)).posture_notes)


def test_package_list_yaml_mentioning_helmet_is_not_evidence(tmp_path: Path):
    """포털 실측: shared/references/approved-packages.yaml 의 'helmet' 이 루트 프로젝트 증거로 잡혔다."""
    _express(tmp_path, where="src/server.js")
    (tmp_path / "shared" / "references").mkdir(parents=True)
    (tmp_path / "shared" / "references" / "approved-packages.yaml").write_text("- helmet" + NL, encoding="utf-8")
    assert any(n["id"] == "POSTURE-HEADERS-001" for n in scan_path(str(tmp_path)).posture_notes)
