"""JS·TS 요청 값 추적(js-flow) — 보고서(`scan_code`) 경유: 엔진 이름, 결정 검토, 같은 줄의 기존 발견 유지, 인라인 무시."""
from __future__ import annotations

import textwrap

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_javascript")
pytest.importorskip("tree_sitter_typescript")

from gvskb.scanner import scan_code  # noqa: E402

HEADER = (
    "const express = require('express');\n"
    "const axios = require('axios');\n"
    "const { exec } = require('child_process');\n"
    "const app = express();\n"
)


def _findings(code: str, filename: str = "app.js", rule: str | None = None):
    report = scan_code(HEADER + textwrap.dedent(code), filename=filename)
    return [f for f in report.findings if rule is None or f.rule_id == rule], report


def test_variable_flow_is_a_review_level_js_flow_finding() -> None:
    found, report = _findings("""
        app.get('/a', async (req, res) => {
          const target = req.query.target;
          const r = await axios.get(target);
          res.send(r.data);
        });
    """, rule="KISA-JS-INPUT-12")
    flow = [f for f in found if f.engine == "js-flow"]
    assert len(flow) == 1
    f = flow[0]
    assert f.confidence == "likely" and f.decision.value == "warn" and f.location.line == 8
    assert "js-flow" in report.engines.used


def test_command_flow_is_downgraded_to_review_with_the_python_reason() -> None:
    found, _ = _findings("""
        app.get('/ping', (req, res) => {
          const host = req.query.host;
          exec('ping -c 1 ' + host);
          res.end();
        });
    """, rule="KISA-JS-INPUT-05")
    flow = [f for f in found if f.engine == "js-flow"]
    assert flow and all(f.decision.value == "warn" for f in flow)
    steps = [a for a in flow[0].adjustments if a.get("step") == "web_flow"]
    assert steps and "검사한 흔적을 찾지 못했습니다" in steps[0].get("reason", "")


def test_pattern_only_finding_on_the_same_line_gives_way_to_the_flow() -> None:
    """같은 줄에 정규식(패턴 일치)이 있으면 흐름을 본 발견(유력)이 남는다 — 결정은 그대로 검토다(1회차 적대적 검증:
    템플릿 문자열 명령이 전부 정규식 뒤에 가려졌다)."""
    found, _ = _findings("""
        app.get('/a', async (req, res) => {
          const r = await axios.get(req.query.target);
          res.send(r.data);
        });
    """, rule="KISA-JS-INPUT-12")
    on_line = [f for f in found if f.location.line == 7]
    assert [(f.engine, f.confidence, f.decision.value) for f in on_line] == [("js-flow", "likely", "warn")]


def test_flow_never_lowers_a_stronger_existing_finding() -> None:
    """확인됨·유력이거나 근거와 무관하게 차단으로 남는 발견은 흐름 발견이 대신하지 않는다(결정·근거를 낮추지 않는다)."""
    from gvskb.scanner import _dedupe, _flow_supersedes
    from gvskb.scanners.regex_scanner import build_finding, lookup_rule

    rule = lookup_rule("KISA-JS-INPUT-12")
    flow = build_finding(rule, filename="a.js", line_no=3, evidence="x", engine="js-flow", confidence="likely")
    for conf in ("confirmed", "likely"):
        other = build_finding(rule, filename="a.js", line_no=3, evidence="x", engine="js-taint", confidence=conf)
        assert not _flow_supersedes(flow, other)
        assert [f.engine for f in _dedupe([other, flow])] == ["js-taint"]
    construct = lookup_rule("KISA-PY-INPUT-04")      # 구문 자체가 약점 — 패턴 일치라도 차단으로 남는다
    regex = build_finding(construct, filename="a.py", line_no=3, evidence="x", engine="regex", confidence="pattern-only")
    pyflow = build_finding(construct, filename="a.py", line_no=3, evidence="x", engine="python-flow", confidence="likely")
    if regex.decision.value == "block":
        assert [f.engine for f in _dedupe([regex, pyflow])] == ["regex"]
    plain = build_finding(rule, filename="a.js", line_no=3, evidence="x", engine="regex", confidence="pattern-only")
    assert [f.engine for f in _dedupe([plain, flow])] == ["js-flow"]
    assert [f.engine for f in _dedupe([flow, plain])] == ["js-flow"]


def test_inline_ignore_comment_suppresses_the_flow() -> None:
    found, _ = _findings("""
        app.get('/a', async (req, res) => {
          const target = req.query.target;
          // gvskb: ignore KISA-JS-INPUT-12
          const r = await axios.get(target);
          res.send(r.data);
        });
    """, rule="KISA-JS-INPUT-12")
    assert not [f for f in found if f.engine == "js-flow"]


def test_safe_twin_is_quiet_through_the_report() -> None:
    found, _ = _findings("""
        const ALLOWED = new Set(['api.example.com']);
        app.get('/a', async (req, res) => {
          const target = new URL(String(req.query.target));
          if (!ALLOWED.has(target.hostname)) return res.status(403).end();
          res.send((await axios.get(target.toString())).data);
        });
    """)
    assert not [f for f in found if f.engine == "js-flow"]


def test_typescript_file_and_category_filter() -> None:
    code = HEADER + "app.get('/a', (req, res) => {\n  const h = req.query.h as string;\n  exec('ping ' + h);\n  res.end();\n});\n"
    assert any(f.engine == "js-flow" for f in scan_code(code, filename="a.ts").findings)
    only_secrets = scan_code(code, filename="a.ts", categories={"secret"})
    assert not [f for f in only_secrets.findings if f.engine == "js-flow"]


def test_inline_script_in_html_without_server_markers_is_ignored() -> None:
    html = "<html><body><script>\nconst u = location.search;\nfetch(u);\n</script></body></html>\n"
    assert not [f for f in scan_code(html, filename="page.html").findings if f.engine == "js-flow"]
