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


def test_existing_finding_on_the_same_line_is_kept() -> None:
    """한 줄에 출처와 호출이 함께 있으면 정규식 룰이 이미 보고한다 — 추적 분석이 그 발견을 대체하지 않는다."""
    found, _ = _findings("""
        app.get('/a', async (req, res) => {
          const r = await axios.get(req.query.target);
          res.send(r.data);
        });
    """, rule="KISA-JS-INPUT-12")
    on_line = [f for f in found if f.location.line == 7]
    assert on_line and all(f.engine != "js-flow" for f in on_line)


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
