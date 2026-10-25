"""45차 — 선택 설치 JS/TS 구조 해석 엔진(ts-structure, C 결정 B).

없는 환경: 어댑터가 꺼지고 배너만 남으며 판정은 현행과 같아야 한다.
있는 환경(`pip install vibecode-checker[ts]`): 경계 프로브 H-07 류를 구조로 잡아야 한다.
"""
from __future__ import annotations

import importlib.util

import pytest

from gvskb.diagnostics import check_ts_structure
from gvskb.gate import gate_status
from gvskb.scanner import _ADAPTERS, engine_status, required_engines, scan_code
from gvskb.scanners.ts_structure import ENGINE, TsStructureScanner

_HAS_TS = all(importlib.util.find_spec(m) for m in ("tree_sitter", "tree_sitter_javascript", "tree_sitter_typescript"))


def test_engine_is_registered_but_never_required() -> None:
    assert any(a.name == ENGINE for a in _ADAPTERS)
    assert ENGINE not in required_engines(["javascript", "typescript", "python", "html"])


def test_missing_engine_is_a_banner_not_a_coverage_gap() -> None:
    st = engine_status(languages=["javascript"])
    names_unavailable = {e.name for e in st.unavailable}
    names_used = set(st.used)
    assert (ENGINE in names_used) == _HAS_TS and (ENGINE in names_unavailable) == (not _HAS_TS)
    if not _HAS_TS:
        reason = next(e.reason for e in st.unavailable if e.name == ENGINE)
        assert "[ts]" in reason and "판정 기준은 같습니다" in reason
    r = scan_code("const a = 1;\n", filename="a.js")
    g = gate_status(r)
    assert g["verdict"] != "undetermined" and g["complete"] is True


def test_doctor_reports_optional_engine_as_warn_or_ok() -> None:
    res = check_ts_structure()
    assert len(res) == 1 and res[0]["status"] in ("ok", "warn")


def test_scanner_is_safe_when_unavailable() -> None:
    s = TsStructureScanner()
    if not _HAS_TS:
        assert s.is_available() is False
        assert s.scan("window['ev' + 'al'](x)\n", filename="a.js") == []


@pytest.mark.skipif(not _HAS_TS, reason="tree-sitter 미설치(선택 설치 [ts]) — 설치된 환경에서만 구조 해석을 검증")
def test_obfuscated_global_eval_and_alias_are_detected() -> None:
    code = (
        "function runPayload(payload) {\n  return window[\"ev\" + \"al\"](payload);\n}\n"
        "const f = eval;\nexport function run2(x) { return f(x); }\n"
        "const F = globalThis['Function'];\nexport function run3(x) { return new F(x); }\n"
    )
    hits = sorted((f.location.line, f.engine) for f in scan_code(code, filename="a.js").findings
                  if f.rule_id == "KISA-JS-INPUT-02" and f.engine == ENGINE)
    assert hits == [(2, ENGINE), (5, ENGINE), (7, ENGINE)]


@pytest.mark.skipif(not _HAS_TS, reason="tree-sitter 미설치(선택 설치 [ts])")
def test_typescript_casts_do_not_hide_the_call_and_non_global_lookup_is_quiet() -> None:
    code = "const g = (eval as any);\nexport const run = (x: string) => g!(x);\n"
    assert any(f.engine == ENGINE and f.location.line == 2 for f in scan_code(code, filename="a.ts").findings)
    quiet = "const h = obj['eval'];\nexport const run = (x: string) => h(x);\nconst s = JSON.parse(x);\n"
    assert not [f for f in scan_code(quiet, filename="b.ts").findings if f.engine == ENGINE]


@pytest.mark.skipif(not _HAS_TS, reason="tree-sitter 미설치(선택 설치 [ts])")
def test_hard_variant_h07_detected_when_engine_present() -> None:
    from pathlib import Path

    from gvskb.scanner import scan_path

    r = scan_path(Path(__file__).resolve().parent.parent / "eval_corpus" / "projects" / "h_hard_variants")
    assert any(f.location.file == "obfuscated.js" and f.rule_id == "KISA-JS-INPUT-02" for f in r.findings)


def test_report_lists_engines_and_optional_gap() -> None:
    from gvskb.report import render_html, render_markdown

    r = scan_code("const a = 1;\n", filename="a.js")
    md = render_markdown(r)
    assert "## 검사 엔진" in md and ("미가동(선택) `ts-structure`" in md) == (not _HAS_TS)
    html = render_html(r)
    assert "검사 엔진" in html and ("**" not in html.split("검사 엔진", 1)[1][:600])
