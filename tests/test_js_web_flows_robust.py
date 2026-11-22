"""JS·TS 요청 값 추적(js-flow) — 깨진 코드·거대한 파일·깊은 중첩·tree-sitter 없는 환경에서도 예외를 밖으로 내지 않는다.

이 분석이 실패하거나 일의 양 한도를 넘으면 그 파일의 이 분석만 건너뛰고(빈 결과) 같은 파일의 다른 검사는 계속돼야 한다.
"""
from __future__ import annotations

import time

import pytest

from gvskb.scanner import _ADAPTERS, engine_status, scan_code

HEADER = "const express = require('express');\nconst axios = require('axios');\nconst app = express();\n"


def _ts_available() -> bool:
    from gvskb.scanners._ts_parse import load_languages

    return load_languages() is not None


def _flows(code: str, filename: str = "app.js", *, strict: bool = True):
    from gvskb.scanners._ts_parse import parse
    from gvskb.scanners.js_web_flows import scan_js_flows

    root, src = parse(code, filename)
    return scan_js_flows(root, src, filename, strict=strict)


needs_ts = pytest.mark.skipif(not _ts_available(), reason="tree-sitter 미설치(선택 설치 [ts])")


@needs_ts
def test_broken_code_is_skipped_as_a_whole() -> None:
    """구문 오류가 하나라도 있으면 파일 단위로 건너뛴다 — 다른 함수의 파싱 오류가 쓰임을 가리면 오탐이 된다."""
    code = HEADER + (
        "app.get('/a', async (req, res) => {\n  const t = req.query.t;\n  await axios.get(t);\n});\n"
        "app.get('/b', (req, res) => {\n  if (req.query.t.startsWith('x' {\n});\n"
    )
    assert _flows(code) == []


@needs_ts
def test_same_code_without_the_error_is_reported() -> None:
    code = HEADER + "app.get('/a', async (req, res) => {\n  const t = req.query.t;\n  await axios.get(t);\n});\n"
    assert [h[0] for h in _flows(code)] == ["KISA-JS-INPUT-12"]


@needs_ts
def test_generated_50k_line_file_stays_bounded() -> None:
    """5만 줄 생성 파일 — 크기 한도(512KB)나 일의 양 한도로 건너뛰거나 끝까지 보더라도 몇 초 안에 끝난다."""
    routes = [f"app.get('/r{i}', (req, res) => {{\n  const v{i} = req.query.v;\n  res.json({{ v: v{i} }});\n}});"
              for i in range(12_500)]
    code = HEADER + "\n".join(routes) + "\n"
    assert code.count("\n") >= 50_000
    started = time.perf_counter()
    assert _flows(code, strict=False) == []
    assert time.perf_counter() - started < 10


@needs_ts
def test_many_routes_under_the_size_limit_stay_fast() -> None:
    routes = [f"app.get('/r{i}', async (req, res) => {{\n  const t = req.query.t{i};\n  res.send((await axios.get(t)).data);\n}});"
              for i in range(600)]
    code = HEADER + "\n".join(routes) + "\n"
    started = time.perf_counter()
    hits = _flows(code, strict=False)
    elapsed = time.perf_counter() - started
    assert elapsed < 10, elapsed
    assert len(hits) in (0, 600)                           # 끝까지 봤거나, 한도로 통째로 건너뛰었다(일부만 내지 않는다)


@needs_ts
def test_900_term_concatenation_never_raises() -> None:
    expr = " + ".join(["req.query.a"] * 900)
    code = HEADER + "const fs = require('fs');\napp.get('/c', (req, res) => {\n  const p = " + expr + ";\n  fs.readFileSync(p);\n});\n"
    hits = _flows(code, strict=False)
    assert all(h[0] == "KISA-JS-INPUT-03" for h in hits)


@needs_ts
def test_deep_nesting_never_raises() -> None:
    """문장 걷기는 명시적 스택이다 — 수백 단 중첩에서도 재귀 한도에 걸리지 않는다."""
    depth = 400
    body = "  const t = req.query.t;\n" + "".join("  if (x) {\n" for _ in range(depth)) + "  axios.get(t);\n" + "  }\n" * depth
    code = HEADER + "app.get('/d', (req, res) => {\n" + body + "});\n"
    _flows(code, strict=True)


@needs_ts
def test_deeply_nested_callbacks_never_raise() -> None:
    depth = 300
    inner = "axios.get(t)"
    for _ in range(depth):
        inner = f"run(() => {{ {inner}; }})"
    code = HEADER + "app.get('/d', (req, res) => {\n  const t = req.query.t;\n  " + inner + ";\n});\n"
    _flows(code, strict=False)


def test_scan_code_never_raises_on_hostile_input() -> None:
    for code in (HEADER + "app.get('/x', (req, res) => { " * 2000,
                 HEADER + "\x00\x01" * 100,
                 HEADER + "with (obj) { app.get('/x', (req, res) => axios.get(req.query.u)); }\n"):
        scan_code(code, filename="a.js")


def test_adapter_is_registered_optional_and_unranked() -> None:
    from gvskb.policy import ENGINE_PRECISION
    from gvskb.scanner import required_engines

    assert any(a.name == "js-flow" for a in _ADAPTERS)
    names = [a.name for a in _ADAPTERS]
    assert names.index("js-flow") > names.index("ts-structure")      # 공용 파서의 직전 결과를 다시 쓴다
    assert "js-flow" not in required_engines(["javascript", "typescript", "python", "html"])
    assert "js-flow" not in ENGINE_PRECISION


def test_missing_tree_sitter_turns_the_engine_off(monkeypatch) -> None:
    """tree-sitter 가 없으면 `[]` 와 '미가동' — 줄 단위 대체 분석은 없다."""
    from gvskb.scanners import _ts_parse
    from gvskb.scanners.js_flow_scanner import JsFlowScanner

    monkeypatch.setattr(_ts_parse, "_languages", None)
    monkeypatch.setattr(_ts_parse, "_languages_checked", True)
    s = JsFlowScanner()
    assert s.is_available() is False
    code = HEADER + "app.get('/a', async (req, res) => {\n  const t = req.query.t;\n  await axios.get(t);\n});\n"
    assert s.scan(code, filename="a.js") == []
    st = engine_status(languages=["javascript"])
    reason = next(e.reason for e in st.unavailable if e.name == "js-flow")
    assert "[ts]" in reason and "판정 기준은 같습니다" in reason
    assert "js-flow" not in st.used


@needs_ts
def test_parse_cache_is_keyed_by_content_not_filename() -> None:
    """같은 이름으로 다른 내용을 연달아 돌려도 앞 내용의 나무를 쓰지 않는다(`<memory>` 기본 이름·HTML 사본)."""
    from gvskb.scanners._ts_parse import parse

    a = parse("const a = 1;\n", "<memory>")
    b = parse("const b = 2; const c = 3;\n", "<memory>")
    assert a[1] != b[1] and b[0].named_child_count == 2
    again = parse("const b = 2; const c = 3;\n", "<memory>")
    assert again[0] == b[0]
    ts = parse("const b = 2; const c = 3;\n", "x.ts")
    assert ts[1] == b[1]                                   # 같은 내용이라도 문법이 다르면 다시 파싱한다(열쇠에 문법이 있다)
