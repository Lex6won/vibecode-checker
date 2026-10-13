"""1층 이후 재점검(2026-10-13, safe_check) — ES5 콜백 · LLM 도구 매개변수 · 성능 동치.

근거 정책(24차) 뒤 같은 소스를 다시 돌려 남은 것:
  · 차단 19건 중 8건이 날짜·숫자 필드(`s.ended_at`·`d.pid`)나, 모든 값이 정화된 ES5 `function(){}` 콜백
  · 한 줄 `rows.forEach(function(f){ h+=…; })` 누적은 **발견 자체가 사라지는 미탐**
  · LLM 에이전트 도구 `run_sql(con, sql)` 이 받은 SQL 을 실행하는 진짜 위험이 '유력·검토'로 내려감
기관 제출 소스라 원문은 싣지 않고 **같은 모양의 합성 코드**로 고정한다.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from gvskb.scanner import scan_code
from gvskb.schema import Decision

_ESC = "function esc(s){ return String(s ?? '').replace(/[&<>\"']/g, c => ({'&':'&amp;','<':'&lt;'}[c])); }\n"
_SRC = "const data = JSON.parse(raw);\n"


def _xss(code: str):
    return [f for f in scan_code(code, filename="app.js").findings if f.rule_id == "KISA-JS-INPUT-04"]


def _sql(code: str):
    return [f for f in scan_code(code, filename="app.py").findings if f.rule_id == "GOV-SQL-INJECTION-001"]


# ---------------------------------------------------------------------------
# ② 그대로 차단 — 같은 모양의 진짜 위험
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("code", [
    _ESC + _SRC + "box.innerHTML=data.rows.map(function(f,i){ return '<td>'+f.name+'</td>'; }).join('');\n",
    _ESC + _SRC + "var h='';\ndata.rows.forEach(function(f){ h+='<td>'+f.name+'</td>'; });\nbox.innerHTML=h;\n",
    _ESC + _SRC + "var h='';\ndata.rows.forEach(function(f){\n  h+='<td>'+f.name+'</td>';\n});\nbox.innerHTML=h;\n",
    _ESC + _SRC + "box.innerHTML=data.rows.map(function(f){ var x='<b>'; return x+f.note; }).join('');\n",
    _SRC + "el.innerHTML='<b>'+data.comment+'</b>';\n",
], ids=["map-function-raw", "forEach-oneline-raw", "forEach-multiline-raw", "map-function-local-then-raw", "text-member"])
def test_unsanitized_es5_shapes_stay_blocked(code: str) -> None:
    hits = _xss(code)
    assert hits, "발견이 사라졌습니다(미탐)"
    assert hits[0].decision == Decision.block and hits[0].confidence == "confirmed", \
        [(f.decision, f.severity_adjusted) for f in hits]


def test_llm_tool_registry_parameter_reaching_sql_is_blocked() -> None:
    code = (
        "import re\n"
        "def run_sql(con, sql, limit=200):\n"
        "    s = sql.strip().rstrip(';')\n"
        "    if not re.match(r'(?is)^select\\b', s):\n"
        "        return {'error': 'SELECT only'}\n"
        "    if ' limit ' not in s.lower():\n"
        "        s += f' LIMIT {limit}'\n"
        "    return {'rows': [dict(r) for r in con.execute(s).fetchall()]}\n"
        "TOOLS = [{'name': 'run_sql', 'desc': 'read-only SELECT'}]\n"
    )
    hits = _sql(code)
    assert hits and hits[0].decision == Decision.block and hits[0].confidence == "confirmed"


def test_tool_decorator_parameter_used_as_whole_query_is_blocked() -> None:
    hits = _sql("@mcp.tool()\ndef query(sql: str):\n    return conn.execute(sql).fetchall()\n")
    assert hits and hits[0].decision == Decision.block and hits[0].confidence == "confirmed"


def test_tool_map_with_function_values_is_recognised() -> None:
    code = (
        "def lookup(con, where):\n"
        "    return con.execute('SELECT * FROM t WHERE ' + where).fetchall()\n"
        "tool_map = {'lookup': lookup}\n"
    )
    hits = _sql(code)
    assert hits and hits[0].decision == Decision.block


# ---------------------------------------------------------------------------
# ① 내려가는 것 — 지워지지 않거나(검토) 정화로 인정
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("code", [
    _ESC + _SRC + "box.innerHTML=data.rows.map(function(f,i){ return '<td>'+esc(f.name)+'</td>'; }).join('');\n",
    _ESC + _SRC + "box.innerHTML=data.rows.map(function(f){\n  return '<td>'+esc(f.name)+'</td>';\n}).join('');\n",
    _ESC + _SRC + "box.innerHTML=data.rows.map(f => '<td>'+esc(f.name)+'</td>').join('');\n",
    _ESC + _SRC + "var h='';\ndata.rows.forEach(function(f){ h+='<td>'+esc(f.name)+'</td>'; });\nbox.innerHTML=h;\n",
], ids=["map-function", "map-function-multiline", "map-arrow-concise", "forEach-oneline"])
def test_sanitized_es5_shapes_are_review_not_block(code: str) -> None:
    hits = _xss(code)
    assert hits, "정화된 sink 도 발견은 남는다(검토)"
    assert hits[0].decision == Decision.warn and "정화 호출" in (hits[0].severity_adjusted or ""), \
        [(f.decision, f.severity_adjusted) for f in hits]


@pytest.mark.parametrize("member", ["ended_at", "reg_date", "createdAt", "pid"])
def test_server_date_and_process_fields_are_not_xss_sources(member: str) -> None:
    hits = _xss(_ESC + _SRC + f"el.innerHTML='<span>완료 ('+(data.{member}||'')+') '+esc(data.label)+'</span>';\n")
    assert not hits or hits[0].decision != Decision.block, (member, [(f.decision, f.severity_adjusted) for f in hits])


def test_plain_function_parameter_sql_stays_likely() -> None:
    """도구로 노출되지 않은 함수의 매개변수는 출처를 모른다 — 유력·검토."""
    hits = _sql("def run_sql(con, sql):\n    return con.execute(sql + ' LIMIT 5').fetchall()\n")
    assert hits and hits[0].decision == Decision.warn and hits[0].confidence == "likely"


def test_tool_using_placeholders_is_not_flagged() -> None:
    code = (
        "@mcp.tool()\n"
        "def facts(codes: list):\n"
        "    ph = ','.join('?' * len(codes))\n"
        "    return conn.execute(f'SELECT * FROM t WHERE c IN ({ph})', codes).fetchall()\n"
    )
    assert not _sql(code)


# ---------------------------------------------------------------------------
# 성능 변경은 결과를 바꾸지 않는다
# ---------------------------------------------------------------------------


def test_regex_prefilter_matches_line_by_line_scan() -> None:
    """파일 단위 선별을 끈 것과 켠 것의 발견이 같아야 한다(부정 탐색 패턴 포함)."""
    from gvskb.scanners import regex_scanner as rs

    code = (
        "import os, ssl\n"
        "ctx.verify_mode = ssl.CERT_NONE\n"
        "if (el.innerHTML == '') render();\n"
        "el.innerHTML = '<b>' + label;\n"
        "password = 'hunter2plus9'\n"
        "os.system('ls ' + d)\n"
    )
    for fname in ("a.py", "a.js"):
        with_filter = {(f.rule_id, f.location.line) for f in rs.RegexScanner().scan(code, filename=fname)}
        saved = rs._rules_that_can_match
        rs._rules_that_can_match = lambda code, lang, cats: [  # noqa: E731
            r for r in rs.RULES
            if not (cats and r["category"] not in cats)
            and not ((r.get("languages") or set()) and lang and lang not in r.get("languages"))
        ]
        try:
            without = {(f.rule_id, f.location.line) for f in rs.RegexScanner().scan(code, filename=fname)}
        finally:
            rs._rules_that_can_match = saved
        assert with_filter == without, fname


def test_rule_load_cache_sees_edits(tmp_path: Path) -> None:
    from gvskb.loader import load_all_rules

    src = Path(__file__).resolve().parents[1] / "rules" / "kisa-python" / "KISA-PY-SEC-11.md"
    d = tmp_path / "rules"
    d.mkdir()
    target = d / "KISA-PY-SEC-11.md"
    target.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    first = load_all_rules(d)
    again = load_all_rules(d)
    assert [r.id for r in first] == [r.id for r in again]
    target.write_text(target.read_text(encoding="utf-8") + "\n캐시무효화확인\n", encoding="utf-8")
    edited = load_all_rules(d)
    assert edited and "캐시무효화확인" in edited[0].body, "디스크가 바뀌었는데 캐시를 돌려줬다"
