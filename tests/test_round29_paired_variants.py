"""35차 — 34차 완화마다 **위험 변형을 짝으로** 고정한다 (가이드북 별도검토 2026-10-15, 시나리오 ②).

"오탐을 줄였더니 공격 코드를 함께 면제한다"를 막는 회귀 사례. 안전 쪽은 0건, 위험 쪽은 경고 이상이어야
한다. 쌍 대조에서 실제로 미탐 하나가 나왔다 — `int` 를 다시 정의한 모듈에서 `int(request…)` 를 숫자로
믿어 SQL 삽입을 놓쳤다(요청서 B02 "int 재정의"). 이 파일이 그것을 고정한다.
"""
from __future__ import annotations

import pytest

from gvskb.scanner import scan_code


def _rules(code: str, filename: str) -> list[tuple[str, str]]:
    r = scan_code(code, filename=filename)
    return [(f.rule_id, f.decision.value) for f in r.findings]


def _has(rows, rule_prefix: str) -> bool:
    return any(rule.startswith(rule_prefix) for rule, _ in rows)


# ---------------------------------------------------------------------------
# a) 숫자 변환 — 변환만(안전) / 변환 뒤 원문 재대입(위험) / int 재정의(위험)
# ---------------------------------------------------------------------------

_INT_ONLY = '''
from flask import request
def view(conn):
    days = request.args.get("days", 1, type=int)
    return conn.execute(f"SELECT * FROM t WHERE d > now() - {days}").fetchall()
'''
_INT_THEN_RAW = '''
from flask import request
def view(conn):
    days = request.args.get("days", 1, type=int)
    days = request.args.get("days")
    return conn.execute(f"SELECT * FROM t WHERE d > now() - {days}").fetchall()
'''
_INT_SHADOWED = '''
from flask import request
def int(x):
    return x
def view(conn):
    days = int(request.args.get("days"))
    return conn.execute(f"SELECT * FROM t WHERE d > {days}").fetchall()
'''
_INT_SHADOWED_TYPE_KW = '''
from flask import request
int = str
def view(conn):
    days = request.args.get("days", 1, type=int)
    return conn.execute(f"SELECT * FROM t WHERE d > {days}").fetchall()
'''


def test_numeric_cast_alone_is_safe() -> None:
    assert not _has(_rules(_INT_ONLY, "a.py"), "GOV-SQL-INJECTION")


@pytest.mark.parametrize("code", [_INT_THEN_RAW, _INT_SHADOWED, _INT_SHADOWED_TYPE_KW],
                         ids=["raw-reassign", "def-int", "int=str"])
def test_numeric_cast_variants_stay_risky(code: str) -> None:
    rows = _rules(code, "a.py")
    assert _has(rows, "GOV-SQL-INJECTION"), rows
    assert ("GOV-SQL-INJECTION-001", "block") in rows


def test_shadowed_int_does_not_leak_into_other_modules() -> None:
    """contextvar 는 모듈 단위로 reset 된다 — 앞 파일의 `def int` 가 뒤 파일을 오염시키면 안 된다."""
    _rules(_INT_SHADOWED, "a.py")
    assert not _has(_rules(_INT_ONLY, "b.py"), "GOV-SQL-INJECTION")


# ---------------------------------------------------------------------------
# b) 순수 포맷 함수 — 고정 인수(안전) / 외부 인수(위험)
# ---------------------------------------------------------------------------

_FMT_STATIC = '''
const fmt = (t) => t.replace(/\\n/g, "<br>");
const NOTICE = "안녕하세요\\n공지입니다";
document.getElementById("out").innerHTML = fmt(NOTICE);
'''
_FMT_EXTERNAL = '''
const fmt = (t) => t.replace(/\\n/g, "<br>");
const q = new URLSearchParams(location.search).get("q");
document.getElementById("out").innerHTML = fmt(q);
'''


def test_pure_formatter_with_static_input_is_safe() -> None:
    assert not _has(_rules(_FMT_STATIC, "a.js"), "KISA-JS-INPUT-04")


def test_pure_formatter_with_external_input_is_blocked() -> None:
    assert ("KISA-JS-INPUT-04", "block") in _rules(_FMT_EXTERNAL, "a.js")


# ---------------------------------------------------------------------------
# c) 비밀값 — 키 **이름** 상수(안전) / 실제 키(위험)
# ---------------------------------------------------------------------------

def test_storage_key_names_are_not_secrets() -> None:
    code = 'SESSION_KEY = "admin_authenticated"\nTOKEN_KEY = "nyh_admin_session_v1"\n'
    assert not _has(_rules(code, "settings.py"), "GOV-SECRET")


def test_real_api_key_is_still_a_secret() -> None:
    rows = _rules('API_KEY = "sk-live-4f8A9bQ2xZ7pLm3NqR8tV1wY"\n', "settings.py")
    assert ("GOV-SECRET-APIKEY-001", "block") in rows


# ---------------------------------------------------------------------------
# d) dangerouslySetInnerHTML — 고정 상수(안전) / fetch 값(위험)
# ---------------------------------------------------------------------------

_DSIH_STATIC = '''
const INTRO = "<p>정적 안내문</p>";
export default function Page() {
  return <div dangerouslySetInnerHTML={{ __html: INTRO }} />;
}
'''
_DSIH_FETCH = '''
import { useEffect, useState } from "react";
export default function Page() {
  const [html, setHtml] = useState("");
  useEffect(() => { fetch("/api/doc").then(r => r.text()).then(setHtml); }, []);
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
'''


def test_static_raw_html_is_safe() -> None:
    assert not _has(_rules(_DSIH_STATIC, "page.tsx"), "KISA-JS-INPUT-04")


def test_fetched_raw_html_stays_flagged() -> None:
    assert _has(_rules(_DSIH_FETCH, "page.tsx"), "KISA-JS-INPUT-04")


# ---------------------------------------------------------------------------
# e) 무한 루프 — 탈출 있음(안전) / 탈출 없음(위험)
# ---------------------------------------------------------------------------

_LOOP_BREAK = '''
async function readAll(reader) {
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    handle(value);
  }
}
'''
_LOOP_NO_BREAK = '''
function spin() {
  while (true) {
    poll();
  }
}
'''


def test_stream_loop_with_break_is_safe() -> None:
    assert not _has(_rules(_LOOP_BREAK, "a.js"), "KISA-JS-TIME-01")


def test_loop_without_exit_stays_flagged() -> None:
    assert _has(_rules(_LOOP_NO_BREAK, "a.js"), "KISA-JS-TIME-01")


# ---------------------------------------------------------------------------
# f) 정수 오버플로 — 숫자 변환이 출처를 끊지 않는다(변환된 큰 정수가 바로 그 위험)
# ---------------------------------------------------------------------------

def test_numeric_cast_still_sources_fixed_width_overflow() -> None:
    code = '''
import numpy as np
from flask import request
def v():
    n = int(request.args.get("n"))
    return np.int32(n)
'''
    assert _has(_rules(code, "a.py"), "KISA-PY-INPUT-14")
