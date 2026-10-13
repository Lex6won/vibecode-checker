"""30차 — JS/TS 오염 추적 미탐·오탐 묶음(전면 점검 docs/40 §3-3 재현 목록).

- `req.query.id` 가 숫자 멤버 규칙에 먼저 걸려 발견이 지워짐
- `.length` 꼬리가 식 전체를 상수로 만듦
- `x || \\`…\\`` · `c ? \\`…\\` : x` 에서 템플릿 밖 피연산자가 버려짐
- 같은 줄의 `{` 안으로 선언이 들어가 뒤 줄에서 못 찾음(`const cfg = { title: location.hash }`)
- `letter = location.hash` 의 이름이 `ter`
- `if (…) {` 를 함수 범위로 봄 · 여러 줄 템플릿 닫는 줄의 `}` 유실
- 2026-10-13 회귀: 본문에서 정화하는 헬퍼 `rowHtml(data.row)` 가 차단
- TS: 타입 주석·`?.`·`!.`·구조분해·`export const`
- `tbody`·`draw`·`freq` 가 입력값 이름으로 오인
"""
from __future__ import annotations

import pytest

from gvskb.scanner import scan_code
from gvskb.schema import Decision

_ESC = "function esc(s){ return String(s).replace(/[&<>\"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[c])); }\n"


def _xss(code: str, filename: str = "app.js"):
    return [f for f in scan_code(code, filename=filename).findings if f.rule_id == "KISA-JS-INPUT-04"]


def _blocked(code: str, filename: str = "app.js") -> None:
    hits = _xss(code, filename)
    assert hits, "발견이 사라졌습니다(미탐)"
    assert hits[0].decision == Decision.block and hits[0].confidence == "confirmed", \
        [(f.decision, f.confidence, f.severity_adjusted) for f in hits]


def _review(code: str, filename: str = "app.js") -> None:
    hits = _xss(code, filename)
    assert hits, "정화된 sink 도 발견은 남는다(검토)"
    assert hits[0].decision == Decision.warn, [(f.decision, f.confidence, f.severity_adjusted) for f in hits]


# ---------------------------------------------------------------------------
# 평가 순서
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("src", ["req.query.id", "req.params.id", "req.body.date", "req.body.createdAt"])
def test_request_member_with_numeric_looking_name_is_still_tainted(src: str) -> None:
    _blocked(f"app.get('/x', (req, res) => {{ el.innerHTML = {src}; }});\n")


def test_server_assigned_numeric_member_of_variable_stays_quiet() -> None:
    code = "const data = await res.json();\nel.innerHTML = data.items.length;\nel.innerHTML = row.createdAt;\n"
    hits = _xss(code)
    assert all(f.decision != Decision.block for f in hits), [(f.decision, f.severity_adjusted) for f in hits]


def test_length_tail_does_not_make_whole_expression_constant() -> None:
    _blocked("app.post('/n', (req, res) => { el.innerHTML = '<p>' + req.body.note + '</p> 총 ' + items.length; });\n")


def test_logical_or_with_template_fallback_keeps_the_source() -> None:
    _blocked("const data = await res.json();\nel.innerHTML = data.html || `<p>없음</p>`;\n")


def test_ternary_with_template_branch_keeps_the_other_branch() -> None:
    _blocked("const data = await res.json();\nel.innerHTML = ok ? `<b>x</b>` : data.note;\n")


def test_ternary_with_both_safe_branches_is_quiet() -> None:
    hits = _xss(_ESC + "const data = await res.json();\nel.innerHTML = ok ? `<b>${esc(data.a)}</b>` : `<i>-</i>`;\n")
    assert hits and hits[0].decision == Decision.warn


# ---------------------------------------------------------------------------
# 범위
# ---------------------------------------------------------------------------

def test_declaration_with_brace_on_same_line_is_visible_later() -> None:
    _blocked("const cfg = { title: location.hash };\nel.innerHTML = cfg.title;\n")


def test_keyword_prefixed_identifier_is_not_a_declaration() -> None:
    _blocked("letter = location.hash;\nel.innerHTML = letter;\n")
    _blocked("variables = location.search;\nel.innerHTML = variables;\n")


def test_if_block_is_not_a_function_scope() -> None:
    code = _ESC + """
function render(x) {
  let html = location.hash;
  if (x) {
    html = esc(html);
  }
  html = '<b>fixed</b>';
  el.innerHTML = html;
}
"""
    hits = _xss(code)
    assert all(f.decision != Decision.block for f in hits), [(f.decision, f.severity_adjusted) for f in hits]


def test_multiline_template_closing_line_keeps_scope_in_sync() -> None:
    code = _ESC + """
function a() {
  el.innerHTML = `
    <b>${esc(x)}</b>
  `; }
function b(req) { el.innerHTML = req.body.note; }
"""
    hits = {f.location.line: f for f in _xss(code)}
    assert any(h.decision == Decision.warn for h in hits.values())
    assert any(h.decision == Decision.block and h.confidence == "confirmed" for h in hits.values()), \
        [(ln, h.decision, h.confidence) for ln, h in hits.items()]


# ---------------------------------------------------------------------------
# 정화 헬퍼 회귀
# ---------------------------------------------------------------------------

_ROW = _ESC + "function rowHtml(r){ return '<td>' + esc(r.name) + '</td>'; }\nconst data = await res.json();\n"
_RAW = _ESC + "function rawHtml(r){ return '<td>' + r.name + '</td>'; }\nconst data = await res.json();\n"


@pytest.mark.parametrize("sink", [
    "box.innerHTML = rowHtml(data.row);\n",
    "box.innerHTML = data.rows.map(r => rowHtml(r)).join('');\n",
    "box.innerHTML = data.rows.map(rowHtml).join('');\n",
])
def test_sanitizing_helper_with_source_argument_is_review(sink: str) -> None:
    _review(_ROW + sink)


@pytest.mark.parametrize("sink", [
    "box.innerHTML = rawHtml(data.row);\n",
    "box.innerHTML = data.rows.map(r => rawHtml(r)).join('');\n",
])
def test_passthrough_helper_with_source_argument_is_blocked(sink: str) -> None:
    _blocked(_RAW + sink)


# ---------------------------------------------------------------------------
# TypeScript 표기
# ---------------------------------------------------------------------------

def test_typescript_type_annotation_and_optional_chaining() -> None:
    _blocked("let html: string = req.body.note;\nel.innerHTML = html;\n", "a.ts")
    _blocked("el.innerHTML = res?.data?.note;\n", "a.ts")
    _blocked("el.innerHTML = data!.note + location.hash;\n", "a.ts")


def test_destructuring_and_export_const() -> None:
    _blocked("const { note } = req.body;\nel.innerHTML = note;\n", "a.ts")
    _blocked("const { title: t = '' } = req.query;\nel.innerHTML = t;\n", "a.ts")
    _blocked("export const title = location.hash;\nel.innerHTML = title;\n", "a.ts")


# ---------------------------------------------------------------------------
# 입력값 이름 경계
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", ["tbody", "draw", "freq", "jQuery", "tableBody"])
def test_substring_names_are_not_input_names(name: str) -> None:
    hits = _xss(f"el.innerHTML = {name};\n")
    assert not any("이름이 입력값" in (f.severity_adjusted or "") for f in hits), \
        [(f.decision, f.severity_adjusted) for f in hits]


@pytest.mark.parametrize("name", ["userInput", "rawHtml", "getUserInput", "requestBody", "payload", "body"])
def test_real_input_names_are_still_likely(name: str) -> None:
    from gvskb.scanners.js_taint import _TAINTED_NAME_RE
    assert _TAINTED_NAME_RE.search(name), name
