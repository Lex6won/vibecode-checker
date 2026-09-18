"""개선요청 #34 D3 — HTML 인라인 <script> 는 JavaScript 다.

JS 룰 36개가 전부 `languages: [javascript, typescript]` 라 `.html` 에서는 한 줄도
돌지 않았다. 포털 `my-scans.html` 의 innerHTML XSS 를 통째로 놓쳤다(2026-08-30).
룰에 html 을 더하는 대신 스크립트 블록만 남긴 사본을 javascript 로 한 번 더 검사한다 —
마크업 본문의 설명문(`eval() 을 쓰지 마세요`)에 JS 룰이 걸리지 않게.
"""
from __future__ import annotations

import pytest

from gvskb.scanner import _html_script_view, _script_tag_is_js, scan_code


def _ids(code: str, filename: str = "page.html") -> list[tuple[str, int]]:
    return [(rid, f.location.line) for f in scan_code(code, filename=filename).findings
            for rid in (f.rule_id, *f.also_matched)]  # 병합된 근거 룰 포함(S-8)


def test_inline_script_innerhtml_is_detected_with_correct_line():
    html = ('<html><body><ul id="list"></ul><script>\n'
            'const data = await (await fetch("/api/my-scans")).json();\n'
            'li.innerHTML = s.projectName;\n'
            '</script></body></html>\n')
    assert ("KISA-JS-INPUT-04", 3) in _ids(html)


def test_inline_script_eval_is_detected():
    assert any(r == "KISA-JS-INPUT-02" for r, _ in _ids('<script type="module">\nconst r = eval(userInput);\n</script>\n'))


def test_escaped_innerhtml_in_html_is_not_flagged():
    assert not _ids('<html><script>\nli.innerHTML = escapeHtml(s.projectName);\n</script></html>\n')


def test_markup_prose_does_not_trigger_js_rules():
    html = '<html><p>Do not use eval(userInput). document.write is bad.</p><script src="app.js"></script></html>\n'
    assert not _ids(html)


def test_json_and_template_blocks_are_not_javascript():
    html = ('<script type="application/json">{"q": "SELECT * FROM t WHERE id=" + id}</script>\n'
            '<script type="text/template"><div>eval(x)</div></script>\n')
    assert not _ids(html)
    assert _html_script_view(html, "p.html", None) is None


def test_one_line_script_keeps_line_number_and_ignores_surrounding_markup():
    html = '<div></div><script>document.write(location.hash)</script><p>eval(x)</p>\n'
    ids = _ids(html)
    assert ("KISA-JS-INPUT-04", 1) in ids
    assert not any(r == "KISA-JS-INPUT-02" for r, _ in ids), "스크립트 밖의 eval(x) 는 마크업이다"


def test_script_tag_type_detection():
    assert _script_tag_is_js("")
    assert _script_tag_is_js(' type="module" defer')
    assert _script_tag_is_js(" type=text/javascript")
    assert not _script_tag_is_js(' type="application/json"')
    assert not _script_tag_is_js(" type='text/template'")


def test_non_html_files_unchanged():
    assert _html_script_view("<script>eval(x)</script>", "app.js", None) is None
    assert _html_script_view("<script>eval(x)</script>", "app.py", None) is None
    assert ("KISA-JS-INPUT-02", 1) in _ids("const r = eval(userInput);\n", "app.js")


def test_js_taint_runs_on_inline_script():
    html = ('<script>\n'
            'const q = "SELECT * FROM users WHERE name = \'" + name + "\'";\n'
            'db.query(q);\n'
            '</script>\n')
    assert any(r == "KISA-JS-INPUT-01" for r, _ in _ids(html))


# ── 상수 리터럴 대입은 주입이 아니다(포털 실측: 새 발견 26건 중 9건) ──
@pytest.mark.parametrize("code", [
    'el.innerHTML = "";',
    "el.innerHTML = '';",
    "el.innerHTML = '<p class=\"x\">고정 문구</p>';",
    'el.innerHTML = `<p>static</p>`;',
    'el.innerHTML = `\n  <tr><td>고정</td></tr>\n`;',
])
def test_constant_literal_innerhtml_is_not_reported(code):
    assert not [f for f in scan_code(code + "\n", filename="a.js").findings if f.rule_id == "KISA-JS-INPUT-04"]


# ── 동적 값은 출처로 나뉜다(2026-09-18, 실측 999건 사례) ──
# 외부 출처(URL·요청·입력값·응답)이거나 이름이 입력값을 뜻하면 **차단**(js-taint 발견),
# 출처를 못 찾으면 발견은 남되 **warn(정밀 검토)** — 엔진이 보고도 못 찾은 것과
# 엔진이 못 읽은 것(닫히지 않은 템플릿)은 다르다. 후자는 차단이 그대로 남는다.
@pytest.mark.parametrize("code", [
    'el.innerHTML = `<p>${location.hash}</p>`;',
    'el.innerHTML = "<b>" + userInput + "</b>";',
    'el.innerHTML = params.get("q") || "";',
    'el.innerHTML = `\n  <td>${req.body.name}</td>\n`;',
    'el.innerHTML = `',          # 닫는 백틱 없음 — 읽지 못한 것은 차단 유지(보수적)
])
def test_dynamic_innerhtml_with_external_source_stays_blocked(code):
    hits = [f for f in scan_code(code + "\n", filename="a.js").findings if f.rule_id == "KISA-JS-INPUT-04"]
    assert hits and hits[0].decision.value == "block", code


@pytest.mark.parametrize("code", [
    'el.innerHTML = `<p>${name}</p>`;',
    'el.innerHTML = `\n  <td>${row.name}</td>\n`;',
    "el.innerHTML = '<i>' + label;",
    'el.innerHTML = html;',
])
def test_dynamic_innerhtml_of_unknown_origin_is_kept_as_review(code):
    """출처 미상 — 발견은 **남는다**(삭제 아님). 판정만 차단에서 검토로 내리고 이유를 적는다."""
    hits = [f for f in scan_code(code + "\n", filename="a.js").findings if f.rule_id == "KISA-JS-INPUT-04"]
    assert hits, code
    assert hits[0].decision.value == "warn", code
    assert hits[0].severity.value == "high", "심각도는 그대로 — 판정만 검토로"
    assert "정밀 검토" in (hits[0].severity_adjusted or ""), hits[0].severity_adjusted
