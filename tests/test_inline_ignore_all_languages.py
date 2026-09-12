"""인라인 무시(`gvskb: ignore`)는 **모든 언어**에서 동작해야 한다.

실측 결함(2026-09-12): `RegexScanner.scan` 의 인라인 무시 검사가
``if is_python and ...`` 안에 갇혀 있어 **파이썬에서만** 동작했다. 그런데 룰
카드는 자바스크립트 사용자에게도 같은 주석을 안내한다 —

    rules/kisa-javascript/KISA-JS-INPUT-08.md:88
      "신뢰된 내부 XML 처리는 `gvskb: ignore` 주석으로 예외 처리할 수 있습니다."
    rules/kisa-javascript/KISA-JS-SEC-05.md:89
      "... `gvskb: ignore` 주석으로 예외 처리하세요."

안내대로 해도 경고가 그대로 나오면 사용자는 도구를 신뢰하지 않게 된다. 문서가
약속한 장치가 실제로 동작하는지 언어별로 못 박는다.

함께 좁힌 것: 무시 문구는 **주석 안에 있을 때만** 인정한다. 예전에는 줄 어디에
있든 인정해서, 검사 대상 코드의 문자열 리터럴이 그 문구를 담기만 해도 그 줄의
검사가 꺼졌다 — 검사받는 쪽이 자기 검사를 끄는 통로였다.
"""
from __future__ import annotations

from gvskb.scanners.regex_scanner import RegexScanner, count_inline_ignores


def _rule_ids(code: str, filename: str) -> set[str]:
    return {f.rule_id for f in RegexScanner().scan(code, filename=filename)}


# ---------------------------------------------------------------------------
# 무시가 없으면 잡힌다 (테스트가 공허하지 않음을 먼저 보인다)
# ---------------------------------------------------------------------------

def test_javascript_finding_is_detected_without_ignore() -> None:
    found = _rule_ids('const el = document.getElementById("x");\nel.innerHTML = userInput;\n', "app.js")
    assert found, "무시 주석이 없을 때는 발견이 있어야 이 테스트가 의미를 가진다"


def test_python_finding_is_detected_without_ignore() -> None:
    assert _rule_ids("eval(user_input)\n", "app.py")


# ---------------------------------------------------------------------------
# 언어별 인라인 무시
# ---------------------------------------------------------------------------

def test_javascript_standalone_comment_suppresses_next_line() -> None:
    """JS 는 **단독 주석 줄**로 쓴다 — 지시는 바로 다음 줄에 적용된다."""
    before = _rule_ids("el.innerHTML = userInput;\n", "app.js")
    after = _rule_ids("// gvskb: ignore\nel.innerHTML = userInput;\n", "app.js")
    assert before, "전제: 무시가 없으면 잡힌다"
    assert after == set()


def test_typescript_standalone_comment_works() -> None:
    before = _rule_ids("el.innerHTML = userInput;\n", "app.ts")
    after = _rule_ids("// gvskb: ignore\nel.innerHTML = userInput;\n", "app.ts")
    assert before
    assert after == set()


def test_javascript_block_comment_line_works() -> None:
    before = _rule_ids("el.innerHTML = userInput;\n", "app.js")
    after = _rule_ids("/* gvskb: ignore */\nel.innerHTML = userInput;\n", "app.js")
    assert before
    assert after == set()


def test_javascript_same_line_ignore_is_not_honored() -> None:
    """JS 의 같은 줄 형태는 인정하지 않는다 — 이것이 우회를 닫은 방법이다.

    JS 는 정규식 리터럴과 나눗셈을 문맥 없이 구분할 수 없어(`a = b / c / d`),
    코드 한가운데서 주석 시작 위치를 정확히 찾는 것이 파서 없이는 불가능하다.
    손으로 짠 스캐너를 계속 기우는 대신 **판정이 필요 없는 형태만** 인정한다.
    """
    code = "el.innerHTML = userInput; // gvskb: ignore\n"
    assert _rule_ids(code, "app.js"), "같은 줄 무시는 JS 에서 동작하지 않아야 한다"


def test_standalone_directive_applies_to_only_one_line() -> None:
    """지시 하나가 파일 전체를 끄지 않는다 — 다음 한 줄에만 적용된다."""
    code = (
        "// gvskb: ignore\n"
        "el.innerHTML = a;\n"
        "el.innerHTML = b;\n"
    )
    found = _rule_ids(code, "app.js")
    assert found, "두 번째 줄은 계속 잡혀야 한다"


def test_python_ignore_still_works() -> None:
    assert _rule_ids("eval(user_input)  # gvskb: ignore\n", "app.py") == set()


def test_rule_id_scoped_ignore_only_silences_that_rule() -> None:
    """id 를 지정하면 그 룰만 꺼진다 — 나머지는 계속 본다."""
    all_ids = _rule_ids("eval(user_input)\n", "app.py")
    assert all_ids, "전제: 최소 한 개 룰이 잡힌다"
    target = sorted(all_ids)[0]
    remaining = _rule_ids(f"eval(user_input)  # gvskb: ignore {target}\n", "app.py")
    assert target not in remaining
    assert remaining == all_ids - {target}


# ---------------------------------------------------------------------------
# 주석 밖의 문구는 무시로 인정하지 않는다
# ---------------------------------------------------------------------------

def test_ignore_text_inside_a_string_literal_does_not_suppress() -> None:
    """검사 대상 코드가 자기 검사를 끄지 못하게 한다."""
    code = 'const msg = "gvskb: ignore";\nel.innerHTML = userInput;\n'
    assert _rule_ids(code, "app.js")

    same_line = 'el.innerHTML = userInput + "gvskb: ignore";\n'
    assert _rule_ids(same_line, "app.js"), "문자열 안의 문구는 무시가 아니다"


def test_python_ignore_text_inside_string_does_not_suppress() -> None:
    code = 'label = "gvskb: ignore"\neval(user_input)\n'
    assert _rule_ids(code, "app.py")


def test_url_in_string_cannot_disable_detection() -> None:
    """회귀: URL 의 `//` 가 주석 시작으로 오인돼 검사가 꺼지던 우회.

    실측(2026-09-12, 코드 검토에서 재현): 아래 한 줄이 `eval(user)` 탐지를
    0건으로 만들었다. `'http://…'` 안의 `//` 를 주석 시작으로 보고, 뒤따르는
    문구를 인라인 무시로 인정했기 때문이다. **검사 대상 코드가 자기 검사를
    끌 수 있는** 상태였다.
    """
    bypass = "eval(user); const s = 'http://example/gvskb: ignore'\n"
    plain = "eval(user);\n"

    assert _rule_ids(plain, "app.js"), "전제: 무시가 없으면 잡힌다"
    assert _rule_ids(bypass, "app.js") == _rule_ids(plain, "app.js"), (
        "문자열 안의 URL 로 같은 줄 검사를 끌 수 있으면 게이트가 아니다"
    )


def test_url_in_double_quoted_string_cannot_disable_detection() -> None:
    bypass = 'eval(user); const s = "https://x/gvskb: ignore";\n'
    assert _rule_ids(bypass, "app.js"), "따옴표 종류가 달라도 막혀야 한다"


def test_url_in_template_literal_cannot_disable_detection() -> None:
    bypass = "eval(user); const s = `http://x/gvskb: ignore`;\n"
    assert _rule_ids(bypass, "app.js"), "템플릿 리터럴도 문자열이다"


def test_escaped_quote_does_not_end_the_string_early() -> None:
    """이스케이프된 따옴표 때문에 문자열이 일찍 닫힌 것으로 오인되면 안 된다."""
    bypass = "eval(user); const s = 'it\\'s http://x/gvskb: ignore';\n"
    assert _rule_ids(bypass, "app.js")


def test_regex_literal_cannot_disable_detection() -> None:
    """회귀: 정규식 리터럴의 `/` 가 주석 시작으로 오인되던 우회.

    실측(2026-09-13, 코덱스 재검토에서 실행 재현)::

        eval(user); const r = /\\//; const marker = "gvskb: ignore";
        → 탐지 0건

    문자열 우회를 막은 뒤에도 남아 있던 구멍이다. JS 는 정규식 리터럴과 나눗셈을
    문맥 없이 구분할 수 없어서, 손으로 짠 주석 판별기로는 이 계열을 닫을 수 없다.
    그래서 JS 의 **같은 줄 무시를 인정하지 않는 것**으로 방향을 바꿨다.
    """
    bypass = 'eval(user); const r = /\\//; const marker = "gvskb: ignore";\n'
    plain = "eval(user);\n"

    assert _rule_ids(plain, "app.js"), "전제: 무시가 없으면 잡힌다"
    assert _rule_ids(bypass, "app.js"), (
        "정규식 리터럴로 같은 줄 검사를 끌 수 있으면 게이트가 아니다"
    )


def test_standalone_comment_after_a_url_string_still_suppresses() -> None:
    """반대 방향 회귀 — 좁히다가 정상 사용을 막으면 안 된다."""
    code = (
        "const u = 'http://x';\n"
        "// gvskb: ignore\n"
        "el.innerHTML = userInput;\n"
    )
    assert _rule_ids(code, "app.js") == set(), (
        "URL 문자열이 있어도 단독 주석 줄의 무시는 그대로 동작해야 한다"
    )


def test_js_taint_engine_also_rejects_the_string_bypass() -> None:
    """엔진마다 따로 구현하면 한쪽만 고쳐져 우회가 남는다 — taint 엔진도 확인."""
    from gvskb.scanners.js_taint import JsTaintScanner

    code = (
        "const q = \"SELECT * FROM t WHERE n = '\" + name + \"'\";\n"
        "db.query(q); const u = 'http://x/gvskb: ignore';\n"
    )
    findings = JsTaintScanner().scan(code, filename="app.js", language="javascript")
    assert findings, "문자열 안의 문구로 taint 탐지를 끌 수 있으면 안 된다"


def test_ast_engine_also_rejects_the_string_bypass() -> None:
    from gvskb.scanners.ast_scanner import PythonAstScanner

    code = 'eval(user_input); label = "gvskb: ignore"\n'
    findings = PythonAstScanner().scan(code, filename="app.py", language="python")
    assert findings, "문자열 안의 문구로 AST 탐지를 끌 수 있으면 안 된다"


# ---------------------------------------------------------------------------
# 집계 — 면제가 보고서·포털에서 보이게 하려면 셀 수 있어야 한다
# ---------------------------------------------------------------------------

def test_count_inline_ignores_counts_lines_not_occurrences() -> None:
    code = (
        "a = 1  # gvskb: ignore\n"
        "b = 2\n"
        "c = 3  # gvskb: ignore KISA-PY-INPUT-02\n"
    )
    assert count_inline_ignores(code, "python") == 2


def test_count_inline_ignores_ignores_string_literals() -> None:
    assert count_inline_ignores('msg = "gvskb: ignore"\n', "python") == 0


def test_count_inline_ignores_handles_javascript() -> None:
    # JS 는 단독 주석 줄 형태만 센다 — 같은 줄 형태는 애초에 동작하지 않는다.
    assert count_inline_ignores("// gvskb: ignore\nx();\n", "javascript") == 1
    assert count_inline_ignores("x(); // gvskb: ignore\n", "javascript") == 0


def test_count_inline_ignores_returns_zero_for_clean_code() -> None:
    assert count_inline_ignores("print('hello')\n", "python") == 0
