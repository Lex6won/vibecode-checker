"""인라인 무시(`gvskb: ignore`)는 **모든 언어**에서 동작해야 한다.

실측 결함(2026-09-12): `RegexScanner.scan_code` 의 인라인 무시 검사가
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
    return {f.rule_id for f in RegexScanner().scan_code(code, filename=filename)}


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

def test_javascript_bare_ignore_suppresses_every_rule_on_that_line() -> None:
    before = _rule_ids("el.innerHTML = userInput;\n", "app.js")
    after = _rule_ids("el.innerHTML = userInput; // gvskb: ignore\n", "app.js")
    assert before, "전제: 무시가 없으면 잡힌다"
    assert after == set()


def test_typescript_ignore_works() -> None:
    before = _rule_ids("el.innerHTML = userInput;\n", "app.ts")
    after = _rule_ids("el.innerHTML = userInput; // gvskb: ignore\n", "app.ts")
    assert before
    assert after == set()


def test_javascript_block_comment_ignore_works() -> None:
    before = _rule_ids("el.innerHTML = userInput;\n", "app.js")
    after = _rule_ids("el.innerHTML = userInput; /* gvskb: ignore */\n", "app.js")
    assert before
    assert after == set()


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
    assert count_inline_ignores("x(); // gvskb: ignore\n", "javascript") == 1


def test_count_inline_ignores_returns_zero_for_clean_code() -> None:
    assert count_inline_ignores("print('hello')\n", "python") == 0
