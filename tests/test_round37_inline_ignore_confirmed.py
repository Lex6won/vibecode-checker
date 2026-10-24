"""37차 — 확인된(confirmed) 발견은 인라인 주석으로 끌 수 없다.

외부 입력이 실행 지점에 닿는 것이 **추적으로 확인된** 발견은 "사람이 확인해 달라"는 요청이 아니다.
그런 발견이 `# gvskb: ignore` 한 줄로 꺼지면 게이트가 아니다. 유력(likely)·패턴 일치는 지금처럼 끌 수 있다.
"""
from __future__ import annotations

from pathlib import Path

from gvskb.report import render_markdown
from gvskb.scanner import scan_code, scan_path


def _ids(code: str, filename: str) -> set[str]:
    return {f.rule_id for f in scan_code(code, filename=filename).findings}


def test_confirmed_python_command_injection_survives_inline_ignore() -> None:
    plain = 'import os, sys\nos.system("cp /data/" + sys.argv[1])\n'
    ignored = 'import os, sys\nos.system("cp /data/" + sys.argv[1])  # gvskb: ignore\n'
    assert "KISA-PY-INPUT-05" in _ids(plain, "a.py")
    assert "KISA-PY-INPUT-05" in _ids(ignored, "a.py")
    standalone = 'import os, sys\n# gvskb: ignore\nos.system("cp /data/" + sys.argv[1])\n'
    assert "KISA-PY-INPUT-05" in _ids(standalone, "a.py")


def test_likely_python_eval_is_still_inline_ignorable() -> None:
    # 기존 계약 유지 — 출처를 모르는 eval 은 '유력'이고, 주석으로 끌 수 있다.
    assert "KISA-PY-INPUT-02" in _ids("eval(user_input)\n", "a.py")
    assert "KISA-PY-INPUT-02" not in _ids("eval(user_input)  # gvskb: ignore\n", "a.py")


def test_confirmed_js_dom_xss_survives_inline_ignore() -> None:
    plain = "el.innerHTML = req.body.note;\n"
    ignored = "// gvskb: ignore\nel.innerHTML = req.body.note;\n"
    assert "KISA-JS-INPUT-04" in _ids(plain, "a.js")
    assert "KISA-JS-INPUT-04" in _ids(ignored, "a.js")


def test_likely_js_dom_xss_is_still_inline_ignorable() -> None:
    assert "KISA-JS-INPUT-04" in _ids("el.innerHTML = userInput;\n", "a.js")
    assert "KISA-JS-INPUT-04" not in _ids("// gvskb: ignore\nel.innerHTML = userInput;\n", "a.js")


def test_overridden_directives_are_counted_and_announced(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text(
        'import os, sys\nos.system("cp /data/" + sys.argv[1])  # gvskb: ignore\n'
        "eval(x)  # gvskb: ignore\n",
        encoding="utf-8",
    )
    r = scan_path(tmp_path)
    ss = r.suppression_summary
    assert ss["inline_ignored"] == 2, "지시는 둘 다 센다"
    assert ss["inline_overridden"] == 1, "confirmed 발견 하나에는 적용되지 않았다"
    assert "적용되지 않았습니다" in render_markdown(r)
