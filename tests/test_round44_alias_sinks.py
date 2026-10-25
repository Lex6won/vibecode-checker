"""44차 — 파이썬 별칭·간접 호출로 가린 sink(경계 프로브 H-01~H-03). 파서 없이 `ast` 로 푼다."""
from __future__ import annotations

from gvskb.scanner import scan_code


def _ids(code: str, filename: str = "a.py") -> list[tuple[str, int]]:
    return sorted({(f.rule_id, f.location.line) for f in scan_code(code, filename=filename).findings
                   if f.rule_id in ("KISA-PY-INPUT-02", "KISA-PY-INPUT-05")})


def test_from_import_alias_of_os_system_is_a_command_sink() -> None:
    code = "from os import system as run_cmd\n\ndef cleanup(fname):\n    run_cmd('del ' + fname)\n"
    assert ("KISA-PY-INPUT-05", 4) in _ids(code)
    plain = "from os import system\n\ndef cleanup(fname):\n    system('del ' + fname)\n"
    assert ("KISA-PY-INPUT-05", 4) in _ids(plain)


def test_from_import_alias_of_harmless_name_is_quiet() -> None:
    code = "from os import path as p\nfrom json import loads as run_cmd\n\ndef f(x):\n    return p.join('a', run_cmd(x))\n"
    assert _ids(code) == []


def test_eval_assigned_to_a_name_then_called() -> None:
    code = "def run_expr(user_input):\n    f = eval\n    return f(user_input)\n"
    assert ("KISA-PY-INPUT-02", 3) in _ids(code)


def test_getattr_builtins_with_folded_string() -> None:
    code = ("import builtins\n\ndef run_expr2(user_input):\n    g = getattr(builtins, 'ev' + 'al')\n    return g(user_input)\n\n"
            "def run_expr3(user_input):\n    return getattr(builtins, 'exec')(user_input)\n")
    hits = _ids(code)
    assert ("KISA-PY-INPUT-02", 5) in hits and ("KISA-PY-INPUT-02", 8) in hits


def test_rebound_eval_name_is_not_an_alias() -> None:
    code = "from ast import literal_eval as eval\n\ndef run(x):\n    f = eval\n    return f(x)\n"
    assert ("KISA-PY-INPUT-02", 5) not in _ids(code)
    code2 = "def run(obj, x):\n    g = getattr(obj, 'eval')\n    return g(x)\n"
    assert _ids(code2) == []


def test_hard_variant_corpus_now_detected() -> None:
    from pathlib import Path

    from gvskb.scanner import scan_path

    r = scan_path(Path(__file__).resolve().parent.parent / "eval_corpus" / "projects" / "h_hard_variants")
    got = {(f.location.file, f.rule_id) for f in r.findings}
    assert ("alias_import.py", "KISA-PY-INPUT-05") in got
    assert ("indirect_eval.py", "KISA-PY-INPUT-02") in got
