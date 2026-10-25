"""46차 — TS 말뭉치(k_ts_2026) + TS 문법 정규화(js-taint) + bare exec 템플릿 패턴."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import yaml

from gvskb.scanner import scan_code
from gvskb.scanners.js_taint import _strip_ts_syntax

REPO = Path(__file__).resolve().parent.parent
CORPUS = REPO / "eval_corpus" / "projects" / "k_ts_2026"
_HAS_TS = all(importlib.util.find_spec(m) for m in ("tree_sitter", "tree_sitter_javascript", "tree_sitter_typescript"))


def test_strip_ts_syntax_keeps_lines_and_removes_casts() -> None:
    code = 'import { a as b } from "x";\nconst q = `S ${req.query.n}`;\nconst rows = await db.query(q as string);\nexec(`c ${cmd!}`);\nif (a !== b) run(!ok);\n'
    out = _strip_ts_syntax(code)
    assert out.count("\n") == code.count("\n")
    assert 'import { a as b }' in out and "db.query(q)" in out and "exec(`c ${cmd}`)" in out and "a !== b" in out and "run(!ok)" in out


def test_taint_crosses_ts_cast() -> None:
    code = 'const q = `SELECT * FROM t WHERE n = \'${req.query.name}\'`;\nconst rows = await db.query(q as string);\n'
    hits = [f for f in scan_code(code, filename="r.ts").findings if f.rule_id == "KISA-JS-INPUT-01" and f.engine == "js-taint"]
    assert hits and hits[0].location.line == 2


def test_bare_exec_template_literal_is_command_injection() -> None:
    code = 'import { exec } from "child_process";\nexport function f(cmd: string) {\n  exec(`convert ${cmd}`, () => {});\n}\n'
    assert any(f.rule_id == "KISA-JS-INPUT-05" and f.location.line == 3 for f in scan_code(code, filename="a.ts").findings)
    quiet = 'const m = pattern.exec(`${s}`);\nexec("ls -la", cb);\nconst r = exec(`git status`);\n'
    assert not [f for f in scan_code(quiet, filename="b.js").findings if f.rule_id == "KISA-JS-INPUT-05"]


def test_manifest_points_at_existing_files() -> None:
    m = yaml.safe_load((CORPUS / "manifest.yaml").read_text(encoding="utf-8"))
    ids = [c["id"] for c in m["cases"]]
    assert len(ids) == len(set(ids)) >= 18
    for c in m["cases"]:
        assert (CORPUS / c["root"] / c["file"]).is_file(), c["id"]
    for root in m["negative_roots"]:
        assert (CORPUS / root).is_dir()


def test_ts_corpus_scores_clean() -> None:
    sys.path.insert(0, str(REPO / "scripts"))
    import run_holdout

    out = run_holdout.run("k_ts_2026")
    c = out["counts"]
    assert c["miss"] == 0 and c["news"] == 0 and out["false_positives"] == [], out
    assert c["gap"] == 1
    assert (c["no-engine"] == 0) == _HAS_TS
    if _HAS_TS:
        assert out["recall"] == "17/17"
