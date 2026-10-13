"""정밀도 게이트(scripts/precision_gate.py) — 스냅샷 비교·라벨 대조 순수 함수."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _load():
    spec = importlib.util.spec_from_file_location("precision_gate", REPO / "scripts" / "precision_gate.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _row(file: str, line: int, rule: str, decision: str = "warn", confidence: str = "likely") -> dict:
    return {"file": file, "line": line, "rule": rule, "decision": decision, "severity": "high",
            "confidence": confidence}


def _snap(rows: list[dict], tree: str = "proj") -> dict:
    return {"engine_version": "0.0", "trees": {tree: {"root": "/x/" + tree, "rows": rows, "skipped": [],
                                                      "seconds": 1.0, "scanned": 3}}}


def test_diff_reports_added_removed_and_changed() -> None:
    pg = _load()
    before = _snap([_row("a.py", 1, "R1", "block", "confirmed"), _row("a.py", 2, "R2")])
    after = _snap([_row("a.py", 1, "R1", "warn", "likely"), _row("b.py", 9, "R3")])
    d = pg.diff_snapshots(before, after)["proj"]
    assert [r["line"] for r in d["removed"]] == [2]
    assert [r["file"] for r in d["added"]] == ["b.py"]
    assert d["changed"][0]["before"]["decision"] == "block" and d["changed"][0]["after"]["decision"] == "warn"


def test_labels_catch_regressions_in_both_directions() -> None:
    pg = _load()
    snap = _snap([_row("a.py", 1, "R1", "block", "confirmed"), _row("c.py", 5, "R1", "warn", "likely")])
    labels = [
        {"tree": "proj", "file": "a.py", "line": 1, "rule": "R1", "verdict": "fp-block"},   # 차단이면 안 됨 → 위반
        {"tree": "proj", "file": "a.py", "line": 2, "rule": "R1", "verdict": "tp"},         # 사라짐 → 위반
        {"tree": "proj", "file": "c.py", "line": 5, "rule": "R1", "verdict": "tp"},         # 있음 → 통과
        {"tree": "proj", "file": "d.py", "line": 7, "rule": "R1", "verdict": "fp"},         # 없음 → 통과
        {"tree": "other", "file": "z.py", "line": 1, "rule": "R1", "verdict": "tp"},        # 이 PC 에 없는 트리 → 판정 안 함
    ]
    v = pg.evaluate_labels(snap, labels)
    assert [(x["file"], x["line"]) for x in v] == [("a.py", 1), ("a.py", 2)]
    p = pg.precision_by_rule(snap, labels)["R1"]
    assert p["tp"] == 1 and p["fn"] == 1 and p["fp_reported"] == 1 and p["fp_suppressed"] == 1
    assert p["precision"] == 0.5 and p["recall"] == 0.5


def test_cli_check_exit_code_reflects_violations(tmp_path: Path) -> None:
    pg = _load()
    snap = _snap([_row("a.py", 1, "R1", "block", "confirmed")])
    (tmp_path / "snap.json").write_text(json.dumps(snap), encoding="utf-8")
    (tmp_path / "ok.json").write_text(json.dumps([{"tree": "proj", "file": "a.py", "line": 1, "rule": "R1",
                                                   "verdict": "tp-block"}]), encoding="utf-8")
    (tmp_path / "bad.json").write_text(json.dumps([{"tree": "proj", "file": "a.py", "line": 1, "rule": "R1",
                                                    "verdict": "fp"}]), encoding="utf-8")
    assert pg.main(["check", str(tmp_path / "snap.json"), "--labels", str(tmp_path / "ok.json"), "--json"]) == 0
    assert pg.main(["check", str(tmp_path / "snap.json"), "--labels", str(tmp_path / "bad.json"), "--json"]) == 1
