"""JS·TS 요청 값 추적(js-flow) — 2회차 독립 적대적 검증(2026-11-22) 사례 155건의 회귀 시험.

사례는 `tests/corpus/js_flow_adv_r2.json`: A 처음 보는 코드(안전 44·취약 37), B 겨냥(안전 23·취약 21), D 미끼 5,
P·Q·R·S 탐침(앞 회차에서 놓친 모양의 변형). 구현과 무관한 세션이 썼다. 1회차(test_js_web_flows_adv_r1.py)와 같은 방식으로
공개 입구(`scan_code`)와 직접 호출(`scan_js_flows(strict=True)`)을 둘 다 단정한다.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_javascript")
pytest.importorskip("tree_sitter_typescript")

CORPUS = json.loads((Path(__file__).parent / "corpus" / "js_flow_adv_r2.json").read_text(encoding="utf-8"))["cases"]

#: 설계상 침묵 — 검사의 품질·순서는 판단하지 않는다.
SILENT_BY_DESIGN: dict[str, str] = {
    "D-D-01": "미끼 — 검사처럼 보이는 코드를 거쳤다(검사의 품질은 판단하지 않는다)",
    "D-D-02": "미끼",
    "D-D-03": "미끼",
    "D-D-04": "미끼",
    "D-D-05": "미끼",
    "B-V-18": "허용 목록 검사가 위험한 자리보다 뒤에 있다 — 쓰임의 순서는 보지 않는다(그 값이 다른 데 쓰였으면 침묵)",
}
#: 놓치는 취약 사례(라벨 → 까닭).
KNOWN_MISSES: dict[str, str] = {
    "B-V-06": "Koa 에서 요청 값을 읽는 use 와 라우터를 함께 쓴 파일 — use 가 라우트를 검사하는 미들웨어일 수 있어 파일 전체를 버린다(4-7)",
}
#: 보고가 남는 안전 사례. 비어 있어야 한다.
KNOWN_REPORTS: dict[str, str] = {}


def _hit(found: list[tuple[str, int]], case: dict) -> bool:
    lines = [case["sink_line"]] + ([case["call_line"]] if case.get("call_line") else [])
    return any(rule == case["rule"] and any(ln and abs(line - ln) <= 2 for ln in lines) for rule, line in found)


def _public(case: dict) -> list[tuple[str, int]]:
    from gvskb.scanner import scan_code

    return [(f.rule_id, f.location.line) for f in scan_code(case["code"], filename=case["file"]).findings
            if f.engine == "js-flow"]


def _direct(case: dict) -> list[tuple[str, int]]:
    from gvskb.scanners._ts_parse import parse
    from gvskb.scanners.js_web_flows import scan_js_flows

    root, src = parse(case["code"], case["file"])
    return [(rule, line) for rule, line, *_ in scan_js_flows(root, src, case["file"], strict=True)]


def _expected_report(case: dict) -> bool:
    if case["kind"] == "safe":
        return case["id"] in KNOWN_REPORTS
    return case["id"] not in SILENT_BY_DESIGN and case["id"] not in KNOWN_MISSES


@pytest.mark.parametrize("case", CORPUS, ids=[c["id"] for c in CORPUS])
def test_round2_case(case: dict) -> None:
    expected = _expected_report(case)
    for how, found in (("scan_code", _public(case)), ("direct", _direct(case))):
        reported = bool(found) if case["kind"] == "safe" else _hit(found, case)
        assert reported == expected, (how, case["id"], case["why"], found)


def test_round2_corpus_shape_and_lists() -> None:
    parts = [(c["part"], c["kind"]) for c in CORPUS]
    assert parts.count(("A", "safe")) == 44 and parts.count(("A", "vuln")) == 37
    assert parts.count(("B", "safe")) == 23 and parts.count(("B", "vuln")) == 21
    assert sum(1 for c in CORPUS if c["kind"] == "decoy") == 5 and len(CORPUS) == 155
    ids = {c["id"] for c in CORPUS}
    assert set(SILENT_BY_DESIGN) | set(KNOWN_MISSES) | set(KNOWN_REPORTS) <= ids
