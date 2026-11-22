"""JS·TS 요청 값 추적(js-flow) — 4회차 독립 적대적 검증(2026-11-22) 사례 164건의 회귀 시험.

사례는 `tests/corpus/js_flow_adv_r4.json`: A 처음 보는 코드(안전 52·취약 49), B 필드별 침묵 규칙 겨냥(안전 28·취약 30), D 미끼 5.
구현과 무관한 세션이 썼다. 1~3회차와 같은 방식으로 공개 입구(`scan_code`)와 직접 호출(`scan_js_flows(strict=True)`)을 둘 다 단정한다.

4회차의 핵심: 검사한 필드와 검사하지 않은 필드가 한 싱크 인자로 합쳐지면 싱크 전체가 침묵했다 → 값 묶음마다 따로 판정한다.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_javascript")
pytest.importorskip("tree_sitter_typescript")

CORPUS = json.loads((Path(__file__).parent / "corpus" / "js_flow_adv_r4.json").read_text(encoding="utf-8"))["cases"]

#: 설계상 침묵 — 검사처럼 보이는 코드를 거친 미끼(검사의 품질은 판단하지 않는다).
SILENT_BY_DESIGN: dict[str, str] = {
    "d_decoy_01.js": "미끼 — 길이를 비교했다",
    "d_decoy_03.js": "미끼 — endsWith('.pdf') 를 거쳤다",
    "d_decoy_04.js": "미끼 — startsWith('/') 를 거쳤다",
    "d_decoy_05.js": "미끼 — 공백 포함 여부(includes)를 봤다",
}
#: 미끼지만 보고하는 것이 맞는 사례 — typeof 확인은 있는지·형만 본 것이라 해가 없는 쓰임이다(4-5).
DECOYS_REPORTED: dict[str, str] = {"d_decoy_02.js": "typeof 확인만 — 보호가 아니다"}
#: 놓치는 취약 사례.
KNOWN_MISSES: dict[str, str] = {}
#: 보고가 남는 안전 사례.
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
    if case["part"] == "D":
        return case["id"] in DECOYS_REPORTED
    return case["id"] not in KNOWN_MISSES


@pytest.mark.parametrize("case", CORPUS, ids=[c["id"] for c in CORPUS])
def test_round4_case(case: dict) -> None:
    expected = _expected_report(case)
    for how, found in (("scan_code", _public(case)), ("direct", _direct(case))):
        reported = bool(found) if case["kind"] == "safe" else _hit(found, case)
        assert reported == expected, (how, case["id"], case["why"], found)


def test_round4_corpus_shape_and_lists() -> None:
    parts = [(c["part"], c["kind"]) for c in CORPUS]
    assert parts.count(("A", "safe")) == 52 and parts.count(("A", "vuln")) == 49
    assert parts.count(("B", "safe")) == 28 and parts.count(("B", "vuln")) == 30
    assert sum(1 for c in CORPUS if c["part"] == "D") == 5 and len(CORPUS) == 164
    decoys = {c["id"] for c in CORPUS if c["part"] == "D"}
    assert decoys == set(SILENT_BY_DESIGN) | set(DECOYS_REPORTED)


def test_safe_cases_of_all_rounds_stay_quiet() -> None:
    """1~4회차 안전 사례 전부 — 보고는 합의된 KNOWN_REPORTS 뿐이어야 한다(값 묶음별 판정은 경계를 넓히는 수정이다)."""
    from gvskb.scanner import scan_code

    here = Path(__file__).parent / "corpus"
    reported = []
    total = 0
    for name in ("js_flow_adv_r1.json", "js_flow_adv_r2.json", "js_flow_adv_r3.json", "js_flow_adv_r4.json"):
        for c in json.loads((here / name).read_text(encoding="utf-8"))["cases"]:
            if c["kind"] != "safe":
                continue
            total += 1
            if any(f.engine == "js-flow" for f in scan_code(c["code"], filename=c["file"]).findings):
                reported.append(c["id"])
    assert total == 311
    assert reported == ["B-S-05"]                          # 3회차 권한 게이트 — 보고가 맞다고 합의
