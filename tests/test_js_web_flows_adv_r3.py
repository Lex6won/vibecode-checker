"""JS·TS 요청 값 추적(js-flow) — 3회차 독립 적대적 검증(2026-11-22) 사례 174건의 회귀 시험.

사례는 `tests/corpus/js_flow_adv_r3.json`: A 처음 보는 코드(안전 50·취약 48), B 겨냥(안전 33·취약 38), D 미끼 5.
구현과 무관한 세션이 썼다. 1·2회차와 같은 방식으로 공개 입구(`scan_code`)와 직접 호출(`scan_js_flows(strict=True)`)을 둘 다 단정한다.

3회차의 핵심: 2회차에 넣은 "출처 필드를 읽는 미들웨어만 침묵 사유" 규칙이 출처 목록에 없는 자리(`req.originalUrl`·`req.url`·
`req.path`·`ctx.querystring`·`request.url`)로 같은 값을 검사한 진짜 안전한 코드에서 오탐 9건을 냈다. 함수 미들웨어의 쓰임을
파일 전체의 **필드별 열쇠**로 세도록 바꿨다(URL 원문 → 쿼리 전체, 경로 → 경로 매개변수 전체, 특정 열쇠 → 그 열쇠만).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_javascript")
pytest.importorskip("tree_sitter_typescript")

CORPUS = json.loads((Path(__file__).parent / "corpus" / "js_flow_adv_r3.json").read_text(encoding="utf-8"))["cases"]

#: 설계상 침묵 — 검사처럼 보이는 코드를 거친 미끼(검사의 품질은 판단하지 않는다).
SILENT_BY_DESIGN: dict[str, str] = {
    "D-01": "미끼 — '..' 포함 여부를 봤다(로그만 남기고 계속해도 값을 본 것이다)",
    "D-02": "미끼 — startsWith('http') 를 거쳤다",
    "D-04": "미끼 — 길이를 비교했다",
    "D-05": "미끼 — replace 로 바꾼 값(잘라 내거나 바꿔 쓴 값은 따라가지 않는다)",
}
#: 미끼지만 보고하는 것이 맞는 사례 — `typeof x !== 'string'` 은 있는지·형만 본 것이라 해가 없는 쓰임이다(4-5).
DECOYS_REPORTED: dict[str, str] = {"D-03": "typeof 확인만 — 보호가 아니다"}
#: 놓치는 취약 사례(라벨 → 까닭).
KNOWN_MISSES: dict[str, str] = {
    "A-V-44": "같은 파일 컨트롤러 객체의 메서드(`ctrl.download`)로 넘긴 처리 함수 — 객체 속성은 따라가지 않는다",
}
#: 보고가 남는 안전 사례(라벨 → 까닭).
KNOWN_REPORTS: dict[str, str] = {
    "B-S-05": "관리자 권한 게이트(req.user.role)는 값 검증이 아니다 — 보고가 맞다고 검증 세션과 합의(안전 사례로 분류돼 있을 뿐)",
}


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
    if case["kind"] == "decoy":
        return case["id"] in DECOYS_REPORTED
    return case["id"] not in KNOWN_MISSES


@pytest.mark.parametrize("case", CORPUS, ids=[c["id"] for c in CORPUS])
def test_round3_case(case: dict) -> None:
    expected = _expected_report(case)
    for how, found in (("scan_code", _public(case)), ("direct", _direct(case))):
        reported = bool(found) if case["kind"] == "safe" else _hit(found, case)
        assert reported == expected, (how, case["id"], case["why"], found)


def test_round3_corpus_shape_and_lists() -> None:
    parts = [(c["part"], c["kind"]) for c in CORPUS]
    assert parts.count(("A", "safe")) == 50 and parts.count(("A", "vuln")) == 48
    assert parts.count(("B", "safe")) == 33 and parts.count(("B", "vuln")) == 38
    assert sum(1 for c in CORPUS if c["kind"] == "decoy") == 5 and len(CORPUS) == 174
    ids = {c["id"] for c in CORPUS}
    assert set(SILENT_BY_DESIGN) | set(DECOYS_REPORTED) | set(KNOWN_MISSES) | set(KNOWN_REPORTS) <= ids
    decoys = {c["id"] for c in CORPUS if c["kind"] == "decoy"}
    assert decoys == set(SILENT_BY_DESIGN) | set(DECOYS_REPORTED)
