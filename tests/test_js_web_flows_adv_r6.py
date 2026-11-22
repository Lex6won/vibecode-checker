"""JS·TS 요청 값 추적(js-flow) — 6회차 독립 적대적 검증(2026-11-22, 통과 회차) 사례 171건의 회귀 시험.

사례는 `tests/corpus/js_flow_adv_r6.json`: A 처음 보는 코드(안전 56·취약 49), B 겨냥(안전 31·취약 30), D 미끼(안전 5).
구현과 무관한 세션이 썼다. 1~5회차와 같은 방식으로 공개 입구(`scan_code`)와 직접 호출(`scan_js_flows(strict=True)`)을 둘 다
단정한다. 탐지 판정은 검증 세션과 같다: 같은 룰이 표시된 위험한 자리·호출 줄 가운데 하나의 ±2 안에 있으면 탐지.
이 회차에서는 판정을 고치지 않았다 — 놓친 18건은 까닭과 함께 아래에 고정한다.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_javascript")
pytest.importorskip("tree_sitter_typescript")

CORPUS = json.loads((Path(__file__).parent / "corpus" / "js_flow_adv_r6.json").read_text(encoding="utf-8"))["cases"]

#: 설계상 침묵 — 그 값이 다른 데 쓰였으면 그 쓰임이 검사인지·제대로 된 검사인지·언제 실행되는지는 판단하지 않는다(원칙 1·3).
SILENT_BY_DESIGN: dict[str, str] = {
    "A051": "Array.isArray(배열) — 모르는 함수에 넘긴 쓰임이다",
    "B17": "검사 실패 분기가 경고만 하고 끝내지 않음 — 검사의 품질은 판단하지 않는다",
    "B18": "잘라 낸 사본만 검사하고 원본을 씀 — 사본을 들여다본 결과가 원본의 쓰임으로 잡힌다",
    "B21": "반복문 안의 검사가 기록만 하고 끝내지 않음 — 검사의 품질은 판단하지 않는다",
    "B22": "검증 함수를 정의만 하고 부르지 않음 — 안쪽 함수의 쓰임도 센다(호출 여부는 보지 않는다)",
    "B23": "try 에서 던진 검사 실패를 catch 가 삼킴 — 검사의 품질은 판단하지 않는다",
    "B24": "`![dept, file].some(통과)` — 복합 조건에 쓰였다(판정 방향은 보지 않는다)",
    "B26": "if 허용 {기록} else {경고} — 두 갈래 모두 이어지지만 조건에 쓰였다",
    "B27": "다른 요청 값(mode)이 참일 때만 검사 — 조건부 검사도 쓰임이다",
    "B57": "삼항 안의 캐시 조회 — 캐시인지 허용 목록인지 판단할 수 없어 침묵",
    "B59": "음성 조회로 빠져나가는 가지 안에서 요청 — 그 모양은 허용 목록 검사로 본다(극성 규칙)",
    "B61": "복합 조건(`has && !force`) 안의 조회 — 판단할 수 없어 침묵",
    "B62": "차단 목록(denylist)으로 거름 — 컬렉션 조회는 쓰임이다(목록의 성격은 판단하지 않는다)",
}
#: 놓치는 취약 사례 — 분석이 아직 보지 못하는 자리(다음 단계 과제).
KNOWN_MISSES: dict[str, str] = {
    "A036": "반복문 몸체에서 싱크 뒤의 쓰임이 다음 반복의 앞선 쓰임으로 계산된다(문장 시점을 두 번 돈 합으로 본다) — W1-b",
    "A085": "반복문 몸체에서 싱크 뒤의 쓰임이 다음 반복의 앞선 쓰임으로 계산된다 — W1-b",
    "B40": "`new URL(path, base)` — path 가 절대 주소면 base 를 무시한다. new URL 은 모르는 호출로 침묵",
    "B43": "`axios({ baseURL: req.query.base })` — 설정 객체의 baseURL 은 보지 않는다(url 만 본다)",
    "B45": "URL 객체의 host 속성에 요청 값을 대입 — 객체 속성은 따라가지 않는다",
}
#: 보고가 남는 안전 사례. 비어 있어야 한다.
KNOWN_REPORTS: dict[str, str] = {}


def _hit(found: list[tuple[str, int]], case: dict) -> bool:
    lines = case["sink_lines"] + case["call_lines"]
    return any(rule == case["rule"] and any(abs(line - t) <= 2 for t in lines) for rule, line in found)


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
def test_round6_case(case: dict) -> None:
    expected = _expected_report(case)
    for how, found in (("scan_code", _public(case)), ("direct", _direct(case))):
        reported = bool(found) if case["kind"] == "safe" else _hit(found, case)
        assert reported == expected, (how, case["id"], case["why"], found)


def test_round6_corpus_shape_and_lists() -> None:
    parts = [(c["part"], c["kind"]) for c in CORPUS]
    assert parts.count(("A", "safe")) == 56 and parts.count(("A", "vuln")) == 49
    assert parts.count(("B", "safe")) == 31 and parts.count(("B", "vuln")) == 30
    assert parts.count(("D", "safe")) == 5 and len(CORPUS) == 171
    ids = {c["id"] for c in CORPUS}
    assert set(SILENT_BY_DESIGN) | set(KNOWN_MISSES) | set(KNOWN_REPORTS) <= ids
    assert len(SILENT_BY_DESIGN) + len(KNOWN_MISSES) == 18
