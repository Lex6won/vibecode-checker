"""JS·TS 요청 값 추적(js-flow) — 5회차 독립 적대적 검증(2026-11-22) 사례 164건의 회귀 시험.

사례는 `tests/corpus/js_flow_adv_r5.json`: A 처음 보는 코드(안전 57·취약 46), B 겨냥(안전 27·취약 29), D 미끼(안전 3·취약 2).
구현과 무관한 세션이 썼다. 1~4회차와 같은 방식으로 공개 입구(`scan_code`)와 직접 호출(`scan_js_flows(strict=True)`)을 둘 다 단정한다.

5회차의 핵심: 여러 필드를 합친 중간 변수(`const p = join(BASE, type, file)`)를 싱크에 넣으면 묶음이 하나로 합쳐져 검사 안 된
필드를 보고하지 못했다 → 파생 값은 그 시점에 실린 처음 값들(요청 필드)을 나르고, 처음 값마다 따로 판정한다.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_javascript")
pytest.importorskip("tree_sitter_typescript")

CORPUS = json.loads((Path(__file__).parent / "corpus" / "js_flow_adv_r5.json").read_text(encoding="utf-8"))["cases"]

#: 설계상 침묵 — 검사처럼 보이는 코드를 거친 미끼.
SILENT_BY_DESIGN: dict[str, str] = {
    "D4": "미끼 — 정규식 검사 결과를 쓰지 않았지만 값을 모르는 함수(test)에 넘겼다(쓰임의 결과는 보지 않는다)",
}
#: 놓치는 취약 사례(라벨 → 까닭). 설계상의 한계로 고정한다.
KNOWN_MISSES: dict[str, str] = {
    "A-T12-V1": "가져온 인증 미들웨어를 app.use 로 붙였다 — 모르는 미들웨어는 침묵(4-7)",
    "B2-V4": "허용 목록에 사용자 값을 먼저 넣고 부정 조건으로 조회 — 조회가 참일 때만 이어지는 모양은 허용 목록 검사로 본다(극성 규칙)",
    "B2-V6": "일반 객체 캐시(`cache[url]`) — 계산식 열쇠 조회는 쓰임이다",
    "B3-V4": "다른 라우터의 검증 체인이 같은 필드를 검사 — 필드 쓰임은 파일 단위로 센다",
    "B3-V5": "oneOf 의 우회 갈래(다른 필드로 통과) — 체인이 그 필드를 검사하는 것으로 센다(논쟁)",
    "B3-V6": "검증 체인은 있지만 validationResult 를 확인하지 않음 — 체인이 필드를 쓴 것으로 센다",
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
def test_round5_case(case: dict) -> None:
    expected = _expected_report(case)
    for how, found in (("scan_code", _public(case)), ("direct", _direct(case))):
        reported = bool(found) if case["kind"] == "safe" else _hit(found, case)
        assert reported == expected, (how, case["id"], case["why"], found)


def test_round5_corpus_shape_and_lists() -> None:
    parts = [(c["part"], c["kind"]) for c in CORPUS]
    assert parts.count(("A", "safe")) == 57 and parts.count(("A", "vuln")) == 46
    assert parts.count(("B", "safe")) == 27 and parts.count(("B", "vuln")) == 29
    assert parts.count(("D", "safe")) == 3 and parts.count(("D", "vuln")) == 2 and len(CORPUS) == 164
    ids = {c["id"] for c in CORPUS}
    assert set(SILENT_BY_DESIGN) | set(KNOWN_MISSES) | set(KNOWN_REPORTS) <= ids


def test_safe_cases_of_all_rounds_stay_quiet() -> None:
    """1~6회차 안전 사례 전부 — 보고는 합의된 KNOWN_REPORTS 뿐이어야 한다(처음 값별 판정은 판정 구조를 바꾼 수정이다)."""
    from gvskb.scanner import scan_code

    here = Path(__file__).parent / "corpus"
    reported = []
    total = 0
    for n in range(1, 7):
        for c in json.loads((here / f"js_flow_adv_r{n}.json").read_text(encoding="utf-8"))["cases"]:
            if c["kind"] != "safe":
                continue
            total += 1
            if any(f.engine == "js-flow" for f in scan_code(c["code"], filename=c["file"]).findings):
                reported.append(c["id"])
    assert total == 490
    assert reported == ["B-S-05"]                          # 3회차 권한 게이트 — 보고가 맞다고 합의
