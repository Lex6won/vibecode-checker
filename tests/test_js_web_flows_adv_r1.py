"""JS·TS 요청 값 추적(js-flow) — 1회차 독립 적대적 검증(2026-11-22) 사례 197건의 회귀 시험.

사례는 `tests/corpus/js_flow_adv_r1.json`(본 세트: 안전 50·취약 50·미끼 5, 보충: 안전 28·취약 64). 구현과 무관한 세션이 썼다.
공개 입구(`scan_code`)와 직접 호출(`scan_js_flows(strict=True)`)을 둘 다 단정한다 — 1회차에서는 중복 제거가 정규식(패턴 일치)
뒤에 `js-flow` 발견을 가려, 직접 호출로는 잡히는데 보고서에는 없는 사례가 8건 있었다.

탐지 판정은 검증 세션과 같다: 같은 룰이 위험한 자리 줄(또는 함수 경유면 호출 줄) ±2 안에 있으면 탐지.
보고가 남는 안전 사례는 ``KNOWN_REPORTS``, 놓치는 취약 사례는 ``KNOWN_MISSES``, 설계상 침묵은 ``SILENT_BY_DESIGN`` 에 둔다.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_javascript")
pytest.importorskip("tree_sitter_typescript")

CORPUS = json.loads((Path(__file__).parent / "corpus" / "js_flow_adv_r1.json").read_text(encoding="utf-8"))["cases"]

#: 설계상 침묵 — 검사처럼 보이는 코드가 있으면 그 품질은 판단하지 않는다(미끼), 그리고 이 분석이 볼 수 없는 자리.
SILENT_BY_DESIGN: dict[str, str] = {
    "D01": "미끼 — startsWith('http') 를 거쳤다(검사의 품질은 판단하지 않는다)",
    "D02": "미끼 — endsWith('.pdf') 를 거쳤다",
    "D03": "미끼 — '..' 포함 여부를 봤다",
    "D04": "미끼 — startsWith('/') 를 거쳤다",
    "D05": "미끼 — 앞뒤를 묶지 않은 정규식으로 검사했다",
    "XV02": "고정 기준 주소 뒤에 붙은 값(`https://api.x` + 경로 → `@` 로 호스트를 바꿀 수 있다) — 앞머리 조건의 사각지대",
    "XV04": "sendFile 의 root 옵션 자체가 사용자 값 — root 가 있으면 침묵한다",
}
#: 놓치는 취약 사례(라벨 → 까닭). 범위 밖으로 둔 것.
KNOWN_MISSES: dict[str, str] = {
    "V37": "util.promisify(exec) 로 만든 별칭은 명령 싱크로 풀지 않는다",
    "YV04": "앱 객체가 없는 컨트롤러 파일(exports.x = async (req, res) => …) — 라우트 등록이 다른 파일에 있다",
    "YV15": "multer 가 채운 req.file.originalname 은 요청 필드 출처로 치지 않는다",
}
#: 보고가 남는 안전 사례(라벨 → 까닭). 비어 있어야 한다.
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


@pytest.mark.parametrize("case", CORPUS, ids=[f"{c['set']}-{c['id']}" for c in CORPUS])
def test_round1_case(case: dict) -> None:
    expected = _expected_report(case)
    for how, found in (("scan_code", _public(case)), ("direct", _direct(case))):
        reported = bool(found) if case["kind"] == "safe" else _hit(found, case)
        assert reported == expected, (how, case["id"], case["why"], found)


def test_round1_corpus_shape_and_lists() -> None:
    kinds = [(c["set"], c["kind"]) for c in CORPUS]
    assert kinds.count(("main", "safe")) == 50 and kinds.count(("main", "vuln")) == 50 and kinds.count(("main", "decoy")) == 5
    assert sum(1 for c in CORPUS if c["set"] != "main") == 92
    ids = {c["id"] for c in CORPUS}
    assert set(SILENT_BY_DESIGN) | set(KNOWN_MISSES) | set(KNOWN_REPORTS) <= ids
