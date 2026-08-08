"""외부 회귀 코퍼스 — 남의 코드에서 한 번 고친 판정이 돌아오지 않게.

이 프로젝트가 반복해서 겪은 실패는 **"자기 코퍼스에서만 측정"** 이다. 자체
벤치마크는 100%인데 남의 코드에서 무너졌다(라운드 10: 오탐 87.5% · 라운드 13:
차단 오탐 93.5%). 더 나쁜 것은 **고친 오탐이 조용히 돌아온다**는 점이다 — 룰을
넓히는 수정 한 번이면 재발하는데 자체 코퍼스에는 그 형태가 없어 초록불이 유지된다.

`tests/corpus/external_regression.json` 은 라운드 14에서 판정이 실제로 뒤집힌
자리를 출처(저장소·커밋·경로·줄)와 함께 박제한 것이다. 자세한 배경은
`tests/corpus/README.md`.

**양방향으로 지킨다.** 오탐(`must_not_fire`)만 지키면 감쇄를 넓히다 진탐을 죽이고,
진탐(`must_fire`)만 지키면 오탐이 돌아온다. 둘을 같은 파일에 둔 이유다.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from gvskb.scanner import scan_code

CORPUS_PATH = Path(__file__).parent / "corpus" / "external_regression.json"
CORPUS: list[dict] = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
_IDS = [c["id"] for c in CORPUS]


def _verdicts(case: dict) -> dict[str, str]:
    """rule_id → decision. 같은 룰이 여러 번이면 가장 센 판정을 남긴다."""
    order = {"warn": 0, "review": 1, "block": 2}
    out: dict[str, str] = {}
    for f in scan_code(case["code"], filename=case["filename"]).findings:
        dec = str(getattr(f.decision, "value", f.decision))
        if order.get(dec, 0) >= order.get(out.get(f.rule_id, ""), -1):
            out[f.rule_id] = dec
    return out


def _where(case: dict) -> str:
    o = case["origin"]
    return f"{o['repo']}@{o['commit']} {o['path']}:{o['line']} — {case['why']}"


@pytest.mark.parametrize("case", CORPUS, ids=_IDS)
def test_corpus_false_positives_stay_fixed(case: dict) -> None:
    got = _verdicts(case)
    for rule_id in case["must_not_fire"]:
        assert rule_id not in got, f"오탐 재발: {rule_id}\n  {_where(case)}"


@pytest.mark.parametrize("case", CORPUS, ids=_IDS)
def test_corpus_true_positives_stay_detected(case: dict) -> None:
    """감쇄·좁히기를 넓히다 진짜 위험을 지우는 방향을 막는다."""
    got = _verdicts(case)
    for rule_id in case["must_fire"]:
        assert rule_id in got, f"진탐 소멸: {rule_id}\n  {_where(case)}"


@pytest.mark.parametrize("case", CORPUS, ids=_IDS)
def test_corpus_decision_levels_hold(case: dict) -> None:
    """발화 여부뿐 아니라 **등급**도 고정한다. 차단이 경고로 내려가면 게이트가
    열리고, 경고가 차단으로 올라가면 못 쓰는 도구가 된다."""
    got = _verdicts(case)
    for rule_id in case.get("must_block", []):
        assert got.get(rule_id) == "block", \
            f"차단이 풀렸다: {rule_id} → {got.get(rule_id)}\n  {_where(case)}"
    for rule_id in case.get("must_not_block", []):
        assert got.get(rule_id) != "block", \
            f"차단으로 되돌아갔다: {rule_id}\n  {_where(case)}"


# ---------------------------------------------------------------------------
# 코퍼스 자체의 위생 — 아무것도 지키지 않는 항목이 섞이는 것을 막는다
# ---------------------------------------------------------------------------

def test_corpus_has_no_vacuous_cases() -> None:
    """기대가 하나도 없는 항목은 통과하지만 아무것도 지키지 않는다.
    이런 항목이 늘면 '코퍼스 10건'이 안전감만 주는 숫자가 된다."""
    vacuous = [
        c["id"] for c in CORPUS
        if not (c["must_not_fire"] or c["must_fire"]
                or c.get("must_block") or c.get("must_not_block"))
    ]
    assert not vacuous, f"기대가 비어 있는 항목: {vacuous}"


def test_corpus_entries_are_reproducible_before_the_fix() -> None:
    """모든 항목은 **수정 전 코드에서 실제로 차단으로 재현**되는 것을 확인하고
    등록했다. 발췌가 너무 짧아 원래 조건을 재현하지 못하면 테스트는 통과하지만
    아무것도 지키지 않는다(라운드 12에서 실제로 겪은 실패다).

    이 테스트는 그 확인을 강제하는 표식이다 — 표식 없이 추가된 항목을 막는다."""
    unverified = [c["id"] for c in CORPUS if not c.get("was_blocked_before_fix")]
    assert not unverified, (
        "수정 전 재현 확인 표식이 없는 항목: " + str(unverified) +
        " — tests/corpus/README.md 의 '항목을 추가할 때' 참고"
    )


def test_corpus_cites_a_verifiable_origin() -> None:
    """출처가 없으면 6개월 뒤 아무도 이 코드가 왜 여기 있는지 모른다."""
    for c in CORPUS:
        o = c["origin"]
        assert o.get("repo", "").startswith("https://"), c["id"]
        assert len(o.get("commit", "")) >= 7, c["id"]
        assert o.get("path") and o.get("line"), c["id"]
        assert c.get("why"), f"{c['id']}: 왜 이 판정이 맞는지 적혀 있지 않다"


def test_corpus_covers_both_directions() -> None:
    """오탐만 모으면 감쇄를 넓히다 진탐을 죽이고, 진탐만 모으면 오탐이 돌아온다."""
    assert any(c["must_not_fire"] for c in CORPUS), "오탐 회귀 사례가 없다"
    assert any(c["must_fire"] for c in CORPUS), "진탐 보존 사례가 없다"
