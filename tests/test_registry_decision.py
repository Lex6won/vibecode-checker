"""기관 레지스트리 판정 반영 규칙 — 연동합의 §4-1·§4-2.

**이 테스트가 지키는 것**: 기관 승인이 로컬 악성 탐지를 덮지 못한다는 원칙.

승인은 *시점의 판단*이고 위협 정보는 그 뒤에도 갱신된다. 승인된 버전이 나중에
악성으로 등재됐을 때 승인이 그것을 가리면, 승인 만료일까지(보통 3개월) 초록불이
유지된다. 협상 과정에서 상대 설계가 정확히 이 결함을 갖고 있었고, 그것을 지적한
쪽이 우리이므로 우리 구현이 같은 결함을 갖는 일은 없어야 한다.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from gvskb.tools.check_package import apply_registry_decision


def _days_ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")


def _local(**kw) -> dict:
    """로컬 인텔 캐시 대조만 수행한 결과(원격 OSV 미조회)."""
    base = {
        "name": "requests", "version": "2.31.0", "ecosystem": "pypi",
        "verdict": "checked_clean", "verdict_severity": "info",
        "checked": True, "requires_review": False,
        "is_malicious_package": False, "kev_signals": [],
        "cache_sources_used": ["osv-malicious", "cisa-kev"],
        "cache_stale_sources": [],
        "cache_freshness": {"cisa-kev": _days_ago(1)},
        "note": None,
    }
    base.update(kw)
    return base


APPROVED = {"status": "APPROVED", "approved_by": "경기도 정보보안실",
            "max_env": "E2", "expires_at": "2026-10-13"}
REJECTED = {"status": "REJECTED", "rejected_reason": "유지보수 중단"}


# ---------------------------------------------------------------------------
# 원칙 4 — 로컬 탐지가 최종 안전망
# ---------------------------------------------------------------------------


def test_local_malicious_beats_registry_approval() -> None:
    """승인 이후 악성으로 등재된 경우 — 승인이 악성을 덮으면 안 된다."""
    out = apply_registry_decision(
        _local(verdict="malicious", verdict_severity="high", is_malicious_package=True),
        APPROVED,
    )
    assert out["verdict"] == "malicious", "기관 승인이 로컬 악성 탐지를 덮었다"
    assert out["is_malicious_package"] is True
    assert "승인" in out["note"] and "악성" in out["note"], "판단 근거가 사용자에게 보여야 한다"


def test_kev_signal_beats_registry_approval() -> None:
    """실제 악용(KEV) 신호도 승인보다 위다."""
    out = apply_registry_decision(
        _local(kev_signals=[{"cveID": "CVE-2099-1"}]), APPROVED,
    )
    assert out["verdict"] != "registry_approved"
    assert "KEV" in out["note"]


# ---------------------------------------------------------------------------
# 3분기 규칙 (§4-2)
# ---------------------------------------------------------------------------


def test_approved_with_fresh_cache_is_checked() -> None:
    """캐시가 신선하고 적중이 없으면 — 승인이 확정되고 checked=True."""
    out = apply_registry_decision(_local(), APPROVED)
    assert out["verdict"] == "registry_approved"
    assert out["checked"] is True
    assert out["requires_review"] is False
    assert out["registry_status"] == "ok"
    assert out["registry_decision"]["approved_by"] == "경기도 정보보안실"


def test_approved_with_stale_cache_is_not_marked_checked() -> None:
    """캐시가 낡았으면 대조를 못 한 것이다 — checked=False 로 정직하게 표시.

    다만 낡음은 '번들 반입 한 번'으로 풀리는 **시스템 문제**라 개별 검토로
    올리지 않는다(배너로 알린다). 수백 건에 같은 깃발을 꽂으면 담당자가 그것을
    무시하게 되고, 그러면 그 사이의 진짜 위험도 함께 묻힌다.
    """
    out = apply_registry_decision(
        _local(cache_stale_sources=["cisa-kev"], cache_freshness={"cisa-kev": _days_ago(10)}),
        APPROVED,
    )
    assert out["verdict"] == "registry_approved"
    assert out["checked"] is False, "대조하지 못했는데 검사했다고 표시했다"
    assert out["requires_review"] is False, "시스템 문제를 개별 검토로 올렸다"
    assert "대조하지는 못했" in out["note"]


def test_approved_with_very_stale_cache_requires_review() -> None:
    """유예(30일)를 넘기면 승인 자체를 신뢰할 수 없다 — 그때는 검토로 올린다."""
    out = apply_registry_decision(
        _local(cache_stale_sources=["cisa-kev"], cache_freshness={"cisa-kev": _days_ago(120)}),
        APPROVED,
    )
    assert out["verdict"] == "registry_approved"
    assert out["checked"] is False
    assert out["requires_review"] is True
    assert "120일" in out["note"]


def test_approved_with_no_cache_at_all_requires_review() -> None:
    """캐시가 아예 없으면 경과일도 알 수 없다 — 보수적으로 검토 대상."""
    out = apply_registry_decision(
        _local(cache_sources_used=[], cache_freshness={}), APPROVED,
    )
    assert out["checked"] is False
    assert out["requires_review"] is True


# ---------------------------------------------------------------------------
# REJECTED
# ---------------------------------------------------------------------------


def test_rejected_is_immediate_and_blocking() -> None:
    """차단은 더 강한 신호이고 추가 분석이 판정을 뒤집지 않는다."""
    out = apply_registry_decision(_local(), REJECTED)
    assert out["verdict"] == "registry_rejected"
    assert out["verdict_severity"] == "critical"
    assert out["requires_review"] is True
    assert "유지보수 중단" in out["note"], "차단 사유가 사용자에게 전달돼야 한다"


def test_under_review_falls_through_to_own_analysis() -> None:
    """심사 중·미등록은 자체 분석 결과를 그대로 쓴다 — 판정을 덮지 않는다."""
    for status in ("UNDER_REVIEW", "UNKNOWN"):
        out = apply_registry_decision(_local(), {"status": status})
        assert out["verdict"] == "checked_clean", status
        assert out["registry_status"] == "ok"


# ---------------------------------------------------------------------------
# 사다리·집계 연동
# ---------------------------------------------------------------------------


def test_rejected_severity_reaches_the_blocked_gate() -> None:
    """critical 을 빠뜨리면 기관 차단이 집계에서 통째로 누락된다."""
    from gvskb.tools.check_package import audit_manifest  # noqa: F401  (경로 확인용)

    rejected = apply_registry_decision(_local(), REJECTED)
    blocked = any(
        c.get("is_malicious_package") or c.get("verdict_severity") in ("high", "critical")
        for c in [rejected]
    )
    assert blocked is True


def test_new_verdicts_are_accepted_by_the_schema() -> None:
    """Literal 에 값을 넣지 않으면 검증 실패로 조용히 떨어진다.

    상대 서버가 정확히 이 실수를 했고(enum 누락 → 422), 우리 fail-open 경로가
    그것을 삼켰다면 조용히 넘어갔을 상황이다.
    """
    from gvskb.schema import PackageCheckResult

    for v in ("registry_approved", "registry_rejected"):
        r = PackageCheckResult(name="x", ecosystem="pypi", verdict=v)
        assert r.verdict == v


# ---------------------------------------------------------------------------
# 낡은 차단(stale) — 판정은 같고 안내는 다르다
# ---------------------------------------------------------------------------


def test_stale_block_is_still_a_block() -> None:
    """보관 기한을 넘긴 차단도 차단이다(합의 §4-5).

    조회 실패로 차단이 풀리면 레지스트리 도달을 방해하는 것만으로 우회가 된다.
    """
    out = apply_registry_decision(_local(), {**REJECTED, "stale": True})
    assert out["verdict"] == "registry_rejected"
    assert out["verdict_severity"] == "critical"
    assert out["requires_review"] is True


def test_stale_block_says_it_could_not_be_reconfirmed() -> None:
    """8일째 확인 못 한 차단과 방금 받은 차단의 안내가 같으면 안 된다.

    판정은 둘 다 차단이지만 담당자가 할 일은 다르다 — 후자에는 '해제됐는지
    확인'이 남아 있다. 도구가 자기가 무엇을 모르는지 말하지 않으면, 담당자는
    캐시에 남은 기록을 현재의 확인된 사실로 읽는다.
    """
    fresh = apply_registry_decision(_local(), REJECTED)
    stale = apply_registry_decision(_local(), {**REJECTED, "stale": True})

    assert stale["registry_stale"] is True
    assert fresh["registry_stale"] is False
    assert stale["note"] != fresh["note"]
    assert "로컬 캐시에 남아 있던 것" in stale["note"]
    # 차단이 풀린 것처럼 읽히면 안 된다.
    assert "차단은 그대로 유지됩니다" in stale["note"]
    assert "로컬 캐시에 남아 있던 것" not in fresh["note"]


def test_stale_block_keeps_the_reason() -> None:
    """낡았다는 사실을 덧붙이느라 원래 차단 사유를 잃지 않는다."""
    out = apply_registry_decision(_local(), {**REJECTED, "stale": True})
    assert "사유" in out["note"]
