"""기관 레지스트리 클라이언트 — 연동합의 §2 원칙이 코드로 지켜지는지.

가장 중요한 것은 **의존이 단방향**이라는 점이다. 레지스트리가 없어도·죽어도·
느려도 검사는 계속돼야 하고, 동시에 '물어보지 못했다'가 '승인받았다'처럼
보여서도 안 된다. 이 둘을 함께 만족시키는 게 이 모듈의 존재 이유다.
"""
from __future__ import annotations

import asyncio

import pytest

from gvskb.tools import registry_client as rc


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch):
    for var in ("GVSKB_REGISTRY_URL", "GVSKB_REGISTRY_TOKEN", "GVSKB_MODE",
                "GVSKB_REGISTRY_ALLOW_OFFLINE", "GVSKB_REGISTRY_SUBMIT"):
        monkeypatch.delenv(var, raising=False)
    rc._reset_cache_for_tests()
    yield
    rc._reset_cache_for_tests()


class _Resp:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


def _client_returning(resp, *, raises: Exception | None = None):
    class _C:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return None

        async def post(self, *a, **k):
            if raises is not None:
                raise raises
            return resp

    return _C


# ---------------------------------------------------------------------------
# 원칙 1 — 의존은 단방향
# ---------------------------------------------------------------------------


def test_disabled_without_url() -> None:
    """URL 미설정이면 플러그인 전체가 비활성 — 기존 동작과 100% 동일해야 한다."""
    assert rc.is_enabled() == (False, "disabled")
    assert asyncio.run(rc.lookup_batch([{"ecosystem": "pypi", "name": "x", "version": "1"}])) == {}


def test_offline_requires_explicit_optin(monkeypatch: pytest.MonkeyPatch) -> None:
    """오프라인 모드는 '외부로 나가지 않는다'는 약속이다 — 조용히 바꿀 수 없다."""
    monkeypatch.setenv("GVSKB_REGISTRY_URL", "https://reg.example")
    monkeypatch.setenv("GVSKB_MODE", "offline")
    assert rc.is_enabled() == (False, "disabled")

    monkeypatch.setenv("GVSKB_REGISTRY_ALLOW_OFFLINE", "1")
    assert rc.is_enabled() == (True, "ok")


# ---------------------------------------------------------------------------
# 원칙 3 — fail-open, 그러나 침묵 금지
# ---------------------------------------------------------------------------


def test_lookup_failure_is_fail_open_not_an_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    """조회 실패가 검사를 멈추면 안 된다 — 빈 결과로 돌려준다."""
    monkeypatch.setenv("GVSKB_REGISTRY_URL", "https://reg.example")
    monkeypatch.setattr(rc.httpx, "AsyncClient",
                        _client_returning(None, raises=OSError("connection refused")))
    out = asyncio.run(rc.lookup_batch([{"ecosystem": "pypi", "name": "x", "version": "1"}]))
    assert out == {}


def test_unauthorized_is_distinguished_from_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    """401/403 은 '토큰 문제'이지 '연결 안 됨'이 아니다 — 조치가 다르다."""
    monkeypatch.setenv("GVSKB_REGISTRY_URL", "https://reg.example")
    monkeypatch.setattr(rc.httpx, "AsyncClient", _client_returning(_Resp(status_code=401)))
    out = asyncio.run(rc.lookup_batch([{"ecosystem": "pypi", "name": "x", "version": "1"}]))
    assert "__error__" in out and out["__error__"]["status"] == "unauthorized"


def test_annotate_status_does_not_raise_requires_review() -> None:
    """도달 실패는 시스템 문제다 — 패키지마다 검토 깃발을 꽂으면 경고 피로가 된다."""
    out = rc.annotate_status({"requires_review": False, "verdict": "checked_clean"}, "unreachable")
    assert out["registry_status"] == "unreachable"
    assert out["requires_review"] is False


def test_banner_says_it_was_not_asked_not_that_it_was_approved() -> None:
    text = rc.registry_banner("unreachable")
    assert text and "'승인받았다'는 뜻이 아닙니다" in text
    assert rc.registry_banner("ok") is None


# ---------------------------------------------------------------------------
# 차단은 조회 실패보다 오래 살아남는다 (§4-5)
# ---------------------------------------------------------------------------


def test_rejected_cache_is_demoted_not_deleted_on_expiry(monkeypatch: pytest.MonkeyPatch) -> None:
    """만료 = 삭제가 아니라 강등.

    지워 버리면 장애가 TTL 을 넘긴 순간 차단이 조용히 풀린다 — 레지스트리 도달을
    방해하는 것만으로 차단을 우회할 수 있게 된다.
    """
    purl = "pkg:pypi/bad@1.0.0"
    base = rc.time.monotonic()   # monotonic 은 부팅 이후 경과라 절대값이 크다 — 기준을 잡는다
    rc._cache_put(purl, {"purl": purl, "status": "REJECTED", "rejected_reason": "악성"})
    assert rc._cache_get(purl)["status"] == "REJECTED"

    # TTL 을 넘긴 상황을 만든다.
    monkeypatch.setattr(rc.time, "monotonic", lambda: base + rc._TTL_SECONDS["REJECTED"] + 10)
    still = rc._cache_get(purl)
    assert still is not None, "만료로 차단이 사라졌다"
    assert still["status"] == "REJECTED"
    assert still["stale"] is True


def test_approved_cache_expires_normally(monkeypatch: pytest.MonkeyPatch) -> None:
    """승인은 짧게 만료된다 — 철회 전파가 지연되면 안 되기 때문이다."""
    purl = "pkg:pypi/ok@1.0.0"
    base = rc.time.monotonic()
    rc._cache_put(purl, {"purl": purl, "status": "APPROVED"})
    monkeypatch.setattr(rc.time, "monotonic", lambda: base + rc._TTL_SECONDS["APPROVED"] + 10)
    assert rc._cache_get(purl) is None


# ---------------------------------------------------------------------------
# 제출 필터 (§5-D)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("verdict", ["unknown", "error", "registry_approved", "registry_rejected"])
def test_non_observations_are_not_submitted(verdict: str) -> None:
    """판정이 아닌 것과 **우리가 준 답이 되돌아가는 것**은 보내지 않는다."""
    assert rc.should_submit({"verdict": verdict, "version": "1.0.0"}) is False


def test_version_less_results_are_not_submitted() -> None:
    """버전 미지정은 특정 버전의 사실이 아니다 — 저장 키가 성립하지 않는다."""
    assert rc.should_submit({"verdict": "checked_clean", "version": None}) is False
    assert rc.should_submit({"verdict": "checked_clean", "version": "1.0.0"}) is True


def test_envelope_keeps_result_untouched() -> None:
    """result 는 변환 없는 원본 — 전송 사정으로 판정 모델을 오염시키지 않는다."""
    result = {"name": "x", "version": "1.0.0", "verdict": "checked_clean"}
    env = rc._envelope(result, caller="harness:auto", source_scope="lockfile", now_iso="T")
    assert env["result"] == result
    assert env["caller"] == "harness:auto"
    assert env["source_scope"] == "lockfile"
    assert env["engine_commit"] is None      # 가짜 값을 채우느니 null 이 낫다
    assert env["client"].startswith("gvskb/")


def test_submit_failure_does_not_raise(monkeypatch: pytest.MonkeyPatch) -> None:
    """제출 실패가 검사 실패가 되면 안 된다."""
    monkeypatch.setenv("GVSKB_REGISTRY_URL", "https://reg.example")
    monkeypatch.setattr(rc.httpx, "AsyncClient",
                        _client_returning(None, raises=OSError("boom")))
    out = asyncio.run(rc.submit_batch([{"verdict": "checked_clean", "version": "1.0.0"}]))
    assert out["submitted"] == 0


def test_submit_can_be_disabled_while_lookup_stays_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GVSKB_REGISTRY_URL", "https://reg.example")
    monkeypatch.setenv("GVSKB_REGISTRY_SUBMIT", "0")
    assert rc.is_enabled()[0] is True
    out = asyncio.run(rc.submit_batch([{"verdict": "checked_clean", "version": "1.0.0"}]))
    assert out["reason"] == "disabled"


# ---------------------------------------------------------------------------
# 조회 성공 경로
# ---------------------------------------------------------------------------


def test_lookup_maps_by_purl_regardless_of_order(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GVSKB_REGISTRY_URL", "https://reg.example")
    payload = {"results": [
        {"purl": "pkg:npm/b@2.0.0", "status": "REJECTED"},
        {"purl": "pkg:pypi/a@1.0.0", "status": "APPROVED"},
    ]}
    monkeypatch.setattr(rc.httpx, "AsyncClient", _client_returning(_Resp(payload=payload)))
    out = asyncio.run(rc.lookup_batch([
        {"ecosystem": "pypi", "name": "a", "version": "1.0.0"},
        {"ecosystem": "npm", "name": "b", "version": "2.0.0"},
    ]))
    assert out["pkg:pypi/a@1.0.0"]["status"] == "APPROVED"
    assert out["pkg:npm/b@2.0.0"]["status"] == "REJECTED"


# ---------------------------------------------------------------------------
# audit_manifest 통합 — 배선이 실제로 붙어 있는가
# ---------------------------------------------------------------------------


def test_audit_manifest_applies_registry_rejection(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    """기관 차단이 실제 검사 결과에 반영되고 집계까지 올라가야 한다."""
    monkeypatch.setenv("GVSKB_MODE", "offline")
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path))
    monkeypatch.setenv("GVSKB_REGISTRY_URL", "https://reg.example")
    monkeypatch.setenv("GVSKB_REGISTRY_ALLOW_OFFLINE", "1")
    monkeypatch.setenv("GVSKB_REGISTRY_SUBMIT", "0")
    payload = {"results": [
        {"purl": "pkg:pypi/badpkg@1.0.0", "status": "REJECTED", "rejected_reason": "악성 확인"},
    ]}
    monkeypatch.setattr(rc.httpx, "AsyncClient", _client_returning(_Resp(payload=payload)))

    from gvskb.tools.check_package import audit_manifest

    r = asyncio.run(audit_manifest("badpkg==1.0.0\n", ecosystem="pypi"))
    assert r["registry_status"] == "ok"
    check = r["checks"][0]
    assert check["verdict"] == "registry_rejected"
    assert check["verdict_severity"] == "critical"
    assert r["blocked"] is True, "기관 차단이 집계에서 누락됐다"
    assert "악성 확인" in (check["note"] or "")


def test_audit_manifest_marks_unreachable_without_flagging_every_package(
    monkeypatch: pytest.MonkeyPatch, tmp_path,
) -> None:
    """도달 실패는 시스템 상태로 한 번만 — 패키지마다 검토로 올리지 않는다."""
    monkeypatch.setenv("GVSKB_MODE", "offline")
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path))
    monkeypatch.setenv("GVSKB_REGISTRY_URL", "https://reg.example")
    monkeypatch.setenv("GVSKB_REGISTRY_ALLOW_OFFLINE", "1")
    monkeypatch.setenv("GVSKB_REGISTRY_SUBMIT", "0")
    monkeypatch.setattr(rc.httpx, "AsyncClient",
                        _client_returning(None, raises=OSError("refused")))

    from gvskb.tools.check_package import audit_manifest

    r = asyncio.run(audit_manifest("a==1.0.0\nb==2.0.0\n", ecosystem="pypi"))
    assert r["registry_status"] == "unreachable"
    assert all(c["registry_status"] == "unreachable" for c in r["checks"])
    # 배너가 대신 알린다 — 개별 승격은 하지 않는다.
    from gvskb.report import _registry_banner
    assert _registry_banner([r]) is not None


def test_registry_disabled_leaves_everything_untouched(
    monkeypatch: pytest.MonkeyPatch, tmp_path,
) -> None:
    """원칙 1 — 미설정이면 기존 동작과 100% 동일."""
    monkeypatch.setenv("GVSKB_MODE", "offline")
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path))

    from gvskb.tools.check_package import audit_manifest

    r = asyncio.run(audit_manifest("a==1.0.0\n", ecosystem="pypi"))
    assert r["registry_status"] == "disabled"
    assert r["checks"][0]["registry_status"] == "disabled"
    from gvskb.report import _registry_banner
    assert _registry_banner([r]) is None
