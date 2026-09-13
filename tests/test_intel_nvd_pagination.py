"""NVD 페이지 순회 — 빠짐없이 받고, 어긋나면 저장하지 않는다.

배경(실측 2026-09-13): 최근 7일 창의 totalResults 가 7,149~7,156건인데 어댑터가
첫 2,000건만 받고 성공으로 저장했다. 여기서는 4페이지(7,156건) 모의 응답으로
전 페이지 수집을 확인하고, 중간 실패·합계 불일치·반복 페이지·빈 페이지·깨진
JSON 이 모두 "부분 저장 없음"으로 끝나는지 본다.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from gvskb.intel import IntelCache, update_source
from gvskb.intel.sources import nvd

TOTAL = 7156


def _cve(i: int, *, last_modified: str = "2026-09-10T00:00:00.000", status: str = "Analyzed") -> dict:
    return {"cve": {
        "id": f"CVE-2026-{i:05d}",
        "published": "2026-09-01T00:00:00.000",
        "lastModified": last_modified,
        "vulnStatus": status,
        "metrics": {"cvssMetricV31": [
            {"source": "nvd@nist.gov", "type": "Primary",
             "cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}},
        ]},
        "weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}],
    }}


def _page(start: int, total: int = TOTAL, *, items: list[dict] | None = None,
          per_page: int | None = None, reported_start: int | None = None) -> dict:
    if items is None:
        count = max(0, min(nvd.PAGE_SIZE, total - start))
        items = [_cve(start + k) for k in range(count)]
    return {
        "resultsPerPage": len(items) if per_page is None else per_page,
        "startIndex": start if reported_start is None else reported_start,
        "totalResults": total,
        "vulnerabilities": items,
    }


class Resp:
    def __init__(self, payload=None, status_code: int = 200, headers: dict | None = None,
                 bad_json: bool = False) -> None:
        self._payload = payload
        self.status_code = status_code
        self.headers = headers or {}
        self._bad_json = bad_json

    def json(self):
        if self._bad_json:
            raise ValueError("Expecting value: line 1 column 1")
        return self._payload


class ScriptedClient:
    """startIndex 별로 준비된 응답(또는 응답 목록·예외)을 순서대로 돌려준다."""

    def __init__(self, script: dict[int, list]) -> None:
        self._script = {k: list(v) for k, v in script.items()}
        self.calls: list[dict] = []

    def get(self, url, params=None, headers=None):
        self.calls.append({"url": url, "params": dict(params or {}), "headers": dict(headers or {})})
        start = int((params or {}).get("startIndex", 0))
        queue = self._script.get(start)
        if not queue:
            raise AssertionError(f"예상하지 못한 요청 startIndex={start}")
        item = queue.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


def _sleeps() -> tuple[list[float], callable]:
    seen: list[float] = []
    return seen, seen.append


@pytest.fixture(autouse=True)
def _no_api_key(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.delenv("GVSKB_NVD_CACHE_MAX", raising=False)


# ---------------------------------------------------------------------------
# 전 페이지 수집
# ---------------------------------------------------------------------------

def test_walks_every_page_and_collects_all_7156() -> None:
    client = ScriptedClient({s: [Resp(_page(s))] for s in (0, 2000, 4000, 6000)})
    sleeps, sleep = _sleeps()

    url, items = nvd.fetch_nvd_recent(client, sleep=sleep)

    assert url == nvd.NVD_API_URL
    assert [c["params"]["startIndex"] for c in client.calls] == [0, 2000, 4000, 6000]
    assert all(c["params"]["resultsPerPage"] == 2000 for c in client.calls)
    assert len(items) == TOTAL, "마지막 1,156건까지 모두 수집돼야 한다"
    assert {i["id"] for i in items} == {f"CVE-2026-{k:05d}" for k in range(TOTAL)}
    assert sleeps == [nvd.INTERVAL_NO_KEY] * 3, "페이지 사이에만 공식 권고 간격을 둔다"


def test_api_key_shortens_interval_and_goes_only_in_header(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NVD_API_KEY", "secret-key-123")
    client = ScriptedClient({0: [Resp(_page(0, total=2500))], 2000: [Resp(_page(2000, total=2500))]})
    sleeps, sleep = _sleeps()

    nvd.fetch_nvd_recent(client, sleep=sleep)

    assert sleeps == [nvd.INTERVAL_WITH_KEY]
    for call in client.calls:
        assert call["headers"].get("apiKey") == "secret-key-123"
        assert "secret-key-123" not in call["url"]
        assert "secret-key-123" not in repr(call["params"])


def test_total_zero_returns_empty_without_error() -> None:
    client = ScriptedClient({0: [Resp({"resultsPerPage": 0, "startIndex": 0, "totalResults": 0,
                                       "vulnerabilities": []})]})
    _, items = nvd.fetch_nvd_recent(client, sleep=lambda s: None)
    assert items == []


def test_normalization_keeps_only_decision_fields() -> None:
    client = ScriptedClient({0: [Resp(_page(0, total=1, items=[_cve(1)]))]})
    _, items = nvd.fetch_nvd_recent(client, sleep=lambda s: None)
    item = items[0]
    assert item["cvss31_base_score"] == 7.5
    assert item["cvss31_severity"] == "HIGH"
    assert item["cvss31_source"] == "nvd@nist.gov"
    assert item["cwes"] == [{"value": "CWE-79"}]
    assert "description" not in item, "설명문은 소비자가 없어 담지 않는다(번들 크기)"
    assert "configurations" not in item and "cpe" not in repr(item).lower()


# ---------------------------------------------------------------------------
# 실패 → 부분 결과 미저장
# ---------------------------------------------------------------------------

def test_middle_page_failure_raises_and_keeps_previous_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    cache = IntelCache(tmp_path)
    cache.save("nvd-recent", "x", [{"id": "CVE-OLD", "lastModified": "2026-01-01T00:00:00.000"}])
    script = {
        0: [Resp(_page(0))],
        2000: [Resp(status_code=503)] * (nvd.MAX_RETRIES + 1),
    }
    client = ScriptedClient(script)

    with pytest.raises(nvd.NvdFetchError):
        nvd.fetch_nvd_recent(client, sleep=lambda s: None)

    # 오케스트레이터 통합 — 어댑터 예외는 warn 이고 이전 캐시는 그대로다.
    adapter_client = ScriptedClient({0: [Resp(_page(0))],
                                     2000: [Resp(status_code=503)] * (nvd.MAX_RETRIES + 1)})
    monkeypatch.setattr(nvd.time, "sleep", lambda s: None)   # 실제 대기 없이 재시도 경로만 확인
    result = update_source("nvd-recent", cache=cache, client=adapter_client)
    assert result.status == "warn"
    assert result.item_count == 1
    assert [i["id"] for i in cache.load("nvd-recent").items] == ["CVE-OLD"], "부분 수집분이 저장되면 안 된다"


def test_429_uses_retry_after_then_succeeds() -> None:
    client = ScriptedClient({0: [Resp(status_code=429, headers={"Retry-After": "3"}),
                                 Resp(_page(0, total=1, items=[_cve(1)]))]})
    sleeps, sleep = _sleeps()

    _, items = nvd.fetch_nvd_recent(client, sleep=sleep)

    assert len(items) == 1
    assert sleeps == [3.0]
    assert len(client.calls) == 2


def test_429_retry_after_is_capped() -> None:
    client = ScriptedClient({0: [Resp(status_code=429, headers={"Retry-After": "99999"}),
                                 Resp(_page(0, total=0, items=[]))]})
    sleeps, sleep = _sleeps()
    nvd.fetch_nvd_recent(client, sleep=sleep)
    assert sleeps == [nvd.MAX_RETRY_AFTER]


def test_429_without_retry_after_uses_bounded_backoff_then_gives_up() -> None:
    client = ScriptedClient({0: [Resp(status_code=429)] * (nvd.MAX_RETRIES + 1)})
    sleeps, sleep = _sleeps()
    with pytest.raises(nvd.NvdFetchError, match="HTTP 429"):
        nvd.fetch_nvd_recent(client, sleep=sleep)
    assert sleeps == list(nvd.BACKOFF_SECONDS[:nvd.MAX_RETRIES])
    assert len(client.calls) == nvd.MAX_RETRIES + 1


def test_transient_network_error_is_retried_then_succeeds() -> None:
    client = ScriptedClient({0: [ConnectionError("reset by peer"), Resp(_page(0, total=0, items=[]))]})
    sleeps, sleep = _sleeps()
    nvd.fetch_nvd_recent(client, sleep=sleep)
    assert sleeps == [nvd.BACKOFF_SECONDS[0]]


def test_client_4xx_other_than_429_is_not_retried() -> None:
    client = ScriptedClient({0: [Resp(status_code=404)]})
    with pytest.raises(nvd.NvdFetchError, match="HTTP 404"):
        nvd.fetch_nvd_recent(client, sleep=lambda s: None)
    assert len(client.calls) == 1


def test_malformed_json_raises() -> None:
    client = ScriptedClient({0: [Resp(bad_json=True)]})
    with pytest.raises(nvd.NvdFetchError, match="JSON"):
        nvd.fetch_nvd_recent(client, sleep=lambda s: None)


def test_non_object_json_raises() -> None:
    client = ScriptedClient({0: [Resp(payload=["not", "an", "object"])]})
    with pytest.raises(nvd.NvdFetchError):
        nvd.fetch_nvd_recent(client, sleep=lambda s: None)


def test_total_changing_mid_walk_raises() -> None:
    client = ScriptedClient({0: [Resp(_page(0, total=4000))],
                             2000: [Resp(_page(2000, total=4100))]})
    with pytest.raises(nvd.NvdFetchError, match="totalResults"):
        nvd.fetch_nvd_recent(client, sleep=lambda s: None)


def test_repeated_start_index_in_response_raises() -> None:
    # 두 번째 요청(startIndex=2000)에 서버가 첫 페이지(startIndex=0)를 다시 준다.
    client = ScriptedClient({0: [Resp(_page(0, total=4000))],
                             2000: [Resp(_page(0, total=4000))]})
    with pytest.raises(nvd.NvdFetchError, match="startIndex"):
        nvd.fetch_nvd_recent(client, sleep=lambda s: None)
    assert len(client.calls) == 2, "무한 반복 없이 즉시 중단"


def test_empty_page_before_total_raises() -> None:
    client = ScriptedClient({0: [Resp(_page(0, total=4000))],
                             2000: [Resp(_page(2000, total=4000, items=[], per_page=0))]})
    with pytest.raises(nvd.NvdFetchError, match="빈 페이지"):
        nvd.fetch_nvd_recent(client, sleep=lambda s: None)


def test_results_per_page_mismatch_raises() -> None:
    client = ScriptedClient({0: [Resp(_page(0, total=1, items=[_cve(1)], per_page=2000))]})
    with pytest.raises(nvd.NvdFetchError, match="resultsPerPage"):
        nvd.fetch_nvd_recent(client, sleep=lambda s: None)


def test_non_integer_counters_raise() -> None:
    client = ScriptedClient({0: [Resp({"resultsPerPage": "2000", "startIndex": 0,
                                       "totalResults": 1, "vulnerabilities": [_cve(1)]})]})
    with pytest.raises(nvd.NvdFetchError, match="resultsPerPage"):
        nvd.fetch_nvd_recent(client, sleep=lambda s: None)


def test_page_cap_stops_runaway_walk(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(nvd, "MAX_PAGES", 2)
    client = ScriptedClient({s: [Resp(_page(s, total=8000))] for s in (0, 2000, 4000, 6000)})
    with pytest.raises(nvd.NvdFetchError, match="상한"):
        nvd.fetch_nvd_recent(client, sleep=lambda s: None)
    assert len(client.calls) == 2


# ---------------------------------------------------------------------------
# 중복·거부 상태·키 비노출
# ---------------------------------------------------------------------------

def test_duplicate_cve_across_pages_keeps_newest_last_modified() -> None:
    older = _cve(1, last_modified="2026-09-01T00:00:00.000")
    newer = _cve(1, last_modified="2026-09-12T00:00:00.000")
    newer["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"] = 9.8
    page0 = [_cve(k) for k in range(2000)]
    page0[1] = newer          # CVE-2026-00001 자리에 최신본
    page1 = [_cve(2000 + k) for k in range(500)]
    page1[0] = older
    client = ScriptedClient({0: [Resp(_page(0, total=2500, items=page0))],
                             2000: [Resp(_page(2000, total=2500, items=page1))]})

    _, items = nvd.fetch_nvd_recent(client, sleep=lambda s: None)

    by_id = {i["id"]: i for i in items}
    assert len(items) == 2499, "중복 CVE 는 하나만 남는다"
    assert by_id["CVE-2026-00001"]["cvss31_base_score"] == 9.8
    assert by_id["CVE-2026-00001"]["lastModified"] == "2026-09-12T00:00:00.000"


def test_rejected_status_is_kept_and_flagged_and_updates_previous_cache() -> None:
    rejected = _cve(7, last_modified="2026-09-12T00:00:00.000", status="Rejected")
    client = ScriptedClient({0: [Resp(_page(0, total=1, items=[rejected]))]})
    _, items = nvd.fetch_nvd_recent(client, sleep=lambda s: None)
    assert nvd.is_rejected(items[0])

    prev = [{"id": "CVE-2026-00007", "lastModified": "2026-01-01T00:00:00.000",
             "vulnStatus": "Analyzed", "cvss31_base_score": 9.8}]
    merged = {m["id"]: m for m in nvd.merge_nvd(prev, items)}
    assert merged["CVE-2026-00007"]["vulnStatus"] == "Rejected", "나중에 거부된 CVE 는 상태가 갱신돼야 한다"


def test_merge_keeps_newer_last_modified_even_if_it_is_the_previous_item() -> None:
    prev = [{"id": "CVE-1", "lastModified": "2026-09-12T00:00:00.000", "cvss31_severity": "HIGH"}]
    new = [{"id": "CVE-1", "lastModified": "2026-09-01T00:00:00.000", "cvss31_severity": "LOW"}]
    merged = nvd.merge_nvd(prev, new)
    assert merged[0]["cvss31_severity"] == "HIGH", "lastModified 가 최신인 쪽이 남는다"


def test_api_key_never_appears_in_error_text(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NVD_API_KEY", "super-secret-key")
    leaking = RuntimeError("request failed; headers={'apiKey': 'super-secret-key'}")
    client = ScriptedClient({0: [leaking] * (nvd.MAX_RETRIES + 1)})

    with pytest.raises(nvd.NvdFetchError) as info:
        nvd.fetch_nvd_recent(client, sleep=lambda s: None)

    assert "super-secret-key" not in str(info.value)
    assert "***" in str(info.value)
