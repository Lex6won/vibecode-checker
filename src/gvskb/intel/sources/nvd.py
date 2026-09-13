"""NVD CVE API 2.0 — 최근 수정 CVE 를 **빠짐없이** 받는다.

이 캐시의 역할은 보조 정보(CVSS 병기·상태 확인)다. PyPI/npm 패키지의 취약점과
영향 버전을 판정하는 주 근거는 OSV 다 — NVD 제품명을 패키지명으로 추측하지
않고, CPE·자산 판정용 데이터도 담지 않는다.

무엇이 잘못돼 있었나(실측 2026-09-13): ``resultsPerPage=2000`` 한 페이지만 받고
성공으로 저장했다. 최근 7일 창의 실제 합계는 7,149건(같은 날 다른 시각 조회
7,156건)이라 **한 번의 실행에서 5천 건 이상을 읽지 못했다**. ``totalResults`` 를
보지 않으니 누락은 어디에도 기록되지 않았다.

수집 규칙:

- ``startIndex=0`` 부터 마지막 페이지까지 순차로 받고, **마지막 페이지까지
  끝났을 때만** 결과를 돌려준다. 페이지 하나라도 실패하면 예외 — 오케스트레이터가
  이전 캐시를 그대로 보존한다(부분 결과는 저장하지 않는다).
- 응답의 ``resultsPerPage``·``startIndex``·``totalResults`` 를 매 페이지 검증한다.
  같은 startIndex 반복, 빈 페이지, 페이지 중 합계 변경, 페이지 수 상한 초과는
  모두 실패다 — 무한 반복과 조용한 누락을 둘 다 막는다.
- 429 는 ``Retry-After`` (상한 있음) 또는 제한된 지수 백오프로 재시도하고,
  5xx·일시적 네트워크 오류도 제한 횟수만 재시도한다.
- API 키는 ``apiKey`` **헤더로만** 보내며 URL·로그·예외 문구에 넣지 않는다.

공식 제한(NVD 개발자 안내, https://nvd.nist.gov/developers/start-here):
resultsPerPage 상한 2,000 · lastMod 창 최대 120일 · 키 없음 30초당 5요청 /
키 있음 30초당 50요청 · 요청 사이 6초 대기 권고. 여기서는 키 없음 6초, 키 있음
0.6초 간격을 둔다.
"""
from __future__ import annotations

import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from .base import HttpFetcher, SourceAdapter, register_source

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RECENT_DAYS = 7  # NVD enforces lastModStartDate windows <= 120 days

#: NVD 공식 상한. 이보다 크게 요청하면 NVD 가 2,000 으로 깎아 응답한다.
PAGE_SIZE = 2000
#: 페이지 수 상한 — 7일 창이 40만 건을 넘는 일은 없다. 넘으면 창이나 응답이 잘못된 것.
MAX_PAGES = 200
#: 429·5xx·네트워크 오류 재시도 횟수(첫 시도 제외).
MAX_RETRIES = 3
#: 제한된 지수 백오프(초). Retry-After 가 없을 때 쓴다.
BACKOFF_SECONDS = (6.0, 12.0, 24.0)
#: Retry-After 상한(초) — 서버가 비정상적으로 큰 값을 주더라도 잡을 시간을 붙잡지 않는다.
MAX_RETRY_AFTER = 120.0
#: 페이지 사이 간격(초). 키 없음 5요청/30초 → 6초, 키 있음 50요청/30초 → 0.6초.
INTERVAL_NO_KEY = 6.0
INTERVAL_WITH_KEY = 0.6

REJECTED_STATUS = "Rejected"


class NvdFetchError(RuntimeError):
    """페이지 순회가 끝까지 가지 못했다 — 호출자는 부분 결과를 저장하면 안 된다."""


def _iso_z(d: datetime) -> str:
    # NVD requires extended ISO 8601 with milliseconds, no offset suffix
    return d.strftime("%Y-%m-%dT%H:%M:%S.000")


def _primary_cvss31(metrics: dict) -> dict:
    """cvssMetricV31 항목 중 NIST Primary 를 우선, 없으면 첫 항목."""
    entries = [m for m in (metrics.get("cvssMetricV31") or []) if isinstance(m, dict)]
    if not entries:
        return {}
    for m in entries:
        if str(m.get("type") or "").lower() == "primary":
            return m
    return entries[0]


def _normalize(item: dict) -> dict:
    """저장 범위: CVE ID·published·lastModified·vulnStatus·CWE·CVSS 3.1(+제공 주체).

    설명문·CPE·configurations 는 담지 않는다 — 판정에 쓰지 않는 필드로 번들을
    키우지 않는다(설명문 600자 × 5만 건 ≈ 30MB 가 아무 소비자 없이 실려 있었다).
    """
    cve = item.get("cve") or {}
    metrics = cve.get("metrics") or {}
    cvss_entry = _primary_cvss31(metrics) if isinstance(metrics, dict) else {}
    cvss31 = cvss_entry.get("cvssData") or {}
    return {
        "id": cve.get("id"),
        "published": cve.get("published"),
        "lastModified": cve.get("lastModified"),
        "vulnStatus": cve.get("vulnStatus"),
        "cvss31_base_score": cvss31.get("baseScore"),
        "cvss31_severity": cvss31.get("baseSeverity"),
        "cvss31_source": cvss_entry.get("source"),
        "cwes": [
            {"value": w.get("value")}
            for c in (cve.get("weaknesses") or [])
            for w in (c.get("description") or [])
            if w.get("lang") == "en"
        ],
    }


def is_rejected(item: dict) -> bool:
    """거부(Rejected)된 CVE 는 활성 취약점 근거가 아니다 — 소비자가 이 함수로 거른다."""
    return str(item.get("vulnStatus") or "").strip().lower() == REJECTED_STATUS.lower()


def _api_key() -> str:
    return os.environ.get("NVD_API_KEY", "").strip()


def _redact(text: str, api_key: str) -> str:
    """예외 문구에 키가 섞여 들어오는 경로를 원천 차단한다(헤더 덤프 등)."""
    if api_key and api_key in text:
        return text.replace(api_key, "***")
    return text


def _non_negative_int(data: dict, key: str) -> int:
    value = data.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise NvdFetchError(f"NVD 응답의 {key} 가 음이 아닌 정수가 아닙니다: {value!r}")
    return value


def _retry_after_seconds(resp: Any) -> float | None:
    headers = getattr(resp, "headers", None) or {}
    try:
        raw = headers.get("Retry-After") or headers.get("retry-after")
    except AttributeError:
        return None
    if raw is None:
        return None
    try:
        return min(MAX_RETRY_AFTER, max(0.0, float(str(raw).strip())))
    except ValueError:
        return None  # HTTP-date 형식은 지원하지 않는다 — 백오프로 대체


def _get_page(
    client: HttpFetcher,
    params: dict[str, Any],
    headers: dict[str, str],
    *,
    sleep: Callable[[float], None],
    api_key: str,
) -> dict:
    """페이지 1개를 받는다. 429·5xx·네트워크 오류는 제한 횟수만 재시도한다."""
    start_index = params.get("startIndex")
    last_error = ""
    for attempt in range(MAX_RETRIES + 1):
        try:
            resp = client.get(NVD_API_URL, params=params, headers=headers)
        except Exception as exc:  # noqa: BLE001 — 일시적 네트워크 오류는 재시도 대상
            last_error = _redact(f"{type(exc).__name__}: {exc}", api_key)
            if attempt < MAX_RETRIES:
                sleep(BACKOFF_SECONDS[min(attempt, len(BACKOFF_SECONDS) - 1)])
                continue
            break
        status = int(getattr(resp, "status_code", 200) or 200)
        if status == 429 or 500 <= status < 600:
            last_error = f"HTTP {status}"
            if attempt < MAX_RETRIES:
                wait = _retry_after_seconds(resp) if status == 429 else None
                if wait is None:
                    wait = BACKOFF_SECONDS[min(attempt, len(BACKOFF_SECONDS) - 1)]
                sleep(wait)
                continue
            break
        if status >= 400:
            raise NvdFetchError(f"NVD HTTP {status} (startIndex={start_index}) — 재시도하지 않는 오류")
        try:
            data = resp.json()
        except Exception as exc:  # noqa: BLE001 — 깨진 JSON 은 실패로 처리
            raise NvdFetchError(
                _redact(f"NVD 응답 JSON 해석 실패 (startIndex={start_index}): {type(exc).__name__}", api_key)
            ) from None
        if not isinstance(data, dict):
            raise NvdFetchError(f"NVD 응답이 객체가 아닙니다 (startIndex={start_index})")
        return data
    raise NvdFetchError(
        f"NVD 페이지 요청 실패 (startIndex={start_index}, {MAX_RETRIES + 1}회 시도): {last_error}"
    )


def _keep_newest(collected: dict[str, dict], item: dict) -> None:
    """같은 CVE 가 여러 페이지에 나타나면 lastModified 가 최신인 항목을 남긴다."""
    cve_id = str(item.get("id") or "")
    if not cve_id:
        return
    old = collected.get(cve_id)
    if old is None or str(item.get("lastModified") or "") >= str(old.get("lastModified") or ""):
        collected[cve_id] = item


def fetch_nvd_recent(
    client: HttpFetcher,
    *,
    sleep: Callable[[float], None] | None = None,
) -> tuple[str, list[dict]]:
    """최근 ``RECENT_DAYS`` 일 창을 모든 페이지에 걸쳐 받는다.

    반환은 마지막 페이지까지 검증을 통과했을 때만 이뤄진다. 그 전에 무엇이든
    어긋나면 ``NvdFetchError`` — 부분 결과는 밖으로 나가지 않는다.
    ``sleep`` 은 테스트가 대기를 기록·생략하기 위한 이음매다(기본 ``time.sleep``).
    """
    if sleep is None:
        sleep = time.sleep
    end = datetime.now(timezone.utc).replace(tzinfo=None)
    start = end - timedelta(days=RECENT_DAYS)
    base_params: dict[str, Any] = {
        "lastModStartDate": _iso_z(start),
        "lastModEndDate": _iso_z(end),
        "resultsPerPage": PAGE_SIZE,
    }
    api_key = _api_key()
    headers: dict[str, str] = {"apiKey": api_key} if api_key else {}
    interval = INTERVAL_WITH_KEY if api_key else INTERVAL_NO_KEY

    collected: dict[str, dict] = {}
    start_index = 0
    total: int | None = None
    pages = 0
    raw_count = 0
    seen_indices: set[int] = set()

    while True:
        if pages >= MAX_PAGES:
            raise NvdFetchError(f"페이지 수가 상한({MAX_PAGES})을 넘었습니다 — 합계 {total}, 순회 중단")
        if start_index in seen_indices:
            raise NvdFetchError(f"startIndex={start_index} 가 반복됩니다 — 순회 중단")
        seen_indices.add(start_index)
        if pages > 0:
            sleep(interval)

        data = _get_page(
            client, {**base_params, "startIndex": start_index}, headers,
            sleep=sleep, api_key=api_key,
        )
        pages += 1

        page_size = _non_negative_int(data, "resultsPerPage")
        page_index = _non_negative_int(data, "startIndex")
        page_total = _non_negative_int(data, "totalResults")
        if page_index != start_index:
            raise NvdFetchError(f"요청 startIndex={start_index} 와 응답 startIndex={page_index} 가 다릅니다")
        if total is None:
            total = page_total
        elif page_total != total:
            raise NvdFetchError(
                f"순회 중 totalResults 가 {total} → {page_total} 로 바뀌었습니다 — 이번 실행은 저장하지 않습니다"
            )
        vulns = data.get("vulnerabilities")
        if vulns is None and total == 0:
            vulns = []
        if not isinstance(vulns, list):
            raise NvdFetchError(f"NVD 응답의 vulnerabilities 가 목록이 아닙니다 (startIndex={start_index})")
        if total == 0:
            break
        if not vulns:
            raise NvdFetchError(
                f"startIndex={start_index} 에서 빈 페이지 — 합계 {total} 에 미달인 채 순회 중단"
            )
        if page_size != len(vulns):
            raise NvdFetchError(
                f"resultsPerPage={page_size} 와 실제 항목 수 {len(vulns)} 가 다릅니다 (startIndex={start_index})"
            )
        for v in vulns:
            if isinstance(v, dict) and v.get("cve"):
                raw_count += 1
                _keep_newest(collected, _normalize(v))
        start_index += len(vulns)
        if start_index >= total:
            break

    if total is None:
        raise NvdFetchError("NVD 응답을 받지 못했습니다")
    if raw_count != total:
        raise NvdFetchError(f"수집 {raw_count}건이 totalResults {total}건과 다릅니다 — 저장하지 않습니다")

    items = sorted(collected.values(), key=lambda i: str(i.get("lastModified") or ""), reverse=True)
    return NVD_API_URL, items


#: 누적 캐시 상한(항목 수). 7일 창이 7천 건 안팎이므로 5만 건은 약 7주 분량이다.
#: 이 캐시의 용도는 KEV 신호·오프라인 취약점의 CVSS 병기(우선순위 근거)라 최근
#: 수정분 위주면 충분하다 — lastModified 가 최신인 것부터 남긴다. 기관이 더 넓게
#: 원하면 GVSKB_NVD_CACHE_MAX 로 올린다.
DEFAULT_CACHE_MAX = 50_000


def _cache_max() -> int:
    raw = os.environ.get("GVSKB_NVD_CACHE_MAX", "")
    try:
        return max(1000, int(raw)) if raw else DEFAULT_CACHE_MAX
    except ValueError:
        return DEFAULT_CACHE_MAX


def merge_nvd(prev_items: list[dict], new_items: list[dict]) -> list[dict]:
    """CVE ID 기준 병합 — ``lastModified`` 가 최신인 항목이 남는다.

    예전에는 매일 "최근 7일" 창으로 **덮어써서**, 8일 전에 수정된 CVE 의 CVSS 가
    캐시에서 사라졌다. 누적하면 시간이 지날수록 커버리지가 넓어진다. 나중에
    Rejected 로 바뀐 CVE 도 새 lastModified 로 들어와 상태가 갱신된다.
    """
    by_id: dict[str, dict] = {}
    for i in prev_items:
        _keep_newest(by_id, i)
    for i in new_items:
        _keep_newest(by_id, i)
    merged = sorted(by_id.values(),
                    key=lambda i: str(i.get("lastModified") or ""), reverse=True)
    return merged[:_cache_max()]


register_source(SourceAdapter(
    id="nvd-recent",
    description=(
        f"NIST NVD CVE API 2.0 — CVEs modified in the last {RECENT_DAYS} days, "
        "all pages walked and verified against totalResults, "
        "merged cumulatively into the local cache (newest-modified kept first)"
    ),
    fetch=fetch_nvd_recent,
    merge=merge_nvd,
))
