"""KNVD(KISA 보안취약점 정보포털) 공식 RSS — 국내 보안공지의 **보조 근거**.

역할을 분명히 한다. KNVD 공지는 독립적인 패키지 탐지기가 아니다. OSV 가 PyPI/npm
패키지의 취약점과 영향 버전을 확인하고 그 항목에 정확한 CVE alias 가 있을 때,
같은 CVE ID 를 가진 KNVD 공지를 **한국어 보조 링크**로 붙이는 것이 전부다.
매칭 방법은 ``exact_cve`` 하나뿐이다 — 제품명·패키지명 유사도, 제목 부분 문자열,
제조사 추측, CPE 변환, CVE 없는 공지의 패키지 변환은 하지 않는다. 그리고 KNVD
캐시가 있든 없든 verdict·severity·requires_review·게이트 판정은 바뀌지 않는다.

공식 주소(둘 다 RSS 2.0, UTF-8):

- ``knvd-security-notice`` — https://knvd.krcert.or.kr/rss/security/notice (보안공지)
- ``knvd-public-vuln``     — https://knvd.krcert.or.kr/rss/security/info   (공개 취약점)

한계(실측 2026-09-13): 각 피드는 **최신 10건만** 준다. 매일 받아 누적할 수는
있지만 "KNVD 전체 DB" 나 "완전한 과거 데이터" 가 아니다 — 누적 시작일 이전의
공지는 캐시에 없다. 이 사실을 문서와 결과에 그대로 적는다.

금지(공식 RSS 가 있으므로): SPA 화면 HTML 스크래핑, JS 번들 분석, 비공개 내부
API, 로그인·CAPTCHA·WAF 우회, 화면 구조 의존 셀렉터.

보안 조건: 응답 크기 상한, DTD/외부 엔티티 XML 거부, 최종 URL 이 HTTPS +
``knvd.krcert.or.kr`` 인지 검증, 제목·설명은 일반 텍스트로만 저장(코드·HTML·셸로
실행하지 않고, 보고서는 이스케이프해 렌더링), 링크 기준 중복 제거, 캐시 상한.
"""
from __future__ import annotations

import html
import re
import xml.etree.ElementTree as ET
from datetime import timezone
from email.utils import parsedate_to_datetime
from functools import partial
from typing import Any
from urllib.parse import urlsplit

from .base import HttpFetcher, SourceAdapter, register_source

KNVD_HOST = "knvd.krcert.or.kr"
FEEDS: dict[str, str] = {
    "knvd-security-notice": "https://knvd.krcert.or.kr/rss/security/notice",
    "knvd-public-vuln": "https://knvd.krcert.or.kr/rss/security/info",
}
#: 피드가 현재 주는 항목 수(실측). 문서·doctor 가 "전체 DB 가 아님"을 말할 때 쓴다.
FEED_ITEMS_PER_FETCH = 10

#: 응답 크기 상한. 실측 10건 피드가 144KB 이므로 5MB 는 30배 여유다.
MAX_RESPONSE_BYTES = 5 * 1024 * 1024
#: 누적 캐시 상한(항목 수, 최신 게시물부터 보존). 하루 10건씩이라 5,000 은 1년 이상이다.
DEFAULT_CACHE_MAX = 5_000
MAX_TITLE_CHARS = 300
MAX_SUMMARY_CHARS = 500
MAX_IDS_PER_ITEM = 50

_CVE_RE = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.IGNORECASE)
_CWE_RE = re.compile(r"\bCWE-(\d{1,5})\b", re.IGNORECASE)
_TAG_RE = re.compile(r"<[^>]{0,500}>")
_MD_LINK_RE = re.compile(r"\[([^\]]{0,300})\]\((?:https?://)[^)]{0,2000}\)")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_DTD_RE = re.compile(rb"<!\s*(DOCTYPE|ENTITY)", re.IGNORECASE)


class KnvdFetchError(RuntimeError):
    """피드를 받지 못했거나 신뢰할 수 없는 응답 — 호출자는 이전 캐시를 유지한다."""


def _plain_text(value: str | None, limit: int) -> str:
    """제목·설명을 **일반 텍스트**로 다듬는다. 실행·렌더링 대상이 아니다."""
    text = html.unescape(str(value or ""))
    text = _MD_LINK_RE.sub(r"\1", text)      # [키워드](https://…) → 키워드
    text = _TAG_RE.sub(" ", text)             # 혹시 섞인 HTML 태그 제거
    text = _CONTROL_RE.sub(" ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]


def _ids(text: str, pattern: re.Pattern[str], prefix: str) -> list[str]:
    seen: list[str] = []
    for m in pattern.finditer(text):
        ident = f"{prefix}-" + "-".join(g for g in m.groups() if g is not None)
        ident = ident.upper()
        if ident not in seen:
            seen.append(ident)
            if len(seen) >= MAX_IDS_PER_ITEM:
                break
    return seen


def _published_iso(raw: str | None) -> str | None:
    if not raw:
        return None
    try:
        dt = parsedate_to_datetime(raw.strip())
    except (TypeError, ValueError, IndexError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def is_official_knvd_url(url: str | None) -> bool:
    """HTTPS 이고 호스트가 정확히 knvd.krcert.or.kr 인가(서브도메인·다른 호스트 불가)."""
    try:
        parts = urlsplit(str(url or ""))
    except ValueError:
        return False
    return parts.scheme == "https" and (parts.hostname or "").lower() == KNVD_HOST


def _reject_dtd(raw: bytes) -> None:
    if _DTD_RE.search(raw):
        raise KnvdFetchError("DTD/외부 엔티티가 포함된 XML 은 받지 않습니다(엔티티 확장·외부 참조 차단)")


def parse_knvd_rss(raw: bytes, *, feed_url: str) -> list[dict]:
    """RSS 2.0 바이트 → 정규화 항목 목록(최신 게시물 우선, 링크 기준 중복 제거).

    저장 정보: 제목·공식 링크·게시 시각·정확히 추출한 CVE ID·명시된 CWE ID·
    길이 제한 일반 텍스트 요약·원본 피드 URL. 링크가 공식 호스트가 아닌 항목은
    담지 않는다(신뢰할 수 없는 주소를 보고서에 실을 수 없다).
    """
    if len(raw) > MAX_RESPONSE_BYTES:
        raise KnvdFetchError(f"응답 크기 {len(raw):,}B 가 상한({MAX_RESPONSE_BYTES:,}B)을 넘습니다")
    _reject_dtd(raw)
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise KnvdFetchError(f"RSS XML 해석 실패: {exc}") from None
    if root.tag.lower() != "rss":
        raise KnvdFetchError(f"RSS 문서가 아닙니다(루트 {root.tag!r})")

    items: list[dict] = []
    seen_links: set[str] = set()
    for node in root.iter("item"):
        link = (node.findtext("link") or "").strip()
        if not is_official_knvd_url(link) or link in seen_links:
            continue
        title = _plain_text(node.findtext("title"), MAX_TITLE_CHARS)
        description_raw = node.findtext("description") or ""
        summary = _plain_text(description_raw, MAX_SUMMARY_CHARS)
        # CVE/CWE 는 제목과 설명 **원문 전체**에서 뽑는다(요약은 잘렸을 수 있다).
        haystack = f"{node.findtext('title') or ''}\n{description_raw}"
        seen_links.add(link)
        items.append({
            "title": title,
            "link": link,
            "guid": (node.findtext("guid") or "").strip()[:300] or None,
            "published_at": _published_iso(node.findtext("pubDate")),
            "cve_ids": _ids(haystack, _CVE_RE, "CVE"),
            "cwe_ids": _ids(haystack, _CWE_RE, "CWE"),
            "summary": summary,
            "feed_url": feed_url,
        })
    items.sort(key=lambda i: str(i.get("published_at") or ""), reverse=True)
    return items


def _response_bytes(resp: Any) -> bytes:
    content = getattr(resp, "content", None)
    if content is None and hasattr(resp, "read"):
        content = resp.read()
    return bytes(content or b"")


def fetch_knvd_feed(client: HttpFetcher, source_id: str) -> tuple[str, list[dict]]:
    """공식 RSS 1개를 받는다. 최종 URL·크기·형식이 어긋나면 예외(이전 캐시 유지)."""
    feed_url = FEEDS[source_id]
    resp = client.get(feed_url)
    status = int(getattr(resp, "status_code", 200) or 200)
    if status != 200:
        # 3xx 도 실패다 — 다른 호스트로 보내는 리다이렉트를 따라가지 않는다.
        raise KnvdFetchError(f"KNVD RSS HTTP {status}: {feed_url}")
    final_url = getattr(resp, "url", None)
    if final_url is not None and not is_official_knvd_url(str(final_url)):
        raise KnvdFetchError(f"최종 URL 이 공식 KNVD(HTTPS)가 아닙니다: {final_url}")
    raw = _response_bytes(resp)
    return feed_url, parse_knvd_rss(raw, feed_url=feed_url)


def merge_knvd(prev_items: list[dict], new_items: list[dict]) -> list[dict]:
    """링크 기준 누적 병합 — 새 수집분이 같은 링크를 갱신하고, 최신 게시물부터 보존."""
    by_link: dict[str, dict] = {}
    for i in prev_items:
        if i.get("link"):
            by_link[str(i["link"])] = i
    for i in new_items:
        if i.get("link"):
            by_link[str(i["link"])] = i
    merged = sorted(by_link.values(), key=lambda i: str(i.get("published_at") or ""), reverse=True)
    return merged[:DEFAULT_CACHE_MAX]


for _sid, _url in FEEDS.items():
    register_source(SourceAdapter(
        id=_sid,
        description=(
            f"KISA KNVD official RSS ({_url}) — latest {FEED_ITEMS_PER_FETCH} notices per fetch, "
            "accumulated by link; Korean advisory links attached to OSV findings by exact CVE only "
            "(never changes verdicts)"
        ),
        fetch=partial(fetch_knvd_feed, source_id=_sid),
        merge=merge_knvd,
    ))
