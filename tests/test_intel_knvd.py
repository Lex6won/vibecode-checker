"""KNVD 공식 RSS — 안전하게 받고, 정확한 CVE 에만 붙이고, 판정은 흔들지 않는다.

fixture ``tests/fixtures/knvd_public_vuln_2026-09-13.xml`` 은 2026-09-13 에 받은
공개 취약점 RSS 원본(10건)이다. 형식이 바뀌면 이 파일을 다시 받아 갱신한다.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from gvskb.intel import IntelCache, update_source
from gvskb.intel.lookup import cve_ids_of, knvd_by_cve, knvd_notices_for
from gvskb.intel.sources import knvd
from gvskb.intel.sources.base import SOURCES
from gvskb.tools.check_package import check_package_impl

FIXTURE = Path(__file__).parent / "fixtures" / "knvd_public_vuln_2026-09-13.xml"
NOTICE_URL = knvd.FEEDS["knvd-security-notice"]
INFO_URL = knvd.FEEDS["knvd-public-vuln"]


def _rss(items: str) -> bytes:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n<rss version="2.0"><channel>'
        "<title>보안취약점 정보포털</title><link>https://knvd.krcert.or.kr</link>"
        f"{items}</channel></rss>"
    ).encode("utf-8")


def _item(title: str, link: str, desc: str = "", pub: str = "Fri, 27 Feb 2026 01:22:01 GMT") -> str:
    return (f"<item><title>{title}</title><link>{link}</link><description>{desc}</description>"
            f"<pubDate>{pub}</pubDate></item>")


GITEA = _item(
    "CVE-2026-11111, CVE-2026-22222 | Gitea 원격 코드 실행 및 인증 우회",
    "https://knvd.krcert.or.kr/info/vuln/public/detail?id=aaaa0001",
    "#### 개요\n| CVE | CWE |\n| CVE-2026-11111 | CWE-78 |\n| CVE-2026-22222 | CWE-287 |\n"
    "키워드 [CVE-2026-11111](https://knvd.krcert.or.kr/keywordResult?searchOption=KEYWORD&amp;content=CVE-2026-11111)",
    pub="Mon, 07 Sep 2026 01:00:00 GMT",
)
IPTIME = _item(
    "CVE-2026-24498 | EFM-Networks ipTIME 유무선공유기 제품군 보안 기능 우회",
    "https://knvd.krcert.or.kr/info/vuln/public/detail?id=69a0f1b935077431ee7dd391",
    "| CVE-2026-24498 | 6.0 | Medium | CWE-200 | CAPEC-115 |",
)
NO_CVE = _item("보안 업데이트 권고(정기)", "https://knvd.krcert.or.kr/rss/security/notice-detail?id=bbbb0002",
               "이번 달 정기 보안 업데이트를 적용하세요.")
BAD_CVE = _item("CVE-2026-1 및 CVE-26-12345 표기 오류", "https://knvd.krcert.or.kr/info/vuln/public/detail?id=cccc0003",
                "형식이 틀린 CVE-2026-1 과 CVE-26-12345, 그리고 CVE-2026-123456789 도 있다.")
DUP = _item("중복 링크 공지", "https://knvd.krcert.or.kr/info/vuln/public/detail?id=aaaa0001", "다른 제목, 같은 링크")
OTHER_HOST = _item("CVE-2026-33333 | 다른 호스트", "https://evil.example.org/knvd/detail?id=dddd0004", "CVE-2026-33333")
HTTP_LINK = _item("CVE-2026-44444 | 평문 링크", "http://knvd.krcert.or.kr/info/vuln/public/detail?id=eeee0005",
                  "CVE-2026-44444")
SUBDOMAIN = _item("CVE-2026-55555 | 서브도메인", "https://cdn.knvd.krcert.or.kr/x?id=ffff0006", "CVE-2026-55555")


class Resp:
    def __init__(self, content: bytes = b"", status_code: int = 200, url: str | None = None) -> None:
        self.content = content
        self.status_code = status_code
        self.url = url


class Client:
    def __init__(self, resp: Resp) -> None:
        self._resp = resp
        self.calls: list[str] = []

    def get(self, url, **_kw):
        self.calls.append(url)
        return self._resp


# ---------------------------------------------------------------------------
# 파싱 — 실제 형식 fixture
# ---------------------------------------------------------------------------

def test_real_feed_fixture_parses_ten_items_with_exact_cves() -> None:
    items = knvd.parse_knvd_rss(FIXTURE.read_bytes(), feed_url=INFO_URL)
    assert len(items) == 10, "피드는 현재 최신 10건만 준다(실측) — 바뀌면 문서도 고친다"
    assert all(knvd.is_official_knvd_url(i["link"]) for i in items)
    assert all(i["feed_url"] == INFO_URL for i in items)
    first = next(i for i in items if "24498" in i["title"])
    assert first["cve_ids"] == ["CVE-2026-24498"]
    assert "CWE-200" in first["cwe_ids"]
    assert first["published_at"] == "2026-02-27T01:22:01+00:00"
    assert "ipTIME" in first["title"] and "유무선공유기" in first["title"], "한글 UTF-8 보존"
    assert len(first["summary"]) <= knvd.MAX_SUMMARY_CHARS
    assert "](https://" not in first["summary"] and "<" not in first["summary"], "일반 텍스트만"
    # 최신 게시물 우선
    dates = [i["published_at"] for i in items]
    assert dates == sorted(dates, reverse=True)


def test_parse_extracts_multiple_cves_and_ignores_malformed_forms() -> None:
    items = knvd.parse_knvd_rss(_rss(GITEA + NO_CVE + BAD_CVE), feed_url=NOTICE_URL)
    by_title = {i["title"]: i for i in items}
    gitea = by_title["CVE-2026-11111, CVE-2026-22222 | Gitea 원격 코드 실행 및 인증 우회"]
    assert gitea["cve_ids"] == ["CVE-2026-11111", "CVE-2026-22222"]
    assert gitea["cwe_ids"] == ["CWE-78", "CWE-287"]
    assert by_title["보안 업데이트 권고(정기)"]["cve_ids"] == []
    assert by_title["CVE-2026-1 및 CVE-26-12345 표기 오류"]["cve_ids"] == [], "형식이 틀린 CVE 는 뽑지 않는다"


def test_parse_dedupes_by_link_and_drops_unofficial_links() -> None:
    items = knvd.parse_knvd_rss(_rss(GITEA + DUP + OTHER_HOST + HTTP_LINK + SUBDOMAIN), feed_url=NOTICE_URL)
    assert [i["link"] for i in items] == ["https://knvd.krcert.or.kr/info/vuln/public/detail?id=aaaa0001"]
    assert items[0]["title"].startswith("CVE-2026-11111"), "같은 링크는 첫 항목이 남는다"


def test_parse_rejects_malformed_xml() -> None:
    with pytest.raises(knvd.KnvdFetchError, match="XML"):
        knvd.parse_knvd_rss(b"<rss><channel><item><title>x</title></channel>", feed_url=NOTICE_URL)


def test_parse_rejects_non_rss_document() -> None:
    with pytest.raises(knvd.KnvdFetchError, match="RSS"):
        knvd.parse_knvd_rss(b"<html><body>login</body></html>", feed_url=NOTICE_URL)


@pytest.mark.parametrize("payload", [
    b'<?xml version="1.0"?><!DOCTYPE rss [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]><rss><channel>'
    b"<item><title>&b;</title><link>https://knvd.krcert.or.kr/x</link></item></channel></rss>",
    b'<?xml version="1.0"?><!DOCTYPE rss SYSTEM "http://evil.example.org/x.dtd"><rss><channel></channel></rss>',
    b'<?xml version="1.0"?><rss><channel><!ENTITY xxe SYSTEM "file:///etc/passwd"></channel></rss>',
])
def test_parse_rejects_dtd_and_entities(payload: bytes) -> None:
    with pytest.raises(knvd.KnvdFetchError, match="DTD"):
        knvd.parse_knvd_rss(payload, feed_url=NOTICE_URL)


def test_parse_rejects_oversized_response(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(knvd, "MAX_RESPONSE_BYTES", 200)
    with pytest.raises(knvd.KnvdFetchError, match="상한"):
        knvd.parse_knvd_rss(_rss(GITEA + IPTIME), feed_url=NOTICE_URL)


def test_title_and_summary_are_plain_text_not_html() -> None:
    # RSS 안의 HTML 은 XML 이스케이프(&lt;…&gt;)로 온다 — 파싱 후 태그가 살아난다.
    evil = _item("&lt;script&gt;alert(1)&lt;/script&gt; CVE-2026-77777 &lt;b&gt;굵게&lt;/b&gt;",
                 "https://knvd.krcert.or.kr/info/vuln/public/detail?id=gggg0007",
                 "&lt;img src=x onerror=alert(1)&gt; 설명 &amp; 요약")
    item = knvd.parse_knvd_rss(_rss(evil), feed_url=NOTICE_URL)[0]
    assert "<" not in item["title"] and ">" not in item["title"]
    assert "굵게" in item["title"]
    assert item["cve_ids"] == ["CVE-2026-77777"]
    assert item["summary"] == "설명 & 요약"


# ---------------------------------------------------------------------------
# fetch — 최종 URL·상태 검증, 실패 시 이전 캐시 유지
# ---------------------------------------------------------------------------

def test_fetch_uses_official_url_and_returns_items() -> None:
    client = Client(Resp(_rss(GITEA), url=NOTICE_URL))
    url, items = knvd.fetch_knvd_feed(client, "knvd-security-notice")
    assert client.calls == [NOTICE_URL]
    assert url == NOTICE_URL
    assert len(items) == 1


@pytest.mark.parametrize("final_url", [
    "http://knvd.krcert.or.kr/rss/security/notice",
    "https://evil.example.org/rss/security/notice",
    "https://knvd.krcert.or.kr.evil.example.org/rss",
])
def test_fetch_rejects_non_official_final_url(final_url: str) -> None:
    client = Client(Resp(_rss(GITEA), url=final_url))
    with pytest.raises(knvd.KnvdFetchError, match="공식 KNVD"):
        knvd.fetch_knvd_feed(client, "knvd-security-notice")


def test_fetch_treats_redirect_as_failure() -> None:
    client = Client(Resp(b"", status_code=302, url=NOTICE_URL))
    with pytest.raises(knvd.KnvdFetchError, match="HTTP 302"):
        knvd.fetch_knvd_feed(client, "knvd-security-notice")


def test_both_feeds_are_registered_as_separate_sources() -> None:
    assert {"knvd-security-notice", "knvd-public-vuln"} <= set(SOURCES)
    assert SOURCES["knvd-security-notice"].merge is knvd.merge_knvd


def test_update_source_failure_keeps_previous_cache(tmp_path: Path) -> None:
    cache = IntelCache(tmp_path)
    prev = knvd.parse_knvd_rss(_rss(GITEA), feed_url=NOTICE_URL)
    cache.save("knvd-security-notice", NOTICE_URL, prev)
    result = update_source("knvd-security-notice", cache=cache, client=Client(Resp(b"<broken", url=NOTICE_URL)))
    assert result.status == "warn"
    assert [i["link"] for i in cache.load("knvd-security-notice").items] == [prev[0]["link"]]


def test_update_source_accumulates_across_runs(tmp_path: Path) -> None:
    cache = IntelCache(tmp_path)
    assert update_source("knvd-public-vuln", cache=cache, client=Client(Resp(_rss(IPTIME), url=INFO_URL))).ok
    assert update_source("knvd-public-vuln", cache=cache, client=Client(Resp(_rss(GITEA), url=INFO_URL))).ok
    links = {i["link"] for i in cache.load("knvd-public-vuln").items}
    assert len(links) == 2, "어제 받은 공지가 오늘 피드에 없어도 사라지면 안 된다"


def test_merge_caps_keeping_newest(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(knvd, "DEFAULT_CACHE_MAX", 3)
    prev = [{"link": f"https://knvd.krcert.or.kr/i?id={k}", "published_at": f"2026-01-{k:02d}T00:00:00+00:00"}
            for k in range(1, 6)]
    merged = knvd.merge_knvd(prev, [])
    assert [i["published_at"][:10] for i in merged] == ["2026-01-05", "2026-01-04", "2026-01-03"]


# ---------------------------------------------------------------------------
# 조회 인덱스 — 캐시당 한 번, CVE 조회는 dict
# ---------------------------------------------------------------------------

def test_knvd_index_is_built_once_per_cache_entry(tmp_path: Path) -> None:
    cache = IntelCache(tmp_path)
    cache.save("knvd-public-vuln", INFO_URL, knvd.parse_knvd_rss(_rss(GITEA + IPTIME), feed_url=INFO_URL))
    entry = cache.load("knvd-public-vuln")
    first = knvd_by_cve(entry)
    assert knvd_by_cve(cache.load("knvd-public-vuln")) is first, "같은 캐시면 같은 인덱스 객체"
    assert set(first) == {"CVE-2026-11111", "CVE-2026-22222", "CVE-2026-24498"}
    cache.save("knvd-public-vuln", INFO_URL, knvd.parse_knvd_rss(_rss(IPTIME), feed_url=INFO_URL))
    assert knvd_by_cve(cache.load("knvd-public-vuln")) is not first, "캐시가 바뀌면 다시 만든다"


def test_cve_ids_of_takes_only_exact_cve_forms() -> None:
    assert cve_ids_of({"id": "GHSA-x", "aliases": ["CVE-2026-11111", "PYSEC-2026-1", "cve-2026-22222"]}) == \
        ["CVE-2026-11111", "CVE-2026-22222"]
    assert cve_ids_of({"id": "CVE-2026-1", "aliases": []}) == ["CVE-2026-1"]  # 형태 검증은 피드 쪽에서


def test_notices_for_matches_exact_cve_only(tmp_path: Path) -> None:
    cache = IntelCache(tmp_path)
    cache.save("knvd-public-vuln", INFO_URL, knvd.parse_knvd_rss(_rss(GITEA + IPTIME), feed_url=INFO_URL))
    notices, used = knvd_notices_for(["CVE-2026-11111"], cache)
    assert used == ["knvd-public-vuln"]
    assert len(notices) == 1
    n = notices[0]
    assert n["source"] == "KNVD" and n["match_method"] == "exact_cve" and n["cve_id"] == "CVE-2026-11111"
    assert n["source_url"] == "https://knvd.krcert.or.kr/info/vuln/public/detail?id=aaaa0001"
    assert n["published_at"] == "2026-09-07T01:00:00+00:00" and n["fetched_at"]
    # 제목 부분 문자열·제품명으로는 절대 붙지 않는다
    assert knvd_notices_for(["CVE-2026-99999"], cache) == ([], [])
    assert knvd_notices_for([], cache) == ([], [])


# ---------------------------------------------------------------------------
# check-package 통합 — 링크만 붙고 판정은 완전히 같다
# ---------------------------------------------------------------------------

def _write_cache(cache_dir: Path, source_id: str, items: list[dict], *, ecosystems: list[str] | None = None) -> None:
    cache_dir.mkdir(parents=True, exist_ok=True)
    blob = json.dumps(items, sort_keys=True, ensure_ascii=False).encode("utf-8")
    envelope = {
        "schema_version": 2, "source_id": source_id,
        "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "url": "https://example/test", "sha256": hashlib.sha256(blob).hexdigest(),
        "item_count": len(items), "items": items,
    }
    if ecosystems is not None:
        envelope["ecosystems"] = ecosystems
    (cache_dir / f"{source_id}.json").write_text(json.dumps(envelope, ensure_ascii=False), encoding="utf-8")


def _flask_vuln(aliases: list[str]) -> dict:
    return {
        "id": "GHSA-flask-0001", "summary": "flask session fixation", "modified": "2026-09-01",
        "aliases": aliases, "severity": [],
        "database_specific": {"severity": "HIGH"},
        "affected": [{"package": {"name": "flask", "ecosystem": "PyPI"},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.2.5"}]}]}],
    }


@pytest.fixture
def offline_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    monkeypatch.setenv("GVSKB_MODE", "offline")
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path))
    _write_cache(tmp_path, "osv-malicious", [], ecosystems=["PyPI"])
    _write_cache(tmp_path, "osv-vulns", [_flask_vuln(["CVE-2026-11111"])], ecosystems=["PyPI"])
    return tmp_path


INVARIANT_FIELDS = ("verdict", "verdict_severity", "requires_review", "max_cve", "in_kev",
                    "vulnerability_count", "recommended_version", "is_malicious_package", "checked")


def _check() -> dict:
    return asyncio.run(check_package_impl(name="flask", ecosystem="pypi", version="2.0.0"))


def _gate_status_for(check: dict) -> dict:
    from gvskb.gate import gate_status
    from gvskb.scanner import scan_code

    report = scan_code("total = 1\n", filename="a.py")
    report.dependency_audit = {"audits": [{
        "blocked": False, "parsed_count": 1, "checked_count": 1, "unchecked_count": 0,
        "truncated_count": 0, "checks": [check],
    }]}
    return gate_status(report)


def test_knvd_cache_adds_link_but_never_changes_verdict_or_gate(offline_env: Path) -> None:
    before = _check()
    assert before["verdict"] == "vulnerable"
    assert before["advisories"][0]["knvd_notices"] == [], "캐시가 없으면 빈 목록(키는 항상 있다)"
    gate_before = _gate_status_for(before)

    _write_cache(offline_env, "knvd-public-vuln",
                 knvd.parse_knvd_rss(_rss(GITEA + IPTIME), feed_url=INFO_URL))
    after = _check()

    notices = after["advisories"][0]["knvd_notices"]
    assert len(notices) == 1 and notices[0]["cve_id"] == "CVE-2026-11111"
    assert notices[0]["match_method"] == "exact_cve"
    assert "knvd-public-vuln" in after["cache_sources_used"]
    for field in INVARIANT_FIELDS:
        assert before[field] == after[field], f"{field} 가 KNVD 캐시 유무로 바뀌면 안 된다"
    assert _gate_status_for(after) == gate_before, "게이트 판정·사유가 완전히 같아야 한다"


def test_unrelated_knvd_notices_do_not_attach_or_affect_result(offline_env: Path) -> None:
    """Gitea·공유기 공지는 OSV 의 flask CVE 와 CVE 가 다르면 어디에도 붙지 않는다."""
    before = _check()
    gitea_other = _item("CVE-2026-98765 | Gitea 인증 우회",
                        "https://knvd.krcert.or.kr/info/vuln/public/detail?id=hhhh0008", "CVE-2026-98765")
    _write_cache(offline_env, "knvd-security-notice",
                 knvd.parse_knvd_rss(_rss(gitea_other + IPTIME), feed_url=NOTICE_URL))
    after = _check()
    assert after["advisories"][0]["knvd_notices"] == []
    assert "knvd-security-notice" not in after["cache_sources_used"]
    for field in INVARIANT_FIELDS:
        assert before[field] == after[field]
    assert _gate_status_for(after) == _gate_status_for(before)


def test_osv_entry_without_cve_alias_never_gets_knvd_notice(offline_env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """CVE alias 가 없는 OSV 항목은 제목이 패키지명을 담고 있어도 붙지 않는다."""
    _write_cache(offline_env, "osv-vulns", [_flask_vuln([])], ecosystems=["PyPI"])
    flask_named = _item("flask 세션 고정 취약점 보안 공지",
                        "https://knvd.krcert.or.kr/info/vuln/public/detail?id=iiii0009", "Flask 2.0 이하 영향")
    _write_cache(offline_env, "knvd-public-vuln", knvd.parse_knvd_rss(_rss(flask_named), feed_url=INFO_URL))
    r = _check()
    assert r["verdict"] == "vulnerable"
    assert r["advisories"][0]["knvd_notices"] == []


def test_scan_and_offline_check_never_touch_network(offline_env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """검사 중 네트워크 호출을 강제로 예외로 만들어도 scan·check-package 는 로컬 캐시로 동작한다."""
    import httpx

    class Boom:
        def __init__(self, *a, **k):
            raise AssertionError("검사 중 네트워크 클라이언트를 만들면 안 된다")

    monkeypatch.setattr(httpx, "Client", Boom)
    monkeypatch.setattr(httpx, "AsyncClient", Boom)
    _write_cache(offline_env, "knvd-public-vuln", knvd.parse_knvd_rss(_rss(GITEA), feed_url=INFO_URL))
    _write_cache(offline_env, "nvd-recent", [{"id": "CVE-2026-11111", "cvss31_base_score": 7.5,
                                             "cvss31_severity": "HIGH", "vulnStatus": "Analyzed"}])

    from gvskb.scanner import scan_code
    report = scan_code("import os\nos.system(user_input)\n", filename="a.py")
    assert report.findings, "스캔이 정상 수행돼야 한다"

    r = _check()
    assert r["verdict"] == "vulnerable"
    assert r["advisories"][0]["knvd_notices"][0]["cve_id"] == "CVE-2026-11111"


def test_rejected_nvd_cve_is_not_used_as_cvss_evidence(offline_env: Path) -> None:
    from gvskb.tools.check_package import _enrich_with_epss_nvd

    _write_cache(offline_env, "nvd-recent", [
        {"id": "CVE-2026-11111", "cvss31_base_score": 9.8, "cvss31_severity": "CRITICAL", "vulnStatus": "Rejected"},
        {"id": "CVE-2026-22222", "cvss31_base_score": 7.5, "cvss31_severity": "HIGH", "vulnStatus": "Analyzed"},
    ])
    sigs = [{"cveID": "CVE-2026-11111"}, {"cveID": "CVE-2026-22222"}]
    used = _enrich_with_epss_nvd(sigs, IntelCache())
    assert used == ["nvd-recent"]
    assert "cvss31_base_score" not in sigs[0], "Rejected CVE 의 점수는 병기하지 않는다"
    assert sigs[1]["cvss31_base_score"] == 7.5


# ---------------------------------------------------------------------------
# 보고서 — 링크는 붙되 원문은 이스케이프된 텍스트로만
# ---------------------------------------------------------------------------

def test_report_advisory_lines_show_knvd_notice_with_link() -> None:
    from gvskb.report import _advisory_lines

    check = {"advisories": [{
        "id": "GHSA-flask-0001", "severity": "HIGH", "fixed_versions": ["2.2.5"], "summary": "s",
        "knvd_notices": [{
            "source": "KNVD", "cve_id": "CVE-2026-11111", "published_at": "2026-09-07T01:00:00+00:00",
            "title": "Gitea <script>alert(1)</script> 공지", "source_url": "https://knvd.krcert.or.kr/x?id=1",
            "match_method": "exact_cve",
        }, {
            "source": "KNVD", "cve_id": "CVE-2026-11111", "title": "평문 링크", "source_url": "http://knvd.krcert.or.kr/y",
        }],
    }], "vulnerability_count": 1, "recommended_version": "2.2.5"}
    lines = _advisory_lines(check)
    knvd_lines = [(ln, url) for ln, url in lines if "KISA 보안공지" in ln]
    assert len(knvd_lines) == 2
    assert knvd_lines[0][1] == "https://knvd.krcert.or.kr/x?id=1"
    assert "CVE-2026-11111" in knvd_lines[0][0] and "2026-09-07" in knvd_lines[0][0]
    assert knvd_lines[1][1] is None, "HTTPS 가 아닌 주소는 링크로 만들지 않는다"
