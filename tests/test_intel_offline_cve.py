"""오프라인 CVE 대조(osv-vulns) + 누적 캐시(NVD·EPSS) + 로드 메모 — 2026-08-31 신설.

배경(실측 사고): 오프라인 캐시에는 악성 피드(MAL-)와 KEV 만 있어 망분리 환경이
구조적으로 CVE 를 볼 수 없었다 — 취약점 26건짜리 pillow 12.2.0 이 '판정 불가'
로만 남았다. osv-vulns 캐시(버전 범위 보존)가 그 공백을 닫는다. NVD·EPSS 는
"최근 N일" 창으로 **덮어써서** 창 밖 데이터가 매일 사라졌다 — 병합 누적으로 바꾼다.
"""
from __future__ import annotations

import asyncio
import hashlib
import io
import json
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from gvskb.intel import IntelCache, update_source
from gvskb.intel.sources import epss, nvd, osv
from gvskb.intel.sources.base import SOURCES
from gvskb.tools.check_package import (
    _offline_vuln_hits,
    _version_in_affected,
    check_package_impl,
)


def _write_cache(
    cache_dir: Path,
    source_id: str,
    items: list[dict],
    *,
    fetched_at: str | None = None,
    ecosystems: list[str] | None = None,
) -> None:
    """IntelCache.save() 와 동일한 envelope(올바른 sha256 포함)을 만든다."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    blob = json.dumps(items, sort_keys=True, ensure_ascii=False).encode("utf-8")
    envelope = {
        "schema_version": 2,
        "source_id": source_id,
        "fetched_at": fetched_at
        or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "url": "https://example/test",
        "sha256": hashlib.sha256(blob).hexdigest(),
        "item_count": len(items),
        "items": items,
    }
    if ecosystems is not None:
        envelope["ecosystems"] = ecosystems
    (cache_dir / f"{source_id}.json").write_text(
        json.dumps(envelope, ensure_ascii=False), encoding="utf-8"
    )


def _days_ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")


def _vuln(
    vid: str = "GHSA-test-0001",
    name: str = "flask",
    eco: str = "PyPI",
    introduced: str = "0",
    fixed: str | None = "2.2.5",
    last_affected: str | None = None,
    versions: list[str] | None = None,
    severity_label: str | None = None,
    aliases: list[str] | None = None,
) -> dict:
    events: list[dict] = [{"introduced": introduced}]
    if fixed is not None:
        events.append({"fixed": fixed})
    if last_affected is not None:
        events.append({"last_affected": last_affected})
    aff: dict = {"package": {"name": name, "ecosystem": eco}}
    if fixed is not None or last_affected is not None or introduced != "0":
        aff["ranges"] = [{"type": "ECOSYSTEM", "events": events}]
    if versions is not None:
        aff["versions"] = versions
        if "ranges" in aff and fixed is None and last_affected is None:
            del aff["ranges"]
    out: dict = {
        "id": vid,
        "summary": "test advisory",
        "modified": "2026-08-01T00:00:00Z",
        "aliases": aliases or [],
        "affected": [aff],
    }
    if severity_label:
        out["database_specific"] = {"severity": severity_label}
    return out


@pytest.fixture
def offline_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    monkeypatch.setenv("GVSKB_MODE", "offline")
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path))
    return tmp_path


def _seed(cache_dir: Path, vulns: list[dict], *, ecosystems: list[str] | None = None,
          fetched_at: str | None = None) -> None:
    eco = ecosystems or ["PyPI"]
    _write_cache(cache_dir, "osv-malicious", [], ecosystems=eco)
    _write_cache(cache_dir, "osv-vulns", vulns, ecosystems=eco, fetched_at=fetched_at)


# ---------------------------------------------------------------------------
# 버전 매칭 단위 — 모름(None)은 False 가 아니다
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("version,expected", [
    ("2.0.0", True),      # [0, 2.2.5) 안
    ("2.2.4", True),
    ("2.2.5", False),     # fixed 경계 = 고쳐진 버전
    ("3.0.0", False),
])
def test_version_in_affected_introduced_fixed(version: str, expected: bool) -> None:
    aff = _vuln()["affected"][0]
    assert _version_in_affected(aff, version) is expected


def test_version_in_affected_last_affected_is_inclusive() -> None:
    aff = _vuln(fixed=None, last_affected="1.5.0")["affected"][0]
    assert _version_in_affected(aff, "1.5.0") is True   # 폐구간 끝 포함
    assert _version_in_affected(aff, "1.5.1") is False


def test_version_in_affected_open_range_means_all_later_versions() -> None:
    aff = {"package": {"name": "p", "ecosystem": "PyPI"},
           "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}]}]}
    assert _version_in_affected(aff, "99.0.0") is True
    assert _version_in_affected(aff, "0.9.0") is False


def test_version_in_affected_versions_enumeration() -> None:
    aff = {"package": {"name": "p", "ecosystem": "PyPI"},
           "versions": ["1.0.0", "1.0.1"]}
    assert _version_in_affected(aff, "1.0.1") is True
    assert _version_in_affected(aff, "1.0.2") is False


def test_version_in_affected_unparseable_version_is_unknown_not_false() -> None:
    aff = _vuln()["affected"][0]
    assert _version_in_affected(aff, "not-a-version") is None


def test_version_in_affected_git_ranges_are_not_decidable() -> None:
    aff = {"package": {"name": "p", "ecosystem": "PyPI"},
           "ranges": [{"type": "GIT", "events": [{"introduced": "abc123"}, {"fixed": "def456"}]}]}
    # GIT 해시는 비교 불가 — False(안전)가 아니라 None(모름)이어야 한다.
    assert _version_in_affected(aff, "1.0.0") is None


def test_offline_vuln_hits_ecosystem_must_match() -> None:
    items = [_vuln(name="foo", eco="PyPI")]
    matched, undet = _offline_vuln_hits(items, "foo", "npm", "1.0.0")
    assert matched == [] and undet == 0


def test_offline_vuln_hits_pypi_name_normalization() -> None:
    """PEP 503 — et_xmlfile 과 et-xmlfile 은 같은 패키지다."""
    items = [_vuln(name="et-xmlfile", introduced="0", fixed="2.0.0")]
    matched, _ = _offline_vuln_hits(items, "et_xmlfile", "PyPI", "1.0.0")
    assert len(matched) == 1


# ---------------------------------------------------------------------------
# 오프라인 판정 — vulnerable / checked_clean / unknown 사다리
# ---------------------------------------------------------------------------


def test_offline_vulnerable_version_detected_with_recommendation(offline_env: Path) -> None:
    _seed(offline_env, [_vuln()])
    r = asyncio.run(check_package_impl(name="flask", ecosystem="pypi", version="2.0.0"))
    assert r["offline"] is True
    assert r["checked"] is True
    assert r["verdict"] == "vulnerable"
    assert r["vulnerability_count"] == 1
    assert r["recommended_version"] == "2.2.5"
    assert "osv-vulns" in r["cache_sources_used"]
    assert r["requires_review"] is True
    # 오프라인 한계(실재·쿨다운 미확인)를 스스로 밝힌다.
    assert "확인하지 못했습니다" in (r["note"] or "")


def test_offline_fixed_version_is_checked_clean_but_still_reviewed(offline_env: Path) -> None:
    _seed(offline_env, [_vuln()])
    r = asyncio.run(check_package_impl(name="flask", ecosystem="pypi", version="2.2.5"))
    assert r["verdict"] == "checked_clean"
    assert r["checked"] is True
    assert r["max_cve"] == "NONE"
    # 실재(슬롭스쿼팅)·발행일은 여전히 미확인 — 검토 표시는 유지한다.
    assert r["requires_review"] is True


def test_offline_severity_high_when_advisory_high(offline_env: Path) -> None:
    _seed(offline_env, [_vuln(severity_label="HIGH")])
    r = asyncio.run(check_package_impl(name="flask", ecosystem="pypi", version="2.0.0"))
    assert r["verdict"] == "vulnerable"
    assert r["verdict_severity"] == "high"
    assert r["max_cve"] == "HIGH"


def test_offline_kev_cross_check_elevates_to_high(offline_env: Path) -> None:
    """CVE alias 가 KEV 에 있으면 심각도 표기가 없어도 high 로 올라간다."""
    _seed(offline_env, [_vuln(aliases=["CVE-2021-44228"])])
    _write_cache(offline_env, "cisa-kev", [
        {"cveID": "CVE-2021-44228", "vulnerabilityName": "Log4Shell", "dateAdded": "2021-12-10"},
    ])
    r = asyncio.run(check_package_impl(name="flask", ecosystem="pypi", version="2.0.0"))
    assert r["verdict"] == "vulnerable"
    assert r["in_kev"] is True
    assert r["verdict_severity"] == "high"
    assert "KEV" in (r["note"] or "")


def test_offline_no_version_reports_full_history_capped_medium(offline_env: Path) -> None:
    _seed(offline_env, [_vuln(severity_label="CRITICAL")])
    r = asyncio.run(check_package_impl(name="flask", ecosystem="pypi"))
    assert r["verdict"] == "vulnerable"
    assert r["verdict_severity"] == "medium", "버전 미지정은 전체 이력 — 과차단 방지 캡핑"
    assert "버전 미지정" in (r["note"] or "")


def test_offline_unparseable_version_with_advisory_is_unknown(offline_env: Path) -> None:
    """advisory 가 있는데 버전 적용 여부를 못 읽으면 '모름'이지 '이상 없음'이 아니다."""
    _seed(offline_env, [_vuln()])
    r = asyncio.run(check_package_impl(name="flask", ecosystem="pypi", version="weird!!"))
    assert r["verdict"] == "unknown"
    assert r["checked"] is False
    assert r["requires_review"] is True
    assert "해석하지 못했습니다" in (r["note"] or "")


def test_offline_npm_not_covered_cache_cannot_judge(offline_env: Path) -> None:
    """PyPI 만 담은 vulns 캐시로 npm 을 판정하면 안 된다 — 거짓 클린 봉쇄."""
    _seed(offline_env, [_vuln(name="left-pad", eco="npm")], ecosystems=["PyPI"])
    r = asyncio.run(check_package_impl(name="left-pad", ecosystem="npm", version="1.3.0"))
    assert r["verdict"] != "vulnerable"
    assert r["verdict"] != "checked_clean"
    assert r["requires_review"] is True


def test_offline_npm_covered_cache_detects_npm_vuln(offline_env: Path) -> None:
    _seed(offline_env, [_vuln(name="lodash", eco="npm", fixed="4.17.21")],
          ecosystems=["PyPI", "npm"])
    r = asyncio.run(check_package_impl(name="lodash", ecosystem="npm", version="4.17.20"))
    assert r["verdict"] == "vulnerable"
    assert r["recommended_version"] == "4.17.21"


def test_offline_stale_vulns_positive_still_valid(offline_env: Path) -> None:
    _seed(offline_env, [_vuln()], fetched_at=_days_ago(90))
    r = asyncio.run(check_package_impl(name="flask", ecosystem="pypi", version="2.0.0"))
    assert r["verdict"] == "vulnerable", "양성 판정은 낡은 캐시로도 유효하다"
    assert "osv-vulns" in r["cache_stale_sources"]
    assert "오래됐습니다" in (r["note"] or "")


def test_offline_stale_vulns_clean_is_checked_stale(offline_env: Path) -> None:
    _seed(offline_env, [_vuln()], fetched_at=_days_ago(90))
    r = asyncio.run(check_package_impl(name="requests", ecosystem="pypi", version="2.31.0"))
    assert r["verdict"] == "checked_stale"
    assert r["requires_review"] is True


def test_offline_malicious_still_wins_over_vulnerable(offline_env: Path) -> None:
    """악성 > 취약 — 사다리 최상단은 바뀌지 않는다."""
    _write_cache(offline_env, "osv-malicious", [
        {"id": "MAL-2026-1", "affected": [{"package": "flask", "ecosystem": "PyPI"}]},
    ], ecosystems=["PyPI"])
    _write_cache(offline_env, "osv-vulns", [_vuln()], ecosystems=["PyPI"])
    r = asyncio.run(check_package_impl(name="flask", ecosystem="pypi", version="2.0.0"))
    assert r["verdict"] == "malicious"


def test_audit_manifest_offline_detects_vulnerable_pin(offline_env: Path) -> None:
    """매니페스트 검사 통합 — 망분리에서 취약 버전 고정이 실제로 걸린다."""
    from gvskb.tools.check_package import audit_manifest

    _seed(offline_env, [_vuln()])
    r = asyncio.run(audit_manifest("flask==2.0.0\n", ecosystem="pypi"))
    assert r["checked_count"] == 1
    check = r["checks"][0]
    assert check["verdict"] == "vulnerable"
    assert r["requires_review"] is True
    assert r["verdict"] == "review_required"


# ---------------------------------------------------------------------------
# osv-vulns 어댑터 — 전량 보존 + zip 1회 다운로드 공유
# ---------------------------------------------------------------------------


class FakeResponse:
    def __init__(self, content: bytes = b"") -> None:
        self.content = content
        self.status_code = 200

    def raise_for_status(self) -> None:
        pass


class FakeClient:
    def __init__(self, content_by_url: dict[str, bytes]) -> None:
        self._by_url = content_by_url
        self.get_calls: list[str] = []

    def get(self, url: str, **_kw) -> FakeResponse:
        self.get_calls.append(url)
        return FakeResponse(self._by_url.get(url, b""))


def _make_osv_zip(entries: list[dict]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for entry in entries:
            zf.writestr(f"{entry['id']}.json", json.dumps(entry))
    return buf.getvalue()


def test_osv_vulns_adapter_keeps_ranges_and_versions(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GVSKB_OSV_INCLUDE_NPM", raising=False)
    raw = {
        "id": "GHSA-xxxx-yyyy",
        "summary": "sql injection",
        "modified": "2026-01-01T00:00:00Z",
        "aliases": ["CVE-2026-0001"],
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L"}],
        "database_specific": {"severity": "HIGH"},
        "affected": [{
            "package": {"name": "flask", "ecosystem": "PyPI"},
            "ranges": [{"type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "2.2.5"}]}],
            "versions": ["2.0.0", "2.1.0"],
        }],
        "references": [{"type": "ADVISORY", "url": "https://example/adv"}],
    }
    client = FakeClient({f"{osv.GCS_BASE_URL}/PyPI/all.zip": _make_osv_zip([
        raw,
        {"id": "MAL-2026-0001", "affected": [{"package": {"name": "evil", "ecosystem": "PyPI"}}]},
    ])})
    _, items = osv.fetch_osv_vulns(client)
    assert [i["id"] for i in items] == ["GHSA-xxxx-yyyy"], "MAL- 은 vulns 에 섞이면 안 된다"
    aff = items[0]["affected"][0]
    assert aff["package"] == {"name": "flask", "ecosystem": "PyPI"}, "중첩 구조 보존"
    assert aff["ranges"][0]["events"] == [{"introduced": "0"}, {"fixed": "2.2.5"}]
    assert aff["versions"] == ["2.0.0", "2.1.0"]
    assert items[0]["database_specific"] == {"severity": "HIGH"}
    assert items[0]["aliases"] == ["CVE-2026-0001"]


def test_osv_vulns_adapter_skips_withdrawn(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GVSKB_OSV_INCLUDE_NPM", raising=False)
    client = FakeClient({f"{osv.GCS_BASE_URL}/PyPI/all.zip": _make_osv_zip([
        {"id": "GHSA-with", "withdrawn": "2026-01-01T00:00:00Z",
         "affected": [{"package": {"name": "p", "ecosystem": "PyPI"}}]},
    ])})
    _, items = osv.fetch_osv_vulns(client)
    assert items == [], "철회된 advisory 로 경고가 나가면 다음 갱신까지 오탐이다"


def test_osv_zip_downloaded_once_for_both_adapters(monkeypatch: pytest.MonkeyPatch) -> None:
    """update_sources 처럼 같은 클라이언트로 두 어댑터가 돌면 zip 은 1회만 받는다.

    없으면 매일 2×256MB 다운로드가 된다(npm 포함 시).
    """
    monkeypatch.delenv("GVSKB_OSV_INCLUDE_NPM", raising=False)
    client = FakeClient({f"{osv.GCS_BASE_URL}/PyPI/all.zip": _make_osv_zip([
        {"id": "MAL-1", "affected": [{"package": {"name": "e", "ecosystem": "PyPI"}}]},
        {"id": "GHSA-1", "affected": [{"package": {"name": "f", "ecosystem": "PyPI"}}]},
    ])})
    _, mal = osv.fetch_osv_malicious(client)
    _, vulns = osv.fetch_osv_vulns(client)
    assert len(client.get_calls) == 1, "같은 클라이언트면 다운로드는 1회여야 한다"
    assert [i["id"] for i in mal] == ["MAL-1"]
    assert [i["id"] for i in vulns] == ["GHSA-1"]


def test_osv_vulns_registered_as_source() -> None:
    assert "osv-vulns" in SOURCES
    assert SOURCES["osv-vulns"].ecosystems is not None


# ---------------------------------------------------------------------------
# NVD·EPSS 누적 병합 — 창(window) 조회가 데이터를 잊지 않게
# ---------------------------------------------------------------------------


def test_nvd_merge_accumulates_and_newest_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GVSKB_NVD_CACHE_MAX", raising=False)
    prev = [
        {"id": "CVE-1", "lastModified": "2026-01-01", "cvss31_severity": "LOW"},
        {"id": "CVE-2", "lastModified": "2026-01-02"},
    ]
    new = [{"id": "CVE-1", "lastModified": "2026-08-01", "cvss31_severity": "HIGH"}]
    merged = nvd.merge_nvd(prev, new)
    by_id = {m["id"]: m for m in merged}
    assert set(by_id) == {"CVE-1", "CVE-2"}, "창 밖으로 밀린 CVE-2 가 사라지면 안 된다"
    assert by_id["CVE-1"]["cvss31_severity"] == "HIGH", "같은 CVE 는 새 수집분이 이긴다"


def test_nvd_merge_caps_by_newest_modified(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GVSKB_NVD_CACHE_MAX", "1000")
    prev = [{"id": f"CVE-{i}", "lastModified": f"2026-01-{(i % 28) + 1:02d}"} for i in range(1500)]
    merged = nvd.merge_nvd(prev, [])
    assert len(merged) == 1000
    assert merged[0]["lastModified"] >= merged[-1]["lastModified"], "최신 수정분 우선 보존"


def test_epss_merge_keeps_newer_score_per_cve() -> None:
    prev = [{"cve": "CVE-1", "epss": 0.1, "date": "2026-01-01"},
            {"cve": "CVE-2", "epss": 0.5, "date": "2026-01-01"}]
    new = [{"cve": "CVE-1", "epss": 0.9, "date": "2026-08-01"}]
    merged = epss.merge_epss(prev, new)
    by_cve = {m["cve"]: m for m in merged}
    assert by_cve["CVE-1"]["epss"] == 0.9
    assert by_cve["CVE-2"]["epss"] == 0.5, "이번 창에 없던 CVE 의 점수가 사라지면 안 된다"


def test_update_source_applies_merge_for_epss(tmp_path: Path) -> None:
    """오케스트레이터 통합 — 갱신이 덮어쓰기가 아니라 누적인지."""
    cache = IntelCache(tmp_path)
    cache.save("epss-recent", "x", [{"cve": "CVE-OLD", "epss": 0.2, "date": "2026-01-01"}])

    class Client:
        def get(self, url, **kw):
            class R:
                status_code = 200

                @staticmethod
                def json():
                    return {"status": "OK",
                            "data": [{"cve": "CVE-NEW", "epss": "0.7",
                                      "percentile": "0.9", "date": "2026-08-31"}]}

                @staticmethod
                def raise_for_status():
                    return None
            return R()

        def close(self):
            pass

    result = update_source("epss-recent", cache=cache, client=Client())
    assert result.ok
    items = cache.load("epss-recent").items
    cves = {i["cve"] for i in items}
    assert cves == {"CVE-OLD", "CVE-NEW"}, f"누적 병합 실패: {cves}"


# ---------------------------------------------------------------------------
# 캐시 로드 메모 — 대용량 캐시를 패키지마다 재파싱하지 않되, 갱신은 즉시 반영
# ---------------------------------------------------------------------------


def test_cache_load_memo_reflects_overwrite(tmp_path: Path) -> None:
    cache = IntelCache(tmp_path)
    cache.save("t", "u", [{"id": "a"}])
    assert cache.load("t").items == [{"id": "a"}]
    cache.save("t", "u", [{"id": "b"}])
    assert cache.load("t").items == [{"id": "b"}], "저장 후 로드가 옛 메모를 돌려주면 안 된다"


def test_cache_load_memo_reflects_external_rewrite(tmp_path: Path) -> None:
    """save() 를 거치지 않은 파일 교체(번들 import 경로)도 다음 load 에 반영돼야 한다."""
    cache = IntelCache(tmp_path)
    cache.save("t", "u", [{"id": "a"}])
    assert cache.load("t").items == [{"id": "a"}]
    _write_cache(tmp_path, "t", [{"id": "external"}])
    assert cache.load("t").items == [{"id": "external"}]


def test_cache_load_memo_returns_same_parsed_object_when_unchanged(tmp_path: Path) -> None:
    cache = IntelCache(tmp_path)
    cache.save("t", "u", [{"id": "a"}])
    first = cache.load("t")
    second = cache.load("t")
    assert first is second, "파일이 안 바뀌었으면 재파싱하지 않는다(수십 MB 캐시 성능)"


def test_large_cache_saved_compact(tmp_path: Path) -> None:
    """항목 1만 개 초과 캐시는 indent 없이 저장된다 — 파일 크기 절감."""
    cache = IntelCache(tmp_path)
    cache.save("big", "u", [{"id": str(i)} for i in range(10_001)])
    text = (tmp_path / "big.json").read_text(encoding="utf-8")
    assert "\n  " not in text[:200], "대용량 캐시가 indent 로 저장됐다"
    assert cache.load("big").item_count == 10_001
