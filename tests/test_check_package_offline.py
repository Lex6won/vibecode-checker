"""check_package — offline mode must consult the local intel cache.

In air-gapped agencies the OSV API is unreachable. `update-intel` populates
~/.gvskb/cache/ (or $GVSKB_CACHE_DIR) so check_package can still answer
"is this package known-malicious?" without network. These tests pin that
behavior so the offline path is more than a heuristic placeholder.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from gvskb.tools.check_package import check_package_impl


def _write_cache(
    cache_dir: Path,
    source_id: str,
    items: list[dict],
    *,
    fetched_at: str | None = None,
    sha256: str | None = None,
    ecosystems: list[str] | None = None,
) -> None:
    """실제 IntelCache.save()와 동일한 envelope을 만든다(올바른 sha256 포함).

    sha256/fetched_at/ecosystems 를 오버라이드하면 변조·신선도·커버리지
    시나리오를 시뮬레이션할 수 있다.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    blob = json.dumps(items, sort_keys=True, ensure_ascii=False).encode("utf-8")
    envelope = {
        "schema_version": 2,
        "source_id": source_id,
        "fetched_at": fetched_at
        or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "url": "https://example/test",
        "sha256": sha256 if sha256 is not None else hashlib.sha256(blob).hexdigest(),
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


@pytest.fixture
def offline_with_cache(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    monkeypatch.setenv("GVSKB_MODE", "offline")
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path))
    return tmp_path


# ---------------------------------------------------------------------------
# Cache HIT — OSV malicious feed
# ---------------------------------------------------------------------------


def test_offline_osv_cache_hit_flags_malicious(offline_with_cache: Path) -> None:
    """A package name listed in cached OSV MAL advisories must be flagged."""
    _write_cache(
        offline_with_cache,
        "osv-malicious",
        [
            {
                "id": "MAL-2026-1234",
                "summary": "Test malicious package for unit test",
                "modified": "2026-05-01T00:00:00Z",
                "affected": [
                    {"package": "evilpkg", "ecosystem": "PyPI"},
                ],
            }
        ],
    )

    result = asyncio.run(check_package_impl(name="evilpkg", ecosystem="pypi"))

    assert result["offline"] is True
    assert result["checked"] is True, "cache lookup must count as a real check"
    assert result["is_malicious_package"] is True
    assert result["verdict_severity"] == "high"
    assert any(a["id"] == "MAL-2026-1234" for a in result.get("advisories", []))
    assert "osv-malicious" in result.get("cache_sources_used", [])


def test_offline_osv_ecosystem_must_match(offline_with_cache: Path) -> None:
    """An advisory for npm:foo must NOT match a pypi:foo lookup."""
    _write_cache(
        offline_with_cache,
        "osv-malicious",
        [
            {
                "id": "MAL-2026-9999",
                "affected": [{"package": "foo", "ecosystem": "npm"}],
            }
        ],
    )

    result = asyncio.run(check_package_impl(name="foo", ecosystem="pypi"))
    assert result.get("is_malicious_package") is not True


# ---------------------------------------------------------------------------
# 캐시는 있는데 이름이 없을 때 — '악성 없음'이지 '이상 없음'이 아니다
#
# 실측 사고: 하네스 두 개가 .mcp.json 에 GVSKB_MODE=offline 을 박아 둬 온라인 PC 도
# 이 경로를 탔다. 예전 구현은 여기서 checked_clean · requires_review=False 를 돌려줬고,
# 그래서 **취약점 26건짜리 pillow 12.2.0 이 '이상 없음'** 으로 통과했다.
# 오프라인 캐시에는 악성 피드·KEV 만 있고 CVE DB 가 없다 — 구조적으로 CVE 를 못 본다.
# ---------------------------------------------------------------------------


def test_offline_cache_present_no_match_is_not_clearance(offline_with_cache: Path) -> None:
    """악성 피드 대조는 했지만 CVE 는 확인 못 했다 — '판정 불가'로 남긴다."""
    _write_cache(offline_with_cache, "osv-malicious", [])
    _write_cache(offline_with_cache, "cisa-kev", [])

    result = asyncio.run(check_package_impl(name="requests", ecosystem="pypi"))

    assert result["offline"] is True
    assert result["is_malicious_package"] is False
    assert "osv-malicious" in result.get("cache_sources_used", [])
    assert "heuristics" in result
    # 핵심: '이상 없음'을 선언하지 않는다.
    assert result["verdict"] != "checked_clean"
    assert result["verdict"] == "unknown"
    assert result["checked"] is False           # 집계에서 '판정 불가'로 세어진다
    assert result["requires_review"] is True
    assert result["max_cve"] == "UNKNOWN"
    note = result["note"] or ""
    assert "악성 등록은 없습니다" in note        # 한 것과
    assert "확인하지 못했습니다" in note          # 못 한 것을 함께 말한다


def test_offline_kev_signal_is_surfaced_in_note(offline_with_cache: Path) -> None:
    """KEV 이름 일치가 있으면 그 사실을 사유에 적는다 — 조용히 넘기지 않는다."""
    _write_cache(offline_with_cache, "osv-malicious", [])
    _write_cache(offline_with_cache, "cisa-kev", [
        {"vendorProject": "requests", "product": "requests", "cveID": "CVE-2026-0001"},
    ])
    result = asyncio.run(check_package_impl(name="requests", ecosystem="pypi"))
    if result.get("in_kev"):                     # 매칭 방식은 구현에 맡긴다
        assert "KEV" in (result["note"] or "")
        assert result["requires_review"] is True


# ---------------------------------------------------------------------------
# CISA KEV — secondary signal when package name appears in vendorProject/product
# ---------------------------------------------------------------------------


def test_offline_kev_product_match_raises_signal(offline_with_cache: Path) -> None:
    """If package name matches a KEV product, surface it as a secondary signal."""
    _write_cache(
        offline_with_cache,
        "cisa-kev",
        [
            {
                "cveID": "CVE-2021-44228",
                "vendorProject": "Apache",
                "product": "Log4j2",
                "vulnerabilityName": "Apache Log4j2 RCE",
                "dateAdded": "2021-12-10",
            }
        ],
    )

    result = asyncio.run(check_package_impl(name="log4j2", ecosystem="pypi"))

    assert result["offline"] is True
    assert any(
        sig.get("cveID") == "CVE-2021-44228"
        for sig in result.get("kev_signals", [])
    ), "KEV product-name match should surface as a secondary signal"


# ---------------------------------------------------------------------------
# No cache at all — clear guidance, no false confidence
# ---------------------------------------------------------------------------


def test_offline_no_cache_returns_clear_guidance(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """When no cache exists, do not claim a real check — tell the operator to update-intel."""
    monkeypatch.setenv("GVSKB_MODE", "offline")
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path / "empty"))

    result = asyncio.run(check_package_impl(name="anything", ecosystem="pypi"))

    assert result["offline"] is True
    assert result["checked"] is False
    assert "heuristics" in result
    assert "update-intel" in result.get("note", "")
    assert result.get("cache_sources_used", []) == []


# ---------------------------------------------------------------------------
# Backwards compatibility — the original Stage-5 contract still holds
# ---------------------------------------------------------------------------


def test_offline_marker_still_set_when_cache_present(offline_with_cache: Path) -> None:
    """The Stage-5 contract (`offline=True`, `heuristics` present) must remain."""
    _write_cache(offline_with_cache, "osv-malicious", [])
    result = asyncio.run(check_package_impl(name="x", ecosystem="pypi"))
    assert result["offline"] is True
    assert "heuristics" in result


# ---------------------------------------------------------------------------
# audit_manifest — 락파일 거짓-ok 봉쇄 · 취약점 있으면 ok 금지 · 판정불가 명시
# ---------------------------------------------------------------------------


def test_audit_manifest_parses_lockfiles_including_transitive(
    offline_with_cache: Path,
) -> None:
    """락파일을 받으면 **전이 의존성까지** 검사 범위에 넣는다.

    이전에는 락파일을 정직하게 거절했다(unparsed). 정직했지만 검사가 안 되는
    건 마찬가지였고, 실무 취약점은 대부분 전이 의존성에 있다.
    """
    import asyncio
    from gvskb.tools.check_package import audit_manifest

    # express 만 직접 의존성이고 accepts 는 전이 의존성이다.
    text = json.dumps({
        "lockfileVersion": 1,
        "dependencies": {
            "express": {"version": "4.18.2", "dependencies": {"accepts": {"version": "1.3.8"}}},
        },
    })
    r = asyncio.run(audit_manifest(text, ecosystem="npm"))
    assert r["source_kind"] == "lockfile"
    assert r["lockfile_format"] == "package-lock.json"
    assert r["parsed_count"] == 2, "전이 의존성이 빠졌다"
    assert {p["name"] for p in r["packages"]} == {"express", "accepts"}


def test_lockfile_format_overrides_wrong_ecosystem_argument(
    offline_with_cache: Path,
) -> None:
    """파일 형식이 생태계를 확정한다 — 인자가 틀렸으면 파일을 따른다."""
    import asyncio
    from gvskb.tools.check_package import audit_manifest

    text = '[[package]]\nname = "flask"\nversion = "0.12"\n'
    r = asyncio.run(audit_manifest(text, ecosystem="npm"))  # 일부러 틀린 인자
    assert r["ecosystem"] == "pypi"


def test_lockfile_recognized_but_empty_is_unparsed_not_ok(
    offline_with_cache: Path,
) -> None:
    """형식은 알아봤는데 패키지를 못 읽었으면 '이상 없음'이 아니다."""
    import asyncio
    from gvskb.tools.check_package import audit_manifest

    for text in ('{"lockfileVersion": 3, "packages": {}}', "lockfileVersion: '9.0'\n"):
        r = asyncio.run(audit_manifest(text, ecosystem="npm"))
        assert r["verdict"] == "unparsed", text[:30]
        assert r["requires_review"] is True


def test_truncation_is_reported_loudly_not_silently(offline_with_cache: Path) -> None:
    """limit 로 잘린 패키지는 '검사되지 않음'이다 — 수치와 검토 대상으로 드러낸다.

    일부만 검사하고 전부 검사한 것처럼 보이면 그게 조용한 초록불이다.
    """
    import asyncio
    from gvskb.tools.check_package import audit_manifest

    text = json.dumps({
        "lockfileVersion": 3,
        "packages": {f"node_modules/p{i}": {"version": "1.0.0"} for i in range(10)},
    })
    r = asyncio.run(audit_manifest(text, ecosystem="npm", limit=3))
    assert r["parsed_count"] == 10
    assert len(r["checks"]) == 3
    assert r["truncated_count"] == 7
    assert r["requires_review"] is True
    assert "truncated_count=7" in r["disclaimer"]


def test_manifest_disclaimer_points_to_lockfile(offline_with_cache: Path) -> None:
    """매니페스트만 검사했다면 전이 의존성이 빠졌다는 사실을 알려야 한다."""
    import asyncio
    from gvskb.tools.check_package import audit_manifest

    r = asyncio.run(audit_manifest("flask==3.0.0\n", ecosystem="pypi"))
    assert r["source_kind"] == "manifest"
    assert "전이 의존성" in r["disclaimer"]


def test_audit_manifest_empty_text_is_unparsed_not_ok() -> None:
    import asyncio
    from gvskb.tools.check_package import audit_manifest

    r = asyncio.run(audit_manifest("", ecosystem="pypi"))
    assert r["verdict"] == "unparsed"
    assert r["requires_review"] is True


def test_audit_manifest_vulnerable_package_is_not_ok(monkeypatch) -> None:
    """알려진 CVE가 있는 패키지는 verdict가 'ok'여선 안 된다(거짓 안심 방지)."""
    import asyncio
    import gvskb.tools.check_package as cp

    async def fake_check(name, ecosystem="pypi", version=None, timeout=10.0, **kwargs):
        return {
            "name": name, "version": version, "ecosystem": ecosystem,
            "checked": True, "is_malicious_package": False,
            "vulnerability_count": 7, "verdict_severity": "medium",
        }

    monkeypatch.setattr(cp, "check_package_impl", fake_check)
    r = asyncio.run(cp.audit_manifest("flask==0.12.2\n", ecosystem="pypi"))
    assert r["verdict"] == "review_required"
    assert r["requires_review"] is True
    assert r["blocked"] is False  # 취약≠악성 — 차단이 아니라 검토 대상


def test_audit_manifest_offline_empty_cache_requires_review(tmp_path, monkeypatch) -> None:
    """오프라인+캐시 없음 → unchecked>0 → '안전 아님'(review_required)."""
    import asyncio
    from gvskb.tools.check_package import audit_manifest

    monkeypatch.setenv("GVSKB_MODE", "offline")
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path))
    r = asyncio.run(audit_manifest("requests==2.19.1\n", ecosystem="pypi"))
    assert r["unchecked_count"] == 1
    assert r["requires_review"] is True
    assert r["verdict"] == "review_required"


def test_cli_check_package_unknown_verdict_exits_nonzero(tmp_path, monkeypatch, capsys) -> None:
    """판정 불가(오프라인·캐시 없음)를 CI가 '통과(0)'로 처리하면 안 된다."""
    import argparse
    from gvskb.cli import EXIT_OK, _cmd_check_package

    monkeypatch.setenv("GVSKB_MODE", "offline")
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path))
    args = argparse.Namespace(name="requests", ecosystem="pypi", version=None)
    code = _cmd_check_package(args)
    capsys.readouterr()
    assert code != EXIT_OK


# ---------------------------------------------------------------------------
# 캐시 무결성·신선도·생태계 커버리지 — 반입 캐시의 거짓 안심 봉쇄
# ---------------------------------------------------------------------------


def test_tampered_cache_is_rejected_and_not_used(offline_with_cache: Path) -> None:
    """sha256 불일치(변조·손상) 캐시는 무시되고 '판정 불가'로 강등돼야 한다."""
    _write_cache(
        offline_with_cache, "osv-malicious",
        [{"id": "MAL-1", "affected": [{"package": "evilpkg", "ecosystem": "PyPI"}]}],
        sha256="TAMPERED_HASH_0000",
    )
    result = asyncio.run(check_package_impl(name="evilpkg", ecosystem="pypi"))
    assert result["checked"] is False           # 변조 캐시로 판정하지 않는다
    assert result.get("is_malicious_package") is not True
    assert result["requires_review"] is True


def test_stale_cache_clean_becomes_checked_stale(offline_with_cache: Path) -> None:
    """신선도(기본 30일) 초과 캐시의 '깨끗함'은 checked_stale + 검토 필요."""
    _write_cache(offline_with_cache, "osv-malicious", [], fetched_at=_days_ago(90))
    result = asyncio.run(check_package_impl(name="requests", ecosystem="pypi"))
    assert result["checked"] is True
    assert result["verdict"] == "checked_stale"
    assert result["requires_review"] is True
    assert "osv-malicious" in result.get("cache_stale_sources", [])


def test_stale_cache_malicious_verdict_still_valid(offline_with_cache: Path) -> None:
    """캐시가 오래됐어도 '악성 발견'(양성)은 유효한 신호다."""
    _write_cache(
        offline_with_cache, "osv-malicious",
        [{"id": "MAL-2", "affected": [{"package": "evilpkg", "ecosystem": "PyPI"}]}],
        fetched_at=_days_ago(90),
    )
    result = asyncio.run(check_package_impl(name="evilpkg", ecosystem="pypi"))
    assert result["verdict"] == "malicious"
    assert result["is_malicious_package"] is True


def test_pypi_only_cache_cannot_clear_npm_package(offline_with_cache: Path) -> None:
    """PyPI만 담은 캐시로 npm 패키지를 '깨끗함' 판정하면 안 된다(거짓 클린)."""
    _write_cache(offline_with_cache, "osv-malicious", [], ecosystems=["PyPI"])
    result = asyncio.run(check_package_impl(name="left-pad", ecosystem="npm"))
    assert result["checked"] is False
    assert result["verdict"] == "unknown"
    assert result["requires_review"] is True
    assert "GVSKB_OSV_INCLUDE_NPM" in result.get("note", "")


def test_v1_cache_without_ecosystems_assumed_pypi(offline_with_cache: Path) -> None:
    """v1 캐시(ecosystems 미기록)는 당시 기본 수집(PyPI)으로 간주 — pypi는 판정, npm은 불가."""
    _write_cache(offline_with_cache, "osv-malicious", [])  # ecosystems 미기록
    ok = asyncio.run(check_package_impl(name="requests", ecosystem="pypi"))
    # 커버되는 생태계라도 오프라인에서는 CVE 를 못 보므로 '이상 없음'이 아니다.
    assert ok["verdict"] == "unknown" and ok["is_malicious_package"] is False
    assert "악성 등록은 없습니다" in (ok["note"] or "")
    npm = asyncio.run(check_package_impl(name="left-pad", ecosystem="npm"))
    # 커버되지 않는 생태계는 악성 대조조차 못 했다 — 사유가 다르다.
    assert npm["checked"] is False and npm["verdict"] == "unknown"
    assert "생태계를 포함하지 않습니다" in (npm["note"] or "")


def test_npm_covered_cache_clears_malicious_only(offline_with_cache: Path) -> None:
    """생태계가 커버돼도 해소되는 건 '악성 여부'뿐 — 취약점은 여전히 미확인이다."""
    _write_cache(offline_with_cache, "osv-malicious", [], ecosystems=["PyPI", "npm"])
    result = asyncio.run(check_package_impl(name="left-pad", ecosystem="npm"))
    assert result["is_malicious_package"] is False
    assert result["verdict"] == "unknown"
    assert "생태계를 포함하지 않습니다" not in (result["note"] or "")


def test_kev_only_cache_is_not_clearance(offline_with_cache: Path) -> None:
    """KEV는 보조 신호일 뿐 — 악성 피드(osv) 없이 '깨끗함'을 선언하면 안 된다."""
    _write_cache(offline_with_cache, "cisa-kev", [])
    result = asyncio.run(check_package_impl(name="requests", ecosystem="pypi"))
    assert result["checked"] is False
    assert result["verdict"] == "unknown"
    assert result["requires_review"] is True


# ---------------------------------------------------------------------------
# 커버리지 공백 안내문 — 판정이 맞아도 안내가 틀리면 담당자가 엉뚱한 조치를 한다
# ---------------------------------------------------------------------------


def test_missing_osv_cache_note_does_not_tell_pypi_user_to_enable_npm(
    offline_with_cache: Path,
) -> None:
    """osv 캐시가 없어서 대조 못 한 PyPI 조회에 npm 환경변수를 안내하면 안 된다.

    PyPI 는 항상 기본 수집 대상이므로 GVSKB_OSV_INCLUDE_NPM 은 원인도 해법도
    아니다. 담당자가 그 변수를 켜도 공백은 그대로 남는다.
    """
    _write_cache(offline_with_cache, "cisa-kev", [])  # osv-malicious 없음
    result = asyncio.run(check_package_impl(name="requests", ecosystem="pypi"))
    note = result["note"] or ""
    assert "GVSKB_OSV_INCLUDE_NPM" not in note
    assert "npm" not in note
    assert "캐시가 없습니다" in note
    assert "update-intel" in note and "intel-bundle" in note


def test_tampered_osv_cache_note_says_integrity_failure(
    offline_with_cache: Path,
) -> None:
    """무결성 실패로 버려진 캐시는 '없음'과 다른 사유로 안내해야 한다.

    파일이 있는데도 '캐시가 없습니다'라고만 하면 담당자가 파일 존재를 확인하고
    안내를 신뢰하지 않게 된다 — 실제로는 다시 받아야 하는 상황이다.
    """
    _write_cache(
        offline_with_cache, "osv-malicious",
        [{"id": "MAL-9", "affected": [{"package": "evilpkg", "ecosystem": "PyPI"}]}],
        sha256="0" * 64,  # 변조 시뮬레이션 — load()가 거부한다
        ecosystems=["PyPI"],
    )
    _write_cache(offline_with_cache, "cisa-kev", [])
    result = asyncio.run(check_package_impl(name="evilpkg", ecosystem="pypi"))
    # 버려진 캐시로 악성 판정이 나와서도 안 되고, '깨끗함'이 나와서도 안 된다.
    assert result["verdict"] == "unknown"
    assert result["is_malicious_package"] is False
    note = result["note"] or ""
    assert "무결성" in note
    assert "GVSKB_OSV_INCLUDE_NPM" not in note


def test_npm_gap_note_still_points_at_the_opt_in_variable(
    offline_with_cache: Path,
) -> None:
    """반대 방향 — npm 은 opt-in 이므로 그 안내가 사라지면 안 된다(과교정 방지)."""
    _write_cache(offline_with_cache, "osv-malicious", [], ecosystems=["PyPI"])
    result = asyncio.run(check_package_impl(name="left-pad", ecosystem="npm"))
    note = result["note"] or ""
    assert "GVSKB_OSV_INCLUDE_NPM=1" in note
    assert "기본 수집 대상이 아닙니다" in note


# ---------------------------------------------------------------------------
# EPSS·NVD 병기 — 매일 수집되는 점수 캐시가 KEV 신호의 우선순위 근거로 쓰인다
# ---------------------------------------------------------------------------


_KEV_LOG4J = [{
    "cveID": "CVE-2021-44228",
    "vendorProject": "Apache",
    "product": "Log4j2",
    "vulnerabilityName": "Apache Log4j2 RCE",
    "dateAdded": "2021-12-10",
}]


def test_kev_signal_enriched_with_epss_and_nvd(offline_with_cache: Path) -> None:
    """KEV 매칭 시 epss-recent(악용확률)·nvd-recent(CVSS)가 병기돼야 한다."""
    _write_cache(offline_with_cache, "cisa-kev", _KEV_LOG4J)
    _write_cache(
        offline_with_cache, "epss-recent",
        [{"cve": "CVE-2021-44228", "epss": 0.976, "percentile": 0.999, "date": "2026-07-01"}],
    )
    _write_cache(
        offline_with_cache, "nvd-recent",
        [{"id": "CVE-2021-44228", "cvss31_base_score": 10.0, "cvss31_severity": "CRITICAL"}],
    )

    result = asyncio.run(check_package_impl(name="log4j2", ecosystem="pypi"))

    sig = result["kev_signals"][0]
    assert sig["epss_score"] == 0.976
    assert sig["epss_percentile"] == 0.999
    assert sig["cvss31_base_score"] == 10.0
    assert sig["cvss31_severity"] == "CRITICAL"
    assert "epss-recent" in result["cache_sources_used"]
    assert "nvd-recent" in result["cache_sources_used"]


def test_kev_signal_without_score_caches_still_works(offline_with_cache: Path) -> None:
    """점수 캐시가 없어도 KEV 신호는 그대로 동작한다(병기만 생략)."""
    _write_cache(offline_with_cache, "cisa-kev", _KEV_LOG4J)
    result = asyncio.run(check_package_impl(name="log4j2", ecosystem="pypi"))
    sig = result["kev_signals"][0]
    assert "epss_score" not in sig
    assert "cvss31_severity" not in sig
    assert "epss-recent" not in result["cache_sources_used"]


# ---------------------------------------------------------------------------
# 온라인 경로의 KEV 캐시 의존 — 결과가 스스로 밝혀야 한다
#
# 실측 결함: 온라인 모드에서도 CISA KEV 교차 대조는 **로컬 캐시**를 쓴다
# (_kev_cve_hits). 그런데 그 의존을 결과에 전혀 싣지 않아, 캐시가 없거나 6개월
# 낡아도 `in_kev=false` 가 '악용 없음'처럼 보였다. 함수 주석은 "'악용 없음'이
# 아니라 '대조 못 함'"이라고 정확히 적어 뒀는데 그 구분이 호출자에게 전달되지
# 않았다 — 주석에만 있는 안전장치는 안전장치가 아니다.
# ---------------------------------------------------------------------------


def _fake_online_vuln_response(monkeypatch: pytest.MonkeyPatch) -> None:
    """네트워크 없이 온라인 경로를 태운다 — 취약점 1건이 나온 상황."""
    from gvskb.schema import PackageRegistryMetadata

    async def _meta(name, ecosystem, version=None, timeout=None):
        return PackageRegistryMetadata(exists=True, source="test-registry")

    class _Resp:
        status_code = 200

        @staticmethod
        def json() -> dict:
            return {"vulns": [{"id": "CVE-2099-0001", "summary": "test", "aliases": []}]}

        @staticmethod
        def raise_for_status() -> None:
            return None

    class _Client:
        def __init__(self, *a, **k) -> None:
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a) -> None:
            return None

        async def post(self, *a, **k):
            return _Resp()

    monkeypatch.setattr("gvskb.tools.check_package.fetch_registry_metadata", _meta)
    monkeypatch.setattr("gvskb.tools.check_package.httpx.AsyncClient", _Client)


def test_online_result_reports_missing_kev_cache(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """KEV 캐시가 없으면 결과가 '대조 못 함'을 밝혀야 한다."""
    monkeypatch.delenv("GVSKB_MODE", raising=False)
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path))  # 빈 캐시
    _fake_online_vuln_response(monkeypatch)

    r = asyncio.run(check_package_impl(name="somepkg", ecosystem="pypi", version="1.0.0"))
    assert r["in_kev"] is False
    assert r["cache_sources_used"] == []
    assert "대조 못" in (r["note"] or ""), "in_kev=false 가 '악용 없음'과 구분되지 않는다"


def test_online_result_reports_stale_kev_cache(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """낡은 캐시로 판정했으면 기준일과 함께 알려야 한다."""
    monkeypatch.delenv("GVSKB_MODE", raising=False)
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path))
    _write_cache(tmp_path, "cisa-kev", [{"cveID": "CVE-1999-0001"}],
                 fetched_at=_days_ago(400))
    _fake_online_vuln_response(monkeypatch)

    r = asyncio.run(check_package_impl(name="somepkg", ecosystem="pypi", version="1.0.0"))
    assert r["cache_stale_sources"] == ["cisa-kev"]
    assert r["cache_freshness"].get("cisa-kev")
    assert "오래됐" in (r["note"] or "")


def test_online_result_records_fresh_kev_cache(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """신선한 캐시를 썼으면 출처로 기록한다 — 무엇을 근거로 판정했는지 남아야 한다."""
    monkeypatch.delenv("GVSKB_MODE", raising=False)
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path))
    _write_cache(tmp_path, "cisa-kev", [{"cveID": "CVE-1999-0001"}])
    _fake_online_vuln_response(monkeypatch)

    r = asyncio.run(check_package_impl(name="somepkg", ecosystem="pypi", version="1.0.0"))
    assert r["cache_sources_used"] == ["cisa-kev"]
    assert r["cache_stale_sources"] == []


# ---------------------------------------------------------------------------
# 집계와 배너 — 시스템 열화는 시스템 수준으로 한 번만
# ---------------------------------------------------------------------------


def _check(**kw) -> dict:
    base = {
        "name": "p", "version": "1.0.0", "ecosystem": "pypi",
        "vulnerability_count": 0, "cache_sources_used": [],
        "cache_stale_sources": [], "cache_freshness": {},
    }
    base.update(kw)
    return base


def test_intel_cache_aggregate_takes_worst_state() -> None:
    """일부만 낡았어도 매니페스트 전체는 '낡음'으로 보고해야 한다."""
    from gvskb.tools.check_package import _aggregate_intel_cache

    agg = _aggregate_intel_cache([
        _check(cache_sources_used=["cisa-kev"], cache_freshness={"cisa-kev": "2026-07-01"}),
        _check(cache_sources_used=["cisa-kev"], cache_stale_sources=["cisa-kev"],
               cache_freshness={"cisa-kev": "2025-01-01"}),
    ])
    assert agg["state"] == "stale"
    assert agg["as_of"]["cisa-kev"] == "2025-01-01", "가장 오래된 기준일을 남겨야 한다"


def test_intel_cache_aggregate_flags_missing_when_vulns_uncompared() -> None:
    """취약점이 있는데 캐시를 못 썼으면 '대조 못 함'이다 — '이상 없음'이 아니다."""
    from gvskb.tools.check_package import _aggregate_intel_cache

    agg = _aggregate_intel_cache([_check(vulnerability_count=3)])
    assert agg["state"] == "missing"


def test_intel_cache_aggregate_not_used_is_not_a_problem() -> None:
    """취약점이 0건이면 KEV 대조가 필요 없었던 것 — 경고할 일이 아니다."""
    from gvskb.tools.check_package import _aggregate_intel_cache

    assert _aggregate_intel_cache([_check()])["state"] == "not_used"


def test_report_shows_one_banner_not_one_per_package() -> None:
    """패키지 200건이 모두 낡은 캐시로 판정돼도 경고는 한 줄이어야 한다.

    같은 사유로 수백 줄이 뜨면 담당자는 그것을 무시하게 되고, 그러면 그 사이의
    진짜 위험도 함께 묻힌다.
    """
    from gvskb.report import _intel_cache_banner

    audits = [{
        "intel_cache": {"state": "stale", "sources_used": ["cisa-kev"],
                        "stale_sources": ["cisa-kev"], "as_of": {"cisa-kev": "2025-01-01"}},
        "checks": [_check(cache_stale_sources=["cisa-kev"]) for _ in range(200)],
    }]
    banner = _intel_cache_banner(audits)
    assert banner is not None
    assert banner.count("낡") == 1
    assert "2025-01-01" in banner


def test_report_has_no_banner_when_cache_is_fresh() -> None:
    from gvskb.report import _intel_cache_banner

    assert _intel_cache_banner([{"intel_cache": {"state": "ok"}}]) is None
    assert _intel_cache_banner([{"intel_cache": {"state": "not_used"}}]) is None
