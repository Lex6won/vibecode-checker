"""check_package 통일 결과 스키마 + 실재확인·쿨다운·KEV 교차대조 테스트.

핵심 회귀 방지:
- **존재하지 않는 패키지가 '깨끗함'으로 보이던 역효과 제거** — 과거 OSV 빈
  응답이 "취약점 0건"으로 렌더돼 슬롭스쿼팅 이름이 가장 안전해 보였다.
- 온라인/오프라인이 같은 키(PackageCheckResult)를 반환한다.
- 결과에 엔진 버전·검사 시각이 각인된다(출처 증명).
"""
from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

import gvskb.tools.check_package as cp
from gvskb.schema import PackageCheckResult, PackageRegistryMetadata


def _run(coro):
    return asyncio.run(coro)


def _meta(**kw) -> PackageRegistryMetadata:
    return PackageRegistryMetadata(**kw)


def _patch_metadata(monkeypatch: pytest.MonkeyPatch, meta: PackageRegistryMetadata) -> None:
    async def fake_fetch(name, ecosystem="pypi", version=None, timeout=10.0):
        return meta
    monkeypatch.setattr(cp, "fetch_registry_metadata", fake_fetch)


class _FakeResponse:
    def __init__(self, payload: dict):
        self._payload = payload
        self.status_code = 200

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return self._payload


class _FakeAsyncClient:
    """OSV 질의를 가로채는 가짜 httpx.AsyncClient."""

    payload: dict = {"vulns": []}

    def __init__(self, *a, **kw):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, url, json=None):
        return _FakeResponse(type(self).payload)


@pytest.fixture
def osv(monkeypatch: pytest.MonkeyPatch):
    """OSV 응답을 테스트가 지정하게 한다. 반환된 setter 로 payload 를 바꾼다."""
    _FakeAsyncClient.payload = {"vulns": []}
    monkeypatch.setattr(cp.httpx, "AsyncClient", _FakeAsyncClient)

    def set_payload(p: dict) -> None:
        _FakeAsyncClient.payload = p
    return set_payload


# ---------------------------------------------------------------------------
# ① 실재 확인 — 슬롭스쿼팅 역효과 제거 (P0)
# ---------------------------------------------------------------------------


def test_nonexistent_package_is_blocked_not_clean(monkeypatch, osv) -> None:
    """미존재 패키지는 not_found/high — 과거처럼 '취약점 0건'으로 보이면 안 된다."""
    _patch_metadata(monkeypatch, _meta(exists=False))
    r = _run(cp.check_package_impl("fake-ai-invented-pkg", "pypi"))
    assert r["verdict"] == "not_found"
    assert r["verdict_severity"] == "high"          # VCPS-C4-EXISTENCE: BLOCK
    assert r["exists"] is False
    assert r["checked"] is False                     # 취약점 검사 자체가 무의미
    assert r["requires_review"] is True
    assert "존재하지 않" in (r["note"] or "")


def test_existing_clean_package_is_checked_clean(monkeypatch, osv) -> None:
    _patch_metadata(monkeypatch, _meta(exists=True, version_age_days=100, license="MIT"))
    r = _run(cp.check_package_impl("goodpkg", "pypi", version="1.0.0"))
    assert r["verdict"] == "checked_clean"
    assert r["requires_review"] is False
    assert r["exists"] is True
    assert r["license_verdict"] == "allowed"


def test_metadata_fetch_failure_is_review_not_pass(monkeypatch, osv) -> None:
    """실재 미확인(조회 실패)은 checked_clean 이라도 검토 대상으로 남는다."""
    _patch_metadata(monkeypatch, _meta(exists=None, error="timeout"))
    r = _run(cp.check_package_impl("somepkg", "pypi", version="1.0.0"))
    assert r["exists"] is None
    assert r["requires_review"] is True


# ---------------------------------------------------------------------------
# ② 쿨다운(C1) — 발행 직후 버전 HOLD
# ---------------------------------------------------------------------------


def test_fresh_version_gets_cooldown_hold(monkeypatch, osv) -> None:
    _patch_metadata(monkeypatch, _meta(exists=True, version_age_days=1))
    r = _run(cp.check_package_impl("newpkg", "pypi", version="9.9.9", env_grade="E1"))
    assert r["verdict"] == "cooldown_hold"
    assert r["verdict_severity"] == "medium"        # HOLD 는 차단이 아니라 대기
    assert r["requires_review"] is True
    assert r["cooldown"]["ok"] is False
    assert r["cooldown"]["cooldown_days"] == 7


def test_cooldown_not_applied_when_aged(monkeypatch, osv) -> None:
    _patch_metadata(monkeypatch, _meta(exists=True, version_age_days=60))
    r = _run(cp.check_package_impl("oldpkg", "pypi", version="1.0.0", env_grade="E2"))
    assert r["verdict"] == "checked_clean"
    assert r["cooldown"]["ok"] is True


# ---------------------------------------------------------------------------
# ③ 취약점 심각도(C6) — max_cve 와 차단 판정
# ---------------------------------------------------------------------------


def test_high_cve_with_version_blocks(monkeypatch, osv) -> None:
    _patch_metadata(monkeypatch, _meta(exists=True, version_age_days=300))
    osv({"vulns": [{"id": "GHSA-x", "database_specific": {"severity": "HIGH"},
                    "summary": "prototype pollution"}]})
    r = _run(cp.check_package_impl("vulnpkg", "npm", version="4.17.15"))
    assert r["verdict"] == "vulnerable"
    assert r["max_cve"] == "HIGH"
    assert r["verdict_severity"] == "high"           # Critical/High → 차단급(C6)


def test_low_cve_with_version_is_review(monkeypatch, osv) -> None:
    _patch_metadata(monkeypatch, _meta(exists=True, version_age_days=300))
    osv({"vulns": [{"id": "GHSA-y", "database_specific": {"severity": "LOW"}}]})
    r = _run(cp.check_package_impl("mildpkg", "npm", version="1.0.0"))
    assert r["verdict"] == "vulnerable"
    assert r["verdict_severity"] == "medium"


def test_versionless_vulns_capped_to_review(monkeypatch, osv) -> None:
    """버전 미지정 조회는 전체 이력 취약점 — high 차단이 아니라 검토로 캡핑."""
    _patch_metadata(monkeypatch, _meta(exists=True, version_age_days=300))
    osv({"vulns": [{"id": "GHSA-z", "database_specific": {"severity": "CRITICAL"}}]})
    r = _run(cp.check_package_impl("requests", "pypi"))  # version=None
    assert r["verdict"] == "vulnerable"
    assert r["verdict_severity"] == "medium"
    assert "버전 미지정" in (r["note"] or "")


def test_install_script_flagged_for_review(monkeypatch, osv) -> None:
    _patch_metadata(monkeypatch, _meta(
        exists=True, version_age_days=300,
        install_scripts="present", install_script_names=["postinstall"],
    ))
    r = _run(cp.check_package_impl("scripty", "npm", version="1.0.0"))
    assert r["verdict"] == "checked_clean"           # 스크립트 자체는 차단 아님(C2=WARN)
    assert r["requires_review"] is True
    assert "설치 스크립트" in (r["note"] or "")


# ---------------------------------------------------------------------------
# ④ 통일 스키마 + 출처 증명
# ---------------------------------------------------------------------------


def test_result_validates_against_unified_model(monkeypatch, osv) -> None:
    _patch_metadata(monkeypatch, _meta(exists=True, version_age_days=300))
    r = _run(cp.check_package_impl("goodpkg", "pypi", version="1.0.0"))
    parsed = PackageCheckResult.model_validate(r)    # 스키마 계약 — 레지스트리 저장 전제
    assert parsed.engine_version                     # 엔진 버전 각인
    assert parsed.checked_at                         # 검사 시각 각인


def test_offline_result_also_validates(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """오프라인(캐시 없음) 결과도 같은 모델로 파싱돼야 한다 — 온/오프 키 통일."""
    monkeypatch.setenv("GVSKB_MODE", "offline")
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path))
    r = _run(cp.check_package_impl("anything", "pypi", version="1.0", env_grade="E1"))
    parsed = PackageCheckResult.model_validate(r)
    assert parsed.verdict == "unknown"
    assert parsed.exists is None                     # 실재 미확인 명시
    assert parsed.max_cve == "UNKNOWN"               # CVE 미확인 — NONE 아님
    assert r["cooldown"]["ok"] is None               # 발행일 미상 — '통과' 아님


# ---------------------------------------------------------------------------
# ⑤ KEV 교차 대조 (온라인 + 로컬 캐시)
# ---------------------------------------------------------------------------


def _write_kev_cache(cache_dir: Path, items: list[dict]) -> None:
    cache_dir.mkdir(parents=True, exist_ok=True)
    blob = json.dumps(items, sort_keys=True, ensure_ascii=False).encode("utf-8")
    envelope = {
        "schema_version": 2,
        "source_id": "cisa-kev",
        "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "url": "https://example/kev",
        "sha256": hashlib.sha256(blob).hexdigest(),
        "item_count": len(items),
        "items": items,
    }
    (cache_dir / "cisa-kev.json").write_text(json.dumps(envelope, ensure_ascii=False), encoding="utf-8")


def test_kev_cve_alias_match_escalates_to_high(tmp_path, monkeypatch, osv) -> None:
    """취약점의 CVE alias 가 KEV 에 있으면 실제 악용 중 — 심각도 불문 차단급."""
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path))
    _write_kev_cache(tmp_path, [{"cveID": "CVE-2026-9999", "vulnerabilityName": "RCE", "dateAdded": "2026-07-01"}])
    _patch_metadata(monkeypatch, _meta(exists=True, version_age_days=300))
    osv({"vulns": [{"id": "GHSA-k", "aliases": ["CVE-2026-9999"],
                    "database_specific": {"severity": "MODERATE"}}]})
    r = _run(cp.check_package_impl("kevpkg", "npm", version="2.0.0"))
    assert r["in_kev"] is True
    assert r["verdict_severity"] == "high"           # MEDIUM 이어도 KEV 면 차단급
    assert r["kev_signals"][0]["match"] == "cve_alias"


# ---------------------------------------------------------------------------
# ⑥ audit_manifest 집계 — not_found/hold 카운트
# ---------------------------------------------------------------------------


def test_audit_manifest_counts_not_found_and_hold(monkeypatch) -> None:
    results = {
        "fakepkg": {"name": "fakepkg", "ecosystem": "pypi", "checked": False,
                    "verdict": "not_found", "verdict_severity": "high", "requires_review": True},
        "newpkg": {"name": "newpkg", "ecosystem": "pypi", "checked": True,
                   "verdict": "cooldown_hold", "verdict_severity": "medium", "requires_review": True},
        "okpkg": {"name": "okpkg", "ecosystem": "pypi", "checked": True,
                  "verdict": "checked_clean", "verdict_severity": "info", "requires_review": False},
    }

    async def fake_check(name, ecosystem="pypi", version=None, timeout=10.0, env_grade=None):
        return dict(results[name])
    monkeypatch.setattr(cp, "check_package_impl", fake_check)

    audit = _run(cp.audit_manifest("fakepkg\nnewpkg\nokpkg\n", ecosystem="pypi", env_grade="E1"))
    assert audit["not_found_count"] == 1
    assert audit["hold_count"] == 1
    assert audit["env_grade"] == "E1"
    assert audit["blocked"] is True                  # not_found(high) → 차단
    assert audit["engine_version"]
