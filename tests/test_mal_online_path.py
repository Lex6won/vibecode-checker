"""온라인 경로의 악성 권고 — 실시간 답은 물어본 버전 하나만 답한다. 판단할 수 없는 경우를 로컬 색인이 보강한다."""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from gvskb import tools  # noqa: F401 - 패키지 초기화
from gvskb.intel.cache import IntelCache
from gvskb.schema import PackageRegistryMetadata
from gvskb.tools import check_package as cp


def _mal(vid: str, name: str, *versions: str, whole: bool = False) -> dict:
    aff = {"package": {"name": name, "ecosystem": "npm"}}
    if whole:
        aff["ranges"] = [{"type": "SEMVER", "events": [{"introduced": "0"}]}]
    else:
        aff["versions"] = list(versions)
    return {"id": vid, "summary": "악성", "modified": "2026-01-01T00:00:00Z", "affected": [aff]}


@pytest.fixture
def online(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path))
    monkeypatch.delenv("GVSKB_MODE", raising=False)
    state: dict = {"answer": [], "latest": "9.9.9"}

    async def fake_meta(name, ecosystem="npm", version=None, timeout=10.0):
        return PackageRegistryMetadata(exists=True, latest_version=state["latest"], queried_version=version,
                                       version_exists=True if version else None, license="MIT",
                                       source="test", fetched_at="2026-10-15T00:00:00+00:00")

    async def fake_osv(payload, timeout=10.0, client=None):
        return {"vulns": state["answer"]}

    monkeypatch.setattr(cp, "fetch_registry_metadata", fake_meta)
    monkeypatch.setattr(cp, "_osv_query", fake_osv)
    return state


def _seed(tmp_path: Path, *items: dict) -> None:
    from gvskb.intel.sources.osv import _normalize

    cache = IntelCache(tmp_path)
    cache.save("osv-malicious", "t", [_normalize(i) for i in items], ecosystems=["PyPI", "npm"])
    cache.save("osv-vulns", "t", [], ecosystems=["PyPI", "npm"])


def _check(name: str, version: str | None = None, exact: bool = True, spec: str | None = None) -> dict:
    return asyncio.run(cp.check_package_impl(name, ecosystem="npm", version=version, version_exact=exact, mode="online", version_spec=spec))


def test_unresolved_history_keeps_only_whole_package_as_malicious(online: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    online["latest"] = None
    online["answer"] = [_mal("MAL-WHOLE", "x", whole=True), _mal("MAL-SCOPED", "x", "1.0.0")]
    out = _check("x")
    assert out["is_malicious_package"] is True and out["malicious_advisory_count"] == 1
    assert [r["id"] for r in out["malicious_possible"]] == ["MAL-SCOPED"]


def test_unresolved_version_scoped_only_is_not_malicious(online: dict) -> None:
    online["latest"] = None
    online["answer"] = [_mal("MAL-SCOPED", "x", "1.0.0")]
    out = _check("x")
    assert out["is_malicious_package"] is False and out["requires_review"] is True
    assert out["malicious_possible"][0]["reason"] == "version_unpinned"


def test_withdrawn_online_answer_does_not_count(online: dict) -> None:
    online["latest"] = None
    online["answer"] = [{**_mal("MAL-OLD", "x", whole=True), "withdrawn": "2026-01-01T00:00:00Z"}]
    assert _check("x")["is_malicious_package"] is False


def test_range_consults_local_index(online: dict, tmp_path: Path) -> None:
    _seed(tmp_path, _mal("MAL-2026-2307", "axios", "1.14.1"))
    out = _check("axios", "1.14.0", exact=False)
    assert out["is_malicious_package"] is False and out["requires_review"] is True
    assert [r["id"] for r in out["malicious_possible"]] == ["MAL-2026-2307"]
    assert "MAL-2026-2307" in out["note"]


def test_latest_assumed_consults_local_index(online: dict, tmp_path: Path) -> None:
    _seed(tmp_path, _mal("MAL-2025-1", "chalk", "5.6.1"))
    out = _check("chalk")
    assert out["version_resolution"] == "latest-assumed" and out["malicious_possible"]


def test_pinned_legit_outside_listing_stays_clean_online(online: dict, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _seed(tmp_path, _mal("MAL-2025-1", "chalk", "5.6.1"))
    listed = tmp_path / "approved.json"
    listed.write_text('{"packages":[{"ecosystem":"npm","name":"chalk"}]}', encoding="utf-8")
    monkeypatch.setenv("GVSKB_APPROVED_PACKAGES", str(listed))
    out = _check("chalk", "5.3.0")
    assert not out["malicious_possible"] and out["is_malicious_package"] is False


def test_pinned_unverified_newer_than_listing_is_possible_online(online: dict, tmp_path: Path) -> None:
    _seed(tmp_path, _mal("MAL-1", "beautiful-squat", "12.15.13"))
    out = _check("beautiful-squat", "12.15.14")
    assert out["is_malicious_package"] is False and out["requires_review"] is True
    assert out["malicious_possible"][0]["reason"] == "version_outside_unverified"


def test_live_answer_is_not_duplicated_by_local_index(online: dict, tmp_path: Path) -> None:
    _seed(tmp_path, _mal("MAL-1", "chalk", "5.6.1"))
    online["answer"] = [_mal("MAL-1", "chalk", "5.6.1")]
    out = _check("chalk", "5.6.1")
    assert out["is_malicious_package"] is True and not out["malicious_possible"]


def test_online_without_local_cache_still_answers(online: dict) -> None:
    out = _check("anything", "1.0.0")
    assert out["checked"] is True and not out["malicious_possible"]
