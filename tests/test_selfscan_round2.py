"""자기검사(2026-08-29) 2차 수정 — 의존성 게이트 오판정과 룰 2종의 회귀·적대 테스트.

- `expresss 0.0.1`: npm 에 **실존**하는 자리차지 패키지(latest 0.0.0)에 존재하지 않는
  버전. 예전 판정 사다리는 이름 신호를 레지스트리 실재 여부로만 갈라 '이상 없음'
  으로 통과시켰다.
- KISA-PY-SEC-10: known-answer `assert … == hashlib.sha256(b"abc")` 가 차단이었다.
- KISA-PY-SEC-05: 사설망·루프백 `http://` 까지 평문 전송으로 잡았다.
"""
from __future__ import annotations

import asyncio

import pytest

import gvskb.tools.check_package as cp
from gvskb.schema import PackageRegistryMetadata
from gvskb.scanner import scan_code
from gvskb.tools.package_metadata import _parse_npm, _parse_pypi


def _run(coro):
    return asyncio.run(coro)


def _patch(monkeypatch, meta: PackageRegistryMetadata) -> None:
    async def fake_fetch(name, ecosystem="pypi", version=None, timeout=10.0):
        return meta
    monkeypatch.setattr(cp, "fetch_registry_metadata", fake_fetch)
    monkeypatch.setattr(cp, "_is_offline", lambda: False)

    class _Resp:
        status_code = 200
        def raise_for_status(self): return None
        def json(self): return {"vulns": []}

    class _Client:
        def __init__(self, *a, **kw): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return None
        async def post(self, *a, **kw): return _Resp()
        async def get(self, *a, **kw): return _Resp()

    monkeypatch.setattr(cp.httpx, "AsyncClient", _Client)


def _ids(code: str, filename: str = "app.py") -> set[str]:
    return {f.rule_id for f in scan_code(code, filename=filename).findings}


# ── D-1: 버전 실재 여부 ─────────────────────────────────────────────────────

def test_npm_version_exists_false_when_version_missing():
    data = {"dist-tags": {"latest": "0.0.0"}, "time": {"created": "2016-01-01T00:00:00Z", "0.0.0": "2016-01-01T00:00:00Z"},
            "versions": {"0.0.0": {}}}
    assert _parse_npm(data, "0.0.1").version_exists is False
    assert _parse_npm(data, "0.0.0").version_exists is True
    assert _parse_npm(data, None).version_exists is None


def test_pypi_version_exists_false_when_version_missing():
    data = {"info": {"version": "2.0.0"}, "releases": {"2.0.0": [{"upload_time_iso_8601": "2025-01-01T00:00:00Z"}]}}
    assert _parse_pypi(data, "9.9.9").version_exists is False
    assert _parse_pypi(data, "2.0.0").version_exists is True


# ── D-2: 판정 사다리 ────────────────────────────────────────────────────────

def test_existing_squat_package_with_missing_version_is_not_clean(monkeypatch):
    """expresss 0.0.1 재현 — 존재가 면죄부가 되면 안 된다."""
    _patch(monkeypatch, PackageRegistryMetadata(exists=True, latest_version="0.0.0", queried_version="0.0.1",
                                                version_exists=False, source="registry.npmjs.org"))
    r = _run(cp.check_package_impl("expresss", "npm", "0.0.1"))
    assert r["verdict"] == "version_not_found"
    assert r["verdict_severity"] == "high"
    assert r["requires_review"] is True


def test_existing_squat_package_with_real_version_is_suspicious(monkeypatch):
    _patch(monkeypatch, PackageRegistryMetadata(exists=True, latest_version="0.0.0", queried_version="0.0.0",
                                                version_exists=True, version_published_at="2016-01-01T00:00:00Z",
                                                version_age_days=3000, source="registry.npmjs.org"))
    r = _run(cp.check_package_impl("expresss", "npm", "0.0.0"))
    assert r["verdict"] == "suspicious_name"
    assert r["requires_review"] is True


def test_real_popular_package_is_unaffected(monkeypatch):
    """'express' 자체(인기 목록 안)는 이름 신호가 없다."""
    _patch(monkeypatch, PackageRegistryMetadata(exists=True, latest_version="4.19.2", queried_version="4.19.2",
                                                version_exists=True, version_published_at="2024-01-01T00:00:00Z",
                                                version_age_days=500, source="registry.npmjs.org"))
    r = _run(cp.check_package_impl("express", "npm", "4.19.2"))
    assert r["verdict"] == "checked_clean"
    assert r["requires_review"] is False


def test_cooldown_undetermined_requires_review(monkeypatch):
    """발행일을 모르면 '판정 불가'지 통과가 아니다."""
    _patch(monkeypatch, PackageRegistryMetadata(exists=True, latest_version="1.0.0", queried_version="1.0.0",
                                                version_exists=True, source="pypi.org JSON API"))
    r = _run(cp.check_package_impl("somepkg-quite-unique-name", "pypi", "1.0.0"))
    assert r["cooldown"]["ok"] is None
    assert r["requires_review"] is True


def test_not_found_still_blocks(monkeypatch):
    _patch(monkeypatch, PackageRegistryMetadata(exists=False, source="pypi.org JSON API"))
    r = _run(cp.check_package_impl("reqeusts", "pypi", "1.0.0"))
    assert r["verdict"] == "not_found"


# ── D-3: 게이트·보고서 ──────────────────────────────────────────────────────

def test_gate_conditional_on_suspicious_name():
    from gvskb.gate import CONDITIONAL_CRITERIA
    assert "suspicious_name" in CONDITIONAL_CRITERIA and "version_not_found" in CONDITIONAL_CRITERIA


def test_report_severity_critical_for_cvss_critical():
    from gvskb.report import _dep_component_severity
    from gvskb.schema import Severity
    assert _dep_component_severity({"vulnerability_count": 2, "max_cve": "CRITICAL"}) == Severity.critical
    assert _dep_component_severity({"vulnerability_count": 2, "max_cve": "HIGH"}) == Severity.high
    assert _dep_component_severity({"verdict": "suspicious_name"}) == Severity.high
    assert _dep_component_severity({"verdict": "checked_clean", "checked": True}) is None


def test_report_label_puts_name_warning_in_verdict_cell():
    from gvskb.report import _pkg_verdict_label
    lbl = _pkg_verdict_label({"verdict": "suspicious_name", "checked": True,
                              "heuristics": {"typosquat_suspects": [{"similar_to": "express", "edit_distance": 1}]}})
    assert "express" in lbl and "이상 없음" not in lbl


# ── R-6: KISA-PY-SEC-10 ─────────────────────────────────────────────────────

@pytest.mark.parametrize("code", [
    'assert _sha256_bytes(b"abc") == hashlib.sha256(b"abc").hexdigest()',
    'assert hashlib.sha256(b"x").hexdigest() == EXPECTED',
    'self.assertEqual(hashlib.sha256(b"abc").hexdigest(), "ba78…")',
])
def test_sec10_ignores_known_answer_self_tests(code):
    assert "KISA-PY-SEC-10" not in _ids(code)


@pytest.mark.parametrize("code", [
    'if hashlib.sha256(data).hexdigest() == client_hash:',
    'ok = hashlib.sha256(body).hexdigest() == request.headers["X-Sig"]',
    'if request.args.get("sig") == hashlib.md5(payload).hexdigest():',
    'if hashlib.sha256(b"admin").hexdigest() == request.args["h"]: grant()',   # 리터럴이지만 외부값 비교
    'assert hashlib.sha256(token).hexdigest() == received_sig',                # assert 지만 외부값 비교
])
def test_sec10_still_fires_on_external_comparison(code):
    assert "KISA-PY-SEC-10" in _ids(code)


# ── R-7: KISA-PY-SEC-05 ─────────────────────────────────────────────────────

@pytest.mark.parametrize("code", [
    "requests.post('http://10.0.0.5/api')",
    "requests.get('http://localhost:3000/x')",
    "requests.get('http://127.0.0.1/health')",
    "requests.get('http://192.168.1.10:8080/status')",
    "urllib.request.urlopen('http://172.16.0.9/ping')",
])
def test_sec05_ignores_private_plain_http(code):
    assert "KISA-PY-SEC-05" not in _ids(code)


@pytest.mark.parametrize("code", [
    "requests.post('http://api.example.com/login', data={'pw': pw})",
    "requests.get('http://10.0.0.5.evil.com/a')",                              # 경계 우회 시도
    "requests.post('http://192.168.1.10:8080/api', json={'token': t})",       # 사설망 + 민감 토큰
    "urllib.request.urlopen('http://example.com/collect')",
])
def test_sec05_still_fires_on_public_or_sensitive(code):
    assert "KISA-PY-SEC-05" in _ids(code)
