"""자기검사 12차 — 체커 **자신의** 공격면(서버 운영 관점).

룰 검사는 제품 코드 0건이었지만 룰은 정규식이다. 재점검(2026-08-29)에서 직접 찔러
확인한 것: 인텔 번들 반입의 zip-slip(캐시 밖에 실제로 파일이 쓰였다) · 예측 가능한
임시 파일명 · sha256 없는 캐시 통과 · 심볼릭 링크 추적 · pyproject.toml 을 못 읽어
체커가 자기 의존성을 한 번도 검사하지 못한 것 · 마크다운 증거의 백틱 탈출.
"""
from __future__ import annotations

import hashlib
import json
import os
import zipfile
from pathlib import Path

import pytest

from gvskb.intel.bundle import MANIFEST_NAME, _CACHES_PREFIX, _is_safe_member_name, import_bundle
from gvskb.scanner import parse_manifest_packages, scan_path


def _bundle(tmp_path: Path, fname: str, data: bytes = b'{"items": []}') -> Path:
    z = tmp_path / "b.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr(MANIFEST_NAME, json.dumps({"files": [
            {"filename": fname, "source_id": "x", "sha256": hashlib.sha256(data).hexdigest()}]}))
        zf.writestr(_CACHES_PREFIX + fname, data)
    return z


# ── zip-slip ──
@pytest.mark.parametrize("bad", ["../../marker.json", "..\\marker.json", "/etc/marker.json",
                                 "C:evil.json", "a/b.json", "..", ".hidden"])
def test_bundle_rejects_path_traversal_names(tmp_path: Path, bad: str):
    cache = tmp_path / "cache" / "deep"
    res = import_bundle(_bundle(tmp_path, bad), cache_dir=cache)
    assert res["ok"] is False and "경로" in res["error"]
    assert not (tmp_path / "marker.json").exists() and not (tmp_path / "cache" / "marker.json").exists()


def test_bundle_accepts_plain_name_and_writes_inside_cache(tmp_path: Path):
    cache = tmp_path / "cache"
    res = import_bundle(_bundle(tmp_path, "osv-malicious.json"), cache_dir=cache)
    assert res["ok"] is True and (cache / "osv-malicious.json").exists()


def test_safe_member_name_rules():
    assert _is_safe_member_name("cisa-kev.json")
    for bad in ("", ".", "..", "a/b", "a\\b", "c:x", ".env", "-x"):
        assert not _is_safe_member_name(bad), bad


# ── 캐시 무결성: sha256 없는 항목은 쓰지 않는다 ──
def test_cache_without_sha256_is_rejected(tmp_path: Path, capsys):
    from gvskb.intel.cache import IntelCache
    c = IntelCache(tmp_path)
    p = c.path_for("osv-malicious")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"source_id": "osv-malicious", "items": [{"name": "evil"}]}), encoding="utf-8")
    assert c.load("osv-malicious") is None
    assert "sha256 이 없는" in capsys.readouterr().err


# ── 자동 갱신 임시 파일: 예측 가능한 고정 이름을 쓰지 않는다 ──
def test_autopull_no_fixed_temp_name():
    src = Path("src/gvskb/intel/autopull.py").read_text(encoding="utf-8")
    assert 'gettempdir()) / "gvskb-autopull-bundle.zip"' not in src   # 고정 경로 조립 코드
    assert "mkstemp" in src and "MAX_BUNDLE_BYTES" in src


# ── 심볼릭 링크는 따라가지 않는다 ──
def test_symlinked_file_is_skipped_not_read(tmp_path: Path):
    outside = tmp_path / "outside.py"
    outside.write_text('password = "hunter2plus9"\n', encoding="utf-8")
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "ok.py").write_text("x = 1\n", encoding="utf-8")
    try:
        os.symlink(outside, proj / "link.py")
    except (OSError, NotImplementedError):
        pytest.skip("이 계정은 심볼릭 링크를 만들 수 없다")
    rep = scan_path(str(proj))
    assert not rep.findings
    assert any("심볼릭 링크" in s.reason for s in rep.skipped_files)


# ── pyproject.toml 을 매니페스트로 읽는다 ──
def test_pyproject_pep621_and_poetry_are_parsed():
    text = '''
[project]
name = "x"
dependencies = [
  "fastmcp>=2.0.0,<4",
  "pydantic[email]>=2.0,<3 ; python_version >= '3.11'",
  "requests==2.19.1",
  "mylib @ git+https://example.com/x.git",
]
[project.optional-dependencies]
dev = ["pytest>=8.0,<10"]
[tool.poetry.dependencies]
python = "^3.11"
flask = "^0.12.2"
pyyaml = "5.3.1"
[tool.poetry.group.dev.dependencies]
ruff = "*"
'''
    pk = {p["name"]: p for p in parse_manifest_packages(text, "pypi")}
    assert set(pk) == {"fastmcp", "pydantic", "requests", "mylib", "pytest", "flask", "pyyaml", "ruff"}
    assert pk["requests"]["version"] == "2.19.1" and pk["requests"]["version_exact"]
    assert pk["fastmcp"]["version"] == "2.0.0" and not pk["fastmcp"]["version_exact"]
    assert pk["pyyaml"]["version"] == "5.3.1" and pk["pyyaml"]["version_exact"]
    assert pk["flask"]["version"] == "0.12.2" and not pk["flask"]["version_exact"]
    assert pk["mylib"]["version"] is None and pk["ruff"]["version"] is None


def test_requirements_txt_parsing_unchanged():
    pk = parse_manifest_packages("flask==0.12.2\nrequests>=2.19\n# c\n-r base.txt\n", "pypi")
    assert [(p["name"], p["version"], p["version_exact"]) for p in pk] == [
        ("flask", "0.12.2", True), ("requests", "2.19", False)]


def test_check_deps_picks_up_pyproject(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    import subprocess, sys
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="x"\ndependencies=["flask==0.12.2"]\n', encoding="utf-8")
    out = tmp_path / "r.json"
    subprocess.run([sys.executable, "-m", "gvskb.cli", "scan", str(tmp_path), "--check-deps",
                    "--format", "json", "--output", str(out), "--fail-on", "never"],
                   env={**os.environ, "PYTHONPATH": "src", "PYTHONUTF8": "1", "GVSKB_MODE": "offline"},
                   capture_output=True, text=True)
    data = json.loads(out.read_text(encoding="utf-8"))
    audits = data["dependency_audit"]["audits"]
    assert audits and audits[0]["ecosystem"] == "pypi"
    assert [p["name"] for p in audits[0]["packages"]] == ["flask"]


# ── 마크다운 증거의 백틱 탈출 ──
def test_markdown_evidence_with_backtick_stays_inside_code():
    from gvskb.report import _md_code
    assert _md_code("eval(x)") == "`eval(x)`"
    s = _md_code('eval("`; rm -rf /`")')
    assert s.startswith("`` ") and s.endswith(" ``")


# ── 버전 존재 비교는 PEP 440 정규화로 ──
def test_release_key_matches_normalized_version():
    from gvskb.tools.package_metadata import _match_release_key, _pep440_key
    rel = {"0.27.0": [], "1.0": [], "2.1.3": []}
    assert _match_release_key("0.27", rel) == "0.27.0"
    assert _match_release_key("1.0.0", rel) == "1.0"
    assert _match_release_key("v2.1.3", rel) == "2.1.3"
    assert _match_release_key("2.1.4", rel) is None
    assert _pep440_key("1.0.0.0") == "1" and _pep440_key("01.02") == "1.2"


def test_bounded_missing_version_is_unknown_not_high():
    """`pkg>=9.9` 의 하한이 실재하지 않으면 오타·자리차지가 아니다 — 판정 불가로 남긴다."""
    import asyncio
    from unittest.mock import patch
    from gvskb.schema import PackageRegistryMetadata
    from gvskb.tools import check_package as cp
    meta = PackageRegistryMetadata(name="httpx", ecosystem="pypi", exists=True, latest_version="0.28.1",
                                   version_exists=False)
    async def fake_meta(*a, **k): return meta
    async def fake_osv(*a, **k): return {}
    with patch.object(cp, "fetch_registry_metadata", fake_meta), patch.object(cp, "_osv_query", fake_osv):
        bounded = asyncio.run(cp.check_package_impl("httpx", "pypi", version="9.9", version_exact=False))
        exact = asyncio.run(cp.check_package_impl("httpx", "pypi", version="9.9", version_exact=True))
    assert bounded["verdict"] == "unknown" and bounded["verdict_severity"] == "low"
    assert exact["verdict"] == "version_not_found" and exact["verdict_severity"] == "high"
