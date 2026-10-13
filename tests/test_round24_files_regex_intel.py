"""31차 — 파일 선정 · 정규식 여러 줄 패턴 · 비밀 어휘 · 인텔 자동 갱신 · 버전별 라이선스
(전면 점검 docs/40 §3-1·§3-4 + 코덱스 P2).

- `.env`·`.env.local`·`.npmrc`·`web.config` 가 검사된다(예전: suffix 가 ''·'.local' 이라 한 번도 안 봄)
- `.jsp/.ejs/.hbs/.ipynb` 검사
- 거대한 한 줄(JSON 리터럴)이 있어도 파일은 검사되고, 그 줄은 비밀값 룰로만 본다
- 미니파이드 산출물(credentials.json 한 줄)도 비밀값 룰은 돈다
- `migration_20240101.js` 는 해시 파일명이 아니다
- `vendor/` 제외는 기록된다
- 여러 줄 패턴(빈 catch 블록)이 파일 단위로 맞는다
- `/**/ 코드` 줄은 주석이 아니다
- 비밀 어휘: AWS_SECRET_ACCESS_KEY · ENCRYPTION_KEY · signingKey · YAML secret_access_key
- `--check-deps` 전 인텔 자동 갱신 호출 · 신선도 기본 2일
- 핀 버전이 최신과 다르면 그 버전의 라이선스를 쓴다
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from gvskb import cli
from gvskb.scanner import scan_code, scan_path
from gvskb.scanners import regex_scanner

_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzQ9kL2pQ"


def _write(p: Path, content: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def _secret_findings(report) -> list:
    return [f for f in report.findings if f.rule_id.startswith(("GOV-SECRET", "KISA-PY-SEC-06", "KISA-JS-SEC-06"))]


# ---------------------------------------------------------------------------
# 파일 선정
# ---------------------------------------------------------------------------

def test_dotenv_family_and_rc_files_are_scanned(tmp_path: Path) -> None:
    _write(tmp_path / ".env", "DB_PASSWORD=gg2026SecureP@ss\n")
    _write(tmp_path / ".env.local", "API_KEY=sk-abcdefghijklmnopqrstuvwxyz123456\n")
    _write(tmp_path / ".npmrc", "//registry.npmjs.org/:_authToken=npm_" + "A1b2C3d4" * 4 + "Zz9Y\n")
    _write(tmp_path / "web.config", '<add key="password" value="gg2026SecureP@ss" />\n')
    r = scan_path(tmp_path)
    scanned = {s.replace("\\", "/") for s in r.scanned_files}
    assert {".env", ".env.local", ".npmrc", "web.config"} <= scanned
    files_with_secret = {f.location.file.replace("\\", "/") for f in _secret_findings(r)}
    assert ".env" in files_with_secret and ".env.local" in files_with_secret and ".npmrc" in files_with_secret


def test_dotenv_gets_config_language_so_code_rules_stay_quiet() -> None:
    assert regex_scanner._infer_language(".env.local", None) == "config"
    assert regex_scanner._infer_language("deploy/.env.production", None) == "config"
    assert regex_scanner._infer_language(".npmrc", None) == "config"


def test_template_and_notebook_extensions_are_scanned(tmp_path: Path) -> None:
    _write(tmp_path / "view.jsp", '<script>document.getElementById("x").innerHTML = location.hash;</script>\n')
    _write(tmp_path / "page.ejs", "<%= user %>\n")
    nb = {"cells": [{"cell_type": "code", "source": ['PASSWORD = "gg2026SecureP@ss"\n']}]}
    _write(tmp_path / "work.ipynb", json.dumps(nb))
    r = scan_path(tmp_path)
    scanned = {s.replace("\\", "/") for s in r.scanned_files}
    assert {"view.jsp", "page.ejs", "work.ipynb"} <= scanned


def test_giant_line_does_not_drop_the_file(tmp_path: Path) -> None:
    normal = "\n".join(f"const v{i} = {i};" for i in range(300))
    giant = "const CATALOG = " + json.dumps([{"id": i, "name": "x" * 40} for i in range(600)]) + ";"
    code = normal + "\n" + giant + "\nel.innerHTML = location.hash;\n"
    _write(tmp_path / "demo.js", code)
    r = scan_path(tmp_path)
    assert "demo.js" in {s.replace("\\", "/") for s in r.scanned_files}
    assert any("innerHTML" in (f.evidence or "") or "XSS" in f.rule_id for f in r.findings)


def test_secret_in_giant_line_is_still_found(tmp_path: Path) -> None:
    padding = ",".join(f'"k{i}":"v{i}"' for i in range(3000))
    line = '{' + padding + ', "aws_secret_access_key": "' + _KEY + '"}'
    _write(tmp_path / "app.js", "const x = 1;\n" + "const CFG = " + line + ";\n")
    r = scan_path(tmp_path)
    hits = _secret_findings(r)
    assert hits and hits[0].location.line == 2


def test_minified_artifact_still_gets_secret_rules(tmp_path: Path) -> None:
    body = '{"type":"service_account","project_id":"demo",' + '"pad":"' + "x" * 2500 + '",' \
        + '"private_key":"' + _KEY + _KEY + '"}'
    _write(tmp_path / "credentials.json", body)
    r = scan_path(tmp_path)
    assert any(s.path.replace("\\", "/") == "credentials.json" for s in r.skipped_files)
    assert _secret_findings(r), "빌드 산출물로 빠져도 비밀값 룰은 돌아야 한다"


def test_date_stamped_name_is_not_a_hashed_asset(tmp_path: Path) -> None:
    _write(tmp_path / "migration_20240101.js", "el.innerHTML = location.hash;\n")
    _write(tmp_path / "app-3f9a2c1b.js", "el.innerHTML = location.hash;\n")
    r = scan_path(tmp_path)
    scanned = {s.replace("\\", "/") for s in r.scanned_files}
    assert "migration_20240101.js" in scanned
    assert "app-3f9a2c1b.js" not in scanned


def test_vendor_dir_exclusion_is_recorded(tmp_path: Path) -> None:
    _write(tmp_path / "vendor" / "lib.py", "x = 1\n")
    _write(tmp_path / "main.py", "x = 1\n")
    r = scan_path(tmp_path)
    assert any(s.path == "vendor/" and "제외 디렉터리" in s.reason for s in r.skipped_files)


# ---------------------------------------------------------------------------
# 정규식 — 여러 줄 패턴 · 주석 경계
# ---------------------------------------------------------------------------

def test_multiline_empty_catch_block_is_found() -> None:
    code = """
try {
  run();
} catch (e) {
  // ignore
}
"""
    r = scan_code(code, filename="a.js")
    assert any(f.rule_id == "KISA-JS-ERR-03" for f in r.findings)


def test_multiline_pattern_respects_inline_ignore() -> None:
    # JS 는 바로 윗줄 단독 주석 형태만 인정한다(같은 줄 무시는 정규식 리터럴 모호성 때문에 미지원).
    code = """
try { run(); }
// gvskb: ignore KISA-JS-ERR-03
catch (e) {
  // ignore
}
"""
    r = scan_code(code, filename="a.js")
    assert not any(f.rule_id == "KISA-JS-ERR-03" for f in r.findings)


def test_multiline_patterns_are_compiled_separately() -> None:
    from gvskb.scanners.regex_scanner import RULES
    multi = [r for r in RULES if r.get("multi_patterns")]
    assert multi, "줄바꿈을 품은 패턴이 있는 룰이 하나도 분리되지 않았다"
    for r in multi:
        assert all(p not in r["line_patterns"] for p in r["multi_patterns"])


def test_code_after_block_comment_is_not_a_comment_line() -> None:
    r = scan_code("/**/ document.body.innerHTML = location.hash;\n", filename="a.js")
    assert any("XSS" in f.rule_id or "innerHTML" in (f.evidence or "") for f in r.findings)
    r2 = scan_code("/* note */\n", filename="a.js")
    assert r2.findings == []


# ---------------------------------------------------------------------------
# 비밀 어휘
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("line", [
    f'AWS_SECRET_ACCESS_KEY = "{_KEY}"',
    'ENCRYPTION_KEY = "9f8e7d6c5b4a39281706f5e4d3c2b1a0"',
    'const signingKey = "H3xK9mQ2pR7sT1uV5wY8zB4nC6";',
    'MASTER_KEY: "9f8e7d6c5b4a39281706f5e4d3c2b1a0"',
    'session_secret = "H3xK9mQ2pR7sT1uV5wY8zB4nC6"',
])
def test_qualified_secret_names_are_found(line: str) -> None:
    r = scan_code(line + "\n", filename="config.py" if "const" not in line else "config.js")
    assert _secret_findings(r), line


@pytest.mark.parametrize("line", [
    'api_key_header = "X-Upstream-Api-Key"',
    'ENCRYPTION_KEY = os.environ["ENCRYPTION_KEY"]',
    'PRIVATE_KEY = "${PRIVATE_KEY}"',
    'cache_key = "user:profile:v2:" + uid',
    'sort_key = "created_at_desc"',
])
def test_non_secret_key_names_stay_quiet(line: str) -> None:
    r = scan_code(line + "\n", filename="config.py")
    assert not _secret_findings(r), line


def test_yaml_secret_access_key_unquoted() -> None:
    r = scan_code(f"aws:\n  secret_access_key: {_KEY}\n", filename="settings.yaml")
    assert _secret_findings(r)


# ---------------------------------------------------------------------------
# 인텔
# ---------------------------------------------------------------------------

def test_default_intel_freshness_is_two_days() -> None:
    from gvskb.intel.cache import DEFAULT_INTEL_MAX_AGE_DAYS
    assert DEFAULT_INTEL_MAX_AGE_DAYS == 2


def test_check_deps_triggers_auto_intel_refresh(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict] = []

    class _Res:
        attempted = True
        ok = True
        source = "https://example/bundle.zip"
        error = ""

    def fake_update(**kw):
        calls.append(kw)
        return _Res()

    import gvskb.intel.autopull as ap
    monkeypatch.setattr(ap, "maybe_auto_update", fake_update)
    cli._auto_refresh_intel()
    assert calls and calls[0]["verbose"] is False


def test_auto_refresh_failure_does_not_raise(monkeypatch: pytest.MonkeyPatch) -> None:
    import gvskb.intel.autopull as ap

    def boom(**kw):
        raise RuntimeError("network down")

    monkeypatch.setattr(ap, "maybe_auto_update", boom)
    cli._auto_refresh_intel()   # 예외 없이 끝나야 한다


# ---------------------------------------------------------------------------
# 버전별 라이선스
# ---------------------------------------------------------------------------

def test_pinned_version_license_overrides_latest(monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio

    from gvskb.tools import package_metadata as pm

    latest_payload = {
        "info": {"version": "9.0.0", "license": "MIT"},
        "releases": {"1.0.0": [{"upload_time_iso_8601": "2020-01-01T00:00:00Z"}],
                     "9.0.0": [{"upload_time_iso_8601": "2026-01-01T00:00:00Z"}]},
    }

    class _Resp:
        status_code = 200

        def __init__(self, payload):
            self._p = payload

        def json(self):
            return self._p

    class _Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url):
            if url.endswith("/1.0.0/json"):
                return _Resp({"info": {"version": "1.0.0", "license": "AGPL-3.0"}})
            return _Resp(latest_payload)

    monkeypatch.setattr(pm.httpx, "AsyncClient", _Client)
    monkeypatch.delenv("GVSKB_MODE", raising=False)
    meta = asyncio.run(pm.fetch_registry_metadata("demo", "pypi", version="1.0.0"))
    assert meta.license == "AGPL-3.0" and meta.latest_version == "9.0.0"
    meta_latest = asyncio.run(pm.fetch_registry_metadata("demo", "pypi", version="9.0.0"))
    assert meta_latest.license == "MIT"
