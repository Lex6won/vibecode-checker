"""엔진 필수 계약(engines.required) + wheel 설치본 신원(build_info.json) + status 계약.

배경(시험운영 준비 2026-09-13): 체커 결과의 engines 는 used/unavailable/failed 만
있어 "어떤 엔진이 빠지면 판정 불가인가"를 소비자(포털)가 하드코딩해야 했다.
필수 엔진이 실패해도 포털이 allow 를 내는 경로가 있었다. 체커가 대상 언어로
required 를 계산해 주면 포털은 required ∩ (failed ∪ unavailable) 만 보면 된다.

wheel 설치본은 git 정보가 없어 어느 커밋인지 말할 수 없었다 — 빌드 스크립트가
패키지 안에 build_info.json 을 남기고 install_identity 가 그것을 읽는다.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from gvskb import cli, diagnostics
from gvskb.scanner import engine_status, required_engines, scan_code, scan_path

REPO = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# engines.required
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("languages,expected", [
    ([], ["regex"]),
    (["python"], ["regex", "python-ast"]),
    (["javascript"], ["regex", "js-taint"]),
    (["typescript"], ["regex", "js-taint"]),
    (["python", "typescript", "javascript"], ["regex", "python-ast", "js-taint"]),
    (["typescript", "python"], ["regex", "python-ast", "js-taint"]),
    (["html"], ["regex", "js-taint"]),
    (["yaml", "markdown"], ["regex"]),
])
def test_required_engines_by_language(languages: list[str], expected: list[str]) -> None:
    assert required_engines(languages) == expected


def test_semgrep_is_never_required() -> None:
    assert "semgrep" not in required_engines(["python", "javascript", "typescript", "html"])


def test_scan_code_python_requires_python_ast() -> None:
    report = scan_code("import os\nos.system(user_input)\n", filename="a.py")
    assert report.engines.required == ["regex", "python-ast"]
    assert "python-ast" in report.engines.used, "필수 엔진이 정상이면 used 에 있어야 한다"


def test_scan_code_typescript_requires_js_taint() -> None:
    report = scan_code("const q = 'x' + req.query.id;\n", filename="a.ts")
    assert report.engines.required == ["regex", "js-taint"]
    assert "js-taint" in report.engines.used


def test_python_syntax_error_in_one_file_is_not_an_engine_failure(tmp_path: Path) -> None:
    """파일 하나의 문법 오류로 python-ast 가 '실패'로 기록되면 Python 프로젝트 전부가
    incomplete 가 된다(과탐). 파싱 실패는 그 파일에서 AST 가 빠진 것이지 엔진 실패가 아니다."""
    (tmp_path / "ok.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "broken.py").write_text("def (:\n  pass\n", encoding="utf-8")
    report = scan_path(str(tmp_path))
    assert report.engines.required == ["regex", "python-ast"]
    assert [e.name for e in report.engines.failed] == []
    assert "python-ast" in report.engines.used


def test_scan_path_mixed_project_requires_both(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "web.tsx").write_text("export const a = 1;\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("# hi\n", encoding="utf-8")
    report = scan_path(str(tmp_path))
    assert report.engines.required == ["regex", "python-ast", "js-taint"]


def test_scan_path_node_only_does_not_require_python_ast(tmp_path: Path) -> None:
    (tmp_path / "index.js").write_text("const a = 1;\n", encoding="utf-8")
    report = scan_path(str(tmp_path))
    assert report.engines.required == ["regex", "js-taint"]


def test_engine_failure_is_recorded_alongside_required() -> None:
    engines = engine_status({"python-ast": "RuntimeError: boom"}, languages=["python"])
    assert engines.required == ["regex", "python-ast"]
    assert [e.name for e in engines.failed] == ["python-ast"]
    assert "python-ast" not in engines.used


def test_required_is_serialized_in_report_json() -> None:
    data = scan_code("x = 1\n", filename="a.py").model_dump(mode="json")
    assert data["engines"]["required"] == ["regex", "python-ast"]


# ---------------------------------------------------------------------------
# build_info.json → install_identity
# ---------------------------------------------------------------------------

def test_install_identity_reads_build_info_from_wheel(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pkg = tmp_path / "gvskb"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("__version__ = '0.3.0'\n", encoding="utf-8")
    (pkg / "build_info.json").write_text(json.dumps({
        "build_commit": "a" * 40, "build_dirty": False, "package_version": "0.3.0",
        "built_at": "2026-09-13T00:00:00+00:00", "builder": "scripts/build_wheel.py",
    }), encoding="utf-8")
    monkeypatch.setattr(diagnostics, "_gvskb_path", lambda: str(pkg))
    monkeypatch.setattr(diagnostics, "_direct_url_metadata", lambda: {})
    identity = diagnostics.install_identity()
    assert identity["commit_id"] == "a" * 40
    assert identity["short_commit"] == "a" * 12
    assert "build_info.json" in identity["commit_source"]
    assert identity["build"]["build_dirty"] is False


def test_install_identity_without_build_info_falls_back_to_git_or_unknown(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pkg = tmp_path / "gvskb"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("__version__ = '0.3.0'\n", encoding="utf-8")
    monkeypatch.setattr(diagnostics, "_gvskb_path", lambda: str(pkg))
    monkeypatch.setattr(diagnostics, "_direct_url_metadata", lambda: {})
    identity = diagnostics.install_identity()
    # 개발 체크아웃에서는 프로세스가 임포트한 git 커밋이 남아 있을 수 있다 — 여기서
    # 고정하는 것은 "build_info 가 없으면 wheel 신원을 주장하지 않는다"는 사실뿐이다.
    assert "build" not in identity
    assert "build_info.json" not in str(identity.get("commit_source"))


def test_install_digest_is_stable_and_ignores_pycache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pkg = tmp_path / "gvskb"
    (pkg / "__pycache__").mkdir(parents=True)
    (pkg / "__init__.py").write_text("x\n", encoding="utf-8")
    (pkg / "__pycache__" / "a.pyc").write_bytes(b"\x00")
    monkeypatch.setattr(diagnostics, "_gvskb_path", lambda: str(pkg))
    first = diagnostics.install_digest()
    (pkg / "__pycache__" / "b.pyc").write_bytes(b"\x01")
    assert diagnostics.install_digest() == first
    assert first["file_count"] == 1
    (pkg / "__init__.py").write_text("y\n", encoding="utf-8")
    assert diagnostics.install_digest()["sha256"] != first["sha256"]


def test_status_json_exposes_ruleset_schema_and_digest(capsys: pytest.CaptureFixture[str]) -> None:
    class Args:
        json = True

    assert cli._cmd_status(Args()) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["scan_report_schema_version"] == 1
    assert payload["ruleset"]["version"] and payload["ruleset"]["digest"]
    assert payload["install_digest"]["sha256"] and payload["install_digest"]["file_count"] > 0
    assert "install_identity" in payload


# ---------------------------------------------------------------------------
# scripts/build_wheel.py — 순수 함수만(pip 실행은 수동 절차에서)
# ---------------------------------------------------------------------------

def _load_build_script():
    spec = importlib.util.spec_from_file_location("build_wheel", REPO / "scripts" / "build_wheel.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def test_build_info_payload_records_commit_dirty_and_version() -> None:
    mod = _load_build_script()
    info = mod.build_info_payload("b" * 40, dirty=True, version="0.3.0")
    assert info["build_commit"] == "b" * 40 and info["build_dirty"] is True
    assert info["package_version"] == "0.3.0" and info["built_at"].endswith("+00:00")


def test_build_script_reads_package_version_from_single_source() -> None:
    mod = _load_build_script()
    from gvskb import __version__
    assert mod.package_version() == __version__
