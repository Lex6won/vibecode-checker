"""락파일 파서 — 전이 의존성을 검사 범위에 넣는 경로.

**왜 이 테스트가 중요한가.** 매니페스트만 검사하고 "의존성 검사 통과"를 보여 주면
트리의 일부만 본 것을 전부 본 것처럼 알리게 된다. 실무 취약점은 대부분 전이
의존성에 있고, 전이 의존성은 락파일에만 있다.

형식별 실제 표기 차이(pnpm 의 `/foo/1.2.3` vs `/foo@1.2.3`, yarn 클래식 vs berry,
package-lock v1 중첩 트리 vs v2/v3 평면 경로)가 파싱 실패의 주 원인이므로
버전대별 샘플을 모두 고정한다.
"""
from __future__ import annotations

import json

from gvskb.tools.lockfiles import detect_format, parse_lockfile


def _names(result: dict) -> set[str]:
    return {p["name"] for p in result["packages"]}


def _pairs(result: dict) -> set[tuple[str, str | None]]:
    return {(p["name"], p["version"]) for p in result["packages"]}


# ---------------------------------------------------------------------------
# package-lock.json
# ---------------------------------------------------------------------------

_PLOCK_V3 = json.dumps({
    "name": "app",
    "lockfileVersion": 3,
    "packages": {
        "": {"name": "app", "version": "1.0.0"},
        "node_modules/lodash": {"version": "4.17.21"},
        "node_modules/@babel/core": {"version": "7.24.0"},
        "node_modules/a/node_modules/lodash": {"version": "3.10.1"},
        "node_modules/linked": {"link": True, "resolved": "packages/linked"},
    },
})


def test_package_lock_v3_reads_nested_and_scoped() -> None:
    r = parse_lockfile(_PLOCK_V3)
    assert r is not None and r["ecosystem"] == "npm"
    pairs = _pairs(r)
    assert ("lodash", "4.17.21") in pairs
    assert ("@babel/core", "7.24.0") in pairs
    # 중첩 설치된 **다른 버전**도 별도 항목이어야 한다 — 취약한 쪽이 하나라도
    # 있으면 위험은 실재하므로 이름만으로 합치면 안 된다.
    assert ("lodash", "3.10.1") in pairs


def test_package_lock_excludes_project_itself_and_workspace_links() -> None:
    r = parse_lockfile(_PLOCK_V3)
    assert "app" not in _names(r), "루트 프로젝트 자신은 의존성이 아니다"
    assert "linked" not in _names(r), "워크스페이스 링크는 실제 패키지가 아니다"


def test_package_lock_v1_walks_the_nested_tree() -> None:
    text = json.dumps({
        "name": "app",
        "lockfileVersion": 1,
        "dependencies": {
            "express": {
                "version": "4.18.2",
                "dependencies": {"accepts": {"version": "1.3.8"}},
            },
        },
    })
    r = parse_lockfile(text)
    assert r is not None
    # v1 은 중첩 트리다 — 얕게 읽으면 전이 의존성(accepts)을 통째로 놓친다.
    assert _pairs(r) == {("express", "4.18.2"), ("accepts", "1.3.8")}


# ---------------------------------------------------------------------------
# poetry.lock · uv.lock (TOML)
# ---------------------------------------------------------------------------


def test_poetry_lock() -> None:
    r = parse_lockfile('[[package]]\nname = "requests"\nversion = "2.31.0"\n\n'
                       '[[package]]\nname = "urllib3"\nversion = "2.0.7"\n')
    assert r is not None and r["ecosystem"] == "pypi"
    assert _pairs(r) == {("requests", "2.31.0"), ("urllib3", "2.0.7")}


def test_uv_lock_is_distinguished_from_poetry() -> None:
    """판정에는 영향이 없지만 보고서 표기가 정확해야 한다."""
    text = ('[[package]]\nname = "flask"\nversion = "3.0.0"\n'
            'requires-dist = [{ name = "werkzeug" }]\n\n'
            '[[package]]\nname = "werkzeug"\nversion = "3.0.1"\n')
    r = parse_lockfile(text)
    assert r is not None and r["format"] == "uv.lock"
    assert _pairs(r) == {("flask", "3.0.0"), ("werkzeug", "3.0.1")}


# ---------------------------------------------------------------------------
# pnpm-lock.yaml — 버전대별로 키 형식이 다르다
# ---------------------------------------------------------------------------


def test_pnpm_v9_at_style_keys() -> None:
    text = ("lockfileVersion: '9.0'\npackages:\n"
            "  /lodash@4.17.21:\n    resolution: {integrity: sha512-x}\n"
            "  /@babel/core@7.24.0(react@18.0.0):\n    resolution: {integrity: sha512-y}\n")
    r = parse_lockfile(text)
    assert r is not None
    pairs = _pairs(r)
    assert ("lodash", "4.17.21") in pairs
    # peer 해시가 붙어도 버전만 떼어내야 한다
    assert ("@babel/core", "7.24.0") in pairs


def test_pnpm_v6_slash_style_keys() -> None:
    text = ("lockfileVersion: 6.0\npackages:\n"
            "  /lodash/4.17.21:\n    resolution: {integrity: sha512-x}\n"
            "  /@scope/pkg/1.2.3:\n    resolution: {integrity: sha512-y}\n")
    r = parse_lockfile(text)
    assert r is not None
    assert _pairs(r) == {("lodash", "4.17.21"), ("@scope/pkg", "1.2.3")}


# ---------------------------------------------------------------------------
# yarn.lock — 클래식(v1)과 berry(v2+)는 형식 자체가 다르다
# ---------------------------------------------------------------------------


def test_yarn_classic() -> None:
    text = ('# yarn lockfile v1\n\n\n'
            '"@babel/core@^7.0.0", "@babel/core@^7.1.0":\n'
            '  version "7.24.0"\n'
            '  resolved "https://registry.yarnpkg.com/..."\n\n'
            'lodash@^4.17.0:\n  version "4.17.21"\n')
    r = parse_lockfile(text)
    assert r is not None
    assert _pairs(r) == {("@babel/core", "7.24.0"), ("lodash", "4.17.21")}


def test_yarn_berry_is_yaml() -> None:
    text = ('__metadata:\n  version: 6\n\n'
            '"lodash@npm:^4.17.0":\n  version: 4.17.21\n'
            '  resolution: "lodash@npm:4.17.21"\n\n'
            '"@babel/core@npm:^7.0.0":\n  version: 7.24.0\n')
    r = parse_lockfile(text)
    assert r is not None
    assert _pairs(r) == {("lodash", "4.17.21"), ("@babel/core", "7.24.0")}


# ---------------------------------------------------------------------------
# 실패 처리 — 0건을 '이상 없음'으로 바꾸지 않는다
# ---------------------------------------------------------------------------


def test_unknown_format_returns_none_not_empty_success() -> None:
    """형식을 못 알아보면 None — 호출자가 '검사 안 됨'으로 다뤄야 한다."""
    assert parse_lockfile("this is not a lockfile") is None
    assert parse_lockfile("") is None


def test_broken_json_yields_zero_packages_not_a_crash() -> None:
    r = parse_lockfile('{"lockfileVersion": 3, "packages": {')
    assert r is not None and r["packages"] == []


def test_filename_wins_over_content_sniffing() -> None:
    """파일명이 있으면 가장 확실한 신호다."""
    assert detect_format("[[package]]\nname='x'\n", "uv.lock") == ("uv.lock", "pypi")
    assert detect_format("[[package]]\nname='x'\n", "poetry.lock") == ("poetry.lock", "pypi")


# ---------------------------------------------------------------------------
# CLI 통합 — 락파일이 매니페스트를 대체한다
# ---------------------------------------------------------------------------


def test_lockfile_supersedes_manifest_in_same_directory(tmp_path, monkeypatch) -> None:
    """같은 디렉터리에 둘 다 있으면 락파일만 검사한다.

    락파일은 매니페스트의 상위 집합(전이 의존성 포함, 버전 고정)이다. 둘 다
    검사하면 같은 패키지를 두 번 조회하면서 결과는 락파일 쪽이 항상 더 정확하다.
    """
    monkeypatch.setenv("GVSKB_MODE", "offline")
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path / "cache"))
    (tmp_path / "requirements.txt").write_text("flask==3.0.0\n", encoding="utf-8")
    (tmp_path / "poetry.lock").write_text(
        '[[package]]\nname = "flask"\nversion = "3.0.0"\n\n'
        '[[package]]\nname = "werkzeug"\nversion = "3.0.1"\n',
        encoding="utf-8",
    )

    from gvskb.cli import _run_dependency_audit  # noqa: PLC0415
    from gvskb.scanner import scan_path

    report = scan_path(tmp_path)
    audit = _run_dependency_audit(tmp_path, report, env_grade=None, include_installed=False)
    assert audit is not None
    manifests = {a.get("manifest") for a in audit["audits"]}
    assert manifests == {"poetry.lock"}, f"매니페스트가 중복 검사됐다: {manifests}"
    only = audit["audits"][0]
    assert only["source_kind"] == "lockfile"
    # 전이 의존성이 실제로 들어왔는지 — 이게 이 기능의 존재 이유다.
    assert {p["name"] for p in only["packages"]} == {"flask", "werkzeug"}
