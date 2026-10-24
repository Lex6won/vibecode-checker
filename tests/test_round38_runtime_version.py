"""38차 — 프로젝트 런타임 버전(runtime-version): EOL · 보안 수정판 미만. 기준은 config/runtime-baselines.yaml."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from gvskb.scanner import scan_path
from gvskb.scanners.runtime_version import RULE_EOL, RULE_OUTDATED, _parse_version


@pytest.fixture(autouse=True)
def _fixed_today(monkeypatch: pytest.MonkeyPatch):
    # 기준 파일의 as_of 와 같은 날 — 달력이 흘러도 테스트가 흔들리지 않는다.
    monkeypatch.setenv("GVSKB_TODAY", "2026-10-24")


def _w(root: Path, rel: str, text: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def _by(report, rule_id):
    return [f for f in report.findings if f.rule_id == rule_id]


@pytest.mark.parametrize("spec,expected", [
    ("20", (20,)), ("v20.11.1", (20, 11, 1)), ("^22.1.0", (22, 1, 0)), (">=18", (18,)), (">=18 <21", (18,)),
    ("18 || >=20", (18,)), ("20.x", (20,)), ("20-alpine", (20,)), ("3.11-slim", (3, 11)), ("python-3.12.4", (3, 12, 4)),
    ("lts/*", None), ("latest", None), ("node", None), ("*", None),
])
def test_version_spec_lower_bound(spec, expected) -> None:
    assert _parse_version(spec) == expected


def test_dockerfile_node_20_is_eol_and_node_24_is_fine(tmp_path: Path) -> None:
    _w(tmp_path, "Dockerfile.frontend", "FROM node:20-alpine AS builder\nRUN npm ci\nFROM node:20-alpine AS runner\n")
    _w(tmp_path, "backend/Dockerfile", "FROM python:3.11-slim\n")
    _w(tmp_path, "ok/Dockerfile", "FROM node:24-alpine\n")
    r = scan_path(tmp_path)
    hits = _by(r, RULE_EOL)
    assert len(hits) == 1, "같은 파일·같은 런타임은 1건"
    f = hits[0]
    assert f.location.file == "Dockerfile.frontend" and "2026-04-30" in f.evidence and "기준 2026-10-24" in f.evidence
    assert f.confidence == "likely" and f.decision.value == "warn"


def test_python_eol_and_eol_soon(tmp_path: Path) -> None:
    _w(tmp_path, ".python-version", "3.9.18\n")
    _w(tmp_path, "svc/pyproject.toml", '[project]\nname = "x"\nrequires-python = ">=3.10"\n')
    _w(tmp_path, "ok/pyproject.toml", '[project]\nname = "y"\nrequires-python = ">=3.12"\n')
    r = scan_path(tmp_path)
    hits = {f.location.file.replace("\\", "/"): f for f in _by(r, RULE_EOL)}
    assert set(hits) == {".python-version", "svc/pyproject.toml"}
    assert "지원 종료(2025-10-31)" in hits[".python-version"].evidence
    assert "임박" in hits["svc/pyproject.toml"].evidence


def test_node_patch_pin_below_security_release_is_outdated(tmp_path: Path) -> None:
    _w(tmp_path, ".nvmrc", "22.12.0\n")
    _w(tmp_path, "ok/.nvmrc", "22.23.4\n")
    _w(tmp_path, "major/.nvmrc", "22\n")
    r = scan_path(tmp_path)
    hits = _by(r, RULE_OUTDATED)
    assert len(hits) == 1 and hits[0].location.file == ".nvmrc" and "22.23.4" in hits[0].evidence
    assert not _by(r, RULE_EOL)


def test_next_and_electron_from_package_json(tmp_path: Path) -> None:
    _w(tmp_path, "package.json", json.dumps({"name": "x", "version": "1.0.0", "engines": {"node": ">=18"},
                                             "dependencies": {"next": "16.0.10", "electron": "^33.0.0"}}))
    r = scan_path(tmp_path)
    eol = _by(r, RULE_EOL)
    assert {("Node.js" in f.evidence, "Electron" in f.evidence) for f in eol} == {(True, False), (False, True)}
    assert any("node -v 와 무관" in f.evidence for f in eol)
    out = _by(r, RULE_OUTDATED)
    assert len(out) == 1 and "Next.js 16.0.10" in out[0].evidence and "16.2.5" in out[0].evidence


def test_workflow_setup_node_and_unversioned_specs(tmp_path: Path) -> None:
    _w(tmp_path, ".github/workflows/ci.yml", """\
on: push
permissions:
  contents: read
jobs:
  t:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-node@v4
        with:
          node-version: 18
      - uses: actions/setup-node@v4
        with:
          node-version: lts/*
      - run: npm test
""")
    r = scan_path(tmp_path)
    hits = _by(r, RULE_EOL)
    assert len(hits) == 1 and "setup-node" in hits[0].evidence and "메이저 18" in hits[0].evidence


def test_baselines_file_is_loaded_and_dated() -> None:
    from gvskb.scanners.runtime_version import load_baselines
    b = load_baselines()
    assert b["as_of"] == "2026-10-24"
    assert b["node"]["min_secure"]["24"] == "24.22.1"
