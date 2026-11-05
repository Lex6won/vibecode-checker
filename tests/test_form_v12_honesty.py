"""서식 8항목이 근거 없이 '적합'을 내지 않는가 — 적대적 검증(2026-11-06) 재현 사례."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from gvskb.form_v12 import NG, OK, REVIEW, UNDETERMINED, attach_form_v12, form_v12_table
from gvskb.scanner import scan_path
from gvskb.scanners.runtime_version import other_images_from_dockerfile, pin_support
from gvskb.schema import ScanReport
from gvskb.sbom_html import render_sbom_html, render_sbom_html_file


def _rows(report: ScanReport) -> dict[str, dict]:
    return {r["key"]: r for r in form_v12_table(report)["items"]}


def _project(tmp_path: Path, files: dict[str, str]) -> ScanReport:
    for rel, text in files.items():
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    return scan_path(str(tmp_path))


def _clean(name: str, **extra) -> dict:
    return {"name": name, "version": "1.0.0", "ecosystem": "pypi", "checked": True, "verdict": "checked_clean",
            "exists": None, **extra}


def _with_deps(report: ScanReport, checks: list[dict], **audit) -> ScanReport:
    report.dependency_audit = {"audits": [{"ecosystem": "pypi", "manifest": "requirements.txt", "checks": checks, **audit}]}
    report.dependency_check = {"mode": "local", "intel": {"state": "ok"}, "packages_parsed": len(checks)}
    return report


# ── 소스 항목 ──────────────────────────────────────────────────────────
def test_nothing_scanned_is_undetermined_not_ok(tmp_path: Path) -> None:
    rows = _rows(_project(tmp_path, {"notes.bin": "x"}))
    for key in ("pii", "secret", "malicious_code"):
        assert rows[key]["result"] == UNDETERMINED, key


def test_truncated_scan_is_undetermined_not_ok(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "zz.py").write_text("y = 2\n", encoding="utf-8")
    report = scan_path(str(tmp_path), max_files=1)
    rows = _rows(report)
    assert report.coverage.truncated is True
    assert rows["secret"]["result"] == UNDETERMINED and "결손" in rows["secret"]["basis"]


def test_clean_full_scan_stays_ok(tmp_path: Path) -> None:
    rows = _rows(_project(tmp_path, {"a.py": "x = 1\n"}))
    assert rows["pii"]["result"] == OK and rows["secret"]["result"] == OK and rows["malicious_code"]["result"] == OK


def test_execution_block_finding_is_not_ok_for_malicious_code(tmp_path: Path) -> None:
    rows = _rows(_project(tmp_path, {"evil.py": "import base64, os\nexec(base64.b64decode(data))\nos.system(cmd)\n"}))
    assert rows["malicious_code"]["result"] in (REVIEW, NG), rows["malicious_code"]


# ── 지원 종료 ──────────────────────────────────────────────────────────
@pytest.mark.parametrize("runtime,spec,expected", [
    ("node", "24.22.1", "supported"), ("node", ">=22", "supported"), ("node", "21", "unknown"), ("node", "23.1.0", "unknown"),
    ("node", "lts/*", "unknown"), ("node", "20", "eol"), ("node", "14", "eol"), ("node", "22.1.0", "outdated"),
    ("python", "3.12", "supported"), ("python", "3", "unknown"), ("python", "3.99", "unknown"), ("python", "3.6", "eol"),
    ("python", "latest", "unknown"), ("next", "16.2.9", "unknown"),
])
def test_pin_support(runtime: str, spec: str, expected: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GVSKB_TODAY", "2026-11-06")
    assert pin_support(runtime, spec) == expected


@pytest.mark.parametrize("files", [
    {".nvmrc": "lts/*\n"},                                    # 수치 없음
    {".nvmrc": "23\n"},                                       # EOL 인데 표에 없음
    {"package.json": '{"name":"a","dependencies":{"next":"16.2.9"}}'},   # 프레임워크만
    {"tests/fixtures/.nvmrc": "24\n"},                        # 시험 경로의 선언
    {"Dockerfile": "FROM python:latest\n"},
    {"Dockerfile": "FROM python\n"},
    {"Dockerfile": "FROM ruby:2.3\n", ".nvmrc": "24\n"},      # 판정 못 하는 이미지가 섞임
    {".github/workflows/ci.yml": "jobs:\n  a:\n    steps:\n      - uses: actions/setup-node@v4\n        with:\n          node-version: 24\n"},
])
def test_eol_is_not_ok_without_confirmed_runtime(files: dict[str, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GVSKB_TODAY", "2026-11-06")
    assert _rows(_project(tmp_path, files))["eol"]["result"] == REVIEW


def test_eol_ok_only_for_confirmed_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GVSKB_TODAY", "2026-11-06")
    row = _rows(_project(tmp_path, {".python-version": "3.12\n"}))["eol"]
    assert row["result"] == OK and "python 3.12" in row["basis"]


def test_real_eol_is_ng_and_fixture_eol_only_review(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GVSKB_TODAY", "2026-11-06")
    assert _rows(_project(tmp_path / "a", {"Dockerfile": "FROM python:3.6\n"}))["eol"]["result"] == NG
    fixture = _project(tmp_path / "b", {"tests/fixtures/Dockerfile": "FROM python:3.6\n"})
    if any(f.rule_id == "GOV-RUNTIME-EOL-001" and f.severity_adjusted for f in fixture.findings):
        assert _rows(fixture)["eol"]["result"] == REVIEW


def test_suppressed_eol_is_not_reported_as_supported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GVSKB_TODAY", "2026-11-06")
    report = _project(tmp_path, {".nvmrc": "14\n"})
    for finding in report.findings:
        if finding.rule_id == "GOV-RUNTIME-EOL-001":
            finding.suppressed = True
    row = _rows(report)["eol"]
    assert row["result"] == REVIEW and "지원 중" not in row["basis"]


def test_other_images_skip_stage_aliases() -> None:
    text = "FROM node:24 AS build\nFROM build\nFROM scratch\nFROM nginx:1.25\nFROM ghcr.io/acme/base@sha256:abc\nFROM python\n"
    assert [p.spec for p in other_images_from_dockerfile(text)] == ["nginx:1.25", "ghcr.io/acme/base@sha256:abc", "python"]


# ── 패키지 항목 ────────────────────────────────────────────────────────
def _source(tmp_path: Path) -> ScanReport:
    return _project(tmp_path, {"a.py": "x = 1\n"})


@pytest.mark.parametrize("extra,audit,word", [
    ({"version_exact": False}, {}, "고정"),
    ({"version": None, "version_resolution": "latest-assumed"}, {}, "고정"),
    ({"verdict": "checked_stale", "cache_stale_sources": ["osv-vulns"]}, {}, "신선도"),
    ({}, {"truncated_count": 5}, "상한"),
])
def test_incomplete_package_evidence_is_review(extra: dict, audit: dict, word: str, tmp_path: Path) -> None:
    rows = _rows(_with_deps(_source(tmp_path), [_clean("a", **extra)], **audit))
    for key in ("public_vuln", "malicious_package"):
        assert rows[key]["result"] == REVIEW and word in rows[key]["basis"], (key, rows[key])


def test_pinned_clean_package_stays_ok(tmp_path: Path) -> None:
    rows = _rows(_with_deps(_source(tmp_path), [_clean("a")]))
    assert rows["public_vuln"]["result"] == OK and rows["malicious_package"]["result"] == OK


def test_malicious_counts_only_in_malicious_item(tmp_path: Path) -> None:
    rows = _rows(_with_deps(_source(tmp_path), [_clean("evil", is_malicious_package=True, verdict="malicious", vulnerability_count=1)]))
    assert rows["malicious_package"]["result"] == NG and rows["public_vuln"]["result"] != NG


def test_possible_has_its_own_action_not_immediate_removal(tmp_path: Path) -> None:
    row = _rows(_with_deps(_source(tmp_path), [_clean("chalk", malicious_possible=[{"id": "MAL-1"}])]))["malicious_package"]
    assert row["result"] == REVIEW and "즉시 제거" not in row["action"] and "정상 패키지" in row["action"]


def test_missing_registry_metadata_is_not_called_missing_repository(tmp_path: Path) -> None:
    row = _rows(_with_deps(_source(tmp_path), [_clean("a", exists=True, registry_metadata=None)]))["unknown_origin"]
    assert "소스 저장소 주소가 없는" not in row["basis"]


def test_form_failure_does_not_lose_the_report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import gvskb.form_v12 as module

    report = _source(tmp_path)
    monkeypatch.setattr(module, "form_v12_table", lambda _r: (_ for _ in ()).throw(RuntimeError("x")))
    with pytest.warns(UserWarning):
        assert attach_form_v12(report).form_v12 is None


# ── SBOM HTML ─────────────────────────────────────────────────────────
def _component(name: str, **props) -> dict:
    return {"type": "library", "name": name, "version": "1.0.0", "bom-ref": f"pkg:npm/{name}@1.0.0", "purl": f"pkg:npm/{name}@1.0.0",
            "properties": [{"name": f"gvskb:{k}", "value": v} for k, v in props.items()]}


def _doc(components: list[dict], **extra) -> dict:
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {"component": {"name": "app", "bom-ref": "app"}},
            "components": components, **extra}


def test_sbom_html_shows_malicious_and_possible() -> None:
    html = render_sbom_html(_doc([
        _component("evil", verdict="malicious", checked="true"),
        _component("chalk", verdict="checked_clean", checked="true", malicious_possible="MAL-1"),
    ]), source_name="s.json", source_sha256="0")
    assert 'data-status="malicious"' in html and "악성 패키지" in html and "악성 권고 — 확인 필요" in html


def test_sbom_html_size_is_not_quadratic_in_shared_dependency() -> None:
    def size(n: int) -> int:
        parents = [_component(f"p{i}") for i in range(n)]
        hub = _component("hub")
        deps = [{"ref": c["bom-ref"], "dependsOn": [hub["bom-ref"]]} for c in parents]
        return len(render_sbom_html(_doc([*parents, hub], dependencies=deps), source_name="s.json", source_sha256="0"))

    small, large = size(200), size(800)
    assert large < small * 8     # 제곱이면 16배


def test_sbom_html_quotes_source_link() -> None:
    html = render_sbom_html(_doc([]), source_name="a#b c%20.json", source_sha256="0")
    assert 'href="a%23b%20c%2520.json"' in html


def test_sbom_report_refuses_to_overwrite_source(tmp_path: Path) -> None:
    source = tmp_path / "x.json"
    source.write_text(json.dumps(_doc([])), encoding="utf-8")
    before = source.read_bytes()
    with pytest.raises(ValueError):
        render_sbom_html_file(source, source)
    assert source.read_bytes() == before


@pytest.mark.parametrize("patch", [
    {"metadata": ["x"]}, {"components": [{"licenses": ["x"]}]}, {"dependencies": ["x"]}, {"vulnerabilities": [{"affects": ["x"]}]},
    {"metadata": {"component": "x"}}, {"vulnerabilities": [{"ratings": ["x"]}]},
])
def test_sbom_report_turns_malformed_structure_into_value_error(patch: dict, tmp_path: Path) -> None:
    source = tmp_path / "x.json"
    source.write_text(json.dumps({**_doc([]), **patch}), encoding="utf-8")
    with pytest.raises(ValueError):
        render_sbom_html_file(source, tmp_path / "x.html")
