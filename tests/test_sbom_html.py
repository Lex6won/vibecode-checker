"""SBOM HTML 열람 보고서(설계 A3) — 원본 값만 옮기고, 한 파일로 열리며, 스크립트가 막혀도 내용이 보인다."""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from gvskb.sbom_html import MISSING, render_sbom_html, render_sbom_html_file

REPO = Path(__file__).resolve().parent.parent


def _doc() -> dict:
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": "urn:uuid:00000000-0000-0000-0000-000000000001",
        "metadata": {"timestamp": "2026-11-04T00:00:00Z", "tools": {"components": [{"name": "gvskb", "version": "0.6.1"}]},
                     "component": {"bom-ref": "root:demo", "name": "demo-app"}},
        "components": [
            {"bom-ref": "pkg:pypi/flask@3.1.0", "name": "flask", "version": "3.1.0", "type": "library", "purl": "pkg:pypi/flask@3.1.0",
             "licenses": [{"license": {"id": "BSD-3-Clause"}}],
             "properties": [{"name": "gvskb:verdict", "value": "vulnerable"}, {"name": "gvskb:checked", "value": "true"}]},
            {"bom-ref": "pkg:npm/<script>alert(1)</script>@1.0.0", "name": "<script>alert(1)</script>", "version": "1.0.0",
             "type": "library", "purl": "pkg:npm/%3Cscript%3E@1.0.0"},
            {"bom-ref": "pkg:maven/org.example/lib@2.0", "name": "lib", "version": "2.0", "purl": "pkg:maven/org.example/lib@2.0"},
        ],
        "dependencies": [{"ref": "root:demo", "dependsOn": ["pkg:pypi/flask@3.1.0", "pkg:npm/<script>alert(1)</script>@1.0.0"]}],
        "vulnerabilities": [{"id": "GHSA-xxxx-yyyy-zzzz", "description": "test advisory", "ratings": [{"severity": "high"}],
                             "affects": [{"ref": "pkg:pypi/flask@3.1.0"}], "source": {"name": "OSV", "url": "https://osv.dev/x"}}],
    }


def test_values_are_escaped_and_embedded_json_cannot_close_the_script() -> None:
    page = render_sbom_html(_doc(), source_name="demo.sbom.cdx.json", source_sha256="ab" * 32)
    assert "<script>alert(1)</script>" not in page
    data = re.search(r'<script id="sbom-data" type="application/json">(.*?)</script>', page, re.S).group(1)
    assert "<" not in data and json.loads(data)["root_name"] == "demo-app"


def test_single_file_without_external_resources() -> None:
    page = render_sbom_html(_doc(), source_name="demo.sbom.cdx.json", source_sha256="ab" * 32)
    assert "<link" not in page and "sbom-viewer.js" not in page and "woff" not in page
    assert not re.search(r'<script[^>]+src=', page)
    assert not re.search(r'url\(\s*["\']?https?:', page)
    # 원본 JSON 은 같은 폴더의 파일로만 가리킨다.
    assert 'href="demo.sbom.cdx.json" download' in page


def test_all_panes_are_visible_without_script() -> None:
    page = render_sbom_html(_doc(), source_name="demo.sbom.cdx.json", source_sha256="ab" * 32)
    for pane in ("packages", "dependencies", "vulnerabilities", "provenance"):
        tag = re.search(rf'<section id="pane-{pane}"[^>]*>', page).group(0)
        assert "hidden" not in tag, pane
    assert "html:not(.js) .tabs" in page and "classList.add('js')" in page


def test_missing_values_are_not_invented() -> None:
    page = render_sbom_html(_doc(), source_name="demo.sbom.cdx.json", source_sha256="ab" * 32)
    data = json.loads(re.search(r'<script id="sbom-data" type="application/json">(.*?)</script>', page, re.S).group(1))
    by_name = {c["name"]: c for c in data["components"]}
    assert by_name["flask"]["licenses"] == "BSD-3-Clause"
    assert by_name["lib"]["licenses"] == MISSING and by_name["lib"]["supplier"] == MISSING
    assert by_name["lib"]["kind"] == "unknown", "a component with no recorded relation is not called direct"
    assert by_name["flask"]["vulnerability_count"] == 1
    assert "취약점 미기록 ≠ 안전 보증" in page


def test_ecosystem_filter_comes_from_the_data() -> None:
    page = render_sbom_html(_doc(), source_name="demo.sbom.cdx.json", source_sha256="ab" * 32)
    options = re.search(r'<select id="ecosystem">(.*?)</select>', page).group(1)
    assert "<option>PyPI</option>" in options and "<option>npm</option>" in options and "<option>Maven</option>" in options


def test_rejects_non_cyclonedx() -> None:
    with pytest.raises(ValueError):
        render_sbom_html({"spdxVersion": "SPDX-2.3"}, source_name="x.json", source_sha256="0" * 64)


def test_file_helper_and_cli_write_stem_sbom_html(tmp_path: Path) -> None:
    src = tmp_path / "proj_2026.sbom.cdx.json"
    src.write_text(json.dumps(_doc()), encoding="utf-8")
    out = render_sbom_html_file(src)
    assert out.endswith("proj_2026.sbom.html") and Path(out).exists()
    target = tmp_path / "custom.html"
    proc = subprocess.run([sys.executable, "-m", "gvskb.cli", "sbom-report", str(src), "-o", str(target)],
                          capture_output=True, text=True, encoding="utf-8", cwd=str(REPO),
                          env={**__import__("os").environ, "PYTHONPATH": str(REPO / "src"), "PYTHONUTF8": "1"})
    assert proc.returncode == 0, proc.stderr[-400:]
    assert target.exists() and "SBOM 구성요소·의존관계 보고서" in target.read_text(encoding="utf-8")
    bad = tmp_path / "bad.json"
    bad.write_text("{}", encoding="utf-8")
    proc = subprocess.run([sys.executable, "-m", "gvskb.cli", "sbom-report", str(bad)], capture_output=True, text=True,
                          encoding="utf-8", cwd=str(REPO),
                          env={**__import__("os").environ, "PYTHONPATH": str(REPO / "src"), "PYTHONUTF8": "1"})
    assert proc.returncode == 2
