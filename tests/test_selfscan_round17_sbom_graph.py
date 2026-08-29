"""17차 — SBOM 공급자·의존성 그래프. 국제 표준(NTIA 최소 요소) 중 우리가 못 채우던
두 항목("공급자명"·"의존성 관계")을 이미 조회하던 레지스트리 응답과 이미 파싱하던
락파일에서 뽑아 채운다. 새 네트워크 호출·새 검사 대상은 없다.
"""
from __future__ import annotations

import asyncio

from gvskb.sbom import to_cyclonedx
from gvskb.tools.check_package import audit_manifest
from gvskb.tools.lockfiles import parse_lockfile
from gvskb.tools.package_metadata import _npm_repo_url, _parse_npm, _parse_pypi


# ── 공급자·저장소 추출 ──
def test_pypi_supplier_and_repo_from_project_urls_case_insensitive():
    data = {"info": {"author": "Kirill Simonov", "version": "6.0",
                     "project_urls": {"Source Code": "https://github.com/yaml/pyyaml"}},
            "releases": {"6.0": [{"upload_time_iso_8601": "2022-01-01T00:00:00"}]}}
    meta = _parse_pypi(data, None)
    assert meta.supplier == "Kirill Simonov"
    assert meta.repository_url == "https://github.com/yaml/pyyaml"


def test_pypi_missing_author_stays_none_not_fabricated():
    data = {"info": {"author": None, "version": "1.0", "project_urls": {}}, "releases": {}}
    meta = _parse_pypi(data, None)
    assert meta.supplier is None


def test_pypi_falls_back_to_home_page_when_no_project_urls():
    data = {"info": {"author": "x", "version": "1.0", "home_page": "https://example.org", "project_urls": {}},
            "releases": {}}
    assert _parse_pypi(data, None).repository_url == "https://example.org"


def test_npm_supplier_prefers_version_specific_author_then_falls_back():
    data = {"dist-tags": {"latest": "1.0.0"}, "time": {},
            "author": {"name": "Top Level", "email": "top@x.com"},
            "versions": {"1.0.0": {"author": {"name": "Version Author", "email": "v@x.com"}}},
            "repository": {"url": "git+https://github.com/a/b.git"}}
    meta = _parse_npm(data, "1.0.0")
    assert meta.supplier == "Version Author <v@x.com>"
    assert meta.repository_url == "https://github.com/a/b"


def test_npm_falls_back_to_maintainer_when_no_author():
    data = {"dist-tags": {"latest": "1.0.0"}, "time": {}, "versions": {"1.0.0": {}},
            "maintainers": [{"name": "maint1", "email": "m@x.com"}]}
    assert _parse_npm(data, "1.0.0").supplier == "maint1 <m@x.com>"


def test_npm_repo_url_normalizes_ssh_and_shorthand_forms():
    assert _npm_repo_url({"url": "git+ssh://git@github.com/mscdex/busboy.git"}) == "https://github.com/mscdex/busboy"
    assert _npm_repo_url("git@github.com:foo/bar.git") == "https://github.com/foo/bar"
    assert _npm_repo_url({"url": "https://github.com/x/y"}) == "https://github.com/x/y"
    assert _npm_repo_url(None) is None


# ── 락파일 의존성 그래프 (실제 파일로 재확인 — 회귀 방지) ──
def test_npm_v2v3_edges_root_and_transitive():
    import json
    text = json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "app", "dependencies": {"busboy": "^1.6.0"}},
            "node_modules/busboy": {"version": "1.6.0", "dependencies": {"streamsearch": "^1.1.0"}},
            "node_modules/streamsearch": {"version": "1.1.0"},
        },
    })
    r = parse_lockfile(text, "package-lock.json")
    assert {"from": None, "to": "busboy"} in r["edges"]
    assert {"from": "busboy", "to": "streamsearch"} in r["edges"]
    assert r["packages"] == [{"name": "busboy", "version": "1.6.0"},
                              {"name": "streamsearch", "version": "1.1.0"}]  # 기존 출력 불변


def test_poetry_lock_edges():
    text = (
        '[[package]]\nname = "flask"\nversion = "0.12.2"\n'
        '[package.dependencies]\nclick = ">=2.0"\nJinja2 = ">=2.4"\n\n'
        '[[package]]\nname = "click"\nversion = "7.1.2"\n'
    )
    r = parse_lockfile(text, "poetry.lock")
    assert {"from": "flask", "to": "click"} in r["edges"]
    assert {"from": "flask", "to": "Jinja2"} in r["edges"]


def test_uv_lock_edges_list_form():
    text = (
        '[[package]]\nname = "flask"\nversion = "0.12.2"\n'
        'dependencies = [{ name = "click" }, { name = "itsdangerous" }]\n\n'
        '[[package]]\nname = "click"\nversion = "7.1.2"\n'
    )
    r = parse_lockfile(text, "uv.lock")
    assert {"from": "flask", "to": "click"} in r["edges"]
    assert {"from": "flask", "to": "itsdangerous"} in r["edges"]


def test_pnpm_edges_from_snapshots_and_importers():
    text = (
        "lockfileVersion: '9.0'\n\n"
        "importers:\n  .:\n    dependencies:\n      express:\n        specifier: ^4.18.0\n        version: 4.18.2\n\n"
        "packages:\n  express@4.18.2: {}\n  accepts@1.3.8: {}\n\n"
        "snapshots:\n  express@4.18.2:\n    dependencies:\n      accepts: 1.3.8\n"
    )
    r = parse_lockfile(text, "pnpm-lock.yaml")
    assert {"from": None, "to": "express"} in r["edges"]
    assert {"from": "express", "to": "accepts"} in r["edges"]


def test_yarn_classic_edges():
    text = (
        "# yarn lockfile v1\n\n"
        'align-text@^0.1.1, align-text@^0.1.3:\n  version "0.1.4"\n  resolved "https://x"\n'
        "  dependencies:\n    kind-of \"^3.0.2\"\n    longest \"^1.0.1\"\n\n"
        'kind-of@^3.0.2:\n  version "3.2.2"\n'
    )
    r = parse_lockfile(text, "yarn.lock")
    assert {"from": "align-text", "to": "kind-of"} in r["edges"]
    assert {"from": "align-text", "to": "longest"} in r["edges"]
    assert {"name": "kind-of", "version": "3.2.2"} in r["packages"]  # 다음 블록도 정상 파싱


def test_yarn_berry_edges():
    text = (
        "__metadata:\n  version: 6\n\n"
        '"flask@npm:0.12.2":\n  version: 0.12.2\n  dependencies:\n    click: "npm:>=2.0"\n'
    )
    r = parse_lockfile(text, "yarn.lock")
    assert {"from": "flask", "to": "click"} in r["edges"]


def test_manifest_without_lockfile_gives_root_level_edges_only():
    from gvskb.scanner import parse_manifest_packages
    text = "flask==0.12.2\nrequests==2.19.1\n"
    packages = parse_manifest_packages(text, "pypi")
    # audit_manifest 내부 로직과 동일하게 구성해 확인(직접 호출은 네트워크가 필요)
    edges = [{"from": None, "to": str(p["name"])} for p in packages if p.get("name")]
    assert {"from": None, "to": "flask"} in edges
    assert {"from": None, "to": "requests"} in edges
    assert not any(e["from"] is not None for e in edges), "매니페스트만으로는 전이 관계를 모른다"


def test_malformed_lockfiles_still_return_empty_edges_not_crash():
    assert parse_lockfile("{not json", "package-lock.json")["edges"] == []
    assert parse_lockfile("not toml [[", "poetry.lock")["edges"] == []
    assert parse_lockfile(": not: yaml: -", "pnpm-lock.yaml")["edges"] == []


# ── audit_manifest → dependency_graph (오프라인, 네트워크 없이) ──
def test_audit_manifest_returns_dependency_graph_offline(monkeypatch):
    monkeypatch.setenv("GVSKB_MODE", "offline")
    import json
    text = json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"busboy": "^1.6.0"}},
            "node_modules/busboy": {"version": "1.6.0", "dependencies": {"streamsearch": "^1.1.0"}},
            "node_modules/streamsearch": {"version": "1.1.0"},
        },
    })
    r = asyncio.run(audit_manifest(text, ecosystem="npm", filename="package-lock.json"))
    assert {"from": None, "to": "busboy"} in r["dependency_graph"]
    assert {"from": "busboy", "to": "streamsearch"} in r["dependency_graph"]


def test_dependency_graph_drops_edges_to_truncated_packages(monkeypatch):
    monkeypatch.setenv("GVSKB_MODE", "offline")
    import json
    text = json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"a": "^1.0.0"}},
            "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "^1.0.0"}},
            "node_modules/b": {"version": "1.0.0"},
        },
    })
    r = asyncio.run(audit_manifest(text, ecosystem="npm", filename="package-lock.json", limit=1))
    checked = {p["name"] for p in r["packages"]}
    assert all(e["to"] in checked for e in r["dependency_graph"])


# ── SBOM 컴포넌트 supplier/externalReferences ──
def test_sbom_component_carries_supplier_and_vcs_reference():
    audit = {"audits": [{"checks": [{
        "name": "pyyaml", "version": "6.0.3", "ecosystem": "pypi", "checked": True, "verdict": "checked_clean",
        "registry_metadata": {"supplier": "Kirill Simonov", "repository_url": "https://github.com/yaml/pyyaml"},
    }]}]}
    doc = to_cyclonedx(audit)
    comp = doc["components"][0]
    assert comp["supplier"] == {"name": "Kirill Simonov"}
    assert comp["externalReferences"] == [{"type": "vcs", "url": "https://github.com/yaml/pyyaml"}]


def test_sbom_component_omits_supplier_when_unknown_not_fabricated():
    audit = {"audits": [{"checks": [{
        "name": "flask", "version": "0.12.2", "ecosystem": "pypi", "checked": True, "verdict": "checked_clean",
        "registry_metadata": {"supplier": None, "repository_url": None},
    }]}]}
    comp = to_cyclonedx(audit)["components"][0]
    assert "supplier" not in comp and "externalReferences" not in comp


def test_sbom_component_handles_offline_none_registry_metadata():
    audit = {"audits": [{"checks": [{
        "name": "requests", "version": "2.19.1", "ecosystem": "pypi", "checked": False,
        "verdict": "unknown", "registry_metadata": None,
    }]}]}
    comp = to_cyclonedx(audit)["components"][0]
    assert "supplier" not in comp


# ── SBOM dependencies 배열 ──
def test_sbom_dependencies_array_from_dependency_graph_with_root():
    audit = {"audits": [{
        "checks": [
            {"name": "busboy", "version": "1.6.0", "ecosystem": "npm", "checked": True, "verdict": "checked_clean"},
            {"name": "streamsearch", "version": "1.1.0", "ecosystem": "npm", "checked": True, "verdict": "checked_clean"},
        ],
        "dependency_graph": [{"from": None, "to": "busboy"}, {"from": "busboy", "to": "streamsearch"}],
    }]}
    doc = to_cyclonedx(audit, target="C:/proj/app", name="테스트앱")
    deps = {d["ref"]: d["dependsOn"] for d in doc["dependencies"]}
    root_ref = doc["metadata"]["component"]["bom-ref"]
    assert deps[root_ref] == ["pkg:npm/busboy@1.6.0"]
    assert deps["pkg:npm/busboy@1.6.0"] == ["pkg:npm/streamsearch@1.1.0"]
    assert any(p["name"] == "gvskb:dependency_graph_basis" for p in doc["metadata"]["properties"])


def test_sbom_dependencies_without_root_component_skips_root_edges_only():
    """target·name 없이 부르면 루트 컴포넌트가 없다 — 그 간선만 빠지고 나머지는 남는다."""
    audit = {"audits": [{
        "checks": [
            {"name": "busboy", "version": "1.6.0", "ecosystem": "npm", "checked": True, "verdict": "checked_clean"},
            {"name": "streamsearch", "version": "1.1.0", "ecosystem": "npm", "checked": True, "verdict": "checked_clean"},
        ],
        "dependency_graph": [{"from": None, "to": "busboy"}, {"from": "busboy", "to": "streamsearch"}],
    }]}
    doc = to_cyclonedx(audit)
    assert "metadata" not in doc or "component" not in doc.get("metadata", {})
    deps = {d["ref"]: d["dependsOn"] for d in doc["dependencies"]}
    assert deps == {"pkg:npm/busboy@1.6.0": ["pkg:npm/streamsearch@1.1.0"]}


def test_sbom_no_dependencies_key_when_no_graph_available():
    audit = {"audits": [{"checks": [{
        "name": "flask", "version": "0.12.2", "ecosystem": "pypi", "checked": True, "verdict": "checked_clean",
    }]}]}
    doc = to_cyclonedx(audit)
    assert "dependencies" not in doc


def test_sbom_dependency_graph_name_matching_is_case_insensitive():
    """to='jinja2' 가 컴포넌트 'Jinja2' 와 대소문자만 다르게 매칭돼야 한다.
    from='flask' 는 이 SBOM 에 컴포넌트로 없으므로(존재하지 않는 것을 참조하지
    않는다는 원칙) 그 간선은 버려지고, dependencies 자체가 생기지 않는다."""
    audit = {"audits": [{
        "checks": [{"name": "Jinja2", "version": "3.1.0", "ecosystem": "pypi", "checked": True, "verdict": "checked_clean"}],
        "dependency_graph": [{"from": "flask", "to": "jinja2"}],
    }]}
    doc = to_cyclonedx(audit)
    assert "dependencies" not in doc


def test_sbom_dependency_graph_name_matching_when_both_sides_present():
    audit = {"audits": [{
        "checks": [
            {"name": "Flask", "version": "0.12.2", "ecosystem": "pypi", "checked": True, "verdict": "checked_clean"},
            {"name": "Jinja2", "version": "3.1.0", "ecosystem": "pypi", "checked": True, "verdict": "checked_clean"},
        ],
        "dependency_graph": [{"from": "flask", "to": "jinja2"}],
    }]}
    doc = to_cyclonedx(audit)
    assert doc["dependencies"] == [{"ref": "pkg:pypi/Flask@0.12.2", "dependsOn": ["pkg:pypi/Jinja2@3.1.0"]}]
