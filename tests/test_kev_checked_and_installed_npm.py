"""KEV 대조 성립 여부(`kev_checked`)와 npm 설치본 경로 — 2026-08-03 회신 대응.

**이 테스트가 지키는 것 둘.**

1. `in_kev=false` 를 '악용 목록에 없음'으로 읽어도 되는지가 값으로 남는다.
   레지스트리는 `cache_sources_used` 가 비었는지로 이걸 추론하려 했는데, 악성
   피드만 있고 KEV 캐시가 없는 경우 목록은 비어 있지 않으면서 KEV 대조는 되지
   않는다 — 그 추론은 그 경우를 놓친다.

2. `--include-installed` 의 npm 경로가 실제로 패키지를 검사한다. 이 경로는
   requirements 형식 텍스트를 npm(JSON)으로 파싱하려다 실패해 **node_modules 에서
   수집한 전이 의존성이 한 건도 검사되지 않고 있었다.** 화면에는 "형식·ecosystem을
   확인하세요"라고만 나와 도구 자신의 결함이 사용자 입력 문제처럼 보였다.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from gvskb.tools.installed_packages import to_requirements_text

# ---------------------------------------------------------------------------
# kev_checked
# ---------------------------------------------------------------------------


def test_kev_checked_is_false_when_the_cache_is_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """캐시가 없으면 in_kev=false 는 '악용 없음'이 아니라 '대조 못 함'이다."""
    from gvskb.tools.check_package import check_package_impl

    monkeypatch.setenv("GVSKB_MODE", "offline")
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path))
    r = asyncio.run(check_package_impl(name="requests", version="2.31.0", ecosystem="pypi"))
    assert r["in_kev"] is False
    assert r.get("kev_checked") is False, "대조하지 못한 것이 대조한 것처럼 보인다"


def test_kev_checked_is_independent_of_cache_sources_being_nonempty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """악성 피드만 있고 KEV 캐시가 없는 상태 — 레지스트리 추론 규칙이 놓치는 경우.

    `cache_sources_used` 는 비어 있지 않은데(osv-malicious 가 들어 있다) KEV 대조는
    되지 않았다. "비어 있으면 대조 못 함"이라는 규칙은 이 경우 `in_kev=false` 를
    사실로 읽는다.
    """
    from gvskb.intel.cache import IntelCache
    from gvskb.tools.check_package import check_package_impl

    monkeypatch.setenv("GVSKB_MODE", "offline")
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path))
    IntelCache().save("osv-malicious", "local://test", [], ecosystems=["PyPI"])  # KEV 는 저장 안 함

    r = asyncio.run(check_package_impl(name="requests", version="2.31.0", ecosystem="pypi"))
    assert "osv-malicious" in (r.get("cache_sources_used") or [])   # 비어 있지 않다
    assert "cisa-kev" not in (r.get("cache_sources_used") or [])
    assert r.get("kev_checked") is False, (
        "cache_sources_used 가 비었는지로는 KEV 대조 여부를 알 수 없다"
    )


def test_kev_checked_is_true_when_the_kev_cache_was_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from gvskb.intel.cache import IntelCache
    from gvskb.tools.check_package import check_package_impl

    monkeypatch.setenv("GVSKB_MODE", "offline")
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path))
    IntelCache().save("cisa-kev", "local://test", [])

    r = asyncio.run(check_package_impl(name="requests", version="2.31.0", ecosystem="pypi"))
    assert r.get("kev_checked") is True


def test_kev_checked_reaches_the_registry_bundle(tmp_path: Path) -> None:
    """레지스트리가 요청한 값이 실제로 봉투에 실리는지 — 필드만 만들면 소용없다."""
    from gvskb.tools.registry_bundle import build_bundle

    b = build_bundle({"audits": [{
        "source_kind": "manifest",
        "checks": [{
            "name": "requests", "version": "2.31.0", "ecosystem": "pypi",
            "verdict": "not_found", "in_kev": False, "kev_checked": False,
            "cache_sources_used": ["osv-malicious"],
        }],
    }]})
    result = b["items"][0]["result"]
    assert result["kev_checked"] is False
    assert result["cache_sources_used"] == ["osv-malicious"]


# ---------------------------------------------------------------------------
# npm 설치본 경로
# ---------------------------------------------------------------------------


def test_installed_inventory_text_matches_the_ecosystem() -> None:
    """npm 목록은 JSON 이어야 한다 — requirements 형식이면 파서가 통째로 실패한다."""
    pkgs = [{"name": "express", "version": "4.17.0"}]
    assert json.loads(to_requirements_text(pkgs, ecosystem="npm")) == {
        "dependencies": {"express": "4.17.0"},
    }
    assert to_requirements_text(pkgs, ecosystem="pypi") == "express==4.17.0"


def test_npm_installed_packages_are_actually_checked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """node_modules 에서 수집한 패키지가 검사 결과로 이어지는지.

    실측 결함이었다: `--include-installed` 의 npm 경로가 `verdict='unparsed'`,
    `parsed_count=0` 을 내놓아 전이 의존성이 한 건도 검사되지 않았다.
    `--include-installed` 의 존재 이유가 전이 의존성인데 npm 쪽은 통째로 비어 있었다.
    """
    from gvskb import cli

    monkeypatch.setenv("GVSKB_MODE", "offline")
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path / "cache"))
    proj = tmp_path / "proj"
    (proj / "node_modules" / "express").mkdir(parents=True)
    (proj / "node_modules" / "express" / "package.json").write_text(
        '{"name": "express", "version": "4.17.0"}', encoding="utf-8",
    )
    (proj / "package.json").write_text(
        '{"name": "p", "dependencies": {"express": "^4.17.0"}}', encoding="utf-8",
    )
    (proj / "app.py").write_text('print("ok")\n', encoding="utf-8")

    report = tmp_path / "r.md"
    cli.main(["scan", str(proj), "--check-deps", "--include-installed",
              "--format", "json", "-o", str(tmp_path / "r.json")])
    payload = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))

    inv = [a for a in payload["dependency_audit"]["audits"]
           if a.get("source") == "installed-inventory" and a.get("ecosystem") == "npm"]
    assert inv, "npm 설치본 감사 자체가 없다"
    assert inv[0]["verdict"] != "unparsed", "npm 설치본이 파싱되지 않았다"
    assert inv[0]["parsed_count"] >= 1
    assert any(c["name"] == "express" for c in inv[0]["checks"])
    assert report.exists() is False   # -o 는 json 경로만 만든다


def test_installed_direct_dependency_is_labelled_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """설치본 중 매니페스트에 이름이 있는 것은 직접 의존성이다(레지스트리 요청 §3).

    이름은 매니페스트에, 정확한 버전은 설치 흔적에 있다 — 둘을 합쳐야 "직접
    의존성 + 실제 버전"이 되고, 그 판단은 둘 다 읽는 이쪽에서만 할 수 있다.
    """
    from gvskb import cli

    monkeypatch.setenv("GVSKB_MODE", "offline")
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path / "cache"))
    proj = tmp_path / "proj"
    site = proj / ".venv" / "Lib" / "site-packages"
    for name, ver in (("requests", "2.31.0"), ("urllib3", "2.2.1")):
        d = site / f"{name}-{ver}.dist-info"
        d.mkdir(parents=True)
        (d / "METADATA").write_text(
            f"Name: {name}\nVersion: {ver}\n", encoding="utf-8",
        )
    # requests 만 직접 의존성이다. urllib3 는 그것이 끌고 온 전이 의존성이다.
    (proj / "requirements.txt").write_text("requests>=2.28\n", encoding="utf-8")
    (proj / "app.py").write_text('print("ok")\n', encoding="utf-8")

    cli.main(["scan", str(proj), "--check-deps", "--include-installed",
              "--format", "json", "-o", str(tmp_path / "r.json")])
    payload = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))

    inv = [a for a in payload["dependency_audit"]["audits"]
           if a.get("source") == "installed-inventory" and a.get("ecosystem") == "pypi"]
    assert inv, "설치본 감사가 없다"
    scope = {c["name"]: c.get("source_scope") for c in inv[0]["checks"]}
    assert scope.get("requests") == "manifest", "직접 의존성이 심사 큐에 오르지 못한다"
    assert scope.get("urllib3") == "installed"


def test_direct_dependency_carries_the_installed_version_not_the_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """번들에 나가는 것은 경계값 2.28 이 아니라 실제 설치 버전 2.31.0 이어야 한다."""
    from gvskb import cli
    from gvskb.intel.cache import IntelCache
    from gvskb.tools.registry_bundle import build_bundle

    monkeypatch.setenv("GVSKB_MODE", "offline")
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path / "cache"))
    # 캐시가 비면 판정이 unknown 이라 §5-D 로 전부 걸린다 — 여기서 보려는 것은
    # 필터가 아니라 '어느 버전이 실리는가'이므로 대조가 성립하게 해 둔다.
    cache = IntelCache()
    cache.save("osv-malicious", "local://test", [], ecosystems=["PyPI"])
    cache.save("cisa-kev", "local://test", [])
    proj = tmp_path / "proj"
    d = proj / ".venv" / "Lib" / "site-packages" / "requests-2.31.0.dist-info"
    d.mkdir(parents=True)
    (d / "METADATA").write_text("Name: requests\nVersion: 2.31.0\n", encoding="utf-8")
    (proj / "requirements.txt").write_text("requests>=2.28\n", encoding="utf-8")
    (proj / "app.py").write_text('print("ok")\n', encoding="utf-8")

    cli.main(["scan", str(proj), "--check-deps", "--include-installed",
              "--format", "json", "-o", str(tmp_path / "r.json")])
    payload = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))

    bundle = build_bundle(payload["dependency_audit"])
    sent = {(i["result"]["name"], i["result"]["version"], i["source_scope"])
            for i in bundle["items"]}
    assert ("requests", "2.31.0", "manifest") in sent
    assert not any(v == "2.28" for _n, v, _s in sent), "경계값이 사실로 나갔다"


def test_every_check_carries_a_source_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """모든 판정에 출처가 붙는다 — 하네스 집행계약 §4-0 이 이 값으로 차단 범위를 정한다.

    일부 판정에만 붙어 있으면 같은 패키지가 어느 경로로 검사됐느냐에 따라 막히거나
    안 막히게 된다.
    """
    from gvskb import cli

    monkeypatch.setenv("GVSKB_MODE", "offline")
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path / "cache"))
    proj = tmp_path / "proj"
    site = proj / ".venv" / "Lib" / "site-packages" / "urllib3-2.2.1.dist-info"
    site.mkdir(parents=True)
    (site / "METADATA").write_text("Name: urllib3\nVersion: 2.2.1\n", encoding="utf-8")
    (proj / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    (proj / "app.py").write_text('print("ok")\n', encoding="utf-8")

    cli.main(["scan", str(proj), "--check-deps", "--include-installed",
              "--format", "json", "-o", str(tmp_path / "r.json")])
    payload = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))

    valid = {"single", "manifest", "lockfile", "installed"}
    seen = 0
    for a in payload["dependency_audit"]["audits"]:
        for c in a.get("checks") or []:
            seen += 1
            assert c.get("source_scope") in valid, f"{c.get('name')} 에 출처가 없다"
    assert seen >= 2
