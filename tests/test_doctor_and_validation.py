"""diagnostics + validation + CLI doctor/validate-rules 동작 확인."""
from __future__ import annotations

import json
import tomllib
from pathlib import Path

import pytest

from gvskb import cli, diagnostics, validation


def test_diagnostics_offline_runs_without_network() -> None:
    report = diagnostics.run_diagnostics(network=False, expected_minimum=20)
    assert "overall" in report
    assert report["overall"] in {"ok", "warn", "error"}
    names = {c["name"] for c in report["checks"]}
    assert {"Python", "Total rules", "MCP server import"} <= names


def test_diagnostics_runtime_status_for_mcp() -> None:
    status = diagnostics.runtime_status_for_mcp()
    assert status["rules_loaded_ok"] is True
    assert status["total_rules"] >= 20
    assert status["runtime_detection_rules"] >= 1
    assert "disclaimer" in status


def test_doctor_cli_offline_text(capsys: pytest.CaptureFixture[str]) -> None:
    rc = cli.main(["doctor", "--offline"])
    out = capsys.readouterr().out
    assert "gvskb doctor" in out
    assert "Total rules" in out
    assert rc in (cli.EXIT_OK, cli.EXIT_FINDINGS_WARN)


def test_doctor_cli_offline_json(capsys: pytest.CaptureFixture[str]) -> None:
    rc = cli.main(["doctor", "--offline", "--json"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["overall"] in {"ok", "warn", "error"}
    assert isinstance(payload["checks"], list)
    assert len(payload["checks"]) >= 5
    assert rc in (cli.EXIT_OK, cli.EXIT_FINDINGS_WARN)


def test_doctor_respects_gvskb_rules_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An empty rules dir should yield ERROR (total rules under expected minimum)."""
    empty = tmp_path / "empty_rules"
    empty.mkdir()
    monkeypatch.setenv("GVSKB_RULES_DIR", str(empty))
    report = diagnostics.run_diagnostics(network=False, expected_minimum=20)
    statuses = {c["name"]: c["status"] for c in report["checks"]}
    assert statuses.get("Total rules") == "error"
    assert report["overall"] == "error"


def test_doctor_reports_malformed_rule_as_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bad_rules = tmp_path / "bad_rules"
    bad_rules.mkdir()
    (bad_rules / "BROKEN.md").write_text("missing frontmatter\n", encoding="utf-8")
    monkeypatch.setenv("GVSKB_RULES_DIR", str(bad_rules))
    report = diagnostics.run_diagnostics(network=False, expected_minimum=1)
    statuses = {c["name"]: c["status"] for c in report["checks"]}
    assert statuses.get("Rule loader") == "error"
    assert report["overall"] == "error"


def test_validate_rules_current_repo_passes() -> None:
    """The repository's own rules/ must validate cleanly (no ERROR)."""
    rules_dir = Path(__file__).resolve().parent.parent / "rules"
    report = validation.validate_rules_dir(rules_dir)
    error_issues = [i for i in report["issues"] if i["status"] == "error"]
    assert error_issues == [], f"existing rules should not produce errors: {error_issues[:3]}"


def test_validate_rules_detects_regex_compile_failure(tmp_path: Path) -> None:
    bad = tmp_path / "BAD-REGEX-01.md"
    bad.write_text(
        "---\n"
        "id: BAD-REGEX-01\n"
        "title_ko: 잘못된 정규식\n"
        "sources: [{publisher: test, document: t}]\n"
        "severity: high\n"
        "verified_at: 2026-01-01\n"
        "detection:\n"
        "  patterns: ['[invalid(regex']\n"
        "  category: test\n"
        "---\n\n"
        "body\n",
        encoding="utf-8",
    )
    report = validation.validate_rules_dir(tmp_path)
    codes = [i["code"] for i in report["issues"]]
    assert "regex-compile-fail" in codes
    assert report["overall"] == "error"


def _rule_md(rule_id: str, *, extra: str = "", status: str = "approved") -> str:
    return (
        "---\n"
        f"id: {rule_id}\n"
        f"title_ko: 예시 검사용 룰\n"
        "sources: [{publisher: test, document: t}]\n"
        "severity: high\n"
        f"status: {status}\n"
        "verified_at: 2026-01-01\n"
        "detection:\n"
        "  patterns: ['eval\\\\s*\\\\(']\n"
        "  category: test\n"
        f"{extra}"
        "---\n\n"
        "body\n"
    )


def test_validate_rules_flags_runnable_rule_without_examples(tmp_path: Path) -> None:
    """실행형 룰에 examples 가 없으면 evaluate 가 통째로 건너뛴다 — ERROR 로 막는다.

    실측: 이 검사가 없을 때 GOV-PII-RRN-001 이 임의 13자리 정수의 40%를
    주민등록번호로 보고하고 있었는데, examples 가 없어 평가표에 나타나지 않았고
    나머지 룰이 전부 100%라 품질 게이트는 초록불이었다.
    """
    (tmp_path / "NOEX-01.md").write_text(_rule_md("NOEX-01"), encoding="utf-8")
    report = validation.validate_rules_dir(tmp_path)
    codes = {i["code"] for i in report["issues"]}
    assert "examples-missing" in codes
    assert report["overall"] == "error"


def test_validate_rules_requires_negative_examples_too(tmp_path: Path) -> None:
    """positive 만 있으면 재현율만 고정되고 정작 사용자를 괴롭히는 오탐은 방치된다."""
    extra = "examples:\n  language: python\n  positive:\n    - \"eval(user_input)\"\n"
    (tmp_path / "POSONLY-01.md").write_text(_rule_md("POSONLY-01", extra=extra), encoding="utf-8")
    report = validation.validate_rules_dir(tmp_path)
    codes = {i["code"] for i in report["issues"]}
    assert "examples-missing-negative" in codes
    assert report["overall"] == "error"


def test_validate_rules_accepts_rule_with_both_example_kinds(tmp_path: Path) -> None:
    extra = (
        "examples:\n  language: python\n"
        "  positive:\n    - \"eval(user_input)\"\n"
        "  negative:\n    - \"json.loads(user_input)\"\n"
    )
    (tmp_path / "BOTH-01.md").write_text(_rule_md("BOTH-01", extra=extra), encoding="utf-8")
    report = validation.validate_rules_dir(tmp_path)
    codes = {i["code"] for i in report["issues"]}
    assert not {c for c in codes if c.startswith("examples-")}


def test_validate_rules_skips_examples_check_for_unenforced_rules(tmp_path: Path) -> None:
    """proposed 룰은 집행되지 않으므로 예시를 요구하지 않는다(intel 자동 생성 룰)."""
    (tmp_path / "PROP-01.md").write_text(
        _rule_md("PROP-01", status="proposed"), encoding="utf-8",
    )
    report = validation.validate_rules_dir(tmp_path)
    codes = {i["code"] for i in report["issues"]}
    assert "examples-missing" not in codes


def test_validate_rules_detects_duplicate_id(tmp_path: Path) -> None:
    common = (
        "title_ko: duplicate test\n"
        "sources: [{publisher: test, document: t}]\n"
        "severity: low\n"
        "verified_at: 2026-01-01\n"
    )
    (tmp_path / "a.md").write_text(f"---\nid: DUP-01\n{common}---\n\nbody\n", encoding="utf-8")
    (tmp_path / "b.md").write_text(f"---\nid: DUP-01\n{common}---\n\nbody\n", encoding="utf-8")
    report = validation.validate_rules_dir(tmp_path)
    codes = {i["code"] for i in report["issues"]}
    assert "duplicate-rule-id" in codes


def test_validate_rules_cli_json(capsys: pytest.CaptureFixture[str]) -> None:
    rc = cli.main(["validate-rules", "--json"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["overall"] in {"ok", "warn"}  # current repo should not be error
    assert rc in (cli.EXIT_OK, cli.EXIT_FINDINGS_WARN)


def test_mcp_server_status_does_not_call_network() -> None:
    """server_status must be MCP-safe: no network, no exceptions."""
    status = diagnostics.runtime_status_for_mcp()
    assert "OSV" not in status  # no network-dependent fields
    assert status["total_rules"] >= 20


def test_wheel_includes_runtime_policy_and_config_data() -> None:
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    force_include = data["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"]
    assert force_include["rules"] == "gvskb/rules"
    assert force_include["policies"] == "gvskb/policies"
    assert force_include["config"] == "gvskb/config"


# ---------------------------------------------------------------------------
# 인텔 캐시 진단 — 오프라인 운영의 1차 건강신호
# ---------------------------------------------------------------------------


def test_doctor_intel_cache_warns_when_offline_and_missing(monkeypatch, tmp_path):
    """망분리 + 캐시 없음 = check-package 전건 판정불가 상황 — doctor가 WARN으로 알린다."""
    monkeypatch.setenv("GVSKB_MODE", "offline")
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path / "none"))
    from gvskb.diagnostics import check_intel_cache

    results = check_intel_cache()
    cache_checks = [r for r in results if r["name"].startswith("Intel cache:")]
    assert len(cache_checks) == 2  # osv-malicious · cisa-kev
    assert all(r["status"] == "warn" for r in cache_checks)
    assert any("update-intel" in r.get("note", "") for r in cache_checks)
    # 자동 당김 진단도 함께 나온다 — 오프라인인데 배포 폴더가 없으면 경고.
    autopull = [r for r in results if r["name"] == "Intel auto-update"]
    assert len(autopull) == 1
    assert autopull[0]["status"] == "warn"
    assert "GVSKB_INTEL_DIR" in autopull[0].get("note", "")


def test_doctor_intel_cache_ok_when_fresh(monkeypatch, tmp_path):
    monkeypatch.delenv("GVSKB_MODE", raising=False)
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path))
    from gvskb.intel.cache import IntelCache

    cache = IntelCache()
    cache.save("osv-malicious", "https://example/x", [], ecosystems=["PyPI"])
    cache.save("cisa-kev", "https://example/x", [])
    from gvskb.diagnostics import check_intel_cache

    results = check_intel_cache()
    assert all(r["status"] == "ok" for r in results)


def test_server_status_exposes_intel_cache(monkeypatch, tmp_path):
    """에이전트가 scan_dependencies 전에 캐시 존재·신선도를 알 수 있어야 한다."""
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path))
    from gvskb.intel.cache import IntelCache

    IntelCache().save("osv-malicious", "https://example/x", [], ecosystems=["PyPI"])
    from gvskb.diagnostics import runtime_status_for_mcp

    info = runtime_status_for_mcp()
    assert "intel_cache" in info
    osv = info["intel_cache"]["osv-malicious"]
    assert osv["present"] is True
    assert osv["stale"] is False
    assert osv["ecosystems"] == ["PyPI"]
    assert info["intel_cache"]["cisa-kev"]["present"] is False


# ---------------------------------------------------------------------------
# 설치 신원 — 버전 문자열은 신원이 아니다
#
# 실측 사고: __version__ 이 고정된 사이에 들어간 변경분이 전부 같은 버전으로 보였고,
# 연동 하네스 하나가 몇 달 된 설치본을 쓰고 있었는데 **호출 실패 증상으로 역추적할
# 때까지** 아무도 몰랐다. 커밋 SHA 와 도구 목록을 도구가 먼저 말하게 한다.
# ---------------------------------------------------------------------------


def test_registered_tools_matches_fastmcp_registry() -> None:
    """우리가 기록한 도구 목록 == 프레임워크에 실제 등록된 목록.

    server.REGISTERED_TOOLS 는 fastmcp 사설 API 를 피하려고 등록 시점에 직접 남기는
    사본이다. 사본은 반드시 갈라지므로, 갈라지는 순간 여기서 실패하게 둔다.
    """
    import asyncio

    from gvskb.server import REGISTERED_TOOLS, mcp

    actual = {t.name for t in asyncio.run(mcp.list_tools())}
    assert set(REGISTERED_TOOLS) == actual
    assert len(REGISTERED_TOOLS) == len(set(REGISTERED_TOOLS)), "도구 이름이 중복 기록됐습니다"


def test_tool_manifest_matches_registered_tools() -> None:
    """매니페스트가 굳지 않게 — 도구를 추가하고 매니페스트를 잊으면 실패한다."""
    from gvskb.server import REGISTERED_TOOLS

    assert sorted(diagnostics.MCP_TOOL_MANIFEST) == sorted(REGISTERED_TOOLS)


def test_server_status_exposes_commit_and_tool_inventory() -> None:
    """server_status 만 보고도 '어느 커밋의, 어떤 도구를 가진 설치본인지' 알 수 있어야 한다."""
    info = diagnostics.runtime_status_for_mcp()

    assert "commit_id" in info
    assert info["missing_tools"] == []
    assert info["unlisted_tools"] == []
    assert info["tool_inventory_ok"] is True
    assert "server_status" in info["mcp_tools"]
    identity = info["install_identity"]
    assert identity["package_version"] == info["package_version"]
    # 이 저장소 체크아웃에서 돌리면 커밋을 알 수 있어야 한다(.git 이 있는 경우).
    if (Path(__file__).resolve().parents[1] / ".git").exists():
        assert identity["commit_id"] and len(identity["commit_id"]) == 40
        assert identity["short_commit"] == identity["commit_id"][:12]
    else:  # pragma: no cover - sdist 설치본
        assert identity["note"]


def test_commit_id_prefers_pip_direct_url(monkeypatch: pytest.MonkeyPatch) -> None:
    """git URL 로 설치한 경우 pip 이 기록한 커밋을 그대로 신원으로 쓴다."""
    monkeypatch.setattr(diagnostics, "_direct_url_metadata", lambda: {
        "url": "https://example.invalid/org/repo",
        "vcs_info": {"vcs": "git", "commit_id": "a" * 40, "requested_revision": "main"},
    })
    identity = diagnostics.install_identity()
    assert identity["commit_id"] == "a" * 40
    assert identity["commit_source"].startswith("direct_url.json")
    assert identity["requested_revision"] == "main"
    assert "note" not in identity


def test_commit_id_falls_back_to_git_checkout(monkeypatch: pytest.MonkeyPatch) -> None:
    """editable·소스 설치는 pip 에 커밋 기록이 없다 — .git 에서 읽는다."""
    monkeypatch.setattr(diagnostics, "_direct_url_metadata", lambda: {
        "url": "file:///somewhere", "dir_info": {"editable": True},
    })
    identity = diagnostics.install_identity()
    if (Path(__file__).resolve().parents[1] / ".git").exists():
        assert identity["commit_id"] and identity["commit_source"].startswith("git checkout")
        assert identity["editable"] is True
    else:  # pragma: no cover - sdist 설치본
        assert identity["commit_id"] is None


def test_commit_id_unknown_explains_how_to_fix(monkeypatch: pytest.MonkeyPatch) -> None:
    """알 수 없으면 조용히 None 만 주지 말고 해결 방법을 말한다.

    ``commit_id`` 는 **임포트 시점 스냅샷**을 우선하므로(낡은 프로세스가 최신
    커밋을 보고하는 것을 막기 위해), '커밋을 알 수 없는 설치본'을 재현하려면
    디스크와 스냅샷을 **둘 다** 비워야 한다 — sdist·복사본 설치가 그 상태다.
    """
    monkeypatch.setattr(diagnostics, "_direct_url_metadata", dict)
    monkeypatch.setattr(diagnostics, "_git_head_commit", lambda _p: (None, None))
    monkeypatch.setattr(diagnostics, "_LOADED_PROBE", {"commit_id": None})
    identity = diagnostics.install_identity()
    assert identity["commit_id"] is None
    assert identity["commit_source"] == "unavailable"
    assert "pip install" in identity["note"]


def test_git_head_commit_reads_loose_ref(tmp_path: Path) -> None:
    git = tmp_path / ".git"
    (git / "refs" / "heads").mkdir(parents=True)
    (git / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (git / "refs" / "heads" / "main").write_text("b" * 40 + "\n", encoding="utf-8")
    work = tmp_path / "src" / "gvskb"
    work.mkdir(parents=True)
    assert diagnostics._git_head_commit(work) == ("b" * 40, "main")


def test_git_head_commit_reads_packed_refs(tmp_path: Path) -> None:
    """느슨한 ref 가 없는 저장소(git gc 이후)에서도 읽어야 한다."""
    git = tmp_path / ".git"
    git.mkdir()
    (git / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (git / "packed-refs").write_text(
        "# pack-refs with: peeled fully-peeled sorted\n"
        f"{'c' * 40} refs/heads/main\n"
        f"{'d' * 40} refs/remotes/origin/main\n",
        encoding="utf-8",
    )
    assert diagnostics._git_head_commit(tmp_path) == ("c" * 40, "main")


def test_git_head_commit_handles_detached_head(tmp_path: Path) -> None:
    git = tmp_path / ".git"
    git.mkdir()
    (git / "HEAD").write_text("e" * 40 + "\n", encoding="utf-8")
    assert diagnostics._git_head_commit(tmp_path) == ("e" * 40, None)


def test_missing_tool_is_reported_by_name(monkeypatch: pytest.MonkeyPatch) -> None:
    """이 설치본에 없는 도구를 **도구 스스로** 말해야 한다 — 호출 실패로 역추적하지 않게."""
    from gvskb import server

    monkeypatch.setattr(
        server, "REGISTERED_TOOLS",
        [t for t in server.REGISTERED_TOOLS if t not in {"scan_vendor_bundles", "save_report"}],
    )
    inventory = diagnostics.mcp_tool_inventory()
    assert inventory["missing_tools"] == ["save_report", "scan_vendor_bundles"]
    assert inventory["inventory_ok"] is True

    status = {c["name"]: c for c in diagnostics.check_install_identity()}["MCP tools"]
    assert status["status"] == "error"
    assert "scan_vendor_bundles" in status["note"]

    info = diagnostics.runtime_status_for_mcp()
    assert info["missing_tools"] == ["save_report", "scan_vendor_bundles"]


def test_unlisted_tool_flags_manifest_drift(monkeypatch: pytest.MonkeyPatch) -> None:
    """매니페스트에 없는 도구가 등록되면 경고한다 — 목록이 실물보다 낡지 않게."""
    from gvskb import server

    monkeypatch.setattr(server, "REGISTERED_TOOLS", [*server.REGISTERED_TOOLS, "scan_the_moon"])
    inventory = diagnostics.mcp_tool_inventory()
    assert inventory["unlisted_tools"] == ["scan_the_moon"]
    status = {c["name"]: c for c in diagnostics.check_install_identity()}["MCP tools"]
    assert status["status"] == "warn"


def test_tool_inventory_failure_is_not_reported_as_complete(monkeypatch: pytest.MonkeyPatch) -> None:
    """도구 목록을 못 읽는 상황은 '빠진 것 없음'이 아니다 — 조용한 초록불 금지.

    낡은 설치본에는 REGISTERED_TOOLS 자체가 없다. 그때 missing_tools 가 빈
    목록이면 연동 상대는 '멀쩡한 설치'로 읽는다.
    """
    from gvskb import server

    monkeypatch.delattr(server, "REGISTERED_TOOLS", raising=True)
    inventory = diagnostics.mcp_tool_inventory()
    assert inventory["inventory_ok"] is False
    assert inventory["missing_tools"] == list(diagnostics.MCP_TOOL_MANIFEST)
    assert inventory["error"]

    info = diagnostics.runtime_status_for_mcp()
    assert info["tool_inventory_ok"] is False
    assert info["tool_inventory_error"]

    status = {c["name"]: c for c in diagnostics.check_install_identity()}["MCP tools"]
    assert status["status"] == "error"


def test_doctor_reports_install_identity() -> None:
    """doctor 출력에도 커밋·도구 재고가 보여야 한다(사용자는 문제가 생겨야 doctor 를 연다)."""
    report = diagnostics.run_diagnostics(network=False, expected_minimum=20)
    names = {c["name"] for c in report["checks"]}
    assert {"Install commit", "MCP tools"} <= names


# ---------------------------------------------------------------------------
# 결과 필드 계약 — 없는 이름을 읽는 것은 예외가 아니라 침묵이다
#
# 실측: 연동 하네스의 설치 게이트가 max_cve_severity · severity · status ·
# typosquat 를 읽고 있었다. 넷 다 우리 결과에 없는 이름이라 항상 빈 값이 나왔고,
# 그 빈 값이 취약점 심각도 사다리의 입력이었다 — CRITICAL 이 경고로 내려앉는데
# 양쪽 어디에도 예외가 나지 않는다. 대조할 목록을 우리가 내놓아야 한다.
# ---------------------------------------------------------------------------


def test_result_contract_matches_the_real_schema() -> None:
    from gvskb.schema import PackageCheckResult

    contract = diagnostics.package_result_contract()
    assert contract["fields"] == sorted(PackageCheckResult.model_fields)
    # 판정 문자열 목록도 실제 Literal 과 같아야 한다 — 모르는 판정을 만난 게이트는
    # 대개 else 로 흘러 통과시킨다.
    assert "vulnerable" in contract["verdicts"] and "malicious" in contract["verdicts"]


def test_decision_fields_all_exist() -> None:
    """게이트가 읽어야 할 최소 집합이 실제로 존재하는 이름인지 강제한다.

    이 테스트가 없으면 계약 목록 자체가 오타를 담은 채 배포될 수 있다 —
    그러면 하네스는 우리가 준 잘못된 목록을 믿고 같은 침묵을 반복한다.
    """
    contract = diagnostics.package_result_contract()
    missing = [f for f in contract["decision_fields"] if f not in contract["fields"]]
    assert not missing, f"계약에 있는데 실제 결과에 없는 필드: {missing}"


def test_fields_the_harness_wrongly_read_are_absent() -> None:
    """하네스가 읽던 이름들이 실제로 없다는 사실을 회귀로 고정한다.

    나중에 우연히 같은 이름이 생기면 이 테스트가 깨지고, 그때 계약을 다시 맞춘다.
    """
    fields = set(diagnostics.package_result_contract()["fields"])
    for wrong in ("max_cve_severity", "severity", "status", "typosquat"):
        assert wrong not in fields


def test_server_status_exposes_result_contract() -> None:
    info = diagnostics.runtime_status_for_mcp()
    contract = info["package_result_contract"]
    assert "verdict" in contract["fields"]
    assert contract["decision_fields"]
    assert "없는 이름을 읽으면" in contract["note"]
