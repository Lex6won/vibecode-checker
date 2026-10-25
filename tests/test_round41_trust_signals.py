"""41차 — 패키지 신뢰 신호(AGSRC-021). 레지스트리 문서 모양만 쓰는 합성 fixture."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from gvskb.gate import CONDITIONAL_CRITERIA, gate_status
from gvskb.report import _dep_component_severity, _pkg_note, _pkg_verdict_label
from gvskb.scanner import scan_code
from gvskb.tools.package_metadata import _parse_npm, _parse_pypi
from gvskb.tools.trust_signals import (
    TRUST_SIGNAL_LABELS, ai_lure_signal, is_patch_step, npm_trust_signals,
    previous_version, pypi_trust_signals,
)


def _iso(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def _npm(versions: dict[str, dict], queried: str = "1.2.3") -> dict:
    time = {"created": _iso(600)} | {v: _iso(i * 30 + 2) for i, v in enumerate(reversed(list(versions)))}
    return {"dist-tags": {"latest": queried}, "license": "MIT", "time": time, "versions": versions}


def _ver(maint=("alice",), scripts=None, size=1000, deps=None, repo="https://github.com/org-a/pkg", **kw) -> dict:
    d = {
        "maintainers": [{"name": m, "email": f"{m}@mail.example"} for m in maint],
        "scripts": scripts or {}, "dist": {"unpackedSize": size},
        "dependencies": deps or {}, "repository": {"type": "git", "url": f"git+{repo}.git"},
    }
    d.update(kw)
    return d


# ---------------------------------------------------------------------------
# 버전 비교 보조
# ---------------------------------------------------------------------------


def test_previous_version_skips_prerelease_and_higher() -> None:
    assert previous_version("1.2.3", ["1.2.2", "1.3.0", "1.2.3-rc.1", "2.0.0", "1.2.1"]) == "1.2.2"
    assert previous_version("1.0.0", ["1.0.0"]) is None
    assert previous_version("abc", ["1.0.0"]) is None


def test_is_patch_step() -> None:
    assert is_patch_step("1.2.2", "1.2.3")
    assert not is_patch_step("1.1.9", "1.2.0")
    assert not is_patch_step("1.2", "1.2.3")


# ---------------------------------------------------------------------------
# npm — 이전 판과 비교
# ---------------------------------------------------------------------------


def test_npm_identical_consecutive_versions_have_no_signal() -> None:
    doc = _npm({"1.2.2": _ver(), "1.2.3": _ver(size=1100)})
    out = npm_trust_signals(doc, "1.2.3")
    assert out["previous_version"] == "1.2.2"
    assert out["signals"] == []
    assert out["provenance"] is False


def test_npm_new_maintainer_is_signal() -> None:
    doc = _npm({"1.2.2": _ver(maint=("alice",)), "1.2.3": _ver(maint=("alice", "mallory"))})
    keys = [s["key"] for s in npm_trust_signals(doc, "1.2.3")["signals"]]
    assert keys == ["maintainer_changed"]


def test_npm_publisher_outside_maintainers_is_signal() -> None:
    doc = _npm({"1.2.2": _ver(), "1.2.3": _ver(_npmUser={"name": "someone-else"})})
    keys = [s["key"] for s in npm_trust_signals(doc, "1.2.3")["signals"]]
    assert "maintainer_changed" in keys


def test_npm_maintainer_removed_only_is_not_signal() -> None:
    doc = _npm({"1.2.2": _ver(maint=("alice", "bob")), "1.2.3": _ver(maint=("alice",))})
    assert npm_trust_signals(doc, "1.2.3")["signals"] == []


def test_npm_install_hook_added_is_high() -> None:
    doc = _npm({"1.2.2": _ver(), "1.2.3": _ver(scripts={"postinstall": "node setup.js"})})
    sig = npm_trust_signals(doc, "1.2.3")["signals"]
    assert [s["key"] for s in sig] == ["install_hook_added"]
    assert sig[0]["severity"] == "high"


def test_npm_hook_present_in_both_versions_is_not_added() -> None:
    doc = _npm({"1.2.2": _ver(scripts={"postinstall": "x"}), "1.2.3": _ver(scripts={"postinstall": "x"})})
    assert npm_trust_signals(doc, "1.2.3")["signals"] == []


def test_npm_patch_bloat_by_size_and_new_dependency() -> None:
    doc = _npm({"1.2.2": _ver(size=1000), "1.2.3": _ver(size=1400, deps={"left-pad": "^1"})})
    sig = npm_trust_signals(doc, "1.2.3")["signals"]
    assert [s["key"] for s in sig] == ["patch_bloat"]
    assert "+40%" in sig[0]["detail"] and "1개" in sig[0]["detail"]


def test_npm_size_jump_on_minor_release_is_not_patch_bloat() -> None:
    doc = _npm({"1.2.2": _ver(size=1000), "1.3.0": _ver(size=3000, deps={"a": "1"})}, queried="1.3.0")
    assert npm_trust_signals(doc, "1.3.0")["signals"] == []


def test_npm_repo_changed_ignores_url_form() -> None:
    same = _npm({"1.2.2": _ver(repo="https://github.com/org-a/pkg"),
                 "1.2.3": _ver(repository="git@github.com:org-a/pkg.git")})
    assert npm_trust_signals(same, "1.2.3")["signals"] == []
    moved = _npm({"1.2.2": _ver(repo="https://github.com/org-a/pkg"),
                  "1.2.3": _ver(repo="https://github.com/org-b/pkg")})
    assert [s["key"] for s in npm_trust_signals(moved, "1.2.3")["signals"]] == ["repo_changed"]


def test_npm_provenance_recorded_but_signal_kept() -> None:
    cur = _ver(maint=("alice", "mallory"))
    cur["dist"]["attestations"] = {"url": "https://registry.example/attest"}
    doc = _npm({"1.2.2": _ver(), "1.2.3": cur})
    out = npm_trust_signals(doc, "1.2.3")
    assert out["provenance"] is True
    assert [s["key"] for s in out["signals"]] == ["maintainer_changed"]


def test_npm_first_release_has_nothing_to_compare() -> None:
    doc = _npm({"1.0.0": _ver(scripts={"postinstall": "x"})}, queried="1.0.0")
    out = npm_trust_signals(doc, "1.0.0")
    assert out["previous_version"] is None and out["signals"] == []


def test_parse_npm_carries_trust_fields() -> None:
    doc = _npm({"1.2.2": _ver(), "1.2.3": _ver(maint=("alice", "mallory"))})
    meta = _parse_npm(doc, "1.2.3")
    assert meta.previous_version == "1.2.2"
    assert [s["key"] for s in meta.trust_signals] == ["maintainer_changed"]
    assert meta.license == "MIT" and meta.version_age_days is not None


def test_parse_npm_survives_broken_version_doc() -> None:
    doc = _npm({"1.2.2": _ver(), "1.2.3": _ver()})
    doc["versions"]["1.2.2"]["maintainers"] = "garbage"
    doc["versions"]["1.2.2"]["dist"] = 5
    meta = _parse_npm(doc, "1.2.3")
    assert meta.exists is True and meta.license == "MIT"


# ---------------------------------------------------------------------------
# PyPI — 크기 비교만
# ---------------------------------------------------------------------------


def _pypi(sizes: dict[str, int], queried: str) -> dict:
    return {
        "info": {"version": queried, "license": "MIT"},
        "releases": {v: [{"size": s, "upload_time_iso_8601": _iso(10)}] for v, s in sizes.items()},
    }


def test_pypi_patch_size_jump_is_signal() -> None:
    out = pypi_trust_signals(_pypi({"2.0.1": 10_000, "2.0.2": 20_000}, "2.0.2"), "2.0.2")
    assert [s["key"] for s in out["signals"]] == ["patch_bloat"]
    assert out["previous_version"] == "2.0.1"


def test_pypi_small_change_or_minor_release_is_quiet() -> None:
    assert pypi_trust_signals(_pypi({"2.0.1": 10_000, "2.0.2": 11_000}, "2.0.2"), "2.0.2")["signals"] == []
    assert pypi_trust_signals(_pypi({"2.0.1": 10_000, "2.1.0": 30_000}, "2.1.0"), "2.1.0")["signals"] == []


def test_parse_pypi_carries_trust_fields() -> None:
    meta = _parse_pypi(_pypi({"2.0.1": 10_000, "2.0.2": 20_000}, "2.0.2"), "2.0.2")
    assert meta.previous_version == "2.0.1"
    assert [s["key"] for s in meta.trust_signals] == ["patch_bloat"]


# ---------------------------------------------------------------------------
# 이름 + 신생
# ---------------------------------------------------------------------------


def test_ai_lure_requires_both_vocabulary_and_youth() -> None:
    assert ai_lure_signal("codexui-android", 20)["key"] == "ai_lure_name"
    assert ai_lure_signal("my-mcp-server", 5) is not None
    assert ai_lure_signal("codex-helper", 400) is None          # 오래된 패키지
    assert ai_lure_signal("express", 20) is None                # 어휘 없음
    assert ai_lure_signal("claude-tools", None) is None         # 최초 발행 미상 — 추측하지 않음
    assert ai_lure_signal("daily-planner", 3) is None           # 'ai' 부분 문자열은 쓰지 않는다


# ---------------------------------------------------------------------------
# 게이트·보고서 — 조건부만, 차단 아님
# ---------------------------------------------------------------------------


def _audit(check: dict) -> dict:
    return {"audits": [{"blocked": False, "parsed_count": 1, "checked_count": 1,
                        "unchecked_count": 0, "truncated_count": 0, "checks": [check]}]}


def _check(**meta) -> dict:
    return {"name": "pkg", "version": "1.2.3", "ecosystem": "npm", "checked": True,
            "verdict": "checked_clean", "registry_metadata": {"exists": True, **meta}}


def test_trust_is_registered_conditional_criterion() -> None:
    assert "trust" in CONDITIONAL_CRITERIA


def test_gate_trust_signal_is_conditional_not_blocked() -> None:
    r = scan_code("x = 1\n", filename="a.py")
    r.dependency_audit = _audit(_check(
        trust_signals=[{"key": "maintainer_changed", "severity": "medium"}], provenance=True))
    g = gate_status(r)
    assert g["verdict"] == "conditional"
    assert g["blocked"] is False and g["block_reasons"] == []
    assert "trust" in g["conditional_criteria"]
    assert g["trust_signals"] == [{"name": "pkg", "version": "1.2.3",
                                   "signals": ["maintainer_changed"], "provenance": True}]
    assert "신뢰 신호 1종" in g["reason"]


def test_gate_without_signals_unchanged() -> None:
    r = scan_code("x = 1\n", filename="a.py")
    r.dependency_audit = _audit(_check(trust_signals=[]))
    g = gate_status(r)
    assert "trust" not in g["conditional_criteria"] and g["trust_signals"] == []
    assert g["verdict"] == "approved"


def test_report_label_and_note_surface_signals() -> None:
    chk = _check(trust_signals=[{"key": "install_hook_added", "severity": "high"}], provenance=True)
    assert "신뢰 신호" in _pkg_verdict_label(chk)
    note = _pkg_note(chk)
    assert TRUST_SIGNAL_LABELS["install_hook_added"] in note and "≠ 안전" in note
    assert _dep_component_severity(chk) is not None
    assert _dep_component_severity(_check(trust_signals=[])) is None


def test_npm_trusted_publisher_placeholder_is_not_a_new_maintainer() -> None:
    oidc = {"name": "GitHub Actions", "email": "npm-oidc-no-reply@github.example",
            "trustedPublisher": {"id": "github"}, "approver": {"name": "alice"}}
    doc = _npm({"1.2.2": _ver(), "1.2.3": _ver(_npmUser=oidc)})
    assert npm_trust_signals(doc, "1.2.3")["signals"] == []
    oidc_outsider = dict(oidc, approver={"name": "mallory"})
    doc = _npm({"1.2.2": _ver(), "1.2.3": _ver(_npmUser=oidc_outsider)})
    assert [s["key"] for s in npm_trust_signals(doc, "1.2.3")["signals"]] == ["maintainer_changed"]


def test_npm_repo_shorthand_matches_full_url() -> None:
    doc = _npm({"1.2.2": _ver(repo="https://github.com/org-a/pkg"), "1.2.3": _ver(repository="org-a/pkg")})
    assert npm_trust_signals(doc, "1.2.3")["signals"] == []
