"""감사로그(JSONL) 실기록 + 런타임 룰 status 게이트 검증.

- 감사로그: GVSKB_AUDIT_DIR 옵트인, hash-centric(원문·비밀값 미저장), append-only.
- status 게이트: proposed는 기본 미집행(GVSKB_ALLOW_PROPOSED=1 옵트인),
  deprecated는 절대 미집행, approved는 집행. 검색(search_rules)은 게이트와 무관.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from gvskb.scanner import reload_rules, scan_code, scan_path
from gvskb.schema import AuditEvent

# ---------------------------------------------------------------------------
# 감사로그
# ---------------------------------------------------------------------------


def _rows(audit_dir: Path) -> list[dict]:
    out: list[dict] = []
    for p in sorted(audit_dir.glob("audit-*.jsonl")):
        out += [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line]
    return out


def _check(name: str, verdict: str, *, version: str = "1.0.0", checked: bool = True) -> dict:
    return {
        "name": name, "version": version, "ecosystem": "pypi",
        "verdict": verdict, "checked": checked,
    }


def test_package_check_is_recorded_even_when_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """단건 조회는 '이상 없음'도 남긴다 — 사람이 직접 물어본 허용 판정이다.

    실측 공백: record_scan 이 ScanReport 를 전제로 해 패키지 계열 도구에는
    감사 기록이 아예 없었다. "언제 무엇을 허용·차단했는가"가 공공기관 감사
    대상인데 허용 기록이 없으면 답할 수 없다.
    """
    from gvskb.audit import record_package_check

    audit_dir = tmp_path / "audit"
    monkeypatch.setenv("GVSKB_AUDIT_DIR", str(audit_dir))
    record_package_check(
        [_check("requests", "checked_clean", version="2.31.0")],
        tool="check_package", caller="cli:manual", scope="single",
    )
    rows = _rows(audit_dir)
    assert len(rows) == 1
    ev = AuditEvent(**rows[0])
    assert ev.event_type == "package_check"
    assert ev.package == "pkg:pypi/requests@2.31.0"
    assert ev.verdict == "checked_clean"
    assert ev.checked is True
    assert ev.caller == "cli:manual"


def test_bulk_check_records_summary_plus_actionable_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """대량 검사는 집계 1건 + 조치 필요한 것만 — 정상 통과로 로그를 덮지 않는다.

    락파일까지 들어오면 한 번에 수백~수천 건이다. 전부 남기면 감사로그가
    정상 통과 기록으로 뒤덮여 정작 봐야 할 줄이 묻힌다.
    """
    from gvskb.audit import record_package_check

    audit_dir = tmp_path / "audit"
    monkeypatch.setenv("GVSKB_AUDIT_DIR", str(audit_dir))
    checks = [
        _check("clean-a", "checked_clean"),
        _check("clean-b", "checked_clean"),
        _check("ghost", "not_found", checked=False),
        _check("holdme", "cooldown_hold"),
    ]
    record_package_check(
        checks, tool="scan_dependencies", scope="manifest",
        summary={"verdict": "review_required", "ecosystem": "pypi",
                 "checked_count": 3, "unchecked_count": 1,
                 "not_found_count": 1, "hold_count": 1},
    )
    rows = _rows(audit_dir)
    kinds = [r["event_type"] for r in rows]
    assert kinds.count("package_check_batch") == 1
    assert kinds.count("package_check") == 2          # not_found + cooldown_hold 만
    pkgs = {r["package"] for r in rows if r["event_type"] == "package_check"}
    assert pkgs == {"pkg:pypi/ghost@1.0.0", "pkg:pypi/holdme@1.0.0"}
    batch = next(r for r in rows if r["event_type"] == "package_check_batch")
    assert batch["verdict"] == "review_required"
    assert "total=4" in batch["redacted_evidence"]


def test_mcp_check_package_actually_writes_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """배선 확인 — 함수만 있고 호출부가 없으면 감사 공백은 그대로다.

    오프라인 모드로 고정해 네트워크 없이 종단 경로를 탄다.
    """
    import asyncio

    audit_dir = tmp_path / "audit"
    monkeypatch.setenv("GVSKB_AUDIT_DIR", str(audit_dir))
    monkeypatch.setenv("GVSKB_MODE", "offline")
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path / "cache"))
    from gvskb.server import check_package

    asyncio.run(check_package(name="requests", ecosystem="pypi", version="2.31.0",
                              caller="harness:auto"))
    rows = [r for r in _rows(audit_dir) if r["event_type"] == "package_check"]
    assert rows, "check_package 호출이 감사로그에 남지 않았다"
    assert rows[0]["package"] == "pkg:pypi/requests@2.31.0"
    assert rows[0]["caller"] == "harness:auto"
    # 캐시가 비어 판정 불가여도 기록은 남아야 한다 — '판정 못 함'도 감사 대상이다.
    assert rows[0]["checked"] is False


def test_package_check_not_recorded_without_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from gvskb.audit import record_package_check

    monkeypatch.delenv("GVSKB_AUDIT_DIR", raising=False)
    record_package_check([_check("requests", "checked_clean")], tool="check_package")
    assert not list(tmp_path.glob("**/audit-*.jsonl"))


def test_audit_disabled_without_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GVSKB_AUDIT_DIR", raising=False)
    src = tmp_path / "p"
    src.mkdir()
    (src / "a.py").write_text('DB_PASSWORD = "SuperSecretValue123"\n', encoding="utf-8")
    scan_path(src)  # 예외 없이 동작해야 하고
    assert not list(tmp_path.glob("**/audit-*.jsonl"))  # 아무것도 기록하지 않는다


def test_audit_records_scan_and_findings_hash_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    audit_dir = tmp_path / "audit"
    monkeypatch.setenv("GVSKB_AUDIT_DIR", str(audit_dir))
    src = tmp_path / "p"
    src.mkdir()
    (src / "a.py").write_text('DB_PASSWORD = "SuperSecretValue123"\n', encoding="utf-8")

    report = scan_path(src)
    assert report.summary.finding_count > 0

    files = list(audit_dir.glob("audit-*.jsonl"))
    assert len(files) == 1
    raw = files[0].read_text(encoding="utf-8")
    lines = raw.strip().splitlines()
    events = [AuditEvent.model_validate(json.loads(line)) for line in lines]

    assert events[0].event_type == "scan"
    assert events[0].tool == "scan_path"
    assert any(e.event_type in ("block", "warn") for e in events[1:])
    # 발견 이벤트에는 rule_id·finding_id·마스킹 증거가 있어야 한다
    finding_events = [e for e in events if e.event_type in ("block", "warn")]
    assert all(e.rule_id and e.finding_id for e in finding_events)
    # hash-centric 원칙: 원문 비밀값은 절대 저장되지 않는다(마스킹 증거만)
    assert "SuperSecretValue123" not in raw
    assert "REDACTED" in raw


def test_audit_appends_across_scans(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    audit_dir = tmp_path / "audit"
    monkeypatch.setenv("GVSKB_AUDIT_DIR", str(audit_dir))
    src = tmp_path / "p"
    src.mkdir()
    (src / "a.py").write_text("x = 1\n", encoding="utf-8")
    scan_path(src)
    scan_path(src)
    f = list(audit_dir.glob("audit-*.jsonl"))[0]
    lines = f.read_text(encoding="utf-8").strip().splitlines()
    scans = [json.loads(line) for line in lines if json.loads(line)["event_type"] == "scan"]
    assert len(scans) == 2  # append-only — 덮어쓰지 않는다


def test_audit_update_intel_event(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GVSKB_AUDIT_DIR", str(tmp_path / "a"))
    from gvskb.audit import record_update_intel

    record_update_intel(["cisa-kev", "osv-malicious"])
    f = list((tmp_path / "a").glob("audit-*.jsonl"))[0]
    ev = AuditEvent.model_validate(json.loads(f.read_text(encoding="utf-8").strip()))
    assert ev.event_type == "update_intel"
    assert "cisa-kev" in ev.redacted_evidence


# ---------------------------------------------------------------------------
# 런타임 status 게이트
# ---------------------------------------------------------------------------

_RULE_MD = """---
id: TEST-GATE-001
title_ko: 테스트 게이트 룰
status: {status}
sources:
  - publisher: 테스트
    document: 테스트 문서
severity: high
decision_default: warn
verified_at: 2026-06-01
detection:
  patterns:
    - "MAGIC_GATE_TOKEN"
  category: test-gate
---

status 게이트 검증용 룰.
"""


@pytest.fixture
def gated_rules(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """임시 룰 디렉터리에 지정 status의 룰 하나를 놓고 런타임 룰을 리로드한다."""

    def activate(status: str, *, allow_proposed: bool = False) -> None:
        (tmp_path / "TEST-GATE-001.md").write_text(
            _RULE_MD.format(status=status), encoding="utf-8"
        )
        monkeypatch.setenv("GVSKB_RULES_DIR", str(tmp_path))
        if allow_proposed:
            monkeypatch.setenv("GVSKB_ALLOW_PROPOSED", "1")
        else:
            monkeypatch.delenv("GVSKB_ALLOW_PROPOSED", raising=False)
        reload_rules()

    yield activate
    # 전역 RULES 복원 — env를 되돌린 뒤 반드시 다시 로드한다.
    monkeypatch.delenv("GVSKB_RULES_DIR", raising=False)
    monkeypatch.delenv("GVSKB_ALLOW_PROPOSED", raising=False)
    reload_rules()


def _gate_hits() -> set[str]:
    r = scan_code("MAGIC_GATE_TOKEN = 1\n", filename="t.py", language="python")
    return {f.rule_id for f in r.findings}


def test_proposed_rule_not_enforced_by_default(gated_rules) -> None:
    gated_rules("proposed")
    assert "TEST-GATE-001" not in _gate_hits()


def test_proposed_rule_enforced_with_optin(gated_rules) -> None:
    gated_rules("proposed", allow_proposed=True)
    assert "TEST-GATE-001" in _gate_hits()


def test_deprecated_rule_never_enforced(gated_rules) -> None:
    gated_rules("deprecated", allow_proposed=True)
    assert "TEST-GATE-001" not in _gate_hits()


def test_approved_rule_enforced(gated_rules) -> None:
    gated_rules("approved")
    assert "TEST-GATE-001" in _gate_hits()