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