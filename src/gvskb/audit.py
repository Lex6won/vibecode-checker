"""Append-only JSONL 감사로그 — 공공기관 점검 이력 증빙용.

``GVSKB_AUDIT_DIR`` 환경변수를 설정한 경우에만 활성화된다(opt-in). 기록은
``AuditEvent`` 스키마(schema.py)를 그대로 따르며, 원칙은 hash-centric이다:

- 원본 코드·개인정보는 절대 저장하지 않는다. 파일은 경로+크기 해시로만 남기고,
  증거는 스캐너가 이미 마스킹한 ``redacted_evidence`` 240자 캡만 기록한다.
- append-only: 파일은 월 단위(``audit-YYYYMM.jsonl``)로 이어 쓰기만 한다.
- 감사 기록 실패가 스캔을 실패시키지 않는다(stderr 경고 1줄 후 계속).

활성화 예::

    $env:GVSKB_AUDIT_DIR = "D:\\gvskb-audit"   # PowerShell
    gvskb scan ./프로젝트                        # → audit-202607.jsonl 에 append
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from .schema import AuditEvent, Decision, ScanReport


def audit_dir() -> Path | None:
    """감사로그 디렉터리. GVSKB_AUDIT_DIR 미설정이면 None(비활성)."""
    raw = os.environ.get("GVSKB_AUDIT_DIR", "").strip()
    return Path(raw) if raw else None


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _hash(*parts: object) -> str:
    """경로·크기 등 식별자만 해시 — 내용은 절대 넣지 않는다."""
    blob = "|".join(str(p) for p in parts).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:16]


def _append(events: list[AuditEvent]) -> None:
    d = audit_dir()
    if d is None or not events:
        return
    try:
        d.mkdir(parents=True, exist_ok=True)
        path = d / f"audit-{datetime.now(timezone.utc):%Y%m}.jsonl"
        with path.open("a", encoding="utf-8") as fh:
            for ev in events:
                fh.write(json.dumps(ev.model_dump(mode="json"), ensure_ascii=False) + "\n")
    except OSError as exc:
        # 감사 실패는 스캔을 막지 않는다 — 단, 침묵하지도 않는다.
        print(f"[gvskb] ⚠ audit log write failed: {exc}", file=sys.stderr)


def record_scan(report: ScanReport, tool: str, caller: str = "") -> None:
    """스캔 1회를 감사로그에 남긴다: scan 이벤트 1건 + 발견별 block/warn 이벤트.

    allow 판정 발견은 기록하지 않는다(이벤트 타입에 없음 — 조치 대상이 아님).
    caller 는 호출 주체 자율 신고 값(예: 'harness:auto') — 레지스트리의
    request_type(AUTO/MANUAL) 구분 근거가 된다.
    """
    if audit_dir() is None:
        return
    ts = _now_iso()
    events = [AuditEvent(
        event_type="scan",
        timestamp=ts,
        tool=tool,
        caller=caller,
        profile=report.profile,
        target_hash=_hash(report.target, len(report.scanned_files), report.summary.finding_count),
    )]
    for f in report.findings:
        if f.decision == Decision.allow:
            continue
        if f.suppressed:
            # 승인된 예외로 게이트를 통과한 발견 — 감사상 가장 중요한 이벤트다.
            event_type = "approve_bypass"
        elif f.decision == Decision.block:
            event_type = "block"
        else:
            event_type = "warn"
        events.append(AuditEvent(
            event_type=event_type,
            timestamp=ts,
            tool=tool,
            caller=caller,
            profile=report.profile,
            rule_id=f.rule_id,
            decision=f.decision,
            finding_id=f.id,
            target_hash=_hash(f.location.file, f.location.line),
            redacted_evidence=(f.suppress_reason or f.evidence)[:240],  # 마스킹 증거/사유만
        ))
    _append(events)


def record_update_intel(source_ids: list[str], *, tool: str = "update-intel") -> None:
    """인텔 캐시 갱신을 감사로그에 남긴다(어떤 피드를 언제 갱신했나)."""
    if audit_dir() is None:
        return
    _append([AuditEvent(
        event_type="update_intel",
        timestamp=_now_iso(),
        tool=tool,
        target_hash=_hash(",".join(sorted(source_ids))),
        redacted_evidence=",".join(sorted(source_ids))[:240],
    )])