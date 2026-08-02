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
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from .schema import AuditEvent, Decision, ScanReport


def audit_dir() -> Path | None:
    """감사로그 디렉터리. GVSKB_AUDIT_DIR 미설정이면 None(비활성)."""
    raw = os.environ.get("GVSKB_AUDIT_DIR", "").strip()
    return Path(raw) if raw else None


# ---------------------------------------------------------------------------
# caller 검증 — 개인 식별자가 감사 기록에 스며드는 것을 막는다
# ---------------------------------------------------------------------------
#
# 규칙은 연동합의 §3: ``<출처>:<모드>[:부서코드]`` (예 ``harness:auto``).
# 이 규칙을 제안한 것은 우리인데 정작 우리 쪽에 검증이 없었다 — caller 는
# 레지스트리 봉투뿐 아니라 **우리 감사로그에도 그대로 들어가므로**, 호출자가
# 사번·PC명·이메일을 넣으면 기관 감사 기록이 오염된다.
#
# 구조 검사만으로 현실적인 개인 식별자는 대부분 걸린다 — 이메일에는 ``@`` 와
# ``.`` 가, IP 에는 ``.`` 가, PC명·사번에는 ``:`` 가 없다.
_CALLER_BASE_RE = re.compile(r"^[a-z][a-z0-9_-]{0,15}:[a-z][a-z0-9_-]{0,15}$")

# 부서코드는 **코드**이지 이름이 아니다. 숫자만 허용하면 ``cli:manual:홍길동``
# 같은 값이 걸린다. 영숫자 부서코드를 쓰는 기관에서는 이 슬롯만 조용히 아니라
# **경고와 함께** 떨어지고 앞의 ``<출처>:<모드>`` 는 살아남는다 — 규칙을 모르는
# 값 하나 때문에 감사 귀속 전체를 버리는 것이 더 큰 손실이기 때문이다.
_CALLER_DEPT_RE = re.compile(r"^[0-9]{1,16}$")

# 형식을 못 맞춘 값의 대체값. 빈 문자열로 두면 '신고하지 않음'과 구분되지 않아
# 규칙 위반이 감사 기록에서 사라진다.
CALLER_INVALID = "unknown:invalid"


def normalize_caller(raw: str) -> tuple[str, str]:
    """(기록할 caller, 문제 코드). 문제 없으면 코드는 ``""``.

    **순수 함수이며 원본 값을 절대 반환·출력하지 않는다** — 거부한 값을 경고에
    실어 내보내면 막으려던 개인 식별자를 stderr 와 로그로 다시 흘리게 된다.

    문제 코드: ``malformed``(형식 불일치 — 전량 대체) ·
    ``dept_dropped``(부서코드만 규칙 위반 — 그 슬롯만 제거).
    """
    value = (raw or "").strip()
    if not value:
        return "", ""  # 미신고는 위반이 아니다 — 기존 기본값 그대로
    parts = value.split(":")
    if len(parts) == 3:
        base = ":".join(parts[:2])
        if _CALLER_BASE_RE.match(base):
            if _CALLER_DEPT_RE.match(parts[2]):
                return value, ""
            return base, "dept_dropped"
        return CALLER_INVALID, "malformed"
    if len(parts) == 2 and _CALLER_BASE_RE.match(value):
        return value, ""
    return CALLER_INVALID, "malformed"


_CALLER_WARNED: set[str] = set()

_CALLER_WARNINGS = {
    "malformed": (
        "[gvskb] ⚠ caller 값이 형식(<출처>:<모드>[:부서코드])에 맞지 않아 "
        f"'{CALLER_INVALID}' 로 기록합니다. 개인 식별자(이름·사번·PC명·이메일·IP)는 "
        "감사 기록에 넣지 마세요 — 필요한 것은 '무엇이 호출했는가'입니다."
    ),
    "dept_dropped": (
        "[gvskb] ⚠ caller 의 부서코드가 숫자가 아니어서 제거하고 기록합니다"
        "(<출처>:<모드> 는 유지). 부서코드 자리에 이름·사번을 넣지 마세요."
    ),
}


def _warn_caller(code: str) -> None:
    """같은 위반은 프로세스당 한 번만 알린다.

    락파일 800건을 검사하면 같은 caller 로 이벤트가 수백 건 생긴다. 줄마다
    경고하면 담당자가 경고를 무시하게 되고, 그러면 그 사이의 진짜 위험도 함께
    묻힌다 — 조치 단위가 '호출자 설정 수정' 한 건이므로 알림도 한 건이다.
    """
    if not code or code in _CALLER_WARNED:
        return
    _CALLER_WARNED.add(code)
    print(_CALLER_WARNINGS[code], file=sys.stderr)


def safe_caller(raw: str) -> str:
    """검증 + 1회 경고를 묶은 것. 감사·제출 경로는 전부 이걸 거친다."""
    value, code = normalize_caller(raw)
    _warn_caller(code)
    return value


def _reset_caller_warnings_for_tests() -> None:
    _CALLER_WARNED.clear()


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
    caller = safe_caller(caller)
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


def _purl(check: dict) -> str:
    """pkg:<eco>/<name>[@<version>] — 레지스트리·SBOM 과 대조 가능한 표준 형태."""
    eco = str(check.get("ecosystem") or "")
    name = str(check.get("name") or "")
    ver = check.get("version")
    return f"pkg:{eco}/{name}" + (f"@{ver}" if ver else "")


# 조치가 필요 없는 판정 — 대량 검사에서 이것까지 줄줄이 남기면 감사로그가
# 정상 통과 기록으로 뒤덮여 정작 봐야 할 줄이 묻힌다. record_scan 이 allow
# 판정을 남기지 않는 것과 같은 이유다.
_NO_ACTION_VERDICTS = frozenset({"checked_clean"})


def record_package_check(
    checks: list[dict],
    *,
    tool: str,
    caller: str = "",
    scope: str = "single",
    summary: dict | None = None,
) -> None:
    """패키지 판정을 감사로그에 남긴다.

    공공기관 감사에서 "언제 무엇을 허용·차단했는가"는 스캔 결과와 별개의
    질문이다. 그런데 record_scan 은 ScanReport 를 전제로 해 패키지 판정을
    담지 못했고, 그 결과 **패키지 계열 도구에는 감사 기록이 아예 없었다.**

    기록 단위는 규모에 따라 나눈다:

    - 단건(``scope="single"``): 판정이 무엇이든 1건 남긴다. 사람이 직접
      물어본 것이므로 '이상 없음'도 감사 대상이다.
    - 대량(매니페스트·설치본): 집계 1건 + **조치가 필요한 판정만** 개별 기록.
      락파일까지 들어오면 한 번에 수백~수천 건이라, 정상 통과를 전부 남기면
      감사로그가 노이즈가 된다.
    """
    if audit_dir() is None or not checks:
        return
    caller = safe_caller(caller)
    ts = _now_iso()
    events: list[AuditEvent] = []

    if scope != "single":
        s = summary or {}
        events.append(AuditEvent(
            event_type="package_check_batch",
            timestamp=ts,
            tool=tool,
            caller=caller,
            verdict=str(s.get("verdict") or ""),
            target_hash=_hash(scope, s.get("ecosystem"), len(checks)),
            redacted_evidence=(
                f"scope={scope} total={len(checks)} "
                f"checked={s.get('checked_count')} unchecked={s.get('unchecked_count')} "
                f"not_found={s.get('not_found_count')} hold={s.get('hold_count')}"
            )[:240],
        ))

    for c in checks:
        verdict = str(c.get("verdict") or "")
        if scope != "single" and verdict in _NO_ACTION_VERDICTS:
            continue
        events.append(AuditEvent(
            event_type="package_check",
            timestamp=ts,
            tool=tool,
            caller=caller,
            package=_purl(c),
            verdict=verdict,
            checked=bool(c.get("checked", False)),
            target_hash=_hash(_purl(c)),
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