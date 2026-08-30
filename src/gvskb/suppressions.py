"""승인된 예외(bypass) 파일 — `.gvskb-exceptions.yaml`.

오탐이거나 기관이 위험을 수용하기로 결정한 발견을 **숨기지 않고 기록하며**
게이트(exit code·배포 판정)만 통과시키는 장치다. `BypassApproval` 스키마의
정신을 파일로 구현한다: 사유·승인자·만료일이 **전부 있어야만** 유효하다.

스캔 루트의 ``.gvskb-exceptions.yaml``::

    exceptions:
      - rule_id: GOV-FLASK-DEBUG-001
        file: app.py             # 스캔 결과의 파일 경로와 일치(/ 구분)
        line: 47                 # 선택 — 지정하면 그 줄만
        reason: 내부 개발서버 전용 스크립트 — 외부 노출 없음
        approved_by: 김보안(정보보안담당관)
        expires: 2026-12-31

동작 원칙:
- 매칭된 발견은 ``suppressed=True`` 로 표시될 뿐 **리포트에서 사라지지 않는다**
  (보안팀이 "무엇이 왜 면제됐나"를 항상 볼 수 있어야 한다).
- 요약 건수·차단 판정·exit code 는 *비억제* 발견 기준으로 계산된다.
- **만료된 예외는 자동 무효** — 발견이 다시 게이트를 막는다(방치 방지).
- reason/approved_by/expires 중 하나라도 없으면 그 예외는 무효(집행 규율).
- 억제 적용은 감사로그에 ``approve_bypass`` 이벤트로 남는다(audit.py).
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

import yaml

from .schema import Finding

EXCEPTIONS_FILENAME = ".gvskb-exceptions.yaml"

# 중앙(기관) 예외 오버레이 디렉터리 — 레지스트리·보안실이 확정한 예외 판정을
# 내부 배포 지점에서 내려받아 이 디렉터리에 두면, 프로젝트 로컬 예외와 병합돼
# 모든 스캔에 적용된다. 형식은 프로젝트 예외 파일과 동일(사유·승인자·만료 필수).
#
# 준비 단계 주의: 이 디렉터리를 "다운로드 받게" 운영하는 순간 예외 파일은
# 사실상 게이트 통과권이 된다 — 배포 채널에 sha256·서명 검증을 반드시 얹을 것
# (레지스트리 확정 후 배포 설계에서 처리. 현재는 로드 메커니즘만 준비).
EXCEPTIONS_DIR_ENV = "GVSKB_EXCEPTIONS_DIR"

_REQUIRED_FIELDS = ("rule_id", "file", "reason", "approved_by", "expires")


@dataclass
class SuppressionResult:
    """적용 결과 — 리포트·감사로그가 소비한다."""

    applied: int = 0
    expired: list[dict] = field(default_factory=list)   # 만료돼 무효화된 예외
    invalid: list[str] = field(default_factory=list)    # 필수 필드 누락 등 사유


def _norm(path: str) -> str:
    return path.replace("\\", "/").strip("/").lower()


def _read_exceptions_file(p: Path, origin: str) -> list[dict]:
    """예외 yaml 1개를 읽는다. 각 항목에 출처(_origin)를 표시해 감사 추적을 돕는다."""
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except (yaml.YAMLError, OSError, UnicodeDecodeError) as exc:
        print(f"[gvskb] ⚠ 예외 파일을 읽지 못했습니다({p.name}): {exc}", file=sys.stderr)
        return []
    entries = data.get("exceptions")
    if not isinstance(entries, list):
        return []
    return [{**e, "_origin": origin} for e in entries if isinstance(e, dict)]


def load_central_exceptions() -> list[dict]:
    """중앙(기관) 오버레이 디렉터리의 예외를 읽는다 — GVSKB_EXCEPTIONS_DIR.

    디렉터리 안의 *.yaml/*.yml 을 이름순으로 전부 읽는다(레지스트리가 파일
    단위로 배포·갱신할 수 있게). 미설정이면 빈 목록 — 기존 동작과 동일.
    """
    raw = os.environ.get(EXCEPTIONS_DIR_ENV, "").strip()
    if not raw:
        return []
    d = Path(raw)
    if not d.is_dir():
        print(f"[gvskb] ⚠ {EXCEPTIONS_DIR_ENV}={raw} — 디렉터리가 없어 중앙 예외를 건너뜁니다.", file=sys.stderr)
        return []
    out: list[dict] = []
    for p in sorted(d.glob("*.yml")) + sorted(d.glob("*.yaml")):
        out.extend(_read_exceptions_file(p, origin=f"central:{p.name}"))
    return out


def load_exceptions(root: Path) -> list[dict]:
    """프로젝트 로컬 + 중앙 오버레이 예외를 병합해 반환한다.

    로컬을 먼저 두는 이유: 같은 발견에 둘 다 매칭되면 먼저 매칭된 항목이
    적용되는데, 프로젝트가 더 구체적 맥락(파일·라인)을 알기 때문이다.
    어느 쪽이든 사유·승인자·만료가 없으면 무효(집행 규율 동일).
    """
    p = root / EXCEPTIONS_FILENAME if root.is_dir() else root.parent / EXCEPTIONS_FILENAME
    local = _read_exceptions_file(p, origin="project") if p.is_file() else []
    return local + load_central_exceptions()


def _parse_expires(raw: object) -> date | None:
    if isinstance(raw, date):
        return raw
    try:
        return date.fromisoformat(str(raw))
    except (ValueError, TypeError):
        return None


def apply_suppressions(
    findings: list[Finding],
    exceptions: list[dict],
    *,
    today: date | None = None,
) -> SuppressionResult:
    """유효한 예외에 매칭되는 발견을 suppressed 로 표시한다(제거하지 않음)."""
    result = SuppressionResult()
    if not exceptions:
        return result
    today = today or date.today()

    valid: list[dict] = []
    for e in exceptions:
        missing = [k for k in _REQUIRED_FIELDS if not e.get(k)]
        if missing:
            result.invalid.append(
                f"{e.get('rule_id', '?')}: 필수 항목 누락({', '.join(missing)}) — 무효"
            )
            continue
        expires = _parse_expires(e.get("expires"))
        if expires is None:
            result.invalid.append(f"{e.get('rule_id', '?')}: expires 날짜 형식 오류 — 무효")
            continue
        if expires < today:
            result.expired.append(e)  # 만료 — 억제하지 않고 리포트에 경고
            continue
        valid.append({**e, "_expires": expires})

    for f in findings:
        for e in valid:
            # 같은 줄의 다른 룰이 대표로 남고 예외의 rule_id 는 also_matched 에 있을 수 있다.
            if e["rule_id"] not in (f.rule_id, *getattr(f, "also_matched", [])):
                continue
            if _norm(f.location.file) != _norm(str(e["file"])):
                continue
            if e.get("line") is not None and int(e["line"]) != f.location.line:
                continue
            f.suppressed = True
            origin = e.get("_origin", "project")
            origin_tag = f" · 출처: {origin}" if origin != "project" else ""
            f.suppress_reason = (
                f"{e['reason']} (승인: {e['approved_by']} · 만료: {e['_expires'].isoformat()}{origin_tag})"
            )
            result.applied += 1
            break

    for msg in result.invalid:
        print(f"[gvskb] ⚠ 예외 무효: {msg}", file=sys.stderr)
    return result
