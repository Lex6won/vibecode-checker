"""보안성검토 서식 v1.2 「AI 체커 점검 항목」 8개 결과표 (설계 A4).

서식은 AI체커에 8개 항목의 결과를 묻는다. 이 모듈은 리포트에 이미 있는 사실(발견·의존성 검사·게이트)을
그 8개 칸에 옮긴다. 새 탐지는 하지 않는다.

결과 값은 네 가지다.
- ``적합``: 그 항목의 자동 점검을 했고 해당 발견이 없다. **안전 보증이 아니라 탐지 룰 기준의 결과**다.
- ``부적합``: 서식이 금지하는 것이 나왔다(차단 등급 발견, 악성 패키지, 취약 패키지 등).
- ``확인 필요``: 사람이 봐야 결론이 나는 신호가 있다(경고 등급, 라이선스 검토, 레지스트리 미조회 등).
- ``판정 불가``: 그 항목을 검사하지 못했다(위협정보 없음, 패키지 검사 생략).

정직성 원칙: 검사하지 못한 것을 ``적합`` 으로 쓰지 않는다. 게이트 판정(verdict)은 바꾸지 않는다 —
서식의 「결과」 칸과 배포 게이트는 별개다.
"""
from __future__ import annotations

import re
import warnings

from .schema import Decision, ScanReport

FORM_V12_VERSION = "1"

OK, NG, REVIEW, UNDETERMINED = "적합", "부적합", "확인 필요", "판정 불가"
_RANK = {OK: 0, UNDETERMINED: 1, REVIEW: 2, NG: 3}

_MALICIOUS_CODE_CATEGORIES = frozenset({"agent-supply-chain", "hidden-code"})
# 명령 실행·동적 코드·역직렬화·내장 악성코드 계열. 범주가 달라도 차단 등급이면 '적합'으로 쓰지 않는다 — 의도는 사람이 본다.
_EXECUTION_CWES = frozenset({"CWE-77", "CWE-78", "CWE-94", "CWE-95", "CWE-96", "CWE-502", "CWE-506", "CWE-829", "CWE-912"})
_NONPRODUCTION_PATH = re.compile(r"(^|/)(tests?|__tests__|fixtures?|examples?|samples?|docs?)(/|$)", re.I)
_EOL_RULE = "GOV-RUNTIME-EOL-001"
_OUTDATED_RULE = "GOV-RUNTIME-OUTDATED-001"

ITEMS = (
    ("pii", "민감정보"),
    ("secret", "인증정보"),
    ("malicious_code", "악성코드·의심코드"),
    ("public_vuln", "공개 취약요소(CVE 등)"),
    ("unknown_origin", "출처불명 패키지(라이브러리)"),
    ("eol", "지원 종료 구성 요소(EOL)"),
    ("malicious_package", "악성·위장 패키지"),
    ("license", "패키지 라이선스 확인"),
)


def _row(key: str, result: str, count: int, basis: str, action: str = "", rules: list[str] | None = None) -> dict:
    label = dict(ITEMS)[key]
    return {"key": key, "label": label, "result": result, "count": count,
            "basis": basis, "action": action, "rules": sorted(set(rules or []))}


def _finding_row(key: str, findings: list, none_basis: str, action: str, source_gap: str = "") -> dict:
    """소스 발견 기반 항목 — 차단 등급(살아 있는 것)이 있으면 부적합, 그 외 발견은 확인 필요.

    발견이 없어도 소스를 다 보지 못했으면 '적합'이 아니다.
    """
    if not findings:
        return _row(key, UNDETERMINED, 0, source_gap) if source_gap else _row(key, OK, 0, none_basis)
    live_block = [f for f in findings if f.decision == Decision.block and not f.severity_adjusted]
    result = NG if live_block else REVIEW
    basis = f"발견 {len(findings)}건(차단 등급 {len(live_block)}건)"
    return _row(key, result, len(findings), basis, action, [f.rule_id for f in findings])


def _source_gap(report: ScanReport) -> str:
    """소스 항목의 '발견 없음'을 믿을 수 없는 사유 — 하나도 못 봤거나 범위가 잘렸다."""
    from .gate import _coverage_gap

    if not report.scanned_files:
        return "검사한 소스 파일이 없음 — 발견이 없다는 뜻이 아닙니다."
    gap = _coverage_gap(report)
    return f"검사 범위 결손 — {gap}" if gap else ""


def _eol_row(report: ScanReport, active: list, comps: list[dict]) -> dict:
    """지원 종료 항목 — **지원 중임을 표로 확인한 운영 런타임**이 있을 때만 '적합'이다."""
    from .scanners.runtime_version import pin_support

    eol = [f for f in active if f.rule_id == _EOL_RULE]
    live_eol = [f for f in eol if not f.severity_adjusted]
    outdated = [f for f in active if f.rule_id == _OUTDATED_RULE]
    deprecated = [c for c in comps if (c.get("registry_metadata") or {}).get("deprecated")]
    if live_eol:
        return _row("eol", NG, len(live_eol), f"지원 종료 런타임 {len(live_eol)}건", "지원 중인 버전으로 바꾸세요.", [_EOL_RULE])
    if eol or outdated or deprecated:
        n = len(eol) + len(outdated) + len(deprecated)
        note = f"테스트·문서 경로의 지원 종료 런타임 {len(eol)}건 · " if eol else ""
        return _row("eol", REVIEW, n, f"{note}구버전 런타임 {len(outdated)}건 · 관리 중단 패키지 {len(deprecated)}개",
                    "지원 가능한 버전으로 바꾸세요.", [f.rule_id for f in [*eol, *outdated]])

    def label(pin: dict) -> str:
        return f'{pin.get("runtime")} {pin.get("spec")}'

    pins = [p for p in report.runtime_pins if isinstance(p, dict) and not _NONPRODUCTION_PATH.search(str(p.get("file") or ""))]
    # 워크플로의 버전은 빌드 환경이지 운영 환경이 아니다.
    operative = [p for p in pins if p.get("runtime") in ("node", "python") and not str(p.get("where") or "").startswith("workflow")]
    images = [p for p in pins if p.get("runtime") == "image"]
    if images:
        names = ", ".join(sorted({str(p.get("spec")) for p in images})[:5])
        return _row("eol", REVIEW, len(images), f"지원 종료를 판정하지 못한 베이스 이미지: {names}",
                    "이미지의 운영체제·런타임 지원 기간을 확인하세요.")
    if not operative:
        # 버전을 선언하지 않았으면 판단 근거가 없다 — '적합'이 아니다.
        return _row("eol", REVIEW, 0,
                    "운영 런타임 버전 선언을 찾지 못함(.python-version·engines·Dockerfile 등) — 지원 종료 여부를 판단할 근거가 없습니다.",
                    "실제 운영 버전을 고정하고 「언어(버전)」 칸에 적으세요.")
    unsure = [p for p in operative if pin_support(str(p.get("runtime")), str(p.get("spec"))) != "supported"]
    if unsure:
        names = ", ".join(sorted({label(p) for p in unsure})[:5])
        return _row("eol", REVIEW, len(unsure), f"지원 여부를 확인하지 못한 런타임 선언: {names}",
                    "실제 운영 버전을 숫자로 고정하고 지원 기간을 확인하세요.")
    declared = ", ".join(sorted({label(p) for p in operative})[:6])
    return _row("eol", OK, 0, f"선언된 런타임 지원 중: {declared}. 패키지·프레임워크 단위 지원 종료는 아직 판정하지 않습니다.")


def _components(report: ScanReport) -> list[dict]:
    from .report import _dep_audits, _dep_merged_components

    return [c.get("check") or {} for c in _dep_merged_components(_dep_audits(report))]


def form_v12_table(report: ScanReport) -> dict:
    """``{"version", "items": [8행], "overall", "dependency_basis"}`` — 억제된 발견은 세지 않는다."""
    active = [f for f in report.findings if not f.suppressed]
    gate = report.gate or {}
    dep = report.dependency_check or {}
    mode = dep.get("mode")
    intel_state = ((dep.get("intel") or {}).get("state"))
    comps = _components(report)
    unchecked = [c for c in comps if not c.get("checked")]
    source_gap = _source_gap(report)

    rows: list[dict] = []
    rows.append(_finding_row(
        "pii", [f for f in active if f.category == "privacy-public-sector"],
        "개인정보 탐지 룰 기준 발견 없음", "개인정보 값을 소스·설정에서 제거하고 유출 여부를 확인하세요.", source_gap))
    rows.append(_finding_row(
        "secret", [f for f in active if f.category == "secret-scanning"],
        "비밀값 탐지 룰 기준 발견 없음", "노출된 키는 지우는 것으로 끝나지 않습니다 — 재발급하세요.", source_gap))
    malicious_code = [f for f in active if f.category in _MALICIOUS_CODE_CATEGORIES]
    execution = [f for f in active if f.category not in _MALICIOUS_CODE_CATEGORIES and f.decision == Decision.block
                 and not f.severity_adjusted and _EXECUTION_CWES.intersection(f.cwe or [])]
    code_action = "업무 목적과 무관한 실행·전송 코드인지 확인하고 제거하세요."
    code_row = _finding_row(
        "malicious_code", malicious_code, "에이전트·자동실행·숨은 문자·유출 경로 탐지 룰 기준 발견 없음", code_action, source_gap)
    if execution and code_row["result"] != NG:
        code_row = _row("malicious_code", REVIEW, len(malicious_code) + len(execution),
                        f"명령 실행·동적 코드 계열 차단 등급 {len(execution)}건 — 악성 여부는 사람이 판단합니다",
                        code_action, [f.rule_id for f in [*malicious_code, *execution]])
    rows.append(code_row)

    # 패키지 항목 공통 — 검사하지 못했으면 '판정 불가', 매니페스트가 없으면 '확인 필요'.
    if mode == "off":
        pkg_gap = (UNDETERMINED, "패키지 검사를 생략함(--deps off)")
    elif intel_state == "missing" and comps:
        pkg_gap = (UNDETERMINED, "위협정보 캐시가 없어 패키지를 대조하지 못함")
    elif not comps:
        pkg_gap = (REVIEW, "의존성 목록(매니페스트·락파일)을 찾지 못함 — 사용 패키지가 정말 없는지 확인 필요")
    else:
        pkg_gap = None

    from .report import _dep_audits

    audits = _dep_audits(report)
    truncated = sum(int(a.get("truncated_count") or 0) for a in audits)
    unparsed = [a for a in audits if a.get("verdict") == "unparsed"]
    stale = [c for c in comps if c.get("verdict") == "checked_stale" or c.get("cache_stale_sources")]
    inexact = [c for c in comps if c.get("version_exact") is False or not c.get("version")
               or c.get("version_resolution") in ("latest-assumed", "unresolved")]

    def pkg_row(key: str, bad: list[dict], review: list[dict], basis_ok: str, action: str,
                *, review_action: str | None = None, version_matters: bool = False) -> dict:
        if pkg_gap and not bad:
            return _row(key, pkg_gap[0], 0, pkg_gap[1])
        if bad:
            names = ", ".join(sorted({str(c.get("name")) for c in bad})[:5])
            return _row(key, NG, len(bad), f"{len(bad)}개 패키지: {names}", action)
        if review:
            names = ", ".join(sorted({str(c.get("name")) for c in review})[:5])
            return _row(key, REVIEW, len(review), f"{len(review)}개 패키지 확인 필요: {names}", review_action or action)
        if unchecked:
            return _row(key, REVIEW, len(unchecked), f"{len(unchecked)}개 패키지를 검사하지 못함")
        if truncated:
            return _row(key, REVIEW, truncated, f"패키지 {truncated}개는 상한에 걸려 검사하지 못함")
        if unparsed:
            return _row(key, REVIEW, len(unparsed), f"의존성 파일 {len(unparsed)}개를 해석하지 못함")
        if version_matters and stale:
            return _row(key, REVIEW, len(stale), "위협정보가 신선도 기준을 넘음 — 오래된 데이터 기준의 결과입니다", "위협정보를 갱신하고 재점검하세요.")
        if version_matters and inexact:
            return _row(key, REVIEW, len(inexact), f"패키지 {len(inexact)}개는 버전이 고정되지 않아 설치본 기준의 결과가 아닙니다",
                        "버전을 고정(==·락파일)하고 재점검하세요.")
        return _row(key, OK, 0, basis_ok)

    rows.append(pkg_row(
        "public_vuln",
        # 악성 권고도 vulnerability_count 로 세어지지만 그것은 악성·위장 항목의 몫이다.
        [c for c in comps if (c.get("vulnerability_count") and not c.get("is_malicious_package")) or c.get("in_kev") or c.get("verdict") == "vulnerable"],
        [],
        f"패키지 {len(comps)}개 공개 취약점 대조 결과 해당 없음",
        "권장 버전으로 올리고 재점검하세요.", version_matters=True))

    not_found = [c for c in comps if c.get("verdict") in ("not_found", "version_not_found") or c.get("exists") is False]
    registry_unqueried = [c for c in comps if c.get("exists") is None]
    # 저장소에 있어도 소스 저장소 주소가 없으면 출처를 대조할 수 없다. 사용불가 기준은 기관 확정 전이라 '확인 필요'로 둔다.
    no_repository = [c for c in comps if c.get("exists") is True and c.get("registry_metadata") and not c["registry_metadata"].get("repository_url")]
    if not not_found and no_repository and not pkg_gap:
        rows.append(_row(
            "unknown_origin", REVIEW, len(no_repository),
            "소스 저장소 주소가 없는 패키지 "
            f'{len(no_repository)}개: {", ".join(sorted(str(c.get("name")) for c in no_repository)[:5])}',
            "공식 저장소·게시자를 확인하세요. 사용불가 기준은 기관 확정 전입니다."))
    elif not not_found and registry_unqueried and not pkg_gap:
        rows.append(_row(
            "unknown_origin", REVIEW, len(registry_unqueried),
            f"공식 저장소 실재 확인 안 함(패키지 검사 모드 {mode or '미기록'}) — {len(registry_unqueried)}개",
            "출처(공식 저장소·저장소 주소)를 확인하세요."))
    else:
        rows.append(pkg_row(
            "unknown_origin", not_found, [],
            f"패키지 {len(comps)}개 공식 저장소 실재 확인",
            "출처불명 패키지는 사용할 수 없습니다 — 공식 패키지로 바꾸세요."))

    rows.append(_eol_row(report, active, comps))

    rows.append(pkg_row(
        "malicious_package",
        [c for c in comps if c.get("is_malicious_package") or c.get("verdict") == "malicious"],
        # 특정 버전 악성 권고인데 설치될 버전을 모르면 '적합'이 아니다.
        [c for c in comps if c.get("verdict") == "suspicious_name" or c.get("malicious_possible")],
        f"패키지 {len(comps)}개 악성·위장 목록 대조 결과 해당 없음",
        "즉시 제거하고 설치된 PC 를 점검하세요.",
        review_action="버전을 고정하고 공식 저장소에서 의도한 정상 패키지인지 확인하세요.", version_matters=True))

    lic_review = [c for c in comps if c.get("license_verdict") in ("review_required", "unknown")]
    # 라이선스 판정값이 비어 있으면 **조회하지 않은 것**이다(로컬 모드는 레지스트리를 묻지 않는다) — 적합이 아니다.
    lic_unqueried = [c for c in comps if c.get("license_verdict") is None]
    if not lic_review and lic_unqueried and not pkg_gap:
        rows.append(_row(
            "license", REVIEW, len(lic_unqueried),
            (f"저장소에 라이선스 정보가 없음 — {len(lic_unqueried)}개" if mode == "online"
             else f"라이선스 조회 안 함(패키지 검사 모드 {mode or '미기록'}) — {len(lic_unqueried)}개"),
            "패키지 라이선스를 확인하세요. 기관 허용 목록 확정 전 임시 기준입니다."))
    else:
        rows.append(pkg_row(
            "license", [], lic_review,
            f"패키지 {len(comps)}개 라이선스 허용 범위",
            "라이선스 조건(공개 의무·상업 제한)을 확인하세요. 기관 허용 목록 확정 전 임시 기준입니다."))

    overall = max((r["result"] for r in rows), key=lambda v: _RANK[v])
    counts = {v: sum(1 for r in rows if r["result"] == v) for v in (OK, NG, REVIEW, UNDETERMINED)}
    return {
        "version": FORM_V12_VERSION,
        "items": rows,
        "overall": overall,
        "summary": " · ".join(f"{k} {v}" for k, v in counts.items() if v),
        "dependency_basis": {"mode": mode, "intel_state": intel_state, "components": len(comps),
                             "unchecked": len(unchecked), "gate_verdict": gate.get("verdict")},
        "note": "「적합」은 자동 탐지 룰 기준의 결과이며 안전 보증이 아닙니다. 배포 게이트 판정과는 별개입니다.",
    }


def attach_form_v12(report: ScanReport) -> ScanReport:
    # 결과표는 부가 정보다. 여기서 실패했다고 검사 결과 전체를 잃으면 안 된다.
    try:
        report.form_v12 = form_v12_table(report)
    except Exception as exc:  # noqa: BLE001
        report.form_v12 = None
        warnings.warn(f"서식 결과표를 만들지 못했습니다: {exc}", stacklevel=2)
    return report
