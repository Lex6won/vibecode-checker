"""사람이 읽는 한국어 리포트 생성.

공무원이 검사 결과를 그대로 공문 '붙임'(보안팀 제출·보고)으로 사용할 수 있도록
Markdown 한 장 분량의 결론·요약·증거·수정 가이드·재현 절차·면책을 묶어서 출력합니다.
결재(서명)는 상위 공문이 담당하므로 리포트에는 결재 요소를 넣지 않습니다.

핵심 시나리오는 "MCP로 코딩 → 완성 소스 재검증 → 리포트"이므로, 리포트는
*수정 후 다시 검증하는 방법*까지 명시합니다.
"""
from __future__ import annotations

import html
import re
from collections import Counter, defaultdict
from datetime import datetime

from .schema import Decision, Finding, ScanReport, Severity

_SEVERITY_RANK = {Severity.critical: 3, Severity.high: 2, Severity.medium: 1, Severity.low: 0}
_SEVERITY_EMOJI = {
    Severity.critical: "[CRITICAL]",
    Severity.high: "[HIGH]",
    Severity.medium: "[MEDIUM]",
    Severity.low: "[LOW]",
}
_SEVERITY_LABEL_KO = {
    Severity.critical: "치명",
    Severity.high: "높음",
    Severity.medium: "보통",
    Severity.low: "낮음",
}

# 판정 근거 강도 — 같은 심각도라도 근거가 다르면 대응이 달라야 한다.
# "치명 8건"만 크게 뜨고 그중 전부가 패턴 일치였다면 신뢰가 무너진다(실측 사례).
_CONFIDENCE_LABEL_KO = {
    "confirmed": "확인됨(데이터 흐름 추적)",
    "likely": "유력함(구조 분석) — 문맥 확인 권장",
    "pattern-only": "패턴 일치만 — 값의 출처를 직접 확인하세요",
}


def _confidence_label(value: str | None) -> str:
    return _CONFIDENCE_LABEL_KO.get(value or "pattern-only", "패턴 일치만")


def _skip_reason_group(reason: str) -> str:
    """제외 사유를 사람이 이해할 묶음으로 분류한다."""
    r = reason or ""
    if "확장자 아님" in r:
        return "검사 대상 확장자 아님"
    if "벤더 번들" in r:
        return "벤더 번들(외부 라이브러리 · 컴포넌트 검사로 이관)"
    if "빌드 산출물" in r:
        return "빌드 산출물(압축·번들)"
    if "매니페스트" in r:
        return "의존성 매니페스트(별도 검사)"
    if "too large" in r or "크기" in r:
        return "크기 초과"
    if "binary" in r or "바이너리" in r:
        return "바이너리"
    if "encoding" in r or "인코딩" in r:
        return "인코딩 불가"
    if "max_files" in r:
        return "최대 파일 수 도달"
    if "read error" in r or "stat error" in r:
        return "읽기 실패"
    return "기타"


def _skip_breakdown_lines(report: "ScanReport") -> list[str]:
    """제외 파일 요약 줄(사유별 분류 + 필요한 안내)."""
    skips = report.skipped_files or []
    if not skips:
        return []
    groups: dict[str, int] = {}
    for s in skips:
        g = _skip_reason_group(s.reason or "")
        groups[g] = groups.get(g, 0) + 1
    ordered = sorted(groups.items(), key=lambda kv: -kv[1])
    detail = " · ".join(f"{name} {n}" for name, n in ordered)
    out = [f"- 검사 제외: **{len(skips)}건** ({detail})"]
    if groups.get("검사 대상 확장자 아님"):
        out.append(
            "  - '검사 대상 확장자 아님'은 **검사되지 않았다는 뜻**입니다 — 위험이 "
            "없다는 의미가 아닙니다. 필요한 형식이 있으면 담당자에게 문의하세요."
        )
    if groups.get("최대 파일 수 도달"):
        # 여기 '1건'은 파일 1개가 아니라 '절단 사건 1건'이다 — 실제 미검사
        # 파일 수를 함께 적지 않으면 70개 누락이 1건으로 읽힌다.
        missed = next(
            (m.group(2) for s in skips
             if (m := _SOURCE_TRUNC_RE.search(s.reason or ""))),
            None,
        )
        detail = f"**{missed}개 파일이 검사되지 않았습니다**" if missed else "**일부만 검사**했습니다"
        out.append(f"  - ⚠ 최대 파일 수에 걸려 {detail} — `--max-files` 를 늘려 다시 검사하세요.")
    return out


def _duplicate_files_line(report: "ScanReport") -> str:
    """발견이 난 파일이 여러 경로에 복제돼 있으면 한 줄로 알린다.

    같은 인증서·키가 두 폴더에 복사돼 있으면 발견 건수가 그대로 배가 되어
    "위험이 두 배"처럼 보인다 — 실제로는 **같은 자산이 두 곳에 있는 것**이므로
    조치도 한 번에 해야 한다(두 곳 모두 제거·교체).
    """
    dups = report.duplicate_files or []
    if not dups:
        return ""
    total_extra = sum(len(d.get("paths", [])) - 1 for d in dups)
    if total_extra <= 0:
        return ""
    sample = dups[0].get("paths", [])
    where = " · ".join(sample[:2]) + (" …" if len(sample) > 2 else "")
    return (
        f"- 동일 내용 파일 복제: **{len(dups)}종 {total_extra}곳 중복** (예: {where}) "
        "— 같은 자산이므로 조치는 **모든 사본에 함께** 적용하세요"
    )


def _confidence_summary_line(report: "ScanReport") -> str:
    """요약층 한 줄 — 근거 강도 분포. 억제되지 않은 발견만 센다."""
    active = [f for f in report.findings if not f.suppressed]
    if not active:
        return ""
    counts: dict[str, int] = {}
    for f in active:
        counts[f.confidence] = counts.get(f.confidence, 0) + 1
    parts = []
    if counts.get("confirmed"):
        parts.append(f"확인됨 {counts['confirmed']}건")
    if counts.get("likely"):
        parts.append(f"유력함 {counts['likely']}건")
    if counts.get("pattern-only"):
        parts.append(f"**패턴 일치만 {counts['pattern-only']}건**")
    if not parts:
        return ""
    tail = ""
    if counts.get("pattern-only"):
        tail = " — 패턴 일치 항목은 값의 출처를 직접 확인한 뒤 판단하세요"
    return f"- 판정 근거: {' · '.join(parts)}{tail}"

# Map a reference fragment to a human-readable guideline group. Order matters —
# the first matching prefix wins so more specific labels (e.g. "KISA Python")
# are checked before broader ones (e.g. "KISA").
_GUIDELINE_PATTERNS: tuple[tuple[str, str], ...] = (
    ("KISA Python", "KISA Python 시큐어코딩"),
    ("KISA JS", "KISA JavaScript 시큐어코딩"),
    ("KISA",      "KISA"),
    ("MOIS",      "행정안전부 SW 개발보안"),
    ("국정원",     "국정원 AI 보안 가이드"),
    ("OWASP LLM", "OWASP LLM Top 10"),
    ("OWASP Agentic", "OWASP Agentic Top 10"),
    ("OWASP",     "OWASP"),
    ("NIST",      "NIST"),
    ("CISA",      "CISA"),
    ("CWE",       "CWE 분류"),
    ("CVE",       "CVE"),
    ("개인정보",   "개인정보보호위원회"),
)


def _classify_reference(ref: str) -> str | None:
    for needle, label in _GUIDELINE_PATTERNS:
        if needle in ref:
            return label
    return None


def _guideline_distribution(findings: list[Finding]) -> Counter[str]:
    """Count findings per guideline group based on their references.

    A finding can cite multiple guidelines (e.g. KISA + CWE + OWASP). We count
    each *distinct* guideline once per finding to avoid double-weighting.
    """
    counts: Counter[str] = Counter()
    for f in findings:
        seen: set[str] = set()
        for ref in (f.references or []):
            label = _classify_reference(ref)
            if label and label not in seen:
                counts[label] += 1
                seen.add(label)
    return counts


# ---------------------------------------------------------------------------
# 집계 헬퍼 — Markdown/HTML 두 렌더러가 같은 요약 데이터를 공유한다.
# (가) 1페이지 요약, (나) 파일별 세부, (다) 수정 프롬프트가 모두 이걸 쓴다.
# ---------------------------------------------------------------------------

_LINE_LIST_LIMIT = 8
# 상세 카드에 펼쳐 보일 파일 수 상한. 넘으면 '외 N개 파일'로 접고, 전체 목록은
# 수정 프롬프트 블록에 그대로 들어간다(잘라도 정보가 사라지지 않는 자리).
_LOC_FILE_LIMIT = 3


def _by_file(findings: list[Finding]) -> dict[str, list[Finding]]:
    d: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        d[f.location.file].append(f)
    return d


def _ordered_files(by_file: dict[str, list[Finding]]) -> list[str]:
    """위험이 많고 심각한 파일이 위로 오도록 정렬."""
    return sorted(
        by_file.keys(),
        key=lambda fn: (
            -max(_SEVERITY_RANK[f.severity] for f in by_file[fn]),
            -len(by_file[fn]),
            fn,
        ),
    )


def _file_max_severity(findings: list[Finding]) -> Severity:
    return max((f.severity for f in findings), key=lambda s: _SEVERITY_RANK[s])


def _rule_groups(findings: list[Finding]) -> list[dict]:
    """rule_id 단위로 묶어 '무슨 문제 몇 건'을 만든다(위험 유형 Top용).

    같은 룰의 설명을 한 번만 보여주고 위치는 목록으로 합치기 위한 기반.
    심각도 높은 순 → 건수 많은 순으로 정렬.

    **묶음 키에 심각도·결정·조정사유를 함께 넣는다.** rule_id 만으로 묶으면,
    같은 룰이 운영 코드에서는 치명·차단이고 테스트 코드에서는 감쇄된 낮음일 때
    한 카드로 합쳐진다. 그러면 카드 머리의 '심각도 조정: critical → low' 가
    운영 코드의 진짜 시크릿에까지 걸린 것처럼 읽히고, `decision` 은 첫 발견의
    것을 쓰므로 차단이 경고로 표시될 수 있다.
    """
    groups: dict[tuple[str, Severity, Decision, str], list[Finding]] = defaultdict(list)
    for f in findings:
        groups[(f.rule_id, f.severity, f.decision, f.severity_adjusted or "")].append(f)
    rows: list[dict] = []
    for (rid, sev, dec, _adj), fs in groups.items():
        rows.append({
            "rule_id": rid,
            "title": fs[0].plain_title,
            "severity": sev,
            "decision": dec,
            "count": len(fs),
            "files": len({f.location.file for f in fs}),
            "sample": fs[0],
            "findings": fs,
        })
    rows.sort(key=lambda r: (-_SEVERITY_RANK[r["severity"]], -r["count"], r["rule_id"]))
    return rows


def _action_order(findings: list[Finding]) -> list[dict]:
    """조치 순서 — **전체를 3단으로 나눈다. 잘라내지 않는다.**

    예전에는 'Top 3'(위험 유형 3개)만 보여줬다. 실측 질문 두 가지가 거기서 나왔다:
    "왜 일부만 표시하나", "위험은 다 조치해야 하는 것 아닌가". 둘 다 맞는 말이다 —
    잘린 목록은 **"3개만 하면 되나"** 로 읽히고, 그러면 나머지 13건이 조용히 남는다.

    Top-N 이 답하려던 질문("무엇부터 손대나")은 여전히 유효하므로, 자르는 대신
    **순서로** 답한다. 단은 조치의 급함이 실제로 다른 지점에서만 나눈다:

    1. 지금 막아야 하는 것 — 배포를 차단하는 항목(block)
    2. 그다음 — 차단은 아니지만 치명·높음
    3. 나머지 — 보통·낮음(다 고쳐야 하지만 순서상 뒤)
    """
    def key(r: dict) -> tuple:
        block = 0 if r["decision"] == Decision.block else 1
        return (block, -_SEVERITY_RANK[r["severity"]], -r["count"], r["rule_id"])

    groups = sorted(_rule_groups(findings), key=key)
    tiers: list[dict] = [
        {"label": "지금 막아야 하는 것", "hint": "배포가 차단됩니다", "groups": []},
        {"label": "그다음", "hint": "치명·높음", "groups": []},
        {"label": "나머지", "hint": "보통·낮음 — 순서가 뒤일 뿐 조치 대상입니다", "groups": []},
    ]
    for g in groups:
        if g["decision"] == Decision.block:
            tiers[0]["groups"].append(g)
        elif g["severity"] in (Severity.critical, Severity.high):
            tiers[1]["groups"].append(g)
        else:
            tiers[2]["groups"].append(g)
    for t in tiers:
        t["count"] = sum(g["count"] for g in t["groups"])
    return [t for t in tiers if t["groups"]]


def _action_order_note(report: ScanReport) -> str:
    """조치 순서 머리말 — **전부 조치 대상**임을 먼저 못박는다."""
    total = len(report.findings)
    dep_row = _dep_domain_row(report)
    dep_n = (dep_row or {}).get("count") or 0
    scope = f"소스 코드 {total}건" + (f" · 패키지 {dep_n}건" if dep_n else "")
    return (
        f"**{scope} 전부가 조치 대상입니다.** 아래는 '무엇부터' 손댈지의 순서일 뿐, "
        "일부만 고르라는 뜻이 아닙니다. 위에서부터 처리하세요."
    )


def _locations_by_file(
    findings: list[Finding],
    limit_lines: int = _LINE_LIST_LIMIT,
    limit_files: int | None = None,
) -> str:
    """'app.py(line 2, 5); other.js(line 9)' — **파일 경로를 포함한** 위치 문자열.

    상세 카드와 수정 프롬프트가 **같은 함수를 쓴다.** 예전에는 카드가 줄 번호만
    찍어(``line 1, 39, 66``) 어느 파일인지 알 수 없었다 — 실측: 그 인증서 룰은
    2개 파일 × 3줄인데 읽는 사람은 3건으로 읽고 나머지 3건을 찾지 못했다.
    위치를 못 찾으면 고칠 수도 없다. 파일 경로를 아는 함수가 이미 있었는데
    **사람이 읽는 화면에서만 버리고 있었다.**

    ``limit_files`` 는 카드가 길어지지 않게 앞쪽 파일만 보이고 나머지는 개수로
    접는다(전체 목록은 수정 프롬프트 블록에 그대로 들어간다).
    """
    byf: dict[str, list[int]] = defaultdict(list)
    for f in findings:
        byf[f.location.file].append(f.location.line)
    ordered = _ordered_files_by_name(byf)
    shown = ordered[:limit_files] if limit_files else ordered
    parts: list[str] = []
    for fn in shown:
        lines = sorted(set(byf[fn]))
        ls = ", ".join(str(n) for n in lines[:limit_lines])
        if len(lines) > limit_lines:
            ls += f" 외 {len(lines) - limit_lines}건"
        parts.append(f"{fn.replace(chr(92), '/')}(line {ls})")
    text = "; ".join(parts)
    if limit_files and len(ordered) > limit_files:
        text += f" 외 {len(ordered) - limit_files}개 파일"
    return text


def _ordered_files_by_name(byf: dict[str, list[int]]) -> list[str]:
    return sorted(byf.keys(), key=lambda fn: (-len(byf[fn]), fn))


def _build_artifact_skips(report: ScanReport) -> list:
    """빌드 산출물(압축/번들·빌드출력 디렉터리)로 제외된 항목."""
    return [s for s in report.skipped_files if "빌드 산출물" in (s.reason or "")]


# 초보자용 "다음 할 일" 행동 안내. 보안을 몰라도 결과를 받은 직후 바로 따라할
# 수 있도록, 자기가 쓰던 AI 코딩 도구에 그대로 말하는 흐름(고치기→확인→재검사)을
# 제시한다. 결과를 받고 "그래서 뭘 하지?" 에서 막히지 않게 하는 것이 목적.
_SAY_FIX = "방금 보안검사에서 나온 위험들을 안전하게 고쳐줘"
_SAY_RESCAN = "다시 검사해줘"

_ACTION_STEPS: tuple[tuple[str, str, str], ...] = (
    (
        "고치기",
        "지금 코딩하던 AI 도구(커서·클로드 코드 등)에 그대로 말하세요",
        _SAY_FIX,
    ),
    (
        "확인하기",
        "AI가 바꾼 내용을 살펴보고 적용하세요. 업무 로직이 바뀌면 담당자와 상의하세요.",
        "",
    ),
    (
        "다시 검사",
        "고친 뒤 한 번 더 검사해 0건이 되는지 확인하세요. 도구에 이렇게 말하면 됩니다",
        _SAY_RESCAN,
    ),
)

_ACTION_LEAD_BLOCK = "지금 이대로 올리거나 배포하면 안 됩니다. 아래 3단계로 고친 뒤 다시 검사하세요."
_ACTION_LEAD_WARN = "⚠️ 운영에 반영하기 전에 고치는 것을 권합니다. 아래 3단계를 따르세요."
_ACTION_CAVEAT = (
    "코드만으론 안 끝나는 것 — API 키·비밀번호가 노출됐다면 코드에서 지우는 것만으론 "
    "부족합니다. 그 값은 반드시 새로 발급(폐기)하고, 유출이 의심되면 보안담당자에게 알리세요."
)


def _action_lead(report: ScanReport) -> str:
    block_count = report.summary.by_decision.get(Decision.block.value, 0)
    if report.summary.blocked or block_count:
        return _ACTION_LEAD_BLOCK
    return _ACTION_LEAD_WARN


# ---------------------------------------------------------------------------
# 외부 연결 인벤토리 — 위험(findings)과 분리된 "검토용 목록". 사용 금지가 아니라
# 어디로 데이터가 나가는지 보안팀이 보게 한다. PII 인접·국외는 우선 검토 신호.
# ---------------------------------------------------------------------------

_CATEGORY_LABEL_KO = {
    "ai": "외부 AI",
    "analytics": "분석",
    "error": "에러추적",
    "payment": "결제",
    "messaging": "메시지",
    "cdn": "CDN/정적",
    "library": "라이브러리",
    "infra": "인프라",
    "gov-api": "공공 API",
    "platform": "플랫폼 API",
    "api": "API(추정)",
    # "기타"는 카테고리가 아니라 "카탈로그에 없음"이라는 뜻이었다 — 사용자가
    # 성격을 오해하지 않도록 '미분류'로 정직하게 표기한다.
    "unclassified": "미분류",
    "other": "미분류",
}


def _airgap_note(res: list, egress_count: int) -> str:
    """폐쇄망(망분리) 영향 안내문 — 리소스/전송 지점이 있을 때만 표시."""
    parts: list[str] = []
    if res:
        parts.append(
            f"외부 리소스 {len(res)}건은 인터넷 없이 **로딩되지 않아 화면·기능이 "
            "조용히 깨집니다** — 내부 사본(사내 미러)으로 교체하거나 제거하세요"
        )
    if egress_count:
        parts.append(
            f"외부 API·SDK {egress_count}건은 차단되어 기능이 멈추거나, 통제되지 "
            "않은 회선에서는 **정책 위반 전송**이 될 수 있습니다"
        )
    if not parts:
        return ""
    tail = " 외부 스크립트를 유지해야 한다면 변조 방지를 위해 SRI(integrity) 적용을 권장합니다." if res else ""
    return "**폐쇄망(망분리) 배포 시 확인** — " + ". ".join(parts) + "." + tail


def _external_stats(report: ScanReport) -> tuple[int, int, int, int]:
    """(외부 API 수, 플러그인 수, 국외 전송 수, ⚠검토 필요 수)."""
    api = [c for c in report.external_surface if c.kind == "api"]
    pkg = [c for c in report.external_surface if c.kind == "package"]
    gukoe = sum(1 for c in report.external_surface if c.region == "국외")
    warn = sum(1 for c in report.external_surface if c.review_level == "warn")
    return len(api), len(pkg), gukoe, warn


def _cat_ko(cat: str) -> str:
    return _CATEGORY_LABEL_KO.get(cat, cat)


def _verdict_line(report: ScanReport) -> str:
    """One sentence an executive can read without scrolling."""
    summary = report.summary
    if summary.finding_count == 0:
        # 검사 대상 파일이 0개면 "위험 없음"이 아니라 "검사 안 됨" — 저장된
        # 리포트만 보고 안전하다고 오해하지 않도록 결론에서 분명히 구분한다.
        if not report.scanned_files:
            return (
                "⚠ 검사된 파일 없음 — 스캔 대상 파일이 0개입니다. 경로·지원 확장자·"
                "제외 설정을 확인하세요. 이 결과를 '안전'으로 해석하지 마세요."
            )
        return "위험 없음 — 본 검사에서 발견된 위반 사항이 없습니다."
    block_count = summary.by_decision.get(Decision.block.value, 0)
    warn_count = summary.by_decision.get(Decision.warn.value, 0)
    top_sev = summary.highest_severity
    sev_ko = _SEVERITY_LABEL_KO[top_sev] if top_sev else "보통"
    if summary.blocked or block_count:
        return (
            f"차단 권고 — {sev_ko} 등급 포함 총 {summary.finding_count}건 발견, "
            f"이 중 차단(block) {block_count}건. 커밋·배포 전 수정 또는 보안담당자 승인 필요."
        )
    return (
        f"수정 권고 — {sev_ko} 등급 포함 총 {summary.finding_count}건 발견, "
        f"경고(warn) {warn_count}건. 운영 반영 전 우선 검토하세요."
    )


# ---------------------------------------------------------------------------
# 보안팀 제출용 강화 — 검토 범위·한계 고지 / 배포 판정 / 개인정보 요약 /
# 실행 모드 배너 / 같은 줄 다중 지적. MD·HTML 렌더러가 공유한다.
# ---------------------------------------------------------------------------

# 한계 고지 — 비전문가가 "발견 0건 = 안전"으로 오해하지 않도록 문서 상단부에
# 항상 고지한다(발견 유무와 무관). HTML은 핵심 문장만 굵게 강조하기 위해 분리.
_LIMIT_HEAD = "본 도구는 정적 분석 기반의 1차 보안 린터입니다."
_LIMIT_ZERO = "발견 0건이 '안전'을 보장하지 않습니다."
_LIMIT_BODY = (
    "여러 줄에 걸쳐 조립되는 일부 SQL/명령 삽입, 설계·인가·업무로직상 취약점, "
    "실행 중에만 드러나는 취약점은 놓칠 수 있습니다. 의존성(패키지) 취약점은 "
    "scan_dependencies(또는 gvskb check-package)로 별도 점검하세요."
)
_LIMIT_TAIL = "본 결과는 보안담당자의 공식 보안성 검토를 대체하지 않습니다."


def _ext_distribution(scanned_files: list[str]) -> Counter[str]:
    """검사한 파일의 확장자 분포 — 검토 범위(어떤 언어/파일을 봤는지) 표기용."""
    c: Counter[str] = Counter()
    for fp in scanned_files:
        name = fp.replace("\\", "/").rsplit("/", 1)[-1]
        ext = ("." + name.rsplit(".", 1)[-1].lower()) if "." in name else "(확장자 없음)"
        c[ext] += 1
    return c


def _short_reason(reason: str) -> str:
    """생략 사유를 집계용 라벨로 축약.

    분류는 ``_skip_reason_group`` 에 위임한다 — 예전처럼 사유 문자열을 그대로
    쓰면 ``확장자 아님(.pdf)``·``(.png)``… 처럼 **확장자마다 그룹이 쪼개져**
    수십 줄이 되어 요약의 의미가 사라진다.
    """
    return _skip_reason_group(reason or "")


def _unique_location_count(findings: list[Finding]) -> int:
    """같은 (파일, 줄)을 1곳으로 세는 고유 위치 수 — 이중 계상 오해 방지."""
    return len({(f.location.file, f.location.line) for f in findings})


def _multi_rule_lines(findings: list[Finding]) -> list[dict]:
    """한 줄에 여러 룰이 함께 걸린 위치 목록(표시 계층 전용 — core dedupe와 무관)."""
    by_loc: dict[tuple[str, int], list[Finding]] = defaultdict(list)
    for f in findings:
        by_loc[(f.location.file, f.location.line)].append(f)
    rows: list[dict] = []
    for (fn, line), fs in sorted(by_loc.items()):
        rules = sorted({f.rule_id for f in fs})
        if len(rules) >= 2:
            rows.append({"file": fn, "line": line, "rules": rules})
    return rows


# 개인정보·비밀값·LLM 프롬프트 관련 발견 분류 — 공공기관에서 가장 먼저 확인해야
# 하는 유형이라 별도 요약으로 상단 부각한다.
_PRIVACY_CATEGORY_KEYS = ("privacy-public-sector", "secret-scanning", "llm")
_PRIVACY_RULE_KEYS = ("PII", "SECRET", "LLM")


def _is_privacy_related(f: Finding) -> bool:
    cat = (f.category or "").lower()
    if any(k in cat for k in _PRIVACY_CATEGORY_KEYS):
        return True
    rid = (f.rule_id or "").upper()
    return any(k in rid for k in _PRIVACY_RULE_KEYS)


def _privacy_findings(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if _is_privacy_related(f)]


# 배포 판정 표시 색 — _deploy_status() 의 tone 과 1:1.
_VERDICT_COLOR = {
    "none": "#607d8b",
    "block": "#c0392b",
    "warn": "#e67e22",
    "ok": "#2e7d32",
}


def _dep_risk(report: ScanReport) -> tuple[int, int, int, bool]:
    """의존성 감사 → (취약·악성, 판정불가, 미존재, 차단여부). 감사 자체가 없으면 0/False.

    결론 박스가 이 값을 함께 보게 하는 것이 핵심이다. 이전에는 ``dependency_audit``
    이 리포트의 부가 필드로만 존재해, **패키지가 차단 판정이어도 결론은 초록불**
    ("배포 승인 가능")이 나왔다 — 같은 문서 안에서 서로 모순되는 결론이다.
    담당자가 가장 먼저 읽는 곳이 결론 박스이므로 조용한 초록불은 빨간불보다 위험하다.
    """
    audits = _dep_audits(report)
    if not audits:
        return (0, 0, 0, False)
    _checked, unchecked, vuln, blocked, not_found = _dep_stats(audits)
    return (vuln, unchecked, not_found, blocked)


# ---------------------------------------------------------------------------
# 의존성 심각도 — 패키지 판정을 **소스 발견과 같은 자**로 옮긴다.
#
# 왜 필요한가(실측): 보안 분야 개요·심각도 표는 소스 발견만 셌고 패키지는 어느
# 분야에도 없었다. 그런데 결론 박스는 "차단 기준에 걸린 패키지"를 근거로 배포를
# 막는다 — **판정에는 쓰이는데 집계에는 없는** 상태였다. 게다가 두 심각도가 서로
# 다른 방식으로 정해진다(룰은 저작 시 고정, 패키지는 검사 시 계산)는 사실이
# 보고서 어디에도 없어, 읽는 사람은 '높음'끼리 같은 자로 잰 값이라 오해한다.
#
# 아래 매핑은 **표시 계층 전용**이다. ``report.findings``·발견 건수·게이트 판정은
# 건드리지 않는다(패키지를 소스 발견으로 둔갑시키지 않는다). 이 표는 보고서
# 부록 '심각도 판정 기준'에 그대로 실려, 독자가 근거를 확인할 수 있다.
# ---------------------------------------------------------------------------

#: (판정 조건, 심각도, 부록 기준표에 적을 설명). 위에서부터 첫 매칭 우선.
_DEP_SEVERITY_TABLE: tuple[tuple[str, Severity, str], ...] = (
    ("malicious", Severity.critical, "악성 패키지 · 기관 레지스트리 차단 · 레지스트리에 없는 이름(가짜 이름 의심)"),
    ("kev_or_high", Severity.high, "취약점 있음 + CISA KEV 등재 또는 CVSS 심각도 HIGH·CRITICAL"),
    ("vulnerable", Severity.medium, "취약점 있음 (CVSS MEDIUM 이하 또는 심각도 미상)"),
    ("cooldown", Severity.medium, "발행 직후 버전 — 쿨다운 보류(위험 확인이 아니라 '아직 신뢰할 수 없음')"),
)


def _dep_component_severity(check: dict) -> Severity | None:
    """패키지 1건 → 보고서 심각도. None 이면 **등급을 매기지 않는다**.

    등급을 매기지 않는 경우가 두 가지고 성격이 다르다:
    이상 없음(위험이 없다)과 판정 불가(확인하지 못했다). 판정 불가를 '낮음'으로
    적으면 확인하지 못한 것이 확인된 것처럼 보이므로, 등급 대신 별도 칸에 센다.
    """
    if check.get("is_malicious_package") or check.get("verdict") in ("registry_rejected", "not_found"):
        return Severity.critical
    if check.get("vulnerability_count"):
        if check.get("in_kev") or str(check.get("max_cve") or "").upper() in ("HIGH", "CRITICAL"):
            return Severity.high
        return Severity.medium
    if check.get("verdict") == "cooldown_hold":
        return Severity.medium
    return None


def _dep_domain_row(report: ScanReport) -> dict | None:
    """의존성을 '보안 분야' 한 줄로 — 소스 분야 표에 같이 올리기 위한 집계.

    ``count`` 는 등급이 매겨진 **고유 패키지 수**(= 담당자가 업그레이드할 항목 수)이고,
    ``unknown`` 은 판정 불가 수다. 둘을 더하지 않는다 — 조치 단위가 다르다.
    """
    audits = _dep_audits(report)
    if not audits:
        return None
    by_severity: Counter[str] = Counter()
    graded: list[dict] = []
    for comp in _dep_merged_components(audits):
        sev = _dep_component_severity(comp["check"])
        if sev is None:
            continue
        by_severity[sev.value] += 1
        graded.append({**comp, "severity": sev})
    _checked, unchecked, _vuln, _blocked, _nf = _dep_stats(audits)
    if not graded and not unchecked:
        return None
    max_sev = max(
        (g["severity"] for g in graded),
        key=lambda s: _SEVERITY_RANK[s],
        default=None,
    )
    return {
        "label": "의존성·공급망(패키지)",
        "count": len(graded),
        "packages": len(graded),
        "unknown": unchecked,
        "by_severity": by_severity,
        "max_severity": max_sev,
        "components": graded,
    }


def _dep_breakdown_text(dep_row: dict) -> str:
    """의존성 행의 심각도 분포 — 소스 분야와 같은 형식으로."""
    counts = dep_row.get("by_severity") or Counter()
    parts = [
        f"{_SEVERITY_LABEL_KO[sev]} {counts.get(sev.value, 0)}"
        for sev in (Severity.critical, Severity.high, Severity.medium, Severity.low)
        if counts.get(sev.value, 0)
    ]
    return " · ".join(parts) or "—"


def _domain_table_notes(
    report: ScanReport, domains: list[dict], dep_row: dict | None,
) -> list[str]:
    """분야 개요표 아래 각주 — 표의 숫자가 무엇을 세는지 밝힌다.

    실측 오해 두 가지를 잡는다.
    1. **파일 열의 합이 실제 파일 수와 다르다** — 한 파일이 두 분야에 걸리면
       (예: 같은 파일의 주석 계정 + 자원 해제) 분야마다 한 번씩 세어진다.
       건수에는 '고유 위치'를 함께 적어 두면서 파일 수에는 같은 장치가 없었다.
    2. **의존성은 다른 자로 잰다** — 심각도 산정 방식이 소스와 다르고, 판정 불가는
       등급을 매기지 않는다.
    """
    notes: list[str] = []
    files_sum = sum(d["files"] for d in domains)
    unique_files = len({f.location.file for f in report.findings})
    if files_sum != unique_files:
        notes.append(
            f"**파일 열은 분야별로 셉니다** — 한 파일이 여러 분야에 걸리면 각 분야에서 "
            f"한 번씩 세므로 합({files_sum})이 실제 파일 수({unique_files}개)보다 큽니다."
        )
    if dep_row:
        unknown = dep_row.get("unknown") or 0
        notes.append(
            "**의존성·공급망 행은 패키지 단위**입니다(파일이 아니라 고유 패키지 수). "
            "심각도는 소스 룰과 다른 기준으로 정해집니다 — 부록의 심각도 판정 기준 참조."
            + (
                f" 판정 불가 {unknown}건은 확인하지 못한 것이라 등급 없이 별도로 셉니다."
                if unknown else ""
            )
        )
    return notes


def _dep_verdict_clause(report: ScanReport) -> str:
    """배포 판정 문장에 덧붙일 의존성 사유 한 조각 — 위험이 없으면 빈 문자열."""
    vuln, unchecked, not_found, _blocked = _dep_risk(report)
    parts: list[str] = []
    if vuln:
        parts.append(f"취약·악성 패키지 {vuln}건")
    if not_found:
        parts.append(f"레지스트리에 없는 패키지 {not_found}건")
    if unchecked:
        parts.append(f"판정 불가 {unchecked}건(‘안전’이 아닙니다)")
    if not parts:
        return ""
    return " 의존성: " + " · ".join(parts) + "."


def _deploy_verdict(report: ScanReport) -> tuple[str, str]:
    """운영서버 배포 판정 한 줄 + 표시 색 — 보안팀이 승인 근거로 쓰는 결론.

    항상 '잔여 위험' 개념을 함께 언급해 도구 미탐지 영역이 남아 있음을 알린다.
    소스 발견과 **의존성 감사 결과를 함께** 반영한다(둘 중 하나만 위험해도 초록 금지).
    """
    s = report.summary
    status = _deploy_status(report)
    color = _VERDICT_COLOR[status]
    block_n = s.by_decision.get(Decision.block.value, 0)
    warn_n = s.by_decision.get(Decision.warn.value, 0)
    dep_clause = _dep_verdict_clause(report)
    _vuln, _unchecked, _nf, dep_blocked = _dep_risk(report)

    if status == "none":
        return (
            "판정 불가 — 검사된 파일이 0개라 배포 가부를 판단할 수 없습니다. "
            "경로·확장자를 확인해 다시 검사하세요.",
            color,
        )
    if status == "block":
        if block_n and dep_blocked:
            head = (
                f"배포 불가 — 차단(block) {block_n}건과 차단 기준에 걸린 패키지를 "
                "해소하거나 보안담당자 승인이 필요합니다."
            )
        elif dep_blocked:
            head = (
                "배포 불가 — 차단 기준에 걸린 패키지가 있습니다. 해당 패키지를 "
                "안전한 버전으로 올린 뒤 다시 검사하세요."
            )
        else:
            head = (
                f"배포 불가 — 차단(block) {block_n}건을 해소하거나 보안담당자 승인이 "
                "필요합니다."
            )
        return (head + dep_clause + " 미해소 항목은 잔여 위험으로 남습니다.", color)
    if status == "warn":
        if s.finding_count:
            head = f"⚠ 조건부 — 경고 {warn_n}건을 검토한 후 배포하세요."
        else:
            head = "⚠ 조건부 — 소스코드 발견은 없으나 의존성을 먼저 확인해야 합니다."
        return (
            head + dep_clause + " 수정하지 않기로 한 항목은 잔여 위험으로 "
            "기록·관리해야 합니다.",
            color,
        )
    return (
        "심각 위험 미발견 — 단, 아래 '검토 범위 및 한계' 고지를 참조하세요. "
        "본 도구가 탐지하지 못하는 영역은 잔여 위험으로 남습니다.",
        color,
    )


def _scan_mode_note(report: ScanReport) -> str | None:
    """실행 모드·인텔 기준일 배너 — scan_mode가 없으면 아무것도 표시하지 않음."""
    mode = report.scan_mode
    if not mode:
        return None
    fresh = report.intel_freshness or {}
    dates = " · ".join(f"{k} {v}" for k, v in fresh.items())
    if mode == "offline":
        note = "🔌 오프라인(망분리) 검사 — 의존성·인텔 정보는 로컬 캐시 기준입니다"
        if dates:
            note += f" (기준일 {dates})"
        note += (
            ". 기준일 이후 공개된 취약점은 반영되지 않았을 수 있으므로 "
            "미갱신 항목을 '안전'으로 간주하지 마세요."
        )
        return note
    note = "온라인 검사 — 실시간 의존성·인텔 정보를 사용할 수 있는 모드에서 검사했습니다"
    if dates:
        note += f" (기준일 {dates})"
    return note + "."


# ---------------------------------------------------------------------------
# 보안 분야 분류기 — 보안담당자가 "어느 보안 분야가 문제인지" 한눈에 보도록
# rule_id / category 를 9개 분야로 매핑한다. 위에서부터 첫 매칭 우선(first
# match wins)이므로 더 구체적인 분야(개인정보·비밀값)가 먼저 걸린다.
# ---------------------------------------------------------------------------

_DOMAIN_PRIVACY = (1, "개인정보 노출")
_DOMAIN_SECRET = (2, "비밀값·인증정보 노출")
_DOMAIN_INJECTION = (3, "주입·원격 코드 실행")
_DOMAIN_WEB = (4, "웹 취약점")
_DOMAIN_CRYPTO = (5, "암호화·통신 보안")
_DOMAIN_MISCONFIG = (6, "보안 설정 오류")
_DOMAIN_AI = (7, "AI·자동화 위험")
_DOMAIN_QUALITY = (8, "코드 안정성·오류처리")
_DOMAIN_OTHER = (9, "그 외 보안 점검")


def _security_domain(f: Finding) -> tuple[int, str]:
    """발견 1건 → (정렬순서, "이모지 분야명"). 위에서부터 첫 매칭 우선."""
    cat = (f.category or "").lower()
    rid = (f.rule_id or "").upper()
    if cat in ("privacy-public-sector", "public-sector-internal") or "PII" in rid:
        return _DOMAIN_PRIVACY
    if cat == "secret-scanning" or "SECRET" in rid or "SEC-06" in rid or "SEC-13" in rid:
        return _DOMAIN_SECRET
    if any(k in rid for k in (
            "SQL", "CMD", "INPUT-01", "INPUT-02", "INPUT-05", "CODE-03", "CODE-05")):
        return _DOMAIN_INJECTION
    if cat == "xss" or any(k in rid for k in (
            "XSS", "HTML", "INPUT-04", "INPUT-03", "INPUT-07",
            "INPUT-11", "INPUT-12", "INPUT-13")):
        return _DOMAIN_WEB
    if any(k in rid for k in (
            "SEC-04", "SEC-05", "SEC-07", "SEC-10", "SEC-11", "SEC-14", "SEC-15",
            "TLS", "CERT", "CRYPTO")):
        return _DOMAIN_CRYPTO
    if cat == "misconfig" or any(k in rid for k in (
            "FLASK", "DEBUG", "SEC-03", "SEC-12", "ENCAP-02")):
        return _DOMAIN_MISCONFIG
    if cat in ("llm-appsec", "agent-safety") or "LLM" in rid or "AGENT" in rid:
        return _DOMAIN_AI
    if any(k in rid for k in ("CODE", "ERR", "TIME", "ENCAP")):
        return _DOMAIN_QUALITY
    return _DOMAIN_OTHER


def _severity_breakdown(findings: list[Finding]) -> str:
    """'치명 2 · 높음 1 · 보통 1 · 낮음 6' — 분야 안의 심각도 분포.

    **왜 필요한가(실측 오독)**: 분야 표는 `최고 심각도 | 건수` 두 칸이 나란히 있어
    `치명 | 10` 이 **"치명 10건"** 으로 읽혔다. 실제로는 그 분야에서 가장 높은 등급이
    치명이고 전체가 10건(치명 2·높음 1·보통 1·낮음 6)이라는 뜻이다. 한 칸에 등급,
    옆 칸에 총계를 두면 사람은 둘을 붙여 읽는다 — 분포를 함께 적어 끊는다.
    """
    counts = Counter(f.severity for f in findings)
    parts = [
        f"{_SEVERITY_LABEL_KO[sev]} {counts[sev]}"
        for sev in (Severity.critical, Severity.high, Severity.medium, Severity.low)
        if counts[sev]
    ]
    return " · ".join(parts)


def _group_by_domain(findings: list[Finding]) -> list[dict]:
    """분야별로 findings 를 모아 정렬순서대로 반환. 빈 분야는 생략."""
    buckets: dict[tuple[int, str], list[Finding]] = defaultdict(list)
    for f in findings:
        buckets[_security_domain(f)].append(f)
    out: list[dict] = []
    for (order, label), fs in sorted(buckets.items()):
        out.append({
            "order": order,
            "label": label,
            "findings": fs,
            "count": len(fs),
            "files": len({f.location.file for f in fs}),
            "max_severity": _file_max_severity(fs),
            "breakdown": _severity_breakdown(fs),
        })
    return out


def _domain_has_blocker(findings: list[Finding]) -> bool:
    """치명(critical) 또는 차단(block)이 포함된 분야인지 — 기본 펼침 판단용."""
    return any(
        f.decision == Decision.block or f.severity == Severity.critical
        for f in findings
    )


def _hero_line(report: ScanReport) -> tuple[str, str]:
    """판정 히어로 배너 — 비전문가가 첫 문장만 읽어도 되는 쉬운 결론. (문장, 색)."""
    s = report.summary
    if s.finding_count == 0 and not report.scanned_files:
        return (
            "⚠ 검사된 파일이 없습니다 — 경로·확장자를 확인해 다시 검사하세요. "
            "이 결과를 '안전'으로 해석하면 안 됩니다.",
            "#607d8b",
        )
    block_n = s.by_decision.get(Decision.block.value, 0)
    if s.blocked or block_n:
        danger = sum(
            1 for f in report.findings
            if f.decision == Decision.block or f.severity == Severity.critical
        ) or block_n
        return (
            f"지금 이대로 배포하면 안 됩니다 — 치명·차단 위험 {danger}건. "
            "아래를 고치고 다시 검사하세요.",
            "#c0392b",
        )
    if s.finding_count:
        return (
            f"⚠️ 배포 전에 고칠 것이 있습니다 — 주의 필요 {s.finding_count}건. "
            "아래 순서대로 고친 뒤 다시 검사하세요.",
            "#e67e22",
        )
    return (
        "심각한 위험은 발견되지 않았습니다 — 단, 아래 '검토 범위 및 한계'를 꼭 확인하세요.",
        "#2e7d32",
    )


# 배포 승인/미승인 — 두괄식 결과 박스(초록=승인 · 빨강=미승인 · 주황=보류).
# 색과 굵은 글씨로만 구분(장식 아이콘 없이 공문서 톤).
_VERDICT_LABEL = {
    "ok": "배포 승인 가능",
    "block": "배포 미승인 (차단)",
    "warn": "배포 보류 (확인 필요)",
    "none": "판정 불가",
}


def _deploy_status(report: ScanReport) -> str:
    """배포 판정 tone: 'ok'(초록) | 'block'(빨강) | 'warn'(주황) | 'none'(회색).

    소스 발견만이 아니라 **의존성 감사 결과도 함께** 본다. 패키지가 차단 판정이거나
    취약·미존재·판정 불가가 남아 있으면 초록불을 주지 않는다. 반대로 의존성이 전부
    '이상 없음'이면 기존과 같이 초록을 유지한다(과잉 교정 방지).
    """
    s = report.summary
    dep_vuln, dep_unchecked, dep_nf, dep_blocked = _dep_risk(report)
    dep_risky = bool(dep_vuln or dep_unchecked or dep_nf)
    if s.blocked or s.by_decision.get(Decision.block.value, 0) or dep_blocked:
        return "block"
    if s.finding_count == 0 and not report.scanned_files:
        # 소스를 한 건도 보지 못했다. 의존성에 위험이 있으면 그것을 말하고,
        # 없으면 '안전'이 아니라 '판정 불가'로 남긴다.
        return "warn" if dep_risky else "none"
    if s.finding_count or dep_risky:
        return "warn"
    return "ok"


def _verdict_box_md(report: ScanReport) -> list[str]:
    """결론 = 승인/미승인 박스(Markdown). 색은 HTML에서만 — MD는 문구로."""
    label = _VERDICT_LABEL[_deploy_status(report)]
    deploy_text, _ = _deploy_verdict(report)
    return [f"> ### {label}", ">", f"> **배포 판정** · {deploy_text}", ""]


def _verdict_box_html(report: ScanReport) -> str:
    """결론 = 승인(초록)/미승인(빨강) 박스(HTML). 두괄식으로 가장 크게."""
    tone = _deploy_status(report)
    label = _VERDICT_LABEL[tone]
    deploy_text, _ = _deploy_verdict(report)
    return (
        f'<div class="verdict v-{tone}">'
        f'<div class="vstatus">{_esc(label)}</div>'
        f'<div class="vdetail">배포 판정 · {_esc(deploy_text)}</div>'
        "</div>"
    )


def _meta_rows(report: ScanReport, ts: str) -> list[tuple[str, str]]:
    rows = [("대상", report.target), ("검사일시", ts), ("프로파일", _profile_cell(report))]
    if report.scenario:
        rows.append(("시나리오", report.scenario))
    if report.language:
        rows.append(("언어 힌트", report.language))
    # 판정 기준(엔진 + 룰셋) — 재현성의 최소 단위. **쌍으로** 적는다:
    # 엔진 코드가 바뀌어도 판정은 바뀌므로 룰셋만 적으면 재현 가능한 것처럼
    # 보이는 착시가 생긴다. 이 두 값이 같아야 같은 결과가 나온다.
    if report.engine_version or report.ruleset_version or report.ruleset_digest:
        rows.append(("판정 기준", _criteria_cell(report)))
    return rows


def _criteria_cell(report: ScanReport) -> str:
    """"어떤 엔진 + 어떤 룰셋이 이 판정을 냈나" 한 칸."""
    engine = report.engine_version or "(미상)"
    if report.ruleset_version:
        ruleset = f"룰셋 {report.ruleset_version}"
    elif report.ruleset_digest:
        ruleset = f"룰셋 (버전 선언 없음, 지문 {report.ruleset_digest[:12]}…)"
    else:
        ruleset = "룰셋 (미상)"
    cell = f"엔진 {engine} · {ruleset}"
    if report.ruleset_drift:
        cell += f" ⚠ {report.ruleset_drift}"
    return cell


def _profile_cell(report: ScanReport) -> str:
    """머리표의 프로파일 칸 — 요청과 다른 것이 적용됐으면 **그 사실을 같이 적는다**.

    프로파일이 다르면 판정 기준 자체가 다르다. 요청한 이름만 적으면 읽는 사람은
    그 기준으로 판정된 줄 안다(실측: 하네스가 `dev-quick` 을 요청했는데 정책 파일을
    못 찾아 적용되지 않았고, 보고서에는 `dev-quick` 이라고만 찍혔다).
    """
    fb = report.profile_fallback
    if not fb:
        return report.profile
    return (
        f"{fb.get('applied', report.profile)} "
        f"⚠ 요청한 `{fb.get('requested')}` 을(를) 찾지 못해 대체 — {fb.get('reason', '')}"
    )


def _meta_table_md(report: ScanReport, ts: str) -> list[str]:
    """문서 헤더 — 대상·검사일시·프로파일을 키-값 표로(긴 경로도 깔끔하게)."""
    out = ["| 항목 | 값 |", "|---|---|"]
    for k, v in _meta_rows(report, ts):
        val = f"`{v}`" if k in ("대상",) else v
        out.append(f"| {k} | {val} |")
    out.append("")
    return out


def _meta_table_html(report: ScanReport, ts: str) -> str:
    cells = "".join(
        f"<tr><th>{_esc(k)}</th><td>{_esc(v)}</td></tr>" for k, v in _meta_rows(report, ts)
    )
    return f'<table class="metatbl">{cells}</table>'


def _pii_callout_md(pii: list[Finding]) -> list[str]:
    """개인정보·비밀값 주의 콜아웃(Markdown) — '비밀값' 분야 바로 아래에 붙는다."""
    pii_files = len({f.location.file for f in pii})
    return [
        f"> **개인정보·비밀값 주의** — 관련 발견 **{len(pii)}건** · 파일 {pii_files}개. "
        "노출된 비밀값(키·비밀번호)은 코드에서 지우는 것만으로 부족하며 반드시 "
        "**재발급(폐기)** 해야 합니다. 개인정보 유출 정황이 있으면 기관 "
        "개인정보보호 담당자에게 지체 없이 알리세요.",
        "",
    ]


def _pii_callout_html(pii: list[Finding]) -> str:
    """개인정보·비밀값 주의 콜아웃(HTML) — '비밀값' 분야 바로 아래에 붙는다."""
    pii_files = len({f.location.file for f in pii})
    return (
        f'<div class="piibox"><div class="ph">개인정보·비밀값 주의 — '
        f"{len(pii)}건 · 파일 {pii_files}개</div>"
        '<div class="kv" style="font-size:13px">노출된 비밀값(키·비밀번호)은 코드 삭제만으로 '
        "부족합니다 — <b>반드시 재발급(폐기)</b>하고, 개인정보 유출 정황은 기관 "
        "개인정보보호 담당자에게 지체 없이 알리세요.</div></div>"
    )


def render_markdown(
    report: ScanReport,
    *,
    generated_at: datetime | None = None,
    reproduce_command: str | None = None,
) -> str:
    """Render a ScanReport as a self-contained Korean Markdown document.

    Args:
        report: the scan report to render.
        generated_at: timestamp shown in the header (defaults to now).
        reproduce_command: optional exact CLI command that produced this report.
            When omitted, a sensible default referencing the target is emitted.

    이 문서는 공문의 '붙임'으로 제출되는 것을 전제로 한다 — 결재(서명)는
    상위 공문이 담당하므로 리포트 자체에는 결재 요소를 넣지 않는다.

    The output is designed to be readable on its own — anyone can paste it into
    a Word document or print it without needing to query the MCP further.
    """
    ts = (generated_at or datetime.now()).strftime("%Y-%m-%d %H:%M")
    lines: list[str] = []

    # 승인된 예외(suppressed)는 본문 통계·상세에서 분리해 전용 섹션에만 표시.
    # (summary는 스캐너가 이미 비억제 기준으로 계산했다)
    suppressed = [f for f in report.findings if f.suppressed]
    if suppressed:
        report = report.model_copy(
            update={"findings": [f for f in report.findings if not f.suppressed]}
        )

    lines.append("# 코드 보안 검사 결과")
    lines.append("")

    # =====================================================================
    # Layer 1 — 공무원용 (접기 없음, 두괄식): 판정 히어로 → 핵심 숫자 →
    # 다음 3단계 → 가장 먼저 할 일 Top3 → 정직성 배너(모드·예외·의존성·
    # 빌드제외·한계 고지). 어려운 상세는 전부 Layer 2(보안팀)로 내린다.
    # =====================================================================

    # --- ① 문서 헤더(대상·일시·프로파일 표) → 결론(승인/미승인 박스) --------
    lines.extend(_meta_table_md(report, ts))
    lines.append("## 결론")
    lines.append("")
    lines.extend(_verdict_box_md(report))

    # --- ② 핵심 숫자 --------------------------------------------------------
    lines.append("## 요약")
    lines.append("")
    summary = report.summary
    build_skips = _build_artifact_skips(report)
    non_build_skips = [s for s in report.skipped_files if "빌드 산출물" not in (s.reason or "")]
    lines.append(f"- 검사한 파일 수: **{len(report.scanned_files)}건**")
    # 발견 건수와 고유 위치를 함께 표기 — 같은 줄에 여러 룰이 걸리면 건수가
    # 위치 수보다 커지므로, 이중 계상으로 오해하지 않도록 두 수치를 같이 쓴다.
    uniq_locs = _unique_location_count(report.findings)
    lines.append(f"- 발견된 위험: **{summary.finding_count}건** · 고유 위치 **{uniq_locs}곳**")
    lines.append(f"- 차단(block): **{summary.by_decision.get(Decision.block.value, 0)}건**")
    if summary.highest_severity:
        lines.append(
            f"- 최고 심각도: **{_SEVERITY_LABEL_KO[summary.highest_severity]} "
            f"({summary.highest_severity.value})**"
        )
    else:
        lines.append("- 최고 심각도: **—**")
    # 제외 파일은 **사유별로** 보여준다 — 수백 건이 한 줄로 뭉뚱그려지면
    # "무엇이 검사되지 않았는지" 알 수 없어 오히려 불안을 준다.
    for line in _skip_breakdown_lines(report):
        lines.append(line)
    # 의존성(패키지)·승인 예외 수치 — 별도 배너 대신 요약 숫자로 정직하게 표기.
    _dep_audits_sum = _dep_audits(report)
    if _dep_audits_sum:
        _, _dep_unchecked, _dep_vuln, _, _dep_nf = _dep_stats(_dep_audits_sum)
        lines.append(
            f"- 취약 패키지: **{_dep_vuln}건**"
            + (f" · **미존재(가짜 이름 의심) {_dep_nf}건**" if _dep_nf else "")
            + (f" · 판정 불가 {_dep_unchecked}건" if _dep_unchecked else "")
            + " (아래 '의존성(패키지) 취약점 검사')"
        )
    # 소스와 패키지를 합친 '실제 조치할 항목 수' — 둘을 따로만 적으면 담당자가
    # 총량을 못 잡는다. 합계는 표시용이며 발견 건수(게이트 기준)는 그대로 둔다.
    _dep_row_sum = _dep_domain_row(report)
    if _dep_row_sum and _dep_row_sum["count"]:
        lines.append(
            f"- **총 조치 대상: {summary.finding_count + _dep_row_sum['count']}건** "
            f"(소스 코드 {summary.finding_count}건 · 패키지 {_dep_row_sum['count']}건)"
        )
    if suppressed:
        lines.append(f"- 승인된 예외(요약에서 제외): {len(suppressed)}건 (아래 '승인된 예외 내역')")
    # 판정 근거 분포 — 숫자만 크게 보이고 근거가 약하면 신뢰가 무너진다.
    conf_line = _confidence_summary_line(report)
    if conf_line:
        lines.append(conf_line)
    dup_line = _duplicate_files_line(report)
    if dup_line:
        lines.append(dup_line)
    lines.append("")

    # 심각도 표 — 의존성 검사를 했으면 **열을 나눠** 함께 싣는다. 소스와 패키지는
    # 심각도를 정하는 방식이 다르므로(부록 '심각도 판정 기준') 한 칸에 합치지 않고
    # 열로 구분한다. 합계 열은 담당자가 총량을 잡는 용도다.
    _dep_sev = (_dep_row_sum or {}).get("by_severity") or Counter()
    if any(summary.by_severity.values()) or _dep_sev:
        if _dep_sev:
            lines.append("| 심각도 | 소스 코드 | 의존성(패키지) | 합계 |")
            lines.append("|---|---|---|---|")
        else:
            lines.append("| 심각도 | 건수 |")
            lines.append("|---|---|")
        for sev in (Severity.critical, Severity.high, Severity.medium, Severity.low):
            count = summary.by_severity.get(sev.value, 0)
            dep_count = _dep_sev.get(sev.value, 0)
            if not count and not dep_count:
                continue
            if _dep_sev:
                lines.append(
                    f"| {_SEVERITY_LABEL_KO[sev]} ({sev.value}) | {count} | "
                    f"{dep_count} | {count + dep_count} |"
                )
            else:
                lines.append(f"| {_SEVERITY_LABEL_KO[sev]} ({sev.value}) | {count} |")
        if _dep_sev:
            lines.append("")
            lines.append(
                "> 심각도를 정하는 방식이 두 열에서 다릅니다 — 소스는 룰에 미리 정해진 등급, "
                "패키지는 검사 시점의 취약점·악용 정보로 계산합니다(부록 '심각도 판정 기준'). "
                + (
                    f"판정 불가 {_dep_row_sum['unknown']}건은 **확인하지 못한 것**이라 "
                    "등급을 매기지 않고 의존성 절에 따로 셉니다."
                    if _dep_row_sum and _dep_row_sum.get("unknown") else ""
                )
            )
        lines.append("")

    if summary.finding_count == 0:
        lines.append("> 발견된 위험이 없습니다. 그러나 본 도구는 보조 가드레일이며, ")
        lines.append("> 공식 보안성 검토를 대체하지 않습니다.")
        lines.append("")

    # --- ③ 조치 가이드 (초보자용 행동 안내) — 발견이 있을 때만 -------------
    if report.findings:
        lines.append("## 조치 가이드 — 3단계만 따라 하세요")
        lines.append("")
        lines.append(f"**{_action_lead(report)}**")
        lines.append("")
        for i, (title, desc, say) in enumerate(_ACTION_STEPS, 1):
            line = f"{i}. **{title}** — {desc}"
            if say:
                line += f"  → `{say}`"
            lines.append(line)
            if title == "고치기":
                lines.append("   (또는 아래 '수정 프롬프트' 칸을 복사해 붙여넣으세요)")
        lines.append("")
        lines.append(f"> ⚠ **{_ACTION_CAVEAT}**")
        lines.append("")

    # --- ④ 조치 순서 — 전체를 3단으로. 잘라내지 않는다 ---------------------
    if report.findings:
        lines.append("## 조치 순서 — 무엇부터 할지")
        lines.append("")
        lines.append(f"> {_action_order_note(report)}")
        lines.append("")
        for i, tier in enumerate(_action_order(report.findings), 1):
            lines.append(f"**{i}. {tier['label']}** ({tier['hint']}) — {tier['count']}건")
            lines.append("")
            for g in tier["groups"]:
                dec_ko = _DECISION_LABEL_KO.get(g["decision"], g["decision"].value)
                lines.append(
                    f"- [ ] **{g['title']}** — {_SEVERITY_LABEL_KO[g['severity']]}·{dec_ko} · "
                    f"{g['count']}건 · 파일 {g['files']}개 (`{g['rule_id']}`)"
                )
            lines.append("")
        if (_dep_row_order := _dep_domain_row(report)) and _dep_row_order["count"]:
            lines.append(
                f"**{len(_action_order(report.findings)) + 1}. 패키지 업그레이드** "
                f"— {_dep_row_order['count']}건 (아래 '의존성(패키지) 취약점 검사')"
            )
            lines.append("")
            lines.append(
                "> 소스 코드만 고치면 **배포 차단이 풀리지 않습니다** — 패키지도 함께 올리세요."
            )
            lines.append("")
        lines.append(
            "> 📌 **각 항목의 정확한 위치·취약점·대응 방법은 아래 '상세 검토 결과'의 "
            "분야별 카드에서 확인하세요.**"
        )
        lines.append("")

    # --- ⑤ 정직성 배너 — 실행 모드·승인 예외·의존성·빌드 제외·한계 고지 ----
    # 실행 모드·인텔 기준일 — 값이 주입된 경우에만 표시.
    mode_note = _scan_mode_note(report)
    if mode_note:
        lines.append(f"> {mode_note}")
        lines.append("")

    # 승인된 예외 요약 — 게이트 판정 이해에 필수라 결론 근처에 표기.
    lines.extend(_suppression_banner_md(report, suppressed))

    # 의존성 결과는 아래 '의존성(패키지) 취약점 검사' 섹션 + 요약 수치로 전달한다.
    # 여기서는 --check-deps 를 안 써서 아예 검사되지 않은 경우만 경고한다.
    dep_audits = _dep_audits(report)
    if dep_audits and (_reg_banner := _registry_banner(dep_audits)):
        lines.append(f"> {_reg_banner}")
        lines.append("")
    if dep_audits and (_intel_banner := _intel_cache_banner(dep_audits)):
        lines.append(f"> {_intel_banner}")
        lines.append("")
    # 검사되지 않은 패키지는 '이상 없음'이 아니다 — 결론 근처에서 알린다.
    if dep_audits and (_trunc_banner := _dep_truncation_banner(dep_audits)):
        lines.append(f"> {_trunc_banner}")
        lines.append("")
    # 열어보지도 못한 소스 파일도 마찬가지다(의존성 절단과 같은 무게로).
    if _src_trunc := _source_truncation_banner(report):
        lines.append(f"> {_src_trunc}")
        lines.append("")
    # 룰셋이 선언과 다르면 **이 판정은 재현되지 않는다** — 결론 옆에서 말한다.
    for _rs in _ruleset_banners(report):
        lines.append(f"> {_rs}")
        lines.append("")
    manifest_skips = [
        s for s in report.skipped_files if "의존성 매니페스트" in (s.reason or "")
    ]
    if not dep_audits and manifest_skips:
        names = ", ".join(s.path.replace("\\", "/").rsplit("/", 1)[-1] for s in manifest_skips)
        lines.append(
            f"> ⚠ **의존성 검사 별도 필요** — {names} 은(는) 코드 스캔 대상이 아닙니다. "
            f"취약·악성 패키지는 `gvskb check-package` 또는 MCP `scan_dependencies`로 따로 검사하세요."
        )
        lines.append("")

    if build_skips:
        lines.append(
            f"> **빌드 산출물 {len(build_skips)}건 제외** — 압축·번들·캐시 파일은 원본 "
            "소스가 아니라 검사 대상에서 자동 제외했습니다(오탐 방지)."
        )
        lines.append("")

    # --- ⑥ 검토 범위 및 한계 + 면책 — 조치 안내 뒤, 상세 검토 앞(신뢰성 고지) -
    lines.append("## 검토 범위 및 한계")
    lines.append("")
    ext_dist = _ext_distribution(report.scanned_files)
    ext_str = " · ".join(f"{ext} {n}건" for ext, n in ext_dist.most_common()) or "—"
    lines.append("| 구분 | 내용 |")
    lines.append("|---|---|")
    lines.append(
        f"| 검토 범위 | 파일 {len(report.scanned_files)}건 ({ext_str}) · "
        "정적(소스코드) 검사이며 코드를 실행하지 않습니다 |"
    )
    if report.skipped_files:
        reason_counts = Counter(_short_reason(s.reason) for s in report.skipped_files)
        rs = " · ".join(f"{r} {n}건" for r, n in reason_counts.most_common())
        lines.append(f"| 검사 제외 | {len(report.skipped_files)}건 — {rs} (아래 목록 참조) |")
    lines.append("")
    lines.append(
        f"> ⚠ **한계 고지** — {_LIMIT_HEAD} **{_LIMIT_ZERO}** {_LIMIT_BODY} **{_LIMIT_TAIL}**"
    )
    lines.append("")
    lines.append(f"※ 참고 — {report.disclaimer.replace(chr(10), ' ')}")
    lines.append("")

    # =====================================================================
    # Layer 2 — 보안담당자용 상세 검토: 분야 개요 → 분야별 상세(비밀값 분야
    # 직후 개인정보 콜아웃) → 외부 연결 → 의존성 → 승인 예외 → 수정 프롬프트 → 부록.
    # =====================================================================
    lines.append("## 상세 검토 결과")
    lines.append("")

    domains = _group_by_domain(report.findings)

    # --- ⑥ 보안 분야 개요 — 어느 보안 분야가 문제인지 한눈에 ----------------
    lines.append("### 보안 분야 개요")
    lines.append("")
    dep_row = _dep_domain_row(report)
    if domains or dep_row:
        lines.append("| 분야 | 최고 심각도 | 건수 | 심각도별 내역 | 파일 |")
        lines.append("|---|---|---|---|---|")
        for d in domains:
            lines.append(
                f"| {d['label']} | {_SEVERITY_LABEL_KO[d['max_severity']]} | "
                f"{d['count']} | {d['breakdown']} | {d['files']} |"
            )
        if dep_row:
            lines.append(
                f"| {dep_row['label']} | "
                f"{_SEVERITY_LABEL_KO[dep_row['max_severity']] if dep_row['max_severity'] else '—'} | "
                f"{dep_row['count']} | {_dep_breakdown_text(dep_row)} | 패키지 {dep_row['packages']}종 |"
            )
        lines.append("")
        for note in _domain_table_notes(report, domains, dep_row):
            lines.append(f"> {note}")
            lines.append("")

        # 같은 (파일, 줄)에 여러 룰이 걸린 위치 — 표시 계층에서 묶어 보여
        # "건수가 부풀려졌다"는 오해를 막는다(core dedupe와는 무관).
        multi = _multi_rule_lines(report.findings)
        if multi:
            lines.append(
                f"> **같은 줄 다중 지적** — 발견 {summary.finding_count}건 중 고유 위치는 "
                f"{uniq_locs}곳입니다. 아래 위치는 한 줄에 여러 기준(룰)이 함께 걸린 곳으로, "
                "한 곳을 고치면 관련 룰이 함께 해소됩니다."
            )
            lines.append("")
            for m in multi[:12]:
                rules = ", ".join(f"`{r}`" for r in m["rules"])
                lines.append(
                    f"- `{m['file'].replace(chr(92), '/')}:{m['line']}` — "
                    f"관련 룰 {len(m['rules'])}개: {rules}"
                )
            if len(multi) > 12:
                lines.append(f"- … 외 {len(multi) - 12}곳")
            lines.append("")
    else:
        lines.append("> 발견된 위험이 없어 분야별 상세가 없습니다.")
        lines.append("")

    # --- ⑦ 분야별 상세 — 분야마다 룰 그룹 카드(위치·왜 위험·대응·근거).
    #     개인정보·비밀값 콜아웃은 '비밀값·인증정보 노출' 분야(없으면 개인정보
    #     분야) 바로 아래에 붙여 최민감 항목을 그 자리에서 강조한다. -----------
    pii = _privacy_findings(report.findings)
    pii_anchor = max((d["order"] for d in domains if d["order"] <= 2), default=None)
    for d in domains:
        lines.append(
            f"### {d['label']} — {d['count']}건 ({d['breakdown']}) · 파일 {d['files']}개"
        )
        lines.append("")
        for g in _rule_groups(d["findings"]):
            lines.extend(_render_finding_group_md(g))
            lines.append("")
        if pii and d["order"] == pii_anchor:
            lines.extend(_pii_callout_md(pii))
    if pii and pii_anchor is None:  # PII가 다른 분야로만 분류된 드문 경우
        lines.extend(_pii_callout_md(pii))

    # --- ⑨ 외부 연결 인벤토리 (위험과 분리, 발견 0이어도 표시) --------------
    if report.external_surface:
        lines.extend(_render_external_surface_md(report))

    # --- ⑩ 의존성(패키지) 취약점 검사 — 병합된 경우에만 표시 ----------------
    lines.extend(_render_dependency_audit_md(report))

    # --- ⑪ 승인된 예외 내역 — 있을 때만 -------------------------------------
    lines.extend(_render_suppressions_md(suppressed))

    # --- ⑫ 수정 프롬프트 (복사용) --------------------------------------------
    # 의존성 블록도 함께 낸다 — 소스만 고치면 차단이 풀리지 않는데, 그 사실을
    # 사용자가 알 방법이 없었다(도구가 만든 막다른 길).
    dep_prompt = _dep_fix_prompt_text(report)
    if report.findings or dep_prompt:
        lines.append("## 수정 프롬프트 (복사해서 AI에게 전달)")
        lines.append("")
        lines.append(
            f"💬 **가장 쉬운 방법** — 쓰던 AI 도구에 `{_SAY_FIX}` 라고 말하면 끝입니다. "
            "아래 블록은 유형별로 따로 복사해 쓰고 싶을 때 사용하세요."
        )
        lines.append("")
        if dep_prompt:
            lines.append(
                "> ⚠ **패키지 블록을 빠뜨리지 마세요** — 소스 코드만 고치면 의존성 차단이 "
                "그대로 남아 다시 검사해도 배포 판정이 바뀌지 않습니다."
            )
            lines.append("")
        for g in _rule_groups(report.findings):
            lines.append("```text")
            lines.append(_fix_prompt_text(g))
            lines.append("```")
            lines.append("")
        if dep_prompt:
            lines.append("```text")
            lines.append(dep_prompt)
            lines.append("```")
            lines.append("")

    # --- ⑬ 부록 — 가이드라인 분포·생략 파일·재현 절차·재검증 ----------------
    lines.append("## 부록")
    lines.append("")
    # 심각도 기준을 먼저 — 표의 숫자를 읽는 데 필요한 근거이므로 부록 맨 앞에 둔다.
    if report.findings or _dep_domain_row(report):
        lines.extend(_render_severity_criteria_md(report))
    if report.findings:
        dist = _guideline_distribution(report.findings)
        if dist:
            lines.append("### 가이드라인별 분포")
            lines.append("")
            lines.append("> 한 발견 사항이 여러 가이드라인을 인용한 경우 각 그룹에서 1회씩 집계합니다.")
            lines.append("")
            lines.append("| 가이드라인 | 인용 건수 |")
            lines.append("|---|---|")
            for label, count in dist.most_common():
                lines.append(f"| {label} | {count} |")
            lines.append("")

    if non_build_skips:
        lines.append("### 생략된 파일")
        lines.append("")
        for sf in non_build_skips[:30]:
            lines.append(f"- `{sf.path}` — {sf.reason}")
        if len(non_build_skips) > 30:
            lines.append(f"- … 외 {len(non_build_skips) - 30}건")
        lines.append("")
    if build_skips:
        lines.append("### 빌드 산출물 제외")
        lines.append("")
        lines.append(
            "> 압축/번들·빌드 출력 디렉터리는 원본 소스가 아니므로 검사하지 않습니다 (오탐 방지)."
        )
        for sf in build_skips[:15]:
            lines.append(f"- `{sf.path.replace(chr(92), '/')}`")
        if len(build_skips) > 15:
            lines.append(f"- … 외 {len(build_skips) - 15}건")
        lines.append("")

    lines.append("### 재현 절차")
    lines.append("")
    repro = reproduce_command or f"gvskb scan {report.target} --profile {report.profile}"
    lines.append("같은 결과를 다시 만들거나 다른 환경에서 검증하려면 다음과 같이 실행합니다.")
    lines.append("")
    lines.append("```bash")
    lines.append(repro)
    lines.append("```")
    lines.append("")
    lines.append(f"- 프로파일: `{report.profile}`")
    if (_env := _env_grade_line(report)) is not None:
        lines.append(f"- {_env}")
    if report.scenario:
        lines.append(f"- 시나리오: `{report.scenario}`")
    if report.language:
        lines.append(f"- 언어 힌트: `{report.language}`")
    lines.append("- 룰셋은 `gvskb rules` 또는 `gvskb doctor` 로 현재 로드된 목록·버전을 확인할 수 있습니다.")
    lines.append("")

    lines.append("### 수정 후 다시 검증")
    lines.append("")
    lines.append("발견 사항을 수정한 뒤에는 같은 검사를 한 번 더 돌려 회귀를 막으세요.")
    lines.append("")
    lines.append("- **CLI**: 위의 재현 명령(`gvskb scan ...`)을 다시 실행합니다.")
    lines.append(
        "- **MCP (IDE)**: 수정한 코드 블록을 `scan_code` 도구에 다시 넘기거나, 파일 단위라면 "
        "`scan_path` 를 호출합니다."
    )
    lines.append(
        "- **수정 시 LLM 안내**: 처리 순서(차단 → 치명·높음 → 자동수정 → 나머지)를 "
        "그대로 LLM 프롬프트의 지시문으로 사용하면 우선순위가 어긋나지 않습니다."
    )
    lines.append("")

    # (면책은 상단 '검토 범위 및 한계' 아래로 이동했다 — 여기서는 반복하지 않는다)
    lines.append("---")
    lines.append("")
    lines.append("*생성: vibecode-checker · 공공 바이브코딩 보안 가드레일*")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTML 리포트 — MD와 동일한 ScanReport 데이터에서 직접 렌더링하는 "카드 강조형".
# 자체 포함 단일 파일(외부 CDN·폰트·외부 스크립트 없음 — 아무 리소스도 로드하지
# 않는다)이라 망분리·이메일·인쇄(→PDF)에 그대로 쓸 수 있다. 복사 버튼용 인라인
# 스크립트만 있으며 미지원 환경에선 텍스트가 그대로 보인다. 동적 텍스트는 전부
# html.escape 로 이스케이프한다.
# ---------------------------------------------------------------------------

_SEVERITY_COLOR = {
    Severity.critical: "#c0392b",
    Severity.high: "#e67e22",
    Severity.medium: "#c9a227",
    Severity.low: "#7f8c8d",
}
_DECISION_COLOR = {
    Decision.block: "#c0392b",
    Decision.warn: "#e67e22",
    Decision.allow: "#2e7d32",
}
_DECISION_LABEL_KO = {
    Decision.block: "차단",
    Decision.warn: "경고",
    Decision.allow: "허용",
}

_HTML_CSS = """
*{box-sizing:border-box}
body{margin:0;background:#eceff1;color:#1f2937;
  font-family:"Malgun Gothic","맑은 고딕","Apple SD Gothic Neo","Noto Sans KR",
  "Segoe UI",sans-serif;line-height:1.6;font-size:15px}
.page{max-width:820px;margin:24px auto;background:#fff;padding:40px 44px;
  box-shadow:0 1px 6px rgba(0,0,0,.12);border-radius:8px}
h1{font-size:24px;margin:0 0 4px;letter-spacing:-.3px}
h2{font-size:17px;margin:30px 0 12px;padding-bottom:6px;border-bottom:2px solid #e5e7eb}
h3{font-size:15px;margin:22px 0 8px;color:#111827}
.sub{color:#6b7280;font-size:13px;margin-bottom:18px}
.hero{padding:20px 24px;border-radius:10px;color:#fff;margin:10px 0 12px;
  page-break-inside:avoid}
.hero .heromain{font-weight:800;font-size:20px;line-height:1.45}
.hero .herosub{font-size:13px;font-weight:600;opacity:.93;margin-top:8px}
.meta{font-size:14px;color:#374151;margin:0 0 8px}
.meta b{color:#111827}
.depwarn{background:#fff8e1;border:1px solid #f0d27a;border-radius:6px;
  padding:10px 14px;font-size:13.5px;color:#7a5b00;margin:10px 0}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin:10px 0 4px}
.chip{padding:5px 12px;border-radius:999px;font-size:13px;font-weight:600;color:#fff}
.kv{font-size:14px;margin:2px 0}
table{border-collapse:collapse;width:100%;font-size:13.5px;margin:8px 0;table-layout:auto}
th,td{border:1px solid #e5e7eb;padding:6px 10px;text-align:left}
/* 외부 연결 표 — 컬럼 폭을 고정해 '이용 정보'가 찌그러지지 않게 한다.
   긴 호스트명·파일 경로는 줄바꿈을 허용해 가로 스크롤을 만들지 않는다. */
.extbl{table-layout:fixed}
.extbl td{vertical-align:top;word-break:break-word;overflow-wrap:anywhere}
.extbl td.host{font-family:Consolas,"D2Coding",monospace;font-size:12.5px}
.extbl td.loc{font-size:12.5px;color:#374151}
.extbl th{white-space:nowrap}
th{background:#f3f4f6}
ol.steps{margin:6px 0 0;padding-left:22px}
ol.steps li{margin:3px 0}
.card{border:1px solid #e5e7eb;border-left:6px solid #999;border-radius:8px;
  padding:14px 16px;margin:12px 0;background:#fff;page-break-inside:avoid}
.card .badge{display:inline-block;color:#fff;font-weight:700;font-size:12px;
  padding:2px 9px;border-radius:5px;margin-right:8px;vertical-align:middle}
.card .ftitle{font-weight:700;font-size:15px;vertical-align:middle}
.card .loc{color:#6b7280;font-size:13px;margin-left:6px}
.row{margin:7px 0;font-size:14px}
.row .lab{display:inline-block;min-width:104px;color:#6b7280;font-weight:600;vertical-align:top}
.row .val{display:inline-block;max-width:600px}
.tag{display:inline-block;font-size:12px;padding:1px 7px;border-radius:4px;
  background:#eef2ff;color:#3730a3;margin-right:6px}
pre{background:#0f172a;color:#e2e8f0;border-radius:6px;padding:11px 13px;
  font-size:12.5px;overflow:auto;font-family:"D2Coding","Consolas",
  "Courier New",monospace;white-space:pre-wrap;word-break:break-all;margin:6px 0}
code.ev{background:#f1f5f9;border-radius:4px;padding:1px 6px;font-size:12.5px;
  font-family:"Consolas","Courier New",monospace;word-break:break-all}
.disc{background:#f8fafc;border:1px solid #e5e7eb;border-radius:6px;
  padding:12px 16px;font-size:13.5px;color:#475569;margin:8px 0}
.foot{text-align:center;color:#9ca3af;font-size:12px;margin-top:28px}
.buildnote{background:#f1f5f9;border:1px dashed #cbd5e1;border-radius:6px;
  padding:8px 13px;font-size:12.5px;color:#64748b;margin:8px 0}
.actionbox{border:2px solid #2563eb;border-radius:10px;padding:14px 18px;
  margin:12px 0 16px;background:#eff6ff}
.actionbox .ah{font-weight:800;font-size:15px;color:#1e3a8a;margin-bottom:8px}
.actionbox .lead{font-size:14px;color:#1e293b;margin-bottom:10px;font-weight:600}
.actionbox ol{margin:0;padding-left:0;list-style:none;counter-reset:step}
.actionbox li{position:relative;padding:6px 0 6px 34px;font-size:14px;
  border-top:1px solid #dbeafe}
.actionbox li:first-child{border-top:none}
.actionbox li::before{counter-increment:step;content:counter(step);
  position:absolute;left:0;top:6px;width:23px;height:23px;border-radius:50%;
  background:#2563eb;color:#fff;font-weight:800;font-size:12.5px;
  text-align:center;line-height:23px}
.actionbox .say{display:inline-block;background:#1e293b;color:#e2e8f0;
  border-radius:5px;padding:2px 9px;font-size:13px;margin:3px 0;
  font-family:"D2Coding","Consolas",monospace}
.actionbox .caveat{margin-top:10px;background:#fff7ed;border:1px solid #fed7aa;
  border-radius:6px;padding:9px 12px;font-size:12.8px;color:#9a3412}
.stats{display:flex;flex-wrap:wrap;gap:10px;margin:6px 0 4px}
.stat{flex:1 1 120px;border:1px solid #e5e7eb;border-radius:8px;padding:12px 14px;
  background:#fafafa;min-width:120px}
.stat .num{font-size:24px;font-weight:800;line-height:1.1}
.stat .lab{font-size:12.5px;color:#6b7280;margin-top:3px}
.typetbl td.sev,.typetbl td.cnt{text-align:center;white-space:nowrap}
.sevdot{display:inline-block;color:#fff;font-weight:700;font-size:11.5px;
  padding:1px 8px;border-radius:5px}
a.jump{color:#1d4ed8;text-decoration:none;font-weight:600}
a.jump:hover{text-decoration:underline}
ul.todo{list-style:none;margin:6px 0;padding:0}
ul.todo li{border:1px solid #e5e7eb;border-radius:7px;padding:9px 12px;margin:7px 0;
  background:#fff;font-size:14px}
ul.todo .box{font-weight:800;color:#9ca3af;margin-right:8px}
ul.todo .meta2{color:#6b7280;font-size:12.5px;margin-left:6px}
.fixprompt{background:#0f172a;color:#e2e8f0;border-radius:8px;padding:13px 15px;
  margin:10px 0;font-size:12.5px;font-family:"D2Coding","Consolas","Courier New",monospace;
  white-space:pre-wrap;word-break:break-all}
/* 접기형 일반 섹션(분야별 상세·수정 프롬프트·외부 연결·부록 등) */
details.sec{border:1px solid #e5e7eb;border-radius:8px;margin:14px 0;background:#fff;overflow:hidden}
details.sec>summary{cursor:pointer;list-style:none;padding:13px 16px;font-weight:800;font-size:16px;background:#f3f4f6}
details.sec>summary::-webkit-details-marker{display:none}
details.sec>summary::before{content:"▶  ";color:#9ca3af;font-size:12px}
details.sec[open]>summary::before{content:"▼  "}
details.sec>summary:hover{background:#eceef1}
details.sec .secbody{padding:4px 16px 14px}
/* 외부 연결 인벤토리 */
.invnote{background:#eff6ff;border:1px solid #93c5fd;border-radius:8px;padding:11px 15px;
  font-size:13px;color:#1e3a8a;margin:8px 0}
.invnote .hl{color:#9a3412;font-weight:700}
.subh{font-weight:800;font-size:14px;margin:14px 0 6px;color:#111827}
.pill{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:700;color:#fff}
.pill.ai{background:#7c3aed}.pill.analytics{background:#0891b2}.pill.error{background:#475569}
.pill.payment{background:#b45309}.pill.messaging{background:#0d9488}
.pill.library{background:#9ca3af}.pill.other{background:#6b7280}
.pill.infra{background:#64748b}.pill.gov-api{background:#1d4ed8}.pill.platform{background:#0369a1}
.pill.api{background:#78716c}.pill.unclassified{background:#6b7280}
tr.w td{background:#fff7ed}
.go{display:inline-block;padding:1px 7px;border-radius:5px;font-size:11px;font-weight:700}
.go.out{background:#fee2e2;color:#b91c1c}.go.in{background:#dcfce7;color:#166534}.go.q{background:#eef2f7;color:#64748b}
.rev{display:inline-block;padding:1px 8px;border-radius:5px;font-size:11px;font-weight:700}
.rev.warn{background:#fde2c8;color:#9a3412}.rev.info{background:#eef2f7;color:#64748b}
.invcheck{background:#f8fafc;border-left:4px solid #2563eb;padding:9px 13px;font-size:12.5px;color:#334155;margin:12px 0 4px}
.oper{font-size:11px;color:#6b7280;white-space:nowrap}
/* 배포 판정·실행 모드·검토 범위·개인정보 요약 (보안팀 제출용) */
.deploy{border:2px solid #9ca3af;border-radius:8px;padding:12px 16px;font-weight:700;
  font-size:14.5px;margin:0 0 12px;background:#fff;page-break-inside:avoid}
.scanmode{background:#f0f9ff;border:1px solid #7dd3fc;border-radius:6px;
  padding:9px 13px;font-size:13px;color:#075985;margin:8px 0}
.scopebox{background:#fffbeb;border:1px solid #fcd34d;border-radius:8px;
  padding:12px 16px;font-size:13.5px;color:#78350f;margin:8px 0;page-break-inside:avoid}
.piibox{border:2px solid #be185d;background:#fdf2f8;border-radius:10px;
  padding:12px 16px;margin:14px 0;page-break-inside:avoid}
.piibox .ph{font-weight:800;color:#9d174d;font-size:15px;margin-bottom:6px}
.dupnote{background:#f8fafc;border:1px dashed #94a3b8;border-radius:6px;
  padding:9px 13px;font-size:12.8px;color:#475569;margin:8px 0}
/* 문서 헤더 표(대상·검사일시·프로파일) */
.metatbl{border-collapse:collapse;margin:6px 0 14px;font-size:13px;width:100%}
.metatbl th{text-align:left;background:#f3f4f6;color:#374151;padding:6px 10px;
  white-space:nowrap;width:96px;border:1px solid #e5e7eb;font-weight:700}
.metatbl td{padding:6px 10px;color:#111827;border:1px solid #e5e7eb;word-break:break-all}
/* 결론 = 승인(초록)/미승인(빨강) 박스 — 두괄식 결과. 인쇄에서도 색 유지 */
.verdict{border:3px solid;border-radius:12px;padding:16px 20px;margin:6px 0 16px;
  page-break-inside:avoid;-webkit-print-color-adjust:exact;print-color-adjust:exact}
.verdict .vstatus{font-size:22px;font-weight:800;margin-bottom:6px}
.verdict .vdetail{font-size:14px;line-height:1.55}
.v-ok{background:#ecfdf5;border-color:#16a34a;color:#065f46}
.v-block{background:#fef2f2;border-color:#dc2626;color:#991b1b}
.v-warn{background:#fffbeb;border-color:#d97706;color:#92400e}
.v-none{background:#f3f4f6;border-color:#6b7280;color:#374151}
/* 검토 범위 표 */
.scopetbl{border-collapse:collapse;margin:6px 0 10px;font-size:13px;width:100%}
.scopetbl th{text-align:left;background:#f3f4f6;color:#374151;padding:6px 10px;
  white-space:nowrap;width:96px;border:1px solid #e5e7eb;font-weight:700}
.scopetbl td{padding:6px 10px;color:#111827;border:1px solid #e5e7eb}
/* 면책 — 박스 없이 참고 텍스트 */
.discnote{font-size:12px;color:#6b7280;margin:8px 0 4px;line-height:1.5}
/* Top 3 아래 강조 안내(상세 검토로 유도) */
.jumpnote{background:#eff6ff;border-left:4px solid #2563eb;border-radius:0 6px 6px 0;
  padding:9px 13px;font-size:13.5px;color:#1e3a8a;margin:10px 0}
/* 면책 박스(요약부로 이동) — 이미지의 어두운 테두리 박스 */
.discbox{border:2px solid #111827;border-radius:8px;background:#fff;
  padding:12px 16px;font-size:12.8px;color:#374151;margin:10px 0 14px;page-break-inside:avoid}
/* 수정 프롬프트 — '가장 쉬운 방법' 강조 + 복사 버튼 */
.easyfix{border:2px solid #2563eb;background:#eff6ff;border-radius:10px;
  padding:12px 16px;margin:4px 0 12px;page-break-inside:avoid}
.easyfix .eh{font-weight:800;color:#1e3a8a;font-size:15px;margin-bottom:4px}
.easyfix .ed{font-size:12.8px;color:#334155;margin-bottom:8px}
.easyrow{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.saycode{flex:1;min-width:200px;background:#fff;border:1px solid #bfdbfe;border-radius:6px;
  padding:8px 10px;font-size:13px;color:#111827}
.fixwrap{position:relative;margin:8px 0}
.copybtn{cursor:pointer;border:1px solid #2563eb;background:#2563eb;color:#fff;
  border-radius:6px;padding:5px 12px;font-size:12.5px;font-weight:700;white-space:nowrap}
.copybtn:hover{background:#1d4ed8}
.copybtn.ok{background:#16a34a;border-color:#16a34a}
.fixwrap .copybtn{position:absolute;top:8px;right:8px}
.fixwrap .fixprompt{padding-right:70px}
@media print{
  body{background:#fff}
  .page{box-shadow:none;margin:0;max-width:none;border-radius:0;padding:0 6mm}
  .card{break-inside:avoid}
  details.sec{break-inside:auto}
  details.sec>summary::before{content:""}
  details.sec>.secbody{display:block !important}
  /* 최신 Chromium/Edge는 닫힌 <details> 내용을 ::details-content 로 클리핑해
     인쇄에서 상세가 통째로 빠진다 — 인쇄 시 강제로 펼친다(위 display 규칙 유지). */
  details::details-content{content-visibility:visible !important;display:block !important;height:auto !important}
  pre,.fixprompt{white-space:pre-wrap}
}
""".strip()


# 복사 버튼용 인라인 스크립트 — 외부 리소스를 전혀 로딩하지 않는다(자체완결 유지).
# navigator.clipboard 우선, 미지원(file:// 등)이면 execCommand 폴백, 둘 다 안 되면
# 프롬프트 텍스트가 그대로 보이므로 사용자가 직접 선택·복사할 수 있다(우아한 저하).
_COPY_SCRIPT = """
<script>
(function () {
  function fallback(t) {
    try {
      var ta = document.createElement('textarea');
      ta.value = t; ta.style.position = 'fixed'; ta.style.opacity = '0';
      document.body.appendChild(ta); ta.focus(); ta.select();
      document.execCommand('copy'); document.body.removeChild(ta);
      return Promise.resolve();
    } catch (e) { return Promise.reject(e); }
  }
  function copyText(t) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(t).catch(function () { return fallback(t); });
    }
    return fallback(t);
  }
  document.addEventListener('click', function (e) {
    var b = e.target && e.target.closest ? e.target.closest('.copybtn') : null;
    if (!b) return;
    var t = b.getAttribute('data-copy') || '';
    copyText(t).then(function () {
      var o = b.textContent; b.textContent = '✓ 복사됨'; b.classList.add('ok');
      setTimeout(function () { b.textContent = o; b.classList.remove('ok'); }, 1500);
    }).catch(function () { b.textContent = '직접 선택해 복사하세요'; });
  });
})();
</script>
""".strip()


def _esc(text: str) -> str:
    return html.escape(str(text), quote=True)


def _verdict_css_color(report: ScanReport) -> str:
    summary = report.summary
    if summary.finding_count == 0:
        return "#607d8b" if not report.scanned_files else "#2e7d32"
    block_count = summary.by_decision.get(Decision.block.value, 0)
    if summary.blocked or block_count:
        return "#c0392b"
    return "#e67e22"


def render_html(
    report: ScanReport,
    *,
    generated_at: datetime | None = None,
    reproduce_command: str | None = None,
) -> str:
    """Render a ScanReport as a self-contained Korean HTML document (card style).

    Same content as :func:`render_markdown` — both render from the one
    ``ScanReport`` so the two outputs never diverge. The HTML embeds all CSS
    inline (no external CDN/font/script — loads nothing), so it opens in air-gapped environments,
    attaches to email, and prints to PDF as a 붙임 document. 결재(서명)는
    상위 공문이 담당하므로 리포트 자체에는 결재 요소를 넣지 않는다.
    """
    ts = (generated_at or datetime.now()).strftime("%Y-%m-%d %H:%M")
    # 승인된 예외(suppressed)는 본문 통계·상세에서 분리해 전용 섹션에만 표시.
    suppressed = [f for f in report.findings if f.suppressed]
    if suppressed:
        report = report.model_copy(
            update={"findings": [f for f in report.findings if not f.suppressed]}
        )
    summary = report.summary
    p: list[str] = []
    p.append("<!DOCTYPE html>")
    p.append('<html lang="ko"><head><meta charset="utf-8">')
    p.append('<meta name="viewport" content="width=device-width, initial-scale=1">')
    p.append("<title>코드 보안 검사 결과</title>")
    p.append(f"<style>{_HTML_CSS}</style></head><body>")
    p.append('<div class="page">')

    p.append("<h1>코드 보안 검사 결과</h1>")
    p.append('<div class="sub">vibecode-checker · 공공 바이브 코딩 보안 가드레일</div>')

    # === Layer 1 — 공무원용: 문서 헤더 표 → 결론(승인/미승인 박스) ==========
    #   순서: 헤더표 → 결론 박스 → 한눈에 보기 → 조치 가이드 → Top 3 →
    #   정직성 배너 → 검토 범위·한계+면책. 상세는 Layer 2로. ================
    p.append(_meta_table_html(report, ts))
    p.append(_verdict_box_html(report))

    build_skips = _build_artifact_skips(report)

    # --- 한눈에 보기 (핵심 숫자) ---
    p.append("<h2>한눈에 보기</h2>")
    top_sev = summary.highest_severity
    block_n = summary.by_decision.get(Decision.block.value, 0)
    sev_label = (
        f"{_SEVERITY_LABEL_KO[top_sev]}" if top_sev else "—"
    )
    sev_col = _SEVERITY_COLOR[top_sev] if top_sev else "#9ca3af"
    p.append('<div class="stats">')
    p.append(
        f'<div class="stat"><div class="num">{len(report.scanned_files)}</div>'
        '<div class="lab">검사한 파일</div></div>'
    )
    uniq_locs = _unique_location_count(report.findings)
    find_lab = "발견된 위험" + (f" · 고유 위치 {uniq_locs}곳" if report.findings else "")
    p.append(
        f'<div class="stat"><div class="num">{summary.finding_count}</div>'
        f'<div class="lab">{find_lab}</div></div>'
    )
    p.append(
        f'<div class="stat"><div class="num" style="color:'
        f'{"#c0392b" if block_n else "#1f2937"}">{block_n}</div>'
        '<div class="lab">차단(block)</div></div>'
    )
    p.append(
        f'<div class="stat"><div class="num" style="color:{sev_col}">{sev_label}</div>'
        '<div class="lab">최고 심각도</div></div>'
    )
    if report.external_surface:  # (A) 외부 연결 현황을 최상단 요약에 노출
        n_api, n_pkg, gukoe, ext_warn = _external_stats(report)
        n_res = sum(1 for c in report.external_surface if c.kind == "resource")
        sub = f"국외 {gukoe}" + (f"·⚠{ext_warn}" if ext_warn else "")
        if n_res:
            sub += f"·폐쇄망영향 {n_res}"
        p.append(
            f'<div class="stat"><div class="num" style="color:'
            f'{"#c0392b" if ext_warn else "#1f2937"}">{n_api + n_pkg + n_res}</div>'
            f'<div class="lab">외부 연결 ({sub})</div></div>'
        )
    # (B) 의존성 취약 패키지·승인 예외 수치 — 별도 배너 대신 요약 카드로 표기.
    _dep_audits_sum = _dep_audits(report)
    if _dep_audits_sum:
        _, _dep_unchecked, _dep_vuln, _, _dep_nf = _dep_stats(_dep_audits_sum)
        sub = f"미존재 {_dep_nf}" if _dep_nf else (f"판정불가 {_dep_unchecked}" if _dep_unchecked else "검사 시점 기준")
        p.append(
            f'<div class="stat"><div class="num" style="color:'
            f'{"#c0392b" if _dep_vuln else "#1f2937"}">{_dep_vuln}</div>'
            f'<div class="lab">취약 패키지 ({sub})</div></div>'
        )
    if suppressed:
        p.append(
            f'<div class="stat"><div class="num">{len(suppressed)}</div>'
            '<div class="lab">승인된 예외 (요약 제외)</div></div>'
        )
    p.append("</div>")

    # 심각도 칩 — 의존성 검사를 했으면 **줄을 나눠** 함께 보여준다. 두 줄을 합치면
    # 서로 다른 기준으로 잰 값이 한 덩어리로 읽힌다(부록 '심각도 판정 기준').
    dep_row = _dep_domain_row(report)
    _chip_lab = (
        'display:inline-block;margin-right:6px;font-size:12px;color:#475569;font-weight:700'
    )

    def _chip_row(label: str, counts: dict) -> str | None:
        chips = [
            f'<span class="chip" style="background:{_SEVERITY_COLOR[sev]}">'
            f"{_SEVERITY_LABEL_KO[sev]} {counts.get(sev.value, 0)}</span>"
            for sev in (Severity.critical, Severity.high, Severity.medium, Severity.low)
            if counts.get(sev.value, 0)
        ]
        if not chips:
            return None
        lab = f'<span style="{_chip_lab}">{_esc(label)}</span>' if label else ""
        return f'<div class="chips">{lab}{"".join(chips)}</div>'

    src_row = _chip_row("소스 코드" if dep_row else "", summary.by_severity)
    if src_row:
        p.append(src_row)
    if dep_row:
        dep_chips = _chip_row("의존성(패키지)", dep_row["by_severity"])
        if dep_chips:
            p.append(dep_chips)
        if dep_row["count"]:
            p.append(
                f'<div class="kv"><b>총 조치 대상 {summary.finding_count + dep_row["count"]}건</b> '
                f'(소스 코드 {summary.finding_count}건 · 패키지 {dep_row["count"]}건) — '
                "두 심각도는 서로 다른 기준으로 정해집니다(부록 '심각도 판정 기준').</div>"
            )

    if summary.finding_count == 0:
        p.append(
            '<div class="disc">발견된 위험이 없습니다. 다만 본 도구는 보조 가드레일이며 '
            "공식 보안성 검토를 대체하지 않습니다.</div>"
        )

    # --- 조치 가이드 (초보자용 행동 안내) — 발견이 있을 때만 ---------------
    if report.findings:
        p.append('<div class="actionbox">')
        p.append('<div class="ah">조치 가이드 — 3단계만 따라 하세요</div>')
        p.append(f'<div class="lead">{_esc(_action_lead(report))}</div>')
        p.append("<ol>")
        for title, desc, say in _ACTION_STEPS:
            li = f"<b>{_esc(title)}</b> · {_esc(desc)}"
            if say:
                li += f'<br><span class="say">▶ {_esc(say)}</span>'
            if title == "고치기":
                li += '<br><span style="font-size:12.5px;color:#475569">' \
                      "(또는 아래 '수정 프롬프트' 칸의 복사 버튼을 쓰세요)</span>"
            p.append(f"<li>{li}</li>")
        p.append("</ol>")
        p.append(f'<div class="caveat">⚠ <b>{_esc(_ACTION_CAVEAT)}</b></div>')
        p.append("</div>")

    # --- 조치 순서 — 전체를 3단으로. 자르지 않는다 -------------------------
    if report.findings:
        p.append("<h2>조치 순서 — 무엇부터 할지</h2>")
        p.append(f'<div class="kv">{_esc(_action_order_note(report)).replace("**", "")}</div>')
        tiers = _action_order(report.findings)
        for i, tier in enumerate(tiers, 1):
            p.append(
                f'<div class="subh">{i}. {_esc(tier["label"])} '
                f'({_esc(tier["hint"])}) — {tier["count"]}건</div>'
            )
            p.append('<ul class="todo">')
            for g in tier["groups"]:
                dec_ko = _DECISION_LABEL_KO.get(g["decision"], g["decision"].value)
                p.append(
                    f'<li><span class="box">☐</span>'
                    f'<span class="sevdot" style="background:{_SEVERITY_COLOR[g["severity"]]}">'
                    f'{_SEVERITY_LABEL_KO[g["severity"]]}</span> '
                    f"<b>{_esc(g['title'])}</b>"
                    f'<span class="meta2">{dec_ko} · {g["count"]}건 · 파일 {g["files"]}개 · '
                    f'{_esc(g["rule_id"])}</span></li>'
                )
            p.append("</ul>")
        if dep_row_top := _dep_domain_row(report):
            if dep_row_top["count"]:
                p.append(
                    f'<div class="subh">{len(tiers) + 1}. 패키지 업그레이드 — '
                    f'{dep_row_top["count"]}건</div>'
                )
                p.append(
                    '<div class="depwarn">소스 코드만 고치면 <b>배포 차단이 풀리지 않습니다</b> '
                    "— 패키지도 함께 올리세요(아래 '의존성(패키지) 취약점 검사').</div>"
                )
        p.append(
            '<div class="jumpnote">📌 <b>각 항목의 정확한 위치·취약점·대응 방법은 아래 '
            "'상세 검토 결과'의 분야별 카드에서 확인하세요.</b></div>"
        )

    # --- 정직성 배너 — 실행 모드·만료 예외·의존성 미검사 경고 --------------
    # (승인된 예외 '적용'·의존성 '포함' 안내는 요약 수치로 대체 — 배너 최소화)
    mode_note = _scan_mode_note(report)
    if mode_note:
        p.append(f'<div class="scanmode">{_esc(mode_note)}</div>')
    for line in _suppression_banner_md(report, suppressed):
        text = line.lstrip("> ").strip()
        if text:
            p.append(f'<div class="scanmode">{_esc(text).replace("**", "")}</div>')
    dep_audits = _dep_audits(report)
    if dep_audits and (_reg_banner := _registry_banner(dep_audits)):
        p.append(f'<div class="depwarn">{_esc(_reg_banner).replace("**", "")}</div>')
    if dep_audits and (_intel_banner := _intel_cache_banner(dep_audits)):
        p.append(f'<div class="depwarn">{_esc(_intel_banner).replace("**", "")}</div>')
    if dep_audits and (_trunc_banner := _dep_truncation_banner(dep_audits)):
        p.append(f'<div class="depwarn">{_esc(_trunc_banner).replace("**", "")}</div>')
    if _src_trunc := _source_truncation_banner(report):
        p.append(f'<div class="depwarn">{_esc(_src_trunc).replace("**", "")}</div>')
    for _rs in _ruleset_banners(report):
        p.append(f'<div class="depwarn">{_esc(_rs).replace("**", "")}</div>')
    manifest_skips = [s for s in report.skipped_files if "의존성 매니페스트" in (s.reason or "")]
    if not dep_audits and manifest_skips:
        names = ", ".join(s.path.replace("\\", "/").rsplit("/", 1)[-1] for s in manifest_skips)
        p.append(
            '<div class="depwarn">⚠ <b>의존성 검사 별도 필요</b> — '
            f"{_esc(names)} 은(는) 코드 스캔 대상이 아닙니다. 취약·악성 패키지는 "
            '<code class="ev">gvskb check-package</code> 또는 MCP '
            '<code class="ev">scan_dependencies</code>로 따로 검사하세요.</div>'
        )
    if build_skips:
        p.append(
            f'<div class="buildnote">빌드 산출물 {len(build_skips)}건 제외 — '
            "압축·번들·캐시 파일은 원본 소스가 아니라 검사 대상에서 자동 제외했습니다 "
            "(오탐 방지).</div>"
        )

    # --- 검토 범위 및 한계 + 면책 — 조치 안내 뒤, 상세 검토 앞(신뢰성 고지) --
    p.append("<h2>검토 범위 및 한계</h2>")
    ext_dist = _ext_distribution(report.scanned_files)
    ext_str = " · ".join(f"{_esc(ext)} {n}건" for ext, n in ext_dist.most_common()) or "—"
    p.append('<table class="scopetbl"><tr><th>구분</th><th>내용</th></tr>')
    p.append(
        f"<tr><th>검토 범위</th><td>파일 {len(report.scanned_files)}건 ({ext_str}) · "
        "정적(소스코드) 검사이며 코드를 실행하지 않습니다</td></tr>"
    )
    if report.skipped_files:
        reason_counts = Counter(_short_reason(s.reason) for s in report.skipped_files)
        rs = " · ".join(f"{_esc(r)} {n}건" for r, n in reason_counts.most_common())
        note = ""
        if any("확장자 아님" in (s.reason or "") for s in report.skipped_files):
            note = ("<br><b>'검사 대상 확장자 아님'은 검사되지 않았다는 뜻</b>이며 "
                    "위험이 없다는 의미가 아닙니다.")
        p.append(
            f"<tr><th>검사 제외</th><td>{len(report.skipped_files)}건 ({rs}) · "
            f"아래 '생략된 파일' 목록 참조{note}</td></tr>"
        )
    p.append("</table>")
    p.append(
        f'<div class="scopebox">⚠ <b>한계 고지</b> — {_esc(_LIMIT_HEAD)} '
        f"<b>{_esc(_LIMIT_ZERO)}</b> {_esc(_LIMIT_BODY)} <b>{_esc(_LIMIT_TAIL)}</b></div>"
    )
    # 면책 — 박스 없이 '※ 참고' 텍스트로만 제공(가벼운 고지).
    p.append(f'<div class="discnote">※ 참고 — {_esc(report.disclaimer.replace(chr(10), " "))}</div>')

    # =====================================================================
    # Layer 2 — 보안담당자용 상세 검토: 분야 개요 → 분야별 상세(기본 닫힘,
    # 비밀값 분야 직후 개인정보 콜아웃) → 외부 연결 → 의존성 → 승인 예외 →
    # 수정 프롬프트 → 부록
    # =====================================================================
    p.append("<h2>상세 검토 결과</h2>")
    p.append(
        '<div class="kv">각 <b>보안 분야</b>를 클릭해 펼치면 위치·취약점 설명·대응방안·근거를 '
        "확인할 수 있습니다. (인쇄 시에는 모두 펼쳐집니다.)</div>"
    )

    domains = _group_by_domain(report.findings)

    # --- 보안 분야 개요 — 어느 분야가 문제인지 한눈에 -----------------------
    p.append('<div class="subh">보안 분야 개요</div>')
    if domains or dep_row:
        p.append(
            "<table><tr><th>분야</th><th>최고 심각도</th><th>건수</th>"
            "<th>심각도별 내역</th><th>파일</th></tr>"
        )
        for d in domains:
            p.append(
                f"<tr><td>{_esc(d['label'])}</td>"
                f'<td class="sev"><span class="sevdot" style="background:'
                f'{_SEVERITY_COLOR[d["max_severity"]]}">{_SEVERITY_LABEL_KO[d["max_severity"]]}</span></td>'
                f'<td class="cnt">{d["count"]}</td>'
                f"<td>{_esc(d['breakdown'])}</td>"
                f'<td class="cnt">{d["files"]}</td></tr>'
            )
        if dep_row:
            dsev = dep_row["max_severity"]
            sev_cell = (
                f'<span class="sevdot" style="background:{_SEVERITY_COLOR[dsev]}">'
                f"{_SEVERITY_LABEL_KO[dsev]}</span>" if dsev else "—"
            )
            p.append(
                f"<tr><td>{_esc(dep_row['label'])}</td>"
                f'<td class="sev">{sev_cell}</td>'
                f'<td class="cnt">{dep_row["count"]}</td>'
                f"<td>{_esc(_dep_breakdown_text(dep_row))}</td>"
                f'<td class="cnt">패키지 {dep_row["packages"]}종</td></tr>'
            )
        p.append("</table>")
        for note in _domain_table_notes(report, domains, dep_row):
            p.append(f'<div class="dupnote">{_esc(note).replace("**", "")}</div>')

        # 같은 (파일, 줄)에 여러 룰이 걸린 위치 — 건수 부풀림 오해 방지.
        multi = _multi_rule_lines(report.findings)
        if multi:
            items = " · ".join(
                f"<b>{_esc(m['file'].replace(chr(92), '/'))}:{m['line']}</b>"
                f" — 관련 룰 {len(m['rules'])}개 ({_esc(', '.join(m['rules']))})"
                for m in multi[:12]
            )
            if len(multi) > 12:
                items += f" · 외 {len(multi) - 12}곳"
            p.append(
                f'<div class="dupnote"><b>같은 줄 다중 지적</b> — 발견 '
                f"{summary.finding_count}건 중 고유 위치는 {uniq_locs}곳입니다. "
                f"한 줄에 여러 기준(룰)이 함께 걸린 위치: {items}. "
                "한 곳을 고치면 관련 룰이 함께 해소됩니다.</div>"
            )
    else:
        p.append('<div class="disc">발견된 위험이 없어 분야별 상세가 없습니다.</div>')

    # --- 분야별 상세 — 분야마다 <details>(치명·차단 분야는 기본 펼침).
    #     개인정보·비밀값 콜아웃은 '비밀값' 분야(없으면 개인정보) 바로 아래. -----
    pii = _privacy_findings(report.findings)
    pii_anchor = max((d["order"] for d in domains if d["order"] <= 2), default=None)
    for d in domains:
        # 기본은 닫힘(사용자 요청) — 클릭해 펼친다. 인쇄 시에는 print CSS 로 모두 펼쳐짐.
        p.append(
            '<details class="sec"><summary>'
            f'<span class="sevdot" style="background:{_SEVERITY_COLOR[d["max_severity"]]}">'
            f'{_SEVERITY_LABEL_KO[d["max_severity"]]}</span> '
            f'{_esc(d["label"])} — {d["count"]}건 ({_esc(d["breakdown"])}) '
            f'· 파일 {d["files"]}개</summary>'
            '<div class="secbody">'
        )
        for g in _rule_groups(d["findings"]):
            p.extend(_render_rule_group_html(g))
        p.append("</div></details>")
        if pii and d["order"] == pii_anchor:
            p.append(_pii_callout_html(pii))
    if pii and pii_anchor is None:
        p.append(_pii_callout_html(pii))

    # === 승인된 예외 내역 — 있을 때만 =====================================
    p.extend(_render_suppressions_html(suppressed))

    # === 의존성(패키지) 취약점 검사 — 병합된 경우에만 표시 ================
    p.extend(_render_dependency_audit_html(report))

    # === 외부 연결 인벤토리 (위험과 분리, 발견 0이어도 표시) ==============
    if report.external_surface:
        p.extend(_render_external_surface_html(report))

    # === 수정 프롬프트 (복사용) — 기본 접기. 각 블록에 복사 버튼(인라인 JS) ===
    dep_prompt = _dep_fix_prompt_text(report)
    if report.findings or dep_prompt:
        p.append(
            '<details class="sec"><summary>수정 프롬프트 (복사해서 AI에게 전달)'
            '</summary><div class="secbody">'
        )
        # ① 가장 쉬운 방법 — 강조 박스 + 한 줄 프롬프트 복사 버튼
        p.append(
            '<div class="easyfix"><div class="eh">💬 가장 쉬운 방법</div>'
            '<div class="ed">쓰던 AI 도구(커서·클로드 코드 등)에 아래 문장을 그대로 '
            "붙여넣으면 끝입니다. 아래 유형별 블록은 필요할 때 따로 복사하세요.</div>"
            f'<div class="easyrow"><code class="saycode">{_esc(_SAY_FIX)}</code>'
            f'<button type="button" class="copybtn" data-copy="{_esc(_SAY_FIX)}">📋 복사</button>'
            "</div></div>"
        )
        if dep_prompt:
            p.append(
                '<div class="depwarn">⚠ <b>패키지 블록을 빠뜨리지 마세요</b> — 소스 코드만 '
                "고치면 의존성 차단이 그대로 남아 다시 검사해도 배포 판정이 바뀌지 않습니다.</div>"
            )
        # ② 유형별 수정 프롬프트 — 각 블록마다 복사 버튼
        for g in _rule_groups(report.findings):
            text = _fix_prompt_text(g)
            p.append(
                '<div class="fixwrap">'
                f'<button type="button" class="copybtn" data-copy="{_esc(text)}">📋 복사</button>'
                f'<div class="fixprompt">{_esc(text)}</div></div>'
            )
        if dep_prompt:
            p.append(
                '<div class="fixwrap">'
                f'<button type="button" class="copybtn" data-copy="{_esc(dep_prompt)}">📋 복사</button>'
                f'<div class="fixprompt">{_esc(dep_prompt)}</div></div>'
            )
        p.append("</div></details>")

    # === 부록 (기술 정보) — 기본 접기 ====================================
    non_build_skips = [s for s in report.skipped_files if "빌드 산출물" not in (s.reason or "")]
    repro = reproduce_command or f"gvskb scan {report.target} --profile {report.profile}"
    p.append('<details class="sec"><summary>부록 (가이드라인 분포·생략 파일·재현·재검증)'
             '</summary><div class="secbody">')
    if report.findings or dep_row:
        p.extend(_render_severity_criteria_html(report))
    dist = _guideline_distribution(report.findings) if report.findings else None
    if dist:
        p.append('<div class="subh">가이드라인별 분포</div>')
        p.append("<table><tr><th>가이드라인</th><th>인용 건수</th></tr>")
        for label, count in dist.most_common():
            p.append(f"<tr><td>{_esc(label)}</td><td>{count}</td></tr>")
        p.append("</table>")
    if non_build_skips:
        p.append('<div class="subh">생략된 파일</div><table><tr><th>경로</th><th>이유</th></tr>')
        for sf in non_build_skips[:30]:
            p.append(f"<tr><td>{_esc(sf.path)}</td><td>{_esc(sf.reason)}</td></tr>")
        p.append("</table>")
        if len(non_build_skips) > 30:
            p.append(f'<div class="kv">… 외 {len(non_build_skips) - 30}건</div>')
    if build_skips:
        sample = ", ".join(_esc(s.path) for s in build_skips[:6])
        more = f" 외 {len(build_skips) - 6}건" if len(build_skips) > 6 else ""
        p.append(
            f'<div class="buildnote">빌드 산출물 제외 {len(build_skips)}건: {sample}{more} '
            "— 압축/번들·빌드 출력 디렉터리는 원본 소스가 아니므로 검사하지 않습니다.</div>"
        )
    p.append('<div class="subh">재현 절차</div>')
    p.append('<div class="kv">같은 결과를 다시 만들거나 다른 환경에서 검증하려면 다음을 실행합니다.</div>')
    p.append(f"<pre>{_esc(repro)}</pre>")
    if (_env := _env_grade_line(report)) is not None:
        p.append(f'<div class="kv">{_esc(_env.replace("`", ""))}</div>')
    p.append('<div class="subh">수정 후 다시 검증</div>')
    p.append('<ol class="steps">')
    p.append('<li><b>CLI</b>: 위 재현 명령(<code class="ev">gvskb scan ...</code>)을 다시 실행</li>')
    p.append(
        '<li><b>MCP(IDE)</b>: 수정한 코드를 <code class="ev">scan_code</code>에 다시 넘기거나 '
        '파일은 <code class="ev">scan_path</code> 호출</li>'
    )
    p.append("<li><b>LLM 안내</b>: 위 권장 처리 순서(차단→치명·높음→자동수정→나머지)를 그대로 지시문으로 사용</li>")
    p.append("</ol>")
    p.append("</div></details>")

    # (면책은 상단 '검토 범위 및 한계' 아래로 이동했다 — 여기서는 반복하지 않는다)
    p.append('<div class="foot">생성: vibecode-checker · 공공 바이브 코딩 보안 가드레일</div>')
    p.append("</div>")  # .page
    # 복사 버튼용 인라인 스크립트(외부 리소스 로딩 없음 — 자체완결 유지).
    # 클립보드 미지원 환경에서도 프롬프트 텍스트는 그대로 보인다(우아한 저하).
    p.append(_COPY_SCRIPT)
    p.append("</body></html>")
    return "\n".join(p)


def _fix_prompt_text(group: dict) -> str:
    """복사용 수정 프롬프트 한 블록(룰 그룹 기준). AI 도구에 그대로 붙여넣는다."""
    f: Finding = group["sample"]
    sev = _SEVERITY_LABEL_KO[group["severity"]]
    dec = _DECISION_LABEL_KO.get(group["decision"], group["decision"].value)
    locs = _locations_by_file(group["findings"])
    out = [
        f"[{sev}/{dec}] {f.plain_title} ({group['rule_id']}) — {group['count']}건",
        f"위치: {locs}",
    ]
    if f.why_it_matters:
        out.append(f"왜 위험: {f.why_it_matters.strip()}")
    if f.safe_fix:
        out.append(f"안전한 수정 방향: {f.safe_fix.strip()}")
    out.append("지시: 위 위치의 코드를 안전한 패턴으로 수정하고, 수정 후 다시 검사해 주세요.")
    return "\n".join(out)


def _dep_fix_prompt_text(report: ScanReport) -> str | None:
    """의존성 수정 프롬프트 한 블록. 조치할 패키지가 없으면 None.

    **왜 필요한가(실측)**: 이 보고서의 배포 차단 사유 절반이 패키지인데 수정
    프롬프트에는 소스 발견만 있었다. 사용자가 안내대로 "방금 나온 위험들을 고쳐줘"
    라고 하면 소스만 고쳐지고, 다시 검사해도 **여전히 배포 미승인**이다. 왜 안
    풀리는지 알 방법이 없다 — 도구가 만든 막다른 길이다.

    권고 버전은 적지 않는다. 검사 결과에 '고쳐진 버전'이 없어서, 지어내면 틀린
    버전으로 올리게 된다. 대신 **무엇을 왜 올려야 하는지**와 확인 방법을 준다.
    """
    row = _dep_domain_row(report)
    if not row or not row["components"]:
        return None
    comps = sorted(
        row["components"],
        key=lambda c: (-_SEVERITY_RANK[c["severity"]], str(c["check"].get("name") or "").lower()),
    )
    blocked = any(a.get("blocked") for a in _dep_audits(report))
    head = "[차단]" if blocked else "[경고]"
    out = [f"{head} 취약·위험 패키지 {len(comps)}건 — 버전을 올려야 합니다"]
    for comp in comps:
        c = comp["check"]
        detail: list[str] = []
        if c.get("is_malicious_package"):
            detail.append("악성 패키지 — 즉시 제거")
        if c.get("verdict") == "not_found":
            detail.append("레지스트리에 없는 이름(가짜 이름 의심) — 철자 확인 후 제거")
        if c.get("verdict") == "registry_rejected":
            detail.append("기관 레지스트리 차단")
        if c.get("vulnerability_count"):
            sev = str(c.get("max_cve") or "").upper()
            detail.append(
                f"취약점 {c['vulnerability_count']}건"
                + (f" · 최고 {sev}" if sev and sev != "NONE" else "")
                + (" · CISA KEV(실제 악용 중)" if c.get("in_kev") else "")
            )
        if c.get("verdict") == "cooldown_hold":
            detail.append("발행 직후 버전 — 쿨다운 보류")
        # **어느 버전으로** 올릴지까지 말한다. 예전에는 "공식 배포처를 확인해
        # 정하세요"로 판단을 사용자에게 넘겼다 — 도구가 아는 값을 버리고 있었다.
        rec = c.get("recommended_version")
        latest = (c.get("registry_metadata") or {}).get("latest_version")
        if rec:
            target = f" → **{rec} 이상**으로 업그레이드"
        elif latest:
            target = f" → 목표 버전 미상(고쳐진 버전을 모르는 취약점 있음) · 최신 {latest}"
        else:
            target = " → 목표 버전 미상"
        out.append(
            f"- {c.get('name', '?')} {c.get('version') or '(버전 미상)'} "
            f"[{_SEVERITY_LABEL_KO[comp['severity']]}] "
            f"— {' · '.join(detail) or '검토 필요'}{target} "
            f"(출처: {' · '.join(comp['sources'])})"
        )
    out.append(
        "지시: 위 패키지를 적힌 목표 버전 이상으로 올려 주세요. 매니페스트"
        "(requirements.txt·package.json)와 실제 설치본을 **함께** 맞추고, 벤더 번들"
        "(static 의 *.min.js 등)은 해당 파일을 최신 배포본으로 교체하세요. "
        "**목표 버전이 '미상'인 항목만** 공식 배포처(PyPI·npm)의 보안 권고를 확인해 "
        "정하고, 임의로 추측하지 마세요. 업그레이드로 동작이 바뀔 수 있으니 변경 후 "
        "실행해 확인하고, 마지막에 다시 검사해 주세요."
    )
    return "\n".join(out)


def _render_external_surface_html(report: ScanReport) -> list[str]:
    """외부 연결 인벤토리 섹션(HTML) — 접기형. ⚠가 있으면 기본 펼침(절충)."""
    api = [c for c in report.external_surface if c.kind == "api"]
    pkg = [c for c in report.external_surface if c.kind == "package"]
    res = [c for c in report.external_surface if c.kind == "resource"]
    n_api, n_pkg, gukoe, warn = _external_stats(report)
    egress = sum(1 for c in report.external_surface if c.airgap_impact == "egress")
    head_extra = ""
    if gukoe or warn:
        bits = []
        if gukoe:
            bits.append(f"국외 {gukoe}")
        if warn:
            bits.append(f"⚠개인정보 {warn}")
        head_extra = f' · <span style="color:#c0392b">{" · ".join(bits)}</span>'
    res_head = f" · 외부 리소스 {len(res)}" if res else ""
    out: list[str] = [
        f'<details class="sec inv"{" open" if warn else ""}>'
        f"<summary>외부 연결 인벤토리 — API {n_api} · 플러그인 {n_pkg}{res_head}{head_extra}</summary>"
        '<div class="secbody">',
        '<div class="invnote">⚠ <b>사용 금지가 아닙니다.</b> 외부로 데이터를 보낼 수 있는 지점 '
        '목록입니다. <span class="hl">⚠ 개인정보 인접</span>·<span class="hl">국외 전송</span>을 '
        "먼저 확인하세요.</div>",
    ]
    airgap = _airgap_note(res, egress)
    if airgap:
        airgap_html = _esc(airgap).replace("**", "")
        out.append(
            '<div class="invnote" style="border-left:4px solid #b7791f;background:#fffdf5">'
            f"{airgap_html}</div>"
        )
    circ = iter("①②③④")
    if api:
        out.append(f'<div class="subh">{next(circ)} 외부 API 호출 (검토 필요 먼저)</div>')
        # 컬럼 폭을 명시한다 — 자동 배분은 긴 파일 경로가 공간을 먹고 정작 중요한
        # '이용 정보'가 세로로 찌그러진다(실측 가독성 문제). 모델은 별도 칸 대신
        # 이용 정보에 합쳐 칸 수를 줄였다(대부분 '—'라 빈 칸만 차지했음).
        out.append(
            '<table class="extbl">'
            "<colgroup><col style='width:20%'><col style='width:9%'>"
            "<col style='width:23%'><col style='width:30%'>"
            "<col style='width:11%'><col style='width:7%'></colgroup>"
            "<tr><th>대상(호스트)</th><th>종류</th><th>위치</th>"
            "<th>이용 정보(요약)</th><th>국외이전(운영주체)</th><th>검토</th></tr>"
        )
        for c in api:
            cls = ' class="w"' if c.review_level == "warn" else ""
            region = c.region or "확인"
            rcls = "out" if c.region == "국외" else ("in" if c.region == "국내" else "q")
            rev = (
                '<span class="rev warn">검토 필요</span>'
                if c.review_level == "warn"
                else '<span class="rev info">참고</span>'
            )
            if c.context == "doc-or-installer":
                # 설치 안내·스크립트의 다운로드 주소 — 운영 중 전송이 아니므로
                # 국외이전 검토 칸을 비우고 성격을 그대로 밝힌다.
                rev = '<span class="rev info">문서·설치</span>'
                region, rcls, oper = "—", "q", "운영 중 전송 아님"
            # 호출 지점 수 — 첫 위치 + "외 N곳"으로 검토 규모를 보여준다.
            loc = c.location if c.call_count <= 1 else f"{c.location} 외 {c.call_count - 1}곳"
            # 운영주체·국가 — 국외이전 검토는 "누구에게, 어느 나라로"가 특정돼야 한다.
            oper = c.operator or "미상 — 직접 확인"
            # 모델명은 AI 호출에만 있으므로 이용 정보 뒤에 덧붙인다.
            info = c.data_summary + (f" · 모델 {c.model}" if c.model else "")
            out.append(
                f"<tr{cls}><td class='host'>{_esc(c.target)}</td>"
                f'<td><span class="pill {_esc(c.category)}">{_esc(_cat_ko(c.category))}</span></td>'
                f"<td class='loc'>{_esc(loc)}</td>"
                f"<td>{_esc(info)}</td>"
                f'<td><span class="go {rcls}">{_esc(region)}</span>'
                f'<br><span class="oper">{_esc(oper)}</span></td><td>{rev}</td></tr>'
            )
        out.append("</table>")
    if res:
        out.append(f'<div class="subh">{next(circ)} 외부 리소스 로딩 (CDN 등) — 폐쇄망에서 동작 불가</div>')
        out.append(
            "<table><tr><th>대상(호스트)</th><th>위치</th><th>내용</th>"
            "<th>운영주체</th><th>폐쇄망 영향</th></tr>"
        )
        for c in res:
            loc = c.location if c.call_count <= 1 else f"{c.location} 외 {c.call_count - 1}곳"
            out.append(
                f"<tr><td>{_esc(c.target)}</td><td>{_esc(loc)}</td>"
                f"<td>{_esc(c.data_summary)}</td>"
                f"<td>{_esc(c.operator or '미상 — 직접 확인')}</td>"
                '<td><span class="rev warn">로딩 실패 — 화면·기능 파손</span></td></tr>'
            )
        out.append("</table>")
    if pkg:
        out.append(f'<div class="subh">{next(circ)} 설치된 외부 플러그인 · 라이브러리</div>')
        out.append(
            "<table><tr><th>플러그인/라이브러리</th><th>버전</th><th>종류</th>"
            "<th>전송 대상(운영주체)</th><th>이용 정보(요약)</th></tr>"
        )
        for c in pkg:
            out.append(
                f"<tr><td>{_esc(c.target)}</td><td>{_esc(c.version or '—')}</td>"
                f'<td><span class="pill {_esc(c.category)}">{_esc(_cat_ko(c.category))}</span></td>'
                f"<td>{_esc(c.operator or '—')}</td>"
                f"<td>{_esc(c.data_summary)}</td></tr>"
            )
        out.append("</table>")
    out.append(
        '<div class="invcheck"><b>검토 체크리스트</b> — ⚠ 지점마다: ① 무슨 데이터? '
        "② 개인정보 포함? ③ 국외이전 동의·망분리·기관 AI정책 부합? "
        "④ AI API 입력 데이터의 <b>학습 이용·보존 여부</b>는 서비스 약관과 기관 계약"
        "(옵트아웃 설정)으로 확인</div>"
    )
    out.append(
        '<div class="disc">※ <b>최소 목록</b>입니다 — 변수로 조립된 호스트는 누락될 수 있습니다. '
        "'이용 정보·국외'는 검토를 돕는 신호이며 실제 전송 페이로드를 확정하지 않습니다.</div>"
    )
    out.append("</div></details>")
    return out


def _render_rule_group_html(group: dict) -> list[str]:
    """파일 안에서 같은 룰을 한 카드로 묶어 렌더(설명 1번 + 위치목록 + 외 N건)."""
    f: Finding = group["sample"]
    findings: list[Finding] = group["findings"]
    sev_color = _SEVERITY_COLOR[group["severity"]]
    dec_color = _DECISION_COLOR.get(group["decision"], "#555")
    out: list[str] = [f'<div class="card" style="border-left-color:{sev_color}">']
    out.append(
        f'<div><span class="badge" style="background:{sev_color}">'
        f"{_SEVERITY_LABEL_KO[group['severity']]}</span>"
        f'<span class="badge" style="background:{dec_color}">'
        f"{_DECISION_LABEL_KO.get(group['decision'], group['decision'].value)}</span>"
        f'<span class="ftitle">{_esc(f.plain_title)}</span>'
        f'<span class="loc">{group["count"]}건 · 파일 {group["files"]}개</span></div>'
    )
    # 위치는 **파일 경로부터** 적는다 — 줄 번호만으로는 어느 파일인지 알 수 없다.
    out.append(
        f'<div class="row"><span class="lab">위치</span>'
        f'<span class="val"><code class="ev">'
        f'{_esc(_locations_by_file(findings, limit_files=_LOC_FILE_LIMIT))}</code></span></div>'
    )
    out.append(
        f'<div class="row"><span class="tag">{_esc(f.rule_id)}</span>'
        f'<span class="tag">{_esc(f.category)}</span>'
        f'<span class="tag">{_esc(_confidence_label(f.confidence))}</span></div>'
    )
    if f.severity_adjusted:
        out.append(
            f'<div class="row"><span class="lab">심각도 조정</span>'
            f'<span class="val">{_esc(f.severity_adjusted)}</span></div>'
        )
    if f.evidence:
        out.append(
            f'<div class="row"><span class="lab">증거(마스킹됨)</span>'
            f'<span class="val"><code class="ev">{_esc(_oneline(f.evidence))}</code></span></div>'
        )
    if f.why_it_matters:
        out.append(
            f'<div class="row"><span class="lab">왜 위험한가</span>'
            f'<span class="val">{_esc(f.why_it_matters.strip())}</span></div>'
        )
    if f.public_sector_impact:
        out.append(
            f'<div class="row"><span class="lab">공공 업무 영향</span>'
            f'<span class="val">{_esc(", ".join(f.public_sector_impact))}</span></div>'
        )
    if f.safe_fix:
        out.append('<div class="row"><span class="lab">안전한 수정 방향</span></div>')
        out.append(f"<pre>{_esc(f.safe_fix.strip())}</pre>")
    flags = []
    if f.can_auto_fix:
        flags.append("자동 수정 가능 (diff 미리보기 후 적용)")
    if f.requires_approval_to_bypass:
        flags.append("우회 시 보안담당자 승인 + 감사 로그 필요")
    if flags:
        out.append(
            f'<div class="row"><span class="lab">처리</span>'
            f'<span class="val">{_esc(" · ".join(flags))}</span></div>'
        )
    if f.references:
        out.append(
            f'<div class="row"><span class="lab">출처</span>'
            f'<span class="val">{_esc(", ".join(f.references[:5]))}</span></div>'
        )
    out.append("</div>")
    return out


# ---------------------------------------------------------------------------
# 승인된 예외(.gvskb-exceptions.yaml) — 발견을 숨기지 않고 게이트만 통과.
# 보안팀은 "무엇이 왜 면제됐고 언제 만료되나"를 항상 볼 수 있어야 한다.
# ---------------------------------------------------------------------------


def _suppression_banner_md(report: ScanReport, suppressed: list[Finding]) -> list[str]:
    # 승인된 예외 '적용' 안내는 요약 수치(승인된 예외 N건)로 대체하고, 여기서는
    # 놓치면 안 되는 '만료된 예외'(다시 차단 대상)만 경고로 남긴다.
    out: list[str] = []
    ss = report.suppression_summary or {}
    for e in ss.get("expired", []) or []:
        out.append(
            f"> ⚠️ **만료된 예외** — `{e.get('rule_id', '?')}` ({e.get('file', '?')}) 의 예외가 "
            f"{e.get('expires', '?')} 에 만료돼 **다시 차단 대상**입니다. 재승인하거나 수정하세요."
        )
        out.append("")
    return out


def _render_suppressions_md(suppressed: list[Finding]) -> list[str]:
    if not suppressed:
        return []
    out: list[str] = ["## 승인된 예외 내역 (게이트 통과, 기록 유지)", ""]
    out.append("| 룰 | 위치 | 심각도 | 사유(승인·만료 포함) |")
    out.append("|---|---|---|---|")
    for f in suppressed:
        reason = (f.suppress_reason or "").replace("|", "\\|")  # MD 표 파이프 이스케이프
        out.append(
            f"| `{f.rule_id}` | `{f.location.file}:{f.location.line}` | "
            f"{_SEVERITY_LABEL_KO[f.severity]} | {reason} |"
        )
    out.append("")
    out.append("> 예외는 위험이 사라졌다는 뜻이 아닙니다 — 만료일이 지나면 자동으로 다시 차단됩니다.")
    out.append("")
    return out


def _render_suppressions_html(suppressed: list[Finding]) -> list[str]:
    if not suppressed:
        return []
    out: list[str] = [
        '<details class="sec"><summary>승인된 예외 내역 — '
        f"{len(suppressed)}건 (게이트 통과, 기록 유지)</summary>",
        '<div class="secbody">',
        "<table><tr><th>룰</th><th>위치</th><th>심각도</th><th>사유(승인·만료 포함)</th></tr>",
    ]
    for f in suppressed:
        out.append(
            f"<tr><td>{_esc(f.rule_id)}</td>"
            f"<td>{_esc(f.location.file)}:{f.location.line}</td>"
            f"<td>{_esc(_SEVERITY_LABEL_KO[f.severity])}</td>"
            f"<td>{_esc(f.suppress_reason or '')}</td></tr>"
        )
    out.append("</table>")
    out.append('<div class="disc">예외는 위험이 사라졌다는 뜻이 아닙니다 — '
               "만료일이 지나면 자동으로 다시 차단됩니다.</div>")
    out.append("</div></details>")
    return out


# ---------------------------------------------------------------------------
# 의존성(패키지) 취약점 감사 — scan_dependencies/audit_manifest 결과를 사람용
# 리포트에 병합한다. 보안팀이 "코드 + 패키지" 위험을 한 문서에서 보게 하고,
# 판정 불가(unchecked/unparsed)를 '안전'으로 오해하지 않도록 명시한다.
# ---------------------------------------------------------------------------


def _dep_audits(report: ScanReport) -> list[dict]:
    """dependency_audit 필드 → audit dict 목록. 단일 dict / {'audits':[...]} 모두 수용."""
    da = report.dependency_audit
    if not da or not isinstance(da, dict):
        return []
    if isinstance(da.get("audits"), list):
        return [a for a in da["audits"] if isinstance(a, dict)]
    return [da]


def _dep_source_label(audit: dict) -> str:
    """감사 출처를 사람이 읽는 짧은 이름으로. 표의 '출처' 칸에 들어간다."""
    src = str(audit.get("source") or "")
    if src == "vendor-bundle":
        return "벤더 번들"
    if src == "installed-inventory":
        return "설치본"
    return str(audit.get("manifest") or audit.get("ecosystem") or "매니페스트")


def _dep_component_key(check: dict, ecosystem: str) -> tuple[str, str, str]:
    """(생태계, 정규화 이름, 버전) — 같은 컴포넌트를 한 번만 세기 위한 키.

    PEP 503 정규화로 ``et_xmlfile`` 과 ``et-xmlfile`` 을 같은 것으로 본다.
    """
    from .tools.installed_packages import _normalize

    name = str(check.get("name") or "")
    norm = _normalize(name) if ecosystem.lower() == "pypi" else name.lower()
    return (ecosystem.lower(), norm, str(check.get("version") or ""))


def _dep_merged_components(audits: list[dict]) -> list[dict]:
    """모든 감사의 checks 를 **고유 컴포넌트 단위로 병합**한다.

    같은 패키지·같은 버전이 매니페스트·설치본·휠에 각각 있으면 예전에는 그 수만큼
    따로 셌다 — 실측 프로젝트에서 pillow 12.2.0 이 '취약 패키지 3건' 중 2건을
    차지했다(고유 취약 컴포넌트는 pillow·pip 2종). **조치 단위(업그레이드할 패키지)와
    알림 단위가 어긋나면 경고 피로가 생기고, 그 사이로 진짜 위험이 묻힌다**(원칙 6).
    상용 도구(스패로우)는 같은 오류를 3배로 저질러 pillow 하나에 106건을 썼다.

    출처는 버리지 않고 한 행의 ``sources`` 로 모은다 — 조치는 모든 사본에 적용해야 한다.
    """
    merged: dict[tuple[str, str, str], dict] = {}
    for a in audits:
        eco = str(a.get("ecosystem") or "?")
        label = _dep_source_label(a)
        for c in a.get("checks") or []:
            key = _dep_component_key(c, eco)
            cur = merged.get(key)
            if cur is None:
                merged[key] = {"check": c, "ecosystem": eco, "sources": [label]}
                continue
            if label not in cur["sources"]:
                cur["sources"].append(label)
            # 더 많이 아는 쪽을 대표로 삼는다(설치본에만 라이선스가 있는 등).
            if _dep_check_rank(c) > _dep_check_rank(cur["check"]):
                cur["check"] = c
    return list(merged.values())


def _dep_check_rank(check: dict) -> int:
    """대표 레코드 선택 우선순위 — 위험을 아는 쪽 > 검사된 쪽 > 나머지."""
    if check.get("is_malicious_package") or check.get("verdict") == "not_found":
        return 3
    if check.get("vulnerability_count"):
        return 2
    return 1 if check.get("checked") else 0


def _dep_stats(audits: list[dict]) -> tuple[int, int, int, bool, int]:
    """(검사됨, 판정불가, 취약·악성 수, 차단 여부, 미존재 수) 합계.

    ``검사됨``·``판정불가`` 는 **수행한 검사 횟수**(작업량)이고, ``취약·악성``·``미존재``
    는 **고유 컴포넌트 수**(조치 단위)다 — 후자가 담당자가 실제로 처리할 항목 수다.
    """
    checked = sum(int(a.get("checked_count") or 0) for a in audits)
    unchecked = sum(int(a.get("unchecked_count") or 0) for a in audits)
    unchecked += sum(1 for a in audits if a.get("verdict") == "unparsed")  # 파싱 실패도 판정불가
    vuln = 0
    not_found = 0
    for comp in _dep_merged_components(audits):
        c = comp["check"]
        if c.get("is_malicious_package") or c.get("vulnerability_count"):
            vuln += 1
        if c.get("verdict") == "not_found":
            not_found += 1
    # 미존재(슬롭스쿼팅 의심)는 '취약점 검사 불가'로 unchecked 에도 잡히지만,
    # 성격이 다르므로(설치 시도 자체가 위험) 별도 집계해 배너에 드러낸다.
    unchecked = max(0, unchecked - not_found)
    blocked = any(a.get("blocked") for a in audits)
    return checked, unchecked, vuln, blocked, not_found


def _dep_truncation_banner(audits: list[dict]) -> str | None:
    """상한에 걸려 **검사되지 않은** 패키지가 있으면 알린다 — 한 줄만.

    **왜 필요한가(실측 2026-08-08)**: ``lexdiff`` 의 `pnpm-lock.yaml` 은 전이 의존성이
    906개인데 락파일 기본 상한이 500 이라 **406개가 잘렸다**. 그런데 이 사실이
    보고서 어디에도 없었다 — ``truncated_count`` 를 ``report.py`` 가 한 번도 읽지
    않았기 때문이다. 담당자는 "검사됨 500 · 판정불가 N" 이라는 **완결돼 보이는**
    의존성 섹션을 그대로 결재에 올린다. 트리의 45% 를 안 봤다는 사실이 종이에 없다.

    ``unchecked_count`` 와 다르다: 그쪽은 *검사했으나 판정하지 못한* 수이고,
    이쪽은 *아예 보지 않은* 수다. 둘을 합쳐 적으면 "왜 못 봤는지"가 흐려진다.
    """
    total = 0
    parsed = 0
    for a in audits:
        try:
            total += int(a.get("truncated_count") or 0)
            parsed += int(a.get("parsed_count") or 0)
        except (TypeError, ValueError):  # pragma: no cover - 방어
            continue
    if total <= 0:
        return None
    checked = max(0, parsed - total)
    pct = f"{total * 100 // parsed}%" if parsed else "일부"
    return (
        f"⚠ **의존성 {total}개가 검사되지 않았습니다** — 파싱한 {parsed}개 중 {checked}개만 "
        f"검사했습니다(상한에 걸려 {pct} 누락). **이 결과는 의존성 트리 전체를 덮지 "
        "않습니다.** 상한을 올려 다시 검사하세요"
        "(MCP `scan_dependencies` 의 `limit`, CLI `--dep-limit`)."
    )


def _ruleset_banners(report: "ScanReport") -> list[str]:
    """룰셋 재현성 경고 — 최대 두 줄.

    게이트는 "어제 통과한 것이 오늘도 통과한다"가 전제다. 그 전제가 깨진 두 경우:

    ① **드리프트** — 룰이 바뀌었는데 룰셋 버전이 그대로다. 판정이 달라졌는데
       결과에는 같은 버전이 찍혀, 비교하는 사람이 *"룰은 그대로인데 코드가
       나빠졌구나"* 로 잘못 읽는다.
    ② **핀 불일치** — 소비자가 `GVSKB_EXPECT_RULESET` 로 고정한 것과 실제가
       다르다. CI 가 기준선을 잡아 둔 의미가 사라진 상태다.

    둘 다 발견 목록에는 영향을 주지 않는다. 그래서 **결론 근처에서 말해야**
    한다 — 부록에 적으면 아무도 안 본다.
    """
    from . import ruleset as _ruleset

    out: list[str] = []
    if report.ruleset_drift:
        out.append(
            f"⚠ **룰셋 버전이 실제 룰과 다릅니다** — {report.ruleset_drift} "
            "**이 판정은 선언한 버전으로 재현되지 않습니다.**"
        )
    if mismatch := _ruleset.pin_mismatch(report.ruleset_version, report.ruleset_digest):
        out.append(mismatch)
    return out


_SOURCE_TRUNC_RE = re.compile(r"max_files=(\d+) reached — (\d+)개")


def _source_truncation_banner(report: "ScanReport") -> str | None:
    """상한에 걸려 **열어보지도 못한 소스 파일**이 있으면 알린다.

    의존성 쪽과 똑같은 결함이 소스 쪽에도 있었다(실측 2026-08-08): ``lexdiff``
    는 검사 대상이 568개인데 상한이 500이라 **70개가 잘렸다**. 그런데 그 70개가
    ``skipped_files`` 에 **한 줄**로만 들어가, 제외 요약에는 "최대 파일 수 도달
    1건" 으로 보였다 — 담당자가 읽는 숫자는 1이고 실제로 안 본 파일은 70이다.

    제외 요약(``_skip_breakdown_lines``)은 '무엇이 왜 빠졌나'를 나열하는 표라
    이 사실이 목록 속에 묻힌다. 커버리지가 깨졌다는 것은 발견 목록과 같은
    무게로, **결론 근처에서** 말해야 한다.
    """
    for s in report.skipped_files or []:
        m = _SOURCE_TRUNC_RE.search(s.reason or "")
        if not m:
            continue
        limit, missed = int(m.group(1)), int(m.group(2))
        total = limit + missed
        return (
            f"⚠ **소스 파일 {missed}개가 검사되지 않았습니다** — 검사 대상 "
            f"{total}개 중 {limit}개만 검사했습니다(파일 수 상한 도달). "
            "**이 결과는 저장소 전체를 덮지 않습니다.** 상한을 올려 다시 "
            "검사하세요(CLI `--max-files`)."
        )
    return None


def _intel_cache_banner(audits: list[dict]) -> str | None:
    """인텔 캐시 열화 배너 — 매니페스트 전체에 **한 줄만**.

    조치가 "번들 반입 한 번"인 시스템 문제이므로 패키지별로 알리지 않는다.
    수백 건에 같은 깃발을 꽂으면 담당자는 그것을 무시하게 되고, 그러면 그 사이의
    진짜 위험도 함께 묻힌다. 조치 단위가 다르면 알림 단위도 달라야 한다.
    """
    worst = "ok"
    dates: dict[str, str] = {}
    for a in audits:
        ic = a.get("intel_cache") or {}
        state = str(ic.get("state") or "")
        if state == "stale":
            worst = "stale"
        elif state == "missing" and worst != "stale":
            worst = "missing"
        for k, v in (ic.get("as_of") or {}).items():
            if v and (k not in dates or str(v) < dates[k]):
                dates[k] = str(v)
    if worst == "ok":
        return None
    as_of = " · ".join(f"{k} {v[:10]}" for k, v in sorted(dates.items()))
    if worst == "missing":
        return (
            "⚠️ **위협 인텔 캐시 없음** — 취약점이 발견된 패키지를 CISA KEV"
            "(실제 악용 목록)와 **대조하지 못했습니다**. 보고서의 `in_kev` 표시는 "
            "'악용 없음'이 아니라 '대조 못 함'입니다. "
            "`gvskb update-intel`(폐쇄망은 인텔 번들 반입) 후 재검사하세요."
        )
    return (
        f"⚠️ **위협 인텔 캐시가 낡았습니다**{f' (기준일 {as_of})' if as_of else ''} — "
        "그 이후 악용 목록에 오른 취약점은 이 결과에 반영되지 않았습니다. "
        "`gvskb update-intel`(폐쇄망은 인텔 번들 반입)로 갱신하면 해소됩니다. "
        "**패키지 개별 문제가 아니라 검사 환경의 문제입니다.**"
    )


def _severity_criteria_rows(report: ScanReport) -> list[tuple[str, str, str]]:
    """부록 '심각도 판정 기준' 표의 행 — (구분, 심각도, 기준).

    왜 넣는가: 같은 '높음'이라도 소스 발견과 패키지는 **정하는 방식이 다르다**.
    소스는 룰 문서에 사람이 미리 적어 둔 고정 등급이고, 패키지는 검사 시점의
    취약점·악용 정보로 계산한다. 그 사실이 보고서 어디에도 없으면 독자는 두 값을
    같은 자로 잰 것으로 읽고, "왜 이게 높음이냐"에 도구가 답하지 못한다.
    """
    rows: list[tuple[str, str, str]] = [
        (
            "소스 코드 발견", "룰에 고정",
            "각 룰 문서(`rules/`)의 `severity` 값을 그대로 씁니다 — 위험 유형 자체의 등급이며 "
            "검사할 때 계산하지 않습니다. 룰 ID로 원문을 확인할 수 있습니다(`gvskb rule <ID>`).",
        ),
    ]
    if _dep_domain_row(report):
        for _key, sev, desc in _DEP_SEVERITY_TABLE:
            rows.append(("의존성(패키지) — 검사 시 계산", _SEVERITY_LABEL_KO[sev], desc))
        rows.append((
            "의존성(패키지) — 검사 시 계산", "등급 없음",
            "오프라인·조회 실패 등으로 확인하지 못한 것입니다. '이상 없음'과 구분해 등급을 "
            "매기지 않고 별도로 셉니다 — **판정 불가는 안전이 아닙니다.**",
        ))
    return rows


def _render_severity_criteria_md(report: ScanReport) -> list[str]:
    rows = _severity_criteria_rows(report)
    out = ["### 심각도 판정 기준", ""]
    out.append("| 구분 | 심각도 | 기준 |")
    out.append("|---|---|---|")
    for kind, sev, desc in rows:
        out.append(f"| {kind} | {sev} | {desc} |")
    out.append("")
    return out


def _render_severity_criteria_html(report: ScanReport) -> list[str]:
    rows = _severity_criteria_rows(report)
    out = ['<div class="subh">심각도 판정 기준</div>']
    out.append("<table><tr><th>구분</th><th>심각도</th><th>기준</th></tr>")
    for kind, sev, desc in rows:
        out.append(
            f"<tr><td>{_esc(kind)}</td><td>{_esc(sev)}</td>"
            f"<td>{_esc(desc).replace('**', '')}</td></tr>"
        )
    out.append("</table>")
    return out


def _env_grade_line(report: ScanReport) -> str | None:
    """판정에 적용된 실행환경 등급 한 줄. 의존성 검사를 안 했으면 None.

    등급은 쿨다운 기준일(3·7·14일)을 정해 **판정을 바꾼다** — 같은 패키지가
    E1 에서는 통과하고 E2 에서는 `cooldown_hold` 가 된다. 그런데 그 값이 보고서
    어디에도 없었다. 읽는 사람이 어느 기준으로 나온 판정인지 모르면 결과를
    검증할 수 없고, 결재 문서로서도 근거가 비어 있는 셈이다.

    ``--env`` 를 주지 않은 실행도 **적용된 기본 등급**을 그대로 적는다. '지정하지
    않음'과 '적용되지 않음'은 다르다 — 지정하지 않아도 기준일은 적용됐다.
    """
    audits = ((report.dependency_audit or {}).get("audits")) or []
    if not audits:
        return None
    from .vcps import env_grade_summary

    raw = next((a.get("env_grade") for a in audits if a.get("env_grade")), None)
    grade, label, days = env_grade_summary(raw)
    # **누가 정했는지**를 함께 적는다. 이 도구는 실행환경을 탐지하지 않는다 —
    # 부르는 쪽이 넘긴 값이거나 기본값이다. 실측 오해: 개인 PC 에서 돌린 검사가
    # 'E2(내부서버 공용)' 로 찍혀 "왜 내 PC 가 내부서버냐"가 됐다. 값만 있고
    # 출처가 없으면 읽는 사람은 도구가 환경을 판단한 것으로 읽는다.
    origin = (
        f"검사 실행 시 지정(`--env {grade}`)" if raw
        else "지정 없음 · 기본값 적용(이 도구는 실행환경을 자동 판별하지 않습니다)"
    )
    return (
        f"실행환경 등급: `{grade}` ({label}, 쿨다운 기준 {days}일) — {origin}. "
        "이 등급은 **신규 버전 쿨다운 기준일만** 정합니다(취약점·악성 판정에는 영향 없음). "
        "개인 PC 에서 만든 도구라면 `E1`(개인PC 반복도구, 7일)이 기본이며, "
        "`E0`(3일)·`E2`(14일)로 바꿔 재검사할 수 있습니다."
    )


def _registry_banner(audits: list[dict]) -> str | None:
    """기관 레지스트리 도달 실패 배너 — 매니페스트 전체에 **한 줄만**.

    '물어보지 못했다'가 '승인받았다'처럼 보이면 안 되지만, 그렇다고 패키지마다
    검토 깃발을 꽂으면 담당자가 그것을 무시하게 된다. 조치는 '레지스트리 복구'
    한 건이므로 알림도 한 건이다.
    """
    from .tools.registry_client import registry_banner

    # 사람이 붙어야 풀리는 것부터 — 인증(토큰) > 형식 거부(스키마 교정) >
    # 연결 실패(기다리면 풀릴 수 있음). 배너가 하나뿐이므로 순서가 곧 안내다.
    rank = {"unauthorized": 4, "rejected": 3, "unreachable": 2, "item_failed": 1}
    worst, worst_rank = "ok", 0
    for a in audits:
        s = str(a.get("registry_status") or "")
        if rank.get(s, 0) > worst_rank:
            worst, worst_rank = s, rank[s]
    return registry_banner(worst)


def _dep_banner_text(audits: list[dict]) -> str:
    checked, unchecked, vuln, blocked, not_found = _dep_stats(audits)
    if not_found:
        return (f"**의존성 검사 포함** — 저장소에 존재하지 않는 패키지 {not_found}건 발견"
                "(AI가 지어낸 이름 의심). 설치 전 반드시 이름을 확인하세요.")
    if blocked:
        return (f"**의존성 검사 포함** — 악성·고위험 패키지 발견(취약·악성 {vuln}건). "
                "아래 '의존성(패키지) 취약점 검사' 섹션을 확인하세요.")
    if vuln:
        return (f"⚠️ **의존성 검사 포함** — 알려진 취약점 있는 패키지 {vuln}건. "
                "아래 '의존성(패키지) 취약점 검사' 섹션을 확인하세요.")
    if unchecked:
        return (f"⚠️ **의존성 일부 판정 불가** — {unchecked}건은 검사되지 못했습니다"
                "(캐시 없는 오프라인·API 실패·파싱 불가). **판정 불가는 '안전'이 아닙니다.**")
    # 경계값 판정은 조치가 하나(락파일·설치본 검사)이므로 여기서 한 줄로만 알린다.
    # 패키지마다 같은 문장을 달면 20건짜리 매니페스트에서 같은 안내가 20번 나온다.
    bounded = sum(int(a.get("bounded_version_count") or 0) for a in audits)
    if bounded:
        return (f"**의존성 검사 포함** — 패키지 {checked}건, 알려진 취약점 없음. "
                f"다만 {bounded}건은 `>=`·`^` 같은 **범위 표기**라 실제 설치 버전이 "
                "아닐 수 있습니다 — 정확히 보려면 락파일을 쓰거나 `--include-installed` "
                "로 다시 검사하세요.")
    return f"**의존성 검사 포함** — 패키지 {checked}건, 알려진 취약점 없음(검사 시점 기준)."


def _pkg_verdict_label(check: dict) -> str:
    # 기관 레지스트리 판정은 이 도구의 관측이 아니라 **기관의 결정**이므로 먼저,
    # 그리고 출처가 드러나게 표시한다. 단 악성 탐지는 승인보다 위다(원칙 4).
    if check.get("verdict") == "registry_rejected":
        return "⛔ 기관 차단(레지스트리)"
    if check.get("verdict") == "not_found":
        return "❌ 저장소에 없음(가짜 이름 의심)"
    if check.get("is_malicious_package"):
        return "악성 의심"
    n = check.get("vulnerability_count") or 0
    if n:
        # 단위를 붙인다 — '취약·악성 3건'(패키지 수)과 섞여 읽히던 숫자다.
        # 실측 질문: "3건인데 26건은 뭔가, 뭐가 26건인지 알 수가 없다."
        return f"⚠ 개별 취약점 {n}건"
    if check.get("verdict") == "cooldown_hold":
        return "⏸ 발행 직후 — 대기 권고"
    if check.get("verdict") == "registry_approved":
        # checked=False 면 '승인은 받았으나 이번에 대조하지 못함' — 구분해 보여준다.
        return "✅ 기관 승인(레지스트리)" if check.get("checked") else "✅ 기관 승인 · 대조 못 함"
    if check.get("checked"):
        return "이상 없음(검사 시점)"
    return "판정 불가"


def _pkg_license_label(check: dict) -> str:
    """라이선스 표시 — 허용목록 대조 결과를 함께 보여준다(검토 필요는 표시)."""
    lic = (check.get("registry_metadata") or {}).get("license")
    if not lic:
        return "—"
    text = str(lic)[:24]
    if check.get("license_verdict") == "review_required":
        return f"⚠ {text}"
    return text


def _pkg_note(check: dict) -> str:
    bits: list[str] = []
    heur = check.get("heuristics") or {}
    if check.get("verdict") == "not_found":
        bits.append("AI가 지어낸 이름(슬롭스쿼팅) 가능성 — 공식 문서에서 이름 확인")
    if heur.get("typosquat_warning"):
        bits.append("타이포스쿼팅 의심")
    if check.get("in_kev") or check.get("kev_signals"):
        bits.append("CISA KEV 신호")
    cd = check.get("cooldown") or {}
    if cd.get("ok") is False:
        bits.append(f"발행 {cd.get('version_age_days')}일 경과(기준 {cd.get('cooldown_days')}일)")
    meta = check.get("registry_metadata") or {}
    if meta.get("install_scripts") == "present":
        bits.append("설치 스크립트 있음")
    if check.get("license_verdict") == "review_required":
        bits.append(f"라이선스 검토({meta.get('license')})")
    if not check.get("checked") and check.get("note") and check.get("verdict") != "not_found":
        bits.append("검사 불가 사유 있음")
    return " · ".join(bits)


#: 의존성 절 머리에 붙는 단위 설명. 두 숫자가 같은 화면에 있는데 세는 단위가 달라
#: 실제로 "3건인데 26건은 뭐냐"는 질문이 나왔다.
_DEP_UNIT_NOTE = (
    "> **숫자의 단위** — `취약·악성 N건` 은 **패키지 수**(조치 단위: 업그레이드할 대상)이고, "
    "표의 `개별 취약점 N건` 은 **그 패키지 하나에 붙은 보안 권고 수**입니다. "
    "패키지 하나를 올리면 그 패키지의 취약점이 한꺼번에 해소됩니다."
)

_ADVISORY_SEVERITY_KO = {
    "CRITICAL": "치명", "HIGH": "높음", "MEDIUM": "보통", "LOW": "낮음",
    "UNKNOWN": "미상", "NONE": "—",
}

#: 취약점 목록에서 한 화면에 펼칠 상한. 넘으면 접되 **접은 개수를 반드시 적는다**
#: (조용한 절단 금지 — 이 결함이 정확히 그렇게 생겼다).
_ADVISORY_SHOW_LIMIT = 12


_ADVISORY_ID_RE = re.compile(r"^[A-Z][A-Z0-9]{1,14}-[A-Za-z0-9][A-Za-z0-9.\-]{2,60}$")


def advisory_url(advisory_id: str) -> str | None:
    """권고 ID → **원문 주소**. 형태가 확실할 때만 만든다.

    OSV 는 GHSA·CVE·PYSEC·GO·RUSTSEC 을 한 주소 체계로 서비스하므로 규칙 하나면
    전 생태계가 덮인다. 우리가 판정 근거를 OSV 에서 가져왔으니 근거를 확인할
    자리도 거기가 맞다.

    **왜 필요한가(실측 2026-08-08)**: 보고서가 ``GHSA-4r6h-8v6p-xvw6`` 이라는
    문자열만 찍었다. 담당자는 그걸 직접 검색해야 했고, 결재 문서에 **검증할 수 없는
    근거**가 올라갔다. ID 는 아는데 주소를 안 주는 건 근거를 반만 준 것이다.
    """
    aid = str(advisory_id or "").strip()
    if not _ADVISORY_ID_RE.match(aid):
        return None      # 형태가 이상하면 링크를 만들지 않는다 — 죽은 주소는 근거가 아니다
    return f"https://osv.dev/vulnerability/{aid}"


def _advisory_lines(check: dict) -> list[tuple[str, str | None]]:
    """패키지 1건의 개별 취약점 — ``(설명, 원문 주소)``.

    **왜 필요한가(실측 질문)**: "취약·악성 3건인데 26건·8건·2건은 뭔가?" 3은 패키지
    수(조치 단위)이고 26은 그 패키지에 붙은 개별 취약점 수인데, 보고서가 숫자만
    적고 **내역을 한 줄도 보여주지 않아** 무엇이 26건인지 알 방법이 없었다.

    주소를 문자열에 이어 붙이지 않고 따로 돌려주는 이유: HTML 은 ``_esc`` 를 거치므로
    본문에 박아 넣으면 **클릭할 수 없는 글자**가 된다. 렌더러가 각자 링크를 만든다.
    """
    advisories = check.get("advisories") or []
    if not advisories:
        return []
    out: list[tuple[str, str | None]] = []
    for a in advisories[:_ADVISORY_SHOW_LIMIT]:
        sev = _ADVISORY_SEVERITY_KO.get(str(a.get("severity") or "").upper(), "미상")
        fixed = a.get("fixed_versions") or []
        fixed_txt = f" · 해결 {', '.join(fixed[:3])}" if fixed else " · 해결 버전 미상"
        summary = _oneline(str(a.get("summary") or ""), 110)
        aid = a.get("id") or "(ID 미상)"
        out.append((f"{aid} [{sev}]{fixed_txt} — {summary}", advisory_url(aid)))
    hidden = len(advisories) - len(out)
    if hidden > 0:
        out.append((f"… 외 {hidden}건 (전체 목록은 결과 JSON 의 advisories 참조)", None))
    # 수집한 목록이 집계 수치보다 적으면 그 사실을 적는다 — 숫자만 크고 내역이
    # 없으면 읽는 사람은 나머지를 확인할 방법이 없다.
    total = int(check.get("vulnerability_count") or 0)
    if total and total > len(advisories):
        out.append((
            f"※ 집계 {total}건 중 {len(advisories)}건만 내역이 수집됐습니다 "
            "— 나머지는 재검사(온라인)로 채워집니다.", None))
    # 권고 버전이 없을 때가 가장 막막하다 — "고칠 방법이 없다"로 읽히기 때문이다.
    # 레지스트리 밖에 수정본이 있는 경우(xlsx → cdn.sheetjs.com)가 실제로 있으므로
    # 제작사 권고 주소를 함께 준다.
    if not check.get("recommended_version"):
        seen: list[str] = []
        for a in advisories:
            for url in a.get("references") or []:
                if url not in seen:
                    seen.append(url)
        if seen:
            out.append((
                "※ 레지스트리에 올릴 수 있는 수정 버전이 없습니다 — "
                "제작사 권고에서 조치 방법을 확인하세요", seen[0]))
            # 첫 주소가 NVD 로 잡히는 일이 흔한데, 실제 조치 안내는 제작사 쪽에
            # 있는 경우가 많다(xlsx → cdn.sheetjs.com). 두 번째까지 보여준다.
            for url in seen[1:2]:
                out.append(("※ 참고", url))
    return out


def _pkg_upgrade_hint(check: dict) -> str:
    """'어느 버전으로 올려야 하는가' 한 줄. 모르면 모른다고 말한다."""
    rec = check.get("recommended_version")
    latest = (check.get("registry_metadata") or {}).get("latest_version")
    if rec:
        tail = f" (검사 시점 최신 {latest})" if latest and latest != rec else ""
        return f"**{rec} 이상**으로 올리면 위 취약점이 해소됩니다{tail}."
    if latest:
        return (
            f"고쳐진 버전을 확인하지 못한 취약점이 있어 목표 버전을 특정하지 못했습니다 "
            f"— 검사 시점 최신 버전은 **{latest}** 입니다(올린 뒤 재검사로 확인하세요)."
        )
    return "고쳐진 버전 정보를 확인하지 못했습니다 — 공식 배포처의 보안 권고를 확인하세요."


def _render_dependency_audit_md(report: ScanReport) -> list[str]:
    audits = _dep_audits(report)
    if not audits:
        return []
    checked, unchecked, vuln, blocked, not_found = _dep_stats(audits)
    out: list[str] = ["## 의존성(패키지) 취약점 검사", ""]
    out.append(f"> 검사 {checked}건 · 판정 불가 {unchecked}건 · 취약·악성 {vuln}건"
               + (f" · **미존재(가짜 이름 의심) {not_found}건**" if not_found else "")
               + (" · **차단 권고**" if blocked else ""))
    out.append("")
    out.append(_DEP_UNIT_NOTE)
    out.append("")

    # 검사한 곳 목록 — 어디를 봤는지는 남기되, 표는 컴포넌트 단위로 한 번만 낸다.
    out.append("### 검사한 곳")
    out.append("")
    for a in audits:
        title = a.get("manifest") or a.get("ecosystem", "manifest")
        out.append(f"- `{title}` ({a.get('ecosystem', '?')}) — 판정: {a.get('verdict', '?')}")
        if a.get("verdict") == "unparsed":
            out.append(f"  - ⚠ {a.get('note', '파싱하지 못했습니다.')} **파싱 0건은 '안전'이 아닙니다.**")
    out.append("")

    components = _dep_merged_components(audits)
    if components:
        # 조치할 것부터 위로 — 악성·미존재 > 취약 > 판정 불가 > 이상 없음.
        components.sort(
            key=lambda comp: (
                -_dep_check_rank(comp["check"]),
                0 if not comp["check"].get("checked") else 1,
                str(comp["check"].get("name") or "").lower(),
            )
        )
        out.append(f"### 컴포넌트 (고유 {len(components)}종)")
        out.append("")
        out.append("> 같은 패키지가 매니페스트·설치본·번들에 함께 있어도 **한 줄로 셉니다**. "
                   "조치(업그레이드)는 패키지 단위이며, **출처에 적힌 모든 사본에 함께** 적용하세요.")
        out.append("")
        out.append("| 패키지 | 버전 | 라이선스 | 판정 | 출처 | 비고 |")
        out.append("|---|---|---|---|---|---|")
        for comp in components:
            c = comp["check"]
            out.append(
                f"| `{c.get('name', '?')}` | {c.get('version') or '—'} | "
                f"{_pkg_license_label(c)} | {_pkg_verdict_label(c)} | "
                f"{' · '.join(comp['sources'])} | {_pkg_note(c)} |"
            )
        out.append("")

        # 취약점이 있는 패키지는 **무엇이 몇 건인지** 내역을 펼친다.
        for comp in components:
            c = comp["check"]
            lines = _advisory_lines(c)
            if not lines:
                continue
            out.append(
                f"#### `{c.get('name', '?')} {c.get('version') or ''}`".rstrip()
                + f" — 개별 취약점 {c.get('vulnerability_count') or len(lines)}건"
            )
            out.append("")
            for ln, url in lines:
                out.append(f"- {ln}" + (f"\n  - 원문: {url}" if url else ""))
            out.append("")
            out.append(f"→ {_pkg_upgrade_hint(c)}")
            out.append("")
    if unchecked:
        out.append("> ⚠ **판정 불가는 '안전'이 아닙니다** — 온라인 환경 또는 최신 인텔 캐시"
                   "(`gvskb update-intel`)로 다시 검사하세요.")
        out.append("")
    return out


def _render_dependency_audit_html(report: ScanReport) -> list[str]:
    audits = _dep_audits(report)
    if not audits:
        return []
    checked, unchecked, vuln, blocked, not_found = _dep_stats(audits)
    nf = f" · 미존재 {not_found}" if not_found else ""
    out: list[str] = [
        '<details class="sec"><summary>의존성(패키지) 취약점 검사 — '
        f"검사 {checked} · 판정불가 {unchecked} · 취약·악성 {vuln}{nf}</summary>"
        '<div class="secbody">',
        f'<div class="depwarn">{_esc(_DEP_UNIT_NOTE.lstrip("> ")).replace("**", "")}</div>',
    ]
    for a in audits:
        title = a.get("manifest") or a.get("ecosystem", "manifest")
        out.append(f'<div class="subh">{_esc(str(title))} ({_esc(str(a.get("ecosystem", "?")))}) '
                   f"— 판정: {_esc(str(a.get('verdict', '?')))}</div>")
        if a.get("verdict") == "unparsed":
            out.append(f'<div class="depwarn">⚠ {_esc(str(a.get("note", "파싱하지 못했습니다.")))} '
                       "<b>파싱 0건은 '안전'이 아닙니다.</b></div>")

    components = _dep_merged_components(audits)
    if components:
        components.sort(
            key=lambda comp: (
                -_dep_check_rank(comp["check"]),
                0 if not comp["check"].get("checked") else 1,
                str(comp["check"].get("name") or "").lower(),
            )
        )
        out.append(f'<div class="subh">컴포넌트 (고유 {len(components)}종)</div>')
        out.append('<div class="depwarn">같은 패키지가 매니페스트·설치본·번들에 함께 있어도 '
                   '<b>한 줄로 셉니다</b>. 조치는 패키지 단위이며 <b>출처의 모든 사본에 함께</b> '
                   "적용하세요.</div>")
        out.append("<table><tr><th>패키지</th><th>버전</th><th>라이선스</th>"
                   "<th>판정</th><th>출처</th><th>비고</th></tr>")
        for comp in components:
            c = comp["check"]
            bad = c.get("is_malicious_package") or c.get("vulnerability_count")
            cls = ' class="w"' if bad else ""
            out.append(
                f"<tr{cls}><td>{_esc(str(c.get('name', '?')))}</td>"
                f"<td>{_esc(str(c.get('version') or '—'))}</td>"
                f"<td>{_esc(_pkg_license_label(c))}</td>"
                f"<td>{_esc(_pkg_verdict_label(c))}</td>"
                f"<td>{_esc(' · '.join(comp['sources']))}</td>"
                f"<td>{_esc(_pkg_note(c))}</td></tr>"
            )
        out.append("</table>")

        # 취약점 내역 — 패키지마다 접기. 숫자만 있고 내역이 없으면 확인할 방법이 없다.
        for comp in components:
            c = comp["check"]
            lines = _advisory_lines(c)
            if not lines:
                continue
            title = f"{c.get('name', '?')} {c.get('version') or ''}".strip()
            out.append(
                '<details class="sec"><summary>'
                f"{_esc(title)} — 개별 취약점 "
                f"{c.get('vulnerability_count') or len(lines)}건</summary>"
                '<div class="secbody"><ul>'
            )
            for ln, url in lines:
                link = (f' <a href="{_esc(url)}" target="_blank" rel="noopener noreferrer">'
                        "원문 확인 ↗</a>") if url else ""
                out.append(f"<li>{_esc(ln)}{link}</li>")
            out.append("</ul>")
            out.append(
                f'<div class="depwarn">→ {_esc(_pkg_upgrade_hint(c)).replace("**", "")}</div>'
            )
            out.append("</div></details>")
    if unchecked:
        out.append('<div class="depwarn">⚠ <b>판정 불가는 \'안전\'이 아닙니다</b> — 온라인 환경 '
                   '또는 최신 인텔 캐시(<code class="ev">gvskb update-intel</code>)로 다시 검사하세요.</div>')
    out.append("</div></details>")
    return out


def _render_external_surface_md(report: ScanReport) -> list[str]:
    """외부 연결 인벤토리 섹션(Markdown). MD는 접기가 없으므로 표로 펼쳐 출력."""
    api = [c for c in report.external_surface if c.kind == "api"]
    pkg = [c for c in report.external_surface if c.kind == "package"]
    res = [c for c in report.external_surface if c.kind == "resource"]
    n_api, n_pkg, gukoe, warn = _external_stats(report)
    egress = sum(1 for c in report.external_surface if c.airgap_impact == "egress")
    out: list[str] = ["## 외부 연결 인벤토리 (보안팀 검토용)", ""]
    res_bit = f" · 외부 리소스 {len(res)}" if res else ""
    out.append(
        f"> ⚠ **사용 금지가 아닙니다.** 외부로 데이터를 보낼 수 있는 지점 목록입니다 "
        f"(API {n_api} · 플러그인 {n_pkg}{res_bit} · 국외 {gukoe} · ⚠개인정보 {warn}). "
        "⚠ 개인정보 인접·국외 전송을 먼저 확인하세요."
    )
    out.append("")
    airgap = _airgap_note(res, egress)
    if airgap:
        out.append(f"> {airgap}")
        out.append("")
    circ = iter("①②③④")
    if api:
        out.append(f"### {next(circ)} 외부 API 호출 (검토 필요 먼저)")
        out.append("")
        # 모델 컬럼은 이용 정보에 통합했다(AI 호출에만 값이 있어 대부분 빈 칸이었음).
        out.append("| 대상(호스트) | 종류 | 위치 | 이용 정보 | 국외이전(운영주체) | 검토 |")
        out.append("|---|---|---|---|---|---|")
        for c in api:
            mark = "⚠ 검토" if c.review_level == "warn" else "참고"
            loc = c.location if c.call_count <= 1 else f"{c.location} 외 {c.call_count - 1}곳"
            oper = f"{c.region or '확인'} — {c.operator}" if c.operator else f"{c.region or '확인'} — 미상(직접 확인)"
            info = c.data_summary + (f" · 모델 {c.model}" if c.model else "")
            if c.context == "doc-or-installer":
                mark = "문서·설치"
                oper = "—"          # 운영 중 전송이 아니므로 국외이전 판단 불필요
            out.append(
                f"| `{c.target}` | {_cat_ko(c.category)} | "
                f"`{loc}` | {info} | {oper} | {mark} |"
            )
        out.append("")
    if res:
        out.append(f"### {next(circ)} 외부 리소스 로딩 (CDN 등) — 폐쇄망에서 동작 불가")
        out.append("")
        out.append("| 대상(호스트) | 위치 | 내용 | 운영주체 | 폐쇄망 영향 |")
        out.append("|---|---|---|---|---|")
        for c in res:
            loc = c.location if c.call_count <= 1 else f"{c.location} 외 {c.call_count - 1}곳"
            out.append(
                f"| `{c.target}` | `{loc}` | {c.data_summary} | "
                f"{c.operator or '미상(직접 확인)'} | 로딩 실패 — 화면·기능 파손 |"
            )
        out.append("")
    if pkg:
        out.append(f"### {next(circ)} 설치된 외부 플러그인 · 라이브러리")
        out.append("")
        out.append("| 플러그인/라이브러리 | 버전 | 종류 | 전송 대상(운영주체) | 이용 정보 |")
        out.append("|---|---|---|---|---|")
        for c in pkg:
            out.append(
                f"| `{c.target}` | {c.version or '—'} | {_cat_ko(c.category)} | "
                f"{c.operator or '—'} | {c.data_summary} |"
            )
        out.append("")
    out.append(
        "> **검토 체크리스트** — ⚠ 지점마다: ① 무슨 데이터? ② 개인정보 포함? "
        "③ 국외이전 동의·망분리·기관 AI정책 부합? "
        "④ AI API 입력 데이터의 **학습 이용·보존 여부**는 서비스 약관·기관 계약(옵트아웃 설정)으로 확인"
    )
    out.append(
        "> ※ 최소 목록 — 변수로 조립된 호스트는 누락될 수 있고, '이용 정보·국외'는 "
        "검토 신호이며 페이로드 확정이 아닙니다."
    )
    out.append("")
    return out


def _render_finding_group_md(group: dict) -> list[str]:
    """파일 안에서 같은 룰을 한 항목으로 묶어 출력(설명 1번 + 위치목록 + 외 N건)."""
    f: Finding = group["sample"]
    findings: list[Finding] = group["findings"]
    tag = _SEVERITY_EMOJI[group["severity"]]
    out: list[str] = []
    out.append(
        f"#### {tag} {_SEVERITY_LABEL_KO[group['severity']]} · {group['decision'].value} — "
        f"{f.plain_title} ({group['count']}건)"
    )
    out.append("")
    out.append(f"- **위치**: {_locations_by_file(findings, limit_files=_LOC_FILE_LIMIT)}")
    out.append(f"- **룰**: `{f.rule_id}`")
    out.append(f"- **카테고리**: {f.category}")
    out.append(f"- **판정 근거**: {_confidence_label(f.confidence)}")
    # 등급을 낮췄으면 그 사실과 이유를 반드시 함께 보여준다 — 조용히 낮추면
    # 검토자가 "왜 low 인지" 판단할 근거를 잃는다.
    if f.severity_adjusted:
        out.append(f"- **심각도 조정**: {f.severity_adjusted}")
    if f.evidence:
        out.append(f"- **증거(자동 마스킹됨)**: `{_oneline(f.evidence)}`")
    if f.why_it_matters:
        out.append(f"- **왜 위험한가**: {f.why_it_matters.strip()}")
    if f.public_sector_impact:
        out.append(f"- **공공 업무 영향**: {', '.join(f.public_sector_impact)}")
    if f.safe_fix:
        out.append("- **안전한 수정 방향**:")
        out.append("")
        out.append("  ```")
        for ln in f.safe_fix.strip().splitlines():
            out.append(f"  {ln}")
        out.append("  ```")
    if f.can_auto_fix:
        out.append("- **자동 수정 가능**: 예 (diff 미리보기 후 적용)")
    if f.requires_approval_to_bypass:
        out.append("- **우회 시 승인 필요**: 보안담당자 승인 + 감사 로그 기록")
    if f.references:
        refs = ", ".join(f.references[:5])
        out.append(f"- **출처**: {refs}")
    return out


def _oneline(text: str, limit: int = 160) -> str:
    s = " ".join(text.split())
    return s if len(s) <= limit else s[: limit - 1] + "…"


# ---------------------------------------------------------------------------
# SARIF 2.1.0 — CI·보안도구 연동용 표준 출력 (GitHub code scanning 업로드 가능)
# ---------------------------------------------------------------------------

_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def _sarif_level(f: Finding) -> str:
    """SARIF level 매핑 — 차단(block)과 치명·높음은 error로."""
    if f.decision == Decision.block:
        return "error"
    if f.severity in (Severity.critical, Severity.high):
        return "error"
    if f.severity == Severity.medium:
        return "warning"
    return "note"


def render_sarif(report: ScanReport) -> dict:
    """ScanReport → SARIF 2.1.0 dict.

    CI 파이프라인(GitHub code scanning `upload-sarif`)이나 기관 보안도구가
    표준 형식으로 결과를 수집할 수 있게 한다. 사람용 md/html과 동일한
    ScanReport 하나에서 렌더되므로 내용이 갈라지지 않는다.
    """
    rule_index: dict[str, int] = {}
    rules: list[dict] = []
    results: list[dict] = []
    for f in report.findings:
        if f.rule_id not in rule_index:
            rule_index[f.rule_id] = len(rules)
            rules.append({
                "id": f.rule_id,
                "name": f.title or f.rule_id,
                "shortDescription": {"text": f.plain_title or f.title or f.rule_id},
                "fullDescription": {"text": (f.why_it_matters or "")[:1000]},
                "helpUri": "https://github.com/Lex6won/vibecode-checker",
                "defaultConfiguration": {"level": _sarif_level(f)},
                "properties": {
                    "severity": f.severity.value,
                    "decision": f.decision.value,
                    "category": f.category,
                    "references": f.references[:5],
                },
            })
        message = f.plain_title or f.title
        if f.safe_fix:
            message += f" — 수정 방향: {f.safe_fix.strip().splitlines()[0][:200]}"
        entry = {
            "ruleId": f.rule_id,
            "ruleIndex": rule_index[f.rule_id],
            "level": _sarif_level(f),
            "message": {"text": message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.location.file.replace("\\", "/")},
                    "region": {"startLine": max(1, f.location.line)},
                },
            }],
            "partialFingerprints": {"gvskbFindingId": f.id},
        }
        if f.suppressed:
            # SARIF 표준 억제 표기 — 도구들이 자동으로 '해결됨 아님, 면제됨'으로 처리
            entry["suppressions"] = [{
                "kind": "external",
                "justification": (f.suppress_reason or "")[:500],
            }]
        results.append(entry)
    return {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "vibecode-checker",
                "informationUri": "https://github.com/Lex6won/vibecode-checker",
                "rules": rules,
            }},
            "results": results,
            "properties": {
                "target": report.target,
                "profile": report.profile,
                "scan_mode": report.scan_mode or "online",
                "scanned_files": len(report.scanned_files),
                "disclaimer": report.disclaimer,
            },
        }],
    }
