"""사람이 읽는 한국어 리포트 생성.

공무원이 검사 결과를 그대로 상위 결재·보고용으로 사용할 수 있도록
Markdown 한 장 분량의 결론·요약·증거·수정 가이드·재현 절차·면책을 묶어서 출력합니다.

핵심 시나리오는 "MCP로 코딩 → 완성 소스 재검증 → 리포트"이므로, 리포트는
*수정 후 다시 검증하는 방법*까지 명시합니다.
"""
from __future__ import annotations

import html
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

    The output is designed to be readable on its own — anyone can paste it into
    a Word document or print it without needing to query the MCP further.
    """
    ts = (generated_at or datetime.now()).strftime("%Y-%m-%d %H:%M")
    lines: list[str] = []

    lines.append("# 코드 보안 검사 결과")
    lines.append("")

    # --- 결론 (한 줄) -----------------------------------------------------
    lines.append("## 결론")
    lines.append("")
    lines.append(f"> {_verdict_line(report)}")
    lines.append("")

    # 의존성 매니페스트는 코드 스캔이 아니라 SCA로 검사해야 한다 — 코드 스캔
    # 결과만 보고 "의존성도 안전"으로 오해하지 않도록 결론 바로 아래에 강조한다.
    manifest_skips = [
        s for s in report.skipped_files if "의존성 매니페스트" in (s.reason or "")
    ]
    if manifest_skips:
        names = ", ".join(s.path.replace("\\", "/").rsplit("/", 1)[-1] for s in manifest_skips)
        lines.append(
            f"> ⚠️ **의존성 검사 별도 필요** — {names} 은(는) 코드 스캔 대상이 아닙니다. "
            f"취약·악성 패키지는 `gvskb check-package` 또는 MCP `scan_dependencies`로 따로 검사하세요."
        )
        lines.append("")

    lines.append(f"- **대상**: `{report.target}`")
    lines.append(f"- **검사일시**: {ts}")
    lines.append(f"- **프로파일**: {report.profile}")
    if report.scenario:
        lines.append(f"- **시나리오**: {report.scenario}")
    if report.language:
        lines.append(f"- **언어 힌트**: {report.language}")
    lines.append("")

    # --- 요약 -------------------------------------------------------------
    lines.append("## 요약")
    lines.append("")
    summary = report.summary
    lines.append(f"- 검사한 파일 수: **{len(report.scanned_files)}건**")
    if report.skipped_files:
        lines.append(f"- 생략된 파일 수: {len(report.skipped_files)}건 (이유: 크기·바이너리·인코딩 등)")
    lines.append(f"- 발견된 위험: **{summary.finding_count}건**")
    if summary.highest_severity:
        lines.append(
            f"- 최고 심각도: **{_SEVERITY_LABEL_KO[summary.highest_severity]} "
            f"({summary.highest_severity.value})**"
        )
    lines.append(f"- 차단 항목: **{'있음' if summary.blocked else '없음'}**")
    lines.append("")

    if any(summary.by_severity.values()):
        lines.append("| 심각도 | 건수 |")
        lines.append("|---|---|")
        for sev in (Severity.critical, Severity.high, Severity.medium, Severity.low):
            count = summary.by_severity.get(sev.value, 0)
            if count:
                lines.append(f"| {_SEVERITY_LABEL_KO[sev]} ({sev.value}) | {count} |")
        lines.append("")

    if any(summary.by_decision.values()):
        lines.append("| 결정 | 건수 |")
        lines.append("|---|---|")
        for dec, count in summary.by_decision.items():
            if count:
                lines.append(f"| {dec} | {count} |")
        lines.append("")

    # --- 가이드라인별 분포 (출처 집계) -------------------------------------
    if report.findings:
        dist = _guideline_distribution(report.findings)
        if dist:
            lines.append("## 가이드라인별 분포")
            lines.append("")
            lines.append("> 한 발견 사항이 여러 가이드라인을 인용한 경우 각 그룹에서 1회씩 집계합니다.")
            lines.append("")
            lines.append("| 가이드라인 | 인용 건수 |")
            lines.append("|---|---|")
            for label, count in dist.most_common():
                lines.append(f"| {label} | {count} |")
            lines.append("")

    # --- 처리 순서 + 파일별 발견 -----------------------------------------
    if summary.finding_count == 0:
        lines.append("> 발견된 위험이 없습니다. 그러나 본 도구는 보조 가드레일이며, ")
        lines.append("> 공식 보안성 검토를 대체하지 않습니다.")
        lines.append("")
    else:
        lines.append("## 권장 처리 순서")
        lines.append("")
        lines.append("1. **차단(block)** 항목 — 커밋·배포 전에 반드시 수정 또는 보안담당자 승인 필요")
        lines.append("2. **경고(warn) + 치명/높음** — 운영 반영 전 우선 수정")
        lines.append("3. **자동 수정 가능** 항목 — diff 미리보기 후 적용")
        lines.append("4. **나머지 warn** — 차주 정비 일정에 반영")
        lines.append("")

        by_file: dict[str, list[Finding]] = defaultdict(list)
        for f in report.findings:
            by_file[f.location.file].append(f)

        ordered_files = sorted(
            by_file.keys(),
            key=lambda fn: (
                -max(_SEVERITY_RANK[f.severity] for f in by_file[fn]),
                -len(by_file[fn]),
                fn,
            ),
        )

        lines.append("## 파일별 발견 사항")
        lines.append("")
        for fname in ordered_files:
            file_findings = sorted(
                by_file[fname],
                key=lambda f: (-_SEVERITY_RANK[f.severity], f.location.line),
            )
            lines.append(f"### `{fname}` — {len(file_findings)}건")
            lines.append("")
            for f in file_findings:
                lines.extend(_render_finding(f))
                lines.append("")

    if report.skipped_files:
        lines.append("## 생략된 파일")
        lines.append("")
        for sf in report.skipped_files[:30]:
            lines.append(f"- `{sf.path}` — {sf.reason}")
        if len(report.skipped_files) > 30:
            lines.append(f"- … 외 {len(report.skipped_files) - 30}건")
        lines.append("")

    # --- 재현 절차 -------------------------------------------------------
    lines.append("## 재현 절차")
    lines.append("")
    repro = reproduce_command or f"gvskb scan {report.target} --profile {report.profile}"
    lines.append("같은 결과를 다시 만들거나 다른 환경에서 검증하려면 다음과 같이 실행합니다.")
    lines.append("")
    lines.append("```bash")
    lines.append(repro)
    lines.append("```")
    lines.append("")
    lines.append(f"- 프로파일: `{report.profile}`")
    if report.scenario:
        lines.append(f"- 시나리오: `{report.scenario}`")
    if report.language:
        lines.append(f"- 언어 힌트: `{report.language}`")
    lines.append("- 룰셋은 `gvskb rules` 또는 `gvskb doctor` 로 현재 로드된 목록·버전을 확인할 수 있습니다.")
    lines.append("")

    # --- 수정 후 다시 검증 ----------------------------------------------
    lines.append("## 수정 후 다시 검증")
    lines.append("")
    lines.append("발견 사항을 수정한 뒤에는 같은 검사를 한 번 더 돌려 회귀를 막으세요.")
    lines.append("")
    lines.append("- **CLI**: 위의 재현 명령(`gvskb scan ...`)을 다시 실행합니다.")
    lines.append(
        "- **MCP (IDE)**: 수정한 코드 블록을 `scan_code` 도구에 다시 넘기거나, 파일 단위라면 "
        "`scan_path` 를 호출합니다."
    )
    lines.append(
        "- **수정 시 LLM 안내**: 위 권장 처리 순서(차단 → 치명·높음 → 자동수정 → 나머지) 를 "
        "그대로 LLM 프롬프트의 지시문으로 사용하면 우선순위가 어긋나지 않습니다."
    )
    lines.append("")

    # --- 면책 ------------------------------------------------------------
    lines.append("## 면책")
    lines.append("")
    lines.append("> " + report.disclaimer.replace("\n", " "))
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("*생성: vibecode-checker · 공공 바이브코딩 보안 가드레일*")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTML 리포트 — MD와 동일한 ScanReport 데이터에서 직접 렌더링하는 "카드 강조형".
# 자체 포함 단일 파일(외부 CDN·폰트·JS 없음)이라 망분리·이메일·인쇄(→PDF)에
# 그대로 쓸 수 있다. 동적 텍스트는 전부 html.escape 로 이스케이프한다.
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
.sub{color:#6b7280;font-size:13px;margin-bottom:18px}
.banner{padding:16px 20px;border-radius:8px;font-weight:700;font-size:16px;
  color:#fff;margin:8px 0 16px}
.meta{font-size:14px;color:#374151;margin:0 0 8px}
.meta b{color:#111827}
.depwarn{background:#fff8e1;border:1px solid #f0d27a;border-radius:6px;
  padding:10px 14px;font-size:13.5px;color:#7a5b00;margin:10px 0}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin:10px 0 4px}
.chip{padding:5px 12px;border-radius:999px;font-size:13px;font-weight:600;color:#fff}
.kv{font-size:14px;margin:2px 0}
table{border-collapse:collapse;width:100%;font-size:13.5px;margin:8px 0}
th,td{border:1px solid #e5e7eb;padding:6px 10px;text-align:left}
th{background:#f3f4f6}
ol.steps{margin:6px 0 0;padding-left:22px}
ol.steps li{margin:3px 0}
.filehdr{font-size:15px;font-weight:700;margin:22px 0 10px;color:#111827}
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
@media print{
  body{background:#fff}
  .page{box-shadow:none;margin:0;max-width:none;border-radius:0;padding:0 6mm}
  .card{break-inside:avoid}
  pre{white-space:pre-wrap}
}
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
    inline (no external CDN/font/JS), so it opens in air-gapped environments,
    attaches to email, and prints to PDF for an approval record.
    """
    ts = (generated_at or datetime.now()).strftime("%Y-%m-%d %H:%M")
    summary = report.summary
    p: list[str] = []
    p.append("<!DOCTYPE html>")
    p.append('<html lang="ko"><head><meta charset="utf-8">')
    p.append('<meta name="viewport" content="width=device-width, initial-scale=1">')
    p.append("<title>코드 보안 검사 결과</title>")
    p.append(f"<style>{_HTML_CSS}</style></head><body>")
    p.append('<div class="page">')

    p.append("<h1>🛡️ 코드 보안 검사 결과</h1>")
    p.append('<div class="sub">vibecode-checker · 공공 바이브 코딩 보안 가드레일</div>')

    p.append(
        f'<div class="banner" style="background:{_verdict_css_color(report)}">'
        f"{_esc(_verdict_line(report))}</div>"
    )

    manifest_skips = [s for s in report.skipped_files if "의존성 매니페스트" in (s.reason or "")]
    if manifest_skips:
        names = ", ".join(s.path.replace("\\", "/").rsplit("/", 1)[-1] for s in manifest_skips)
        p.append(
            '<div class="depwarn">⚠️ <b>의존성 검사 별도 필요</b> — '
            f"{_esc(names)} 은(는) 코드 스캔 대상이 아닙니다. 취약·악성 패키지는 "
            '<code class="ev">gvskb check-package</code> 또는 MCP '
            '<code class="ev">scan_dependencies</code>로 따로 검사하세요.</div>'
        )

    p.append(f'<div class="meta"><b>대상</b> · {_esc(report.target)}</div>')
    p.append(
        f'<div class="meta"><b>검사일시</b> · {ts} &nbsp;·&nbsp; '
        f'<b>프로파일</b> · {_esc(report.profile)}</div>'
    )
    if report.scenario or report.language:
        extra = []
        if report.scenario:
            extra.append(f"시나리오 {_esc(report.scenario)}")
        if report.language:
            extra.append(f"언어 힌트 {_esc(report.language)}")
        p.append(f'<div class="meta">{" · ".join(extra)}</div>')

    p.append("<h2>요약</h2>")
    chips = []
    for sev in (Severity.critical, Severity.high, Severity.medium, Severity.low):
        c = summary.by_severity.get(sev.value, 0)
        if c:
            chips.append(
                f'<span class="chip" style="background:{_SEVERITY_COLOR[sev]}">'
                f"{_SEVERITY_LABEL_KO[sev]} {c}</span>"
            )
    if chips:
        p.append(f'<div class="chips">{"".join(chips)}</div>')
    p.append(f'<div class="kv">검사한 파일 수: <b>{len(report.scanned_files)}건</b></div>')
    if report.skipped_files:
        p.append(
            f'<div class="kv">생략된 파일 수: {len(report.skipped_files)}건 '
            "(크기·바이너리·인코딩 등)</div>"
        )
    p.append(f'<div class="kv">발견된 위험: <b>{summary.finding_count}건</b></div>')
    if summary.highest_severity:
        p.append(
            f'<div class="kv">최고 심각도: <b>{_SEVERITY_LABEL_KO[summary.highest_severity]} '
            f"({summary.highest_severity.value})</b></div>"
        )
    p.append(f'<div class="kv">차단 항목: <b>{"있음" if summary.blocked else "없음"}</b></div>')

    if report.findings:
        dist = _guideline_distribution(report.findings)
        if dist:
            p.append("<h2>가이드라인별 분포</h2>")
            p.append("<table><tr><th>가이드라인</th><th>인용 건수</th></tr>")
            for label, count in dist.most_common():
                p.append(f"<tr><td>{_esc(label)}</td><td>{count}</td></tr>")
            p.append("</table>")

    if summary.finding_count == 0:
        p.append(
            '<div class="disc">발견된 위험이 없습니다. 다만 본 도구는 보조 가드레일이며 '
            "공식 보안성 검토를 대체하지 않습니다.</div>"
        )
    else:
        p.append("<h2>권장 처리 순서</h2>")
        p.append('<ol class="steps">')
        p.append("<li><b>차단(block)</b> 항목 — 커밋·배포 전 반드시 수정 또는 보안담당자 승인</li>")
        p.append("<li><b>경고(warn) + 치명/높음</b> — 운영 반영 전 우선 수정</li>")
        p.append("<li><b>자동 수정 가능</b> 항목 — diff 미리보기 후 적용</li>")
        p.append("<li><b>나머지 warn</b> — 차주 정비 일정 반영</li>")
        p.append("</ol>")

        by_file: dict[str, list[Finding]] = defaultdict(list)
        for f in report.findings:
            by_file[f.location.file].append(f)
        ordered_files = sorted(
            by_file.keys(),
            key=lambda fn: (-max(_SEVERITY_RANK[f.severity] for f in by_file[fn]), -len(by_file[fn]), fn),
        )
        p.append("<h2>파일별 발견 사항</h2>")
        for fname in ordered_files:
            file_findings = sorted(
                by_file[fname], key=lambda f: (-_SEVERITY_RANK[f.severity], f.location.line)
            )
            p.append(f'<div class="filehdr">📄 {_esc(fname)} — {len(file_findings)}건</div>')
            for f in file_findings:
                p.extend(_render_finding_html(f))

    if report.skipped_files:
        p.append("<h2>생략된 파일</h2><table><tr><th>경로</th><th>이유</th></tr>")
        for sf in report.skipped_files[:30]:
            p.append(f"<tr><td>{_esc(sf.path)}</td><td>{_esc(sf.reason)}</td></tr>")
        p.append("</table>")
        if len(report.skipped_files) > 30:
            p.append(f'<div class="kv">… 외 {len(report.skipped_files) - 30}건</div>')

    repro = reproduce_command or f"gvskb scan {report.target} --profile {report.profile}"
    p.append("<h2>재현 절차</h2>")
    p.append('<div class="kv">같은 결과를 다시 만들거나 다른 환경에서 검증하려면 다음을 실행합니다.</div>')
    p.append(f"<pre>{_esc(repro)}</pre>")

    p.append("<h2>수정 후 다시 검증</h2>")
    p.append('<ol class="steps">')
    p.append('<li><b>CLI</b>: 위 재현 명령(<code class="ev">gvskb scan ...</code>)을 다시 실행</li>')
    p.append(
        '<li><b>MCP(IDE)</b>: 수정한 코드를 <code class="ev">scan_code</code>에 다시 넘기거나 '
        '파일은 <code class="ev">scan_path</code> 호출</li>'
    )
    p.append("<li><b>LLM 안내</b>: 위 권장 처리 순서(차단→치명·높음→자동수정→나머지)를 그대로 지시문으로 사용</li>")
    p.append("</ol>")

    p.append("<h2>면책</h2>")
    p.append(f'<div class="disc">{_esc(report.disclaimer.replace(chr(10), " "))}</div>')

    p.append('<div class="foot">생성: vibecode-checker · 공공 바이브 코딩 보안 가드레일</div>')
    p.append("</div></body></html>")
    return "\n".join(p)


def _render_finding_html(f: Finding) -> list[str]:
    out: list[str] = []
    sev_color = _SEVERITY_COLOR[f.severity]
    dec_color = _DECISION_COLOR.get(f.decision, "#555")
    out.append(f'<div class="card" style="border-left-color:{sev_color}">')
    out.append(
        f'<div><span class="badge" style="background:{sev_color}">'
        f"{_SEVERITY_LABEL_KO[f.severity]}</span>"
        f'<span class="badge" style="background:{dec_color}">'
        f"{_DECISION_LABEL_KO.get(f.decision, f.decision.value)}</span>"
        f'<span class="ftitle">{_esc(f.plain_title)}</span>'
        f'<span class="loc">line {f.location.line}</span></div>'
    )
    out.append(
        f'<div class="row"><span class="tag">{_esc(f.rule_id)}</span>'
        f'<span class="tag">{_esc(f.category)}</span></div>'
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


def _render_finding(f: Finding) -> list[str]:
    out: list[str] = []
    tag = _SEVERITY_EMOJI[f.severity]
    out.append(
        f"#### {tag} {_SEVERITY_LABEL_KO[f.severity]} · {f.decision.value} — "
        f"{f.plain_title} (line {f.location.line})"
    )
    out.append("")
    out.append(f"- **룰**: `{f.rule_id}`")
    out.append(f"- **카테고리**: {f.category}")
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
