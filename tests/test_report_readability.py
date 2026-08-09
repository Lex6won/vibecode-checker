"""라운드 8 — 실제 결재 보고서를 정독하며 나온 판독 결함 6종의 회귀 테스트.

배경: 사용자가 응소ON 보고서(`.check-reports/…보안점검.html`)를 세부까지 읽고 여섯
가지를 물었다. 전부 "숫자는 맞는데 읽는 사람이 알 수 없다" 계열이었다.

1. **위치에 파일 경로가 없다** — 카드가 `line 1, 39, 66` 만 찍었다. 실제로는
   2개 파일 × 3줄인데 3건으로 읽힌다. 위치를 못 찾으면 고칠 수 없다.
2. **의존성이 집계에서 빠졌다** — 배포 차단 사유의 절반이 패키지인데 보안 분야
   개요·심각도 표에는 소스 발견만 있었다(판정에는 쓰이는데 집계에는 없음).
3. **심각도 기준이 두 개인데 설명이 없다** — 소스는 룰에 고정, 패키지는 검사 시
   계산. 같은 '높음'이 같은 자로 잰 값이 아니다.
4. **Top3 과 분야 개요의 단위가 다르다** — 룰 3개(8건) vs 분야 전체(16건).
5. **분야별 '파일' 열의 합이 실제 파일 수와 다르다** — 한 파일이 두 분야에 걸리면
   각 분야에서 한 번씩 센다.
6. **의존성 수정 프롬프트가 없다** — 안내대로 AI에게 고치라고 하면 소스만 고쳐지고
   다시 검사해도 배포 미승인이 유지된다. 도구가 만든 막다른 길이었다.
"""
from __future__ import annotations

from gvskb.report import (
    _dep_component_severity,
    _dep_domain_row,
    _dep_fix_prompt_text,
    _locations_by_file,
    _action_order,
    _action_order_note,
    render_html,
    render_markdown,
)
from gvskb.schema import (
    CodeLocation,
    Decision,
    Finding,
    ScanReport,
    ScanSummary,
    Severity,
)


def _finding(file: str, line: int, rule: str = "GOV-CERT-IN-SOURCE-001") -> Finding:
    return Finding(
        id=f"{rule}:{file}:{line}",
        rule_id=rule,
        title="인증서 파일이 소스에 함께 들어 있습니다",
        plain_title="인증서 파일이 소스에 함께 들어 있습니다",
        severity=Severity.low,
        decision=Decision.warn,
        category="secret-scanning",
        location=CodeLocation(file=file, line=line),
        evidence="-----BEGIN CERTIFICATE-----",
        why_it_matters="인증서 본문은 비밀이 아니지만 같은 폴더의 개인키가 함께 새어 나갑니다.",
        safe_fix="서버의 인증서 저장 경로에서 관리하세요.",
    )


def _multi_file_report() -> ScanReport:
    """같은 룰이 2개 파일 × 3줄 — 실측에서 '3건'으로 오독됐던 모양 그대로."""
    findings = [
        _finding("ssl/site_crt.pem", line) for line in (1, 39, 66)
    ] + [
        _finding("app/ssl/site_crt.pem", line) for line in (1, 39, 66)
    ]
    return ScanReport(
        target="fixture",
        summary=ScanSummary(
            finding_count=len(findings),
            by_severity={"low": len(findings)},
            by_decision={"warn": len(findings)},
            highest_severity=Severity.low,
        ),
        findings=findings,
        scanned_files=["ssl/site_crt.pem", "app/ssl/site_crt.pem"],
    )


def _dep_audit(*checks: dict, blocked: bool = False, unchecked: int = 0) -> dict:
    return {
        "audits": [{
            "ecosystem": "pypi",
            "manifest": "requirements.txt",
            "parsed_count": len(checks),
            "checked_count": len(checks),
            "unchecked_count": unchecked,
            "blocked": blocked,
            "verdict": "blocked" if blocked else "ok",
            "checks": list(checks),
        }],
    }


def _check(name: str, version: str, **over) -> dict:
    base = {
        "name": name, "version": version, "checked": True,
        "is_malicious_package": False, "vulnerability_count": 0,
        "verdict": "checked_clean", "max_cve": "NONE", "in_kev": False,
    }
    base.update(over)
    return base


# ---------------------------------------------------------------------------
# ① 위치에 파일 경로 — 줄 번호만으로는 어느 파일인지 알 수 없다
# ---------------------------------------------------------------------------


def test_detail_shows_file_path_not_only_line_numbers() -> None:
    report = _multi_file_report()
    md, html = render_markdown(report), render_html(report)
    for doc in (md, html):
        # 두 파일이 **각각** 보여야 한다 — 줄 번호 합집합(1, 39, 66)만으로는
        # 6건이 어디에 흩어져 있는지 알 수 없다.
        assert "ssl/site_crt.pem(line 1, 39, 66)" in doc
        assert "app/ssl/site_crt.pem(line 1, 39, 66)" in doc
    # 상세 카드가 파일 없이 줄만 찍던 옛 형태가 남아 있으면 안 된다.
    assert "**위치**: line " not in md
    assert "건 · line " not in html


def test_locations_by_file_folds_extra_files_but_keeps_count() -> None:
    """카드가 길어지지 않게 접되, 몇 개가 더 있는지는 반드시 말한다."""
    findings = [_finding(f"pkg/mod{i}.py", 10 + i) for i in range(6)]
    text = _locations_by_file(findings, limit_files=3)
    assert text.count(";") == 2          # 파일 3개만 펼침
    assert "외 3개 파일" in text          # 나머지는 숨기지 않고 개수로 말한다


def test_html_card_header_shows_file_count() -> None:
    html = render_html(_multi_file_report())
    assert "6건 · 파일 2개" in html


# ---------------------------------------------------------------------------
# ② 의존성 심각도 매핑 — 표시 계층 전용, 규칙을 고정한다
# ---------------------------------------------------------------------------


def test_dependency_severity_mapping_is_fixed() -> None:
    assert _dep_component_severity(_check("evil", "1.0", is_malicious_package=True)) is Severity.critical
    assert _dep_component_severity(_check("ghost", "1.0", verdict="not_found")) is Severity.critical
    assert _dep_component_severity(_check("blocked", "1.0", verdict="registry_rejected")) is Severity.critical
    assert _dep_component_severity(
        _check("pillow", "12.2.0", vulnerability_count=26, max_cve="HIGH")
    ) is Severity.high
    assert _dep_component_severity(
        _check("kevpkg", "1.0", vulnerability_count=1, max_cve="MEDIUM", in_kev=True)
    ) is Severity.high
    assert _dep_component_severity(
        _check("pip", "25.3", vulnerability_count=8, max_cve="MEDIUM")
    ) is Severity.medium
    assert _dep_component_severity(_check("fresh", "0.1", verdict="cooldown_hold")) is Severity.medium


def test_clean_and_unknown_packages_are_not_graded() -> None:
    """이상 없음과 판정 불가는 등급을 매기지 않는다 — 성격이 다르고, 둘 다 등급이 아니다.

    판정 불가를 '낮음'으로 적으면 **확인하지 못한 것이 확인된 것처럼** 보인다.
    """
    assert _dep_component_severity(_check("requests", "2.34.0")) is None
    assert _dep_component_severity(_check("mystery", "1.0", checked=False, verdict="unknown")) is None


def test_unknown_packages_counted_separately_not_as_severity() -> None:
    report = _multi_file_report()
    report.dependency_audit = _dep_audit(
        _check("requests", "2.34.0"), unchecked=2,
    )
    row = _dep_domain_row(report)
    assert row is not None
    assert row["count"] == 0          # 등급이 매겨진 패키지는 없고
    assert row["unknown"] == 2        # 판정 불가는 그대로 남는다


# ---------------------------------------------------------------------------
# ③ 의존성이 분야 개요·심각도 표에 함께 오른다
# ---------------------------------------------------------------------------


def _report_with_deps() -> ScanReport:
    report = _multi_file_report()
    report.dependency_audit = _dep_audit(
        _check("pillow", "12.2.0", verdict="vulnerable", vulnerability_count=26, max_cve="HIGH"),
        _check("pip", "25.3", verdict="vulnerable", vulnerability_count=8, max_cve="MEDIUM"),
        _check("requests", "2.34.0"),
        blocked=True, unchecked=1,
    )
    return report


def test_dependency_row_appears_in_domain_overview() -> None:
    report = _report_with_deps()
    for doc in (render_markdown(report), render_html(report)):
        assert "의존성·공급망(패키지)" in doc
        assert "패키지 2종" in doc


def test_severity_table_splits_source_and_dependency_columns() -> None:
    """두 심각도를 한 칸에 합치지 않는다 — 정하는 방식이 다르다."""
    md = render_markdown(_report_with_deps())
    assert "| 심각도 | 소스 코드 | 의존성(패키지) | 합계 |" in md
    assert "| 높음 (high) | 0 | 1 | 1 |" in md
    assert "| 보통 (medium) | 0 | 1 | 1 |" in md
    assert "| 낮음 (low) | 6 | 0 | 6 |" in md


def test_total_action_items_line_sums_source_and_packages() -> None:
    md = render_markdown(_report_with_deps())
    assert "총 조치 대상: 8건" in md       # 소스 6 + 패키지 2
    assert "소스 코드 6건 · 패키지 2종" in md
    html = render_html(_report_with_deps())
    assert "총 조치 대상 8건" in html


def test_severity_table_stays_single_column_without_dependency_audit() -> None:
    """과잉 교정 방지 — 의존성 검사를 안 했으면 열을 늘리지 않는다."""
    md = render_markdown(_multi_file_report())
    assert "| 심각도 | 건수 |" in md
    # 열이 늘어난 형태가 나오면 안 된다(한계 고지 문장에도 '의존성(패키지)' 가
    # 들어 있으므로 단어가 아니라 **표 머리글**로 확인한다).
    assert "| 심각도 | 소스 코드 |" not in md


# ---------------------------------------------------------------------------
# ④ 심각도 판정 기준표 — "왜 이게 높음이냐"에 도구가 답한다
# ---------------------------------------------------------------------------


def test_appendix_has_severity_criteria_table() -> None:
    for doc in (render_markdown(_report_with_deps()), render_html(_report_with_deps())):
        assert "심각도 판정 기준" in doc
        assert "룰에 고정" in doc                    # 소스 쪽 기준
        assert "CISA KEV" in doc                     # 패키지 쪽 기준
        assert "판정 불가" in doc


def test_severity_criteria_present_even_without_dependency_audit() -> None:
    md = render_markdown(_multi_file_report())
    assert "심각도 판정 기준" in md
    assert "룰에 고정" in md


# ---------------------------------------------------------------------------
# ⑤ 조치 순서 — 잘라내지 않는다 · 분야별 파일 중복
#
# 실측 질문: "'가장 먼저 할 일'이 어떤 의미야? 왜 일부만 표시하지? 위험요소들은
# 모두 조치해야 하는 것 아닌가?" — 맞는 말이다. 잘린 목록은 "3개만 하면 되나"로
# 읽히고 나머지가 조용히 남는다. 자르는 대신 **순서로** 답한다.
# ---------------------------------------------------------------------------


def _tiered_findings() -> list:
    """차단 1 · 치명(경고) 1 · 낮음 2 — 3단이 모두 채워지는 모양."""
    blocked = _finding("secret.pem", 1, rule="R-BLOCK")
    blocked.severity = Severity.critical
    blocked.decision = Decision.block
    high = _finding("app.py", 10, rule="R-HIGH")
    high.severity = Severity.high
    rest = [_finding("a.py", 1, rule="R-LOW1"), _finding("b.py", 2, rule="R-LOW2")]
    return [blocked, high, *rest]


def _tiered_report() -> ScanReport:
    findings = _tiered_findings()
    return ScanReport(
        target="fixture",
        summary=ScanSummary(
            finding_count=len(findings),
            by_severity={"critical": 1, "high": 1, "low": 2},
            by_decision={"block": 1, "warn": 3},
            highest_severity=Severity.critical,
        ),
        findings=findings,
        scanned_files=["secret.pem", "app.py", "a.py", "b.py"],
    )


def test_action_order_covers_every_finding() -> None:
    """3단을 합치면 **전체**가 된다 — 잘라내는 곳이 없어야 한다."""
    findings = _tiered_findings()
    tiers = _action_order(findings)
    assert sum(t["count"] for t in tiers) == len(findings)
    labels = [t["label"] for t in tiers]
    assert labels == ["지금 막아야 하는 것", "그다음", "나머지"]
    assert tiers[0]["count"] == 1        # 차단
    assert tiers[1]["count"] == 1        # 치명·높음(차단 아님)
    assert tiers[2]["count"] == 2        # 나머지


def test_action_order_skips_empty_tiers() -> None:
    """경고만 있는 프로젝트에 '지금 막아야 하는 것' 빈 칸을 만들지 않는다."""
    findings = [_finding("a.py", 1, rule="R-A")]     # 낮음·경고 1건
    tiers = _action_order(findings)
    assert [t["label"] for t in tiers] == ["나머지"]


def test_action_order_note_says_everything_must_be_fixed() -> None:
    """'일부만 고르라는 뜻이 아니다'를 도구가 먼저 말한다."""
    note = _action_order_note(_tiered_report())
    assert "전부가 조치 대상입니다" in note
    assert "일부만 고르라는 뜻이 아닙니다" in note


def test_action_order_is_rendered_in_both_formats() -> None:
    """함수만 있고 화면에 없으면 소용없다(변이 검사에서 빠져나갔던 유형)."""
    report = _tiered_report()
    for doc in (render_markdown(report), render_html(report)):
        assert "조치 순서" in doc
        assert "전부가 조치 대상입니다" in doc
        assert "지금 막아야 하는 것" in doc
        assert "나머지" in doc
        # 4개 룰이 하나도 빠지지 않는다 — 예전 Top 3 는 하나를 잘랐다.
        for rule in ("R-BLOCK", "R-HIGH", "R-LOW1", "R-LOW2"):
            assert rule in doc


def test_package_step_is_listed_in_action_order() -> None:
    """소스만 고쳐서는 끝이 아니라는 사실을 조치 순서에서 말한다.

    **문구는 판정을 따라야 한다(실측 2026-08-09)**: HIGH 취약점은 사다리에서
    조건부 승인인데, 이 자리는 판정과 무관하게 "배포 차단이 풀리지 않습니다"
    라고 말했다. 같은 보고서의 판정 상자는 "차단 사유는 없습니다" 였다 —
    담당자는 둘 중 무엇을 믿어야 할지 알 수 없다. 양방향을 모두 고정한다.
    """
    cond = _tiered_report()
    cond.dependency_audit = _dep_audit(
        _check("pillow", "12.2.0", verdict="vulnerable", vulnerability_count=26, max_cve="HIGH"),
        blocked=True,   # 감사 자체의 옛 플래그 — 게이트가 이걸 따라가면 안 된다
    )
    for doc in (render_markdown(cond), render_html(cond)):
        assert "패키지 업그레이드" in doc
        assert "조치가 끝나지 않습니다" in doc
        assert "배포 차단이 풀리지 않습니다" not in doc

    blocked = _tiered_report()
    blocked.dependency_audit = _dep_audit(
        _check("evil", "1.0", verdict="vulnerable", vulnerability_count=1, max_cve="CRITICAL"),
        blocked=True,
    )
    for doc in (render_markdown(blocked), render_html(blocked)):
        assert "배포 차단이 풀리지 않습니다" in doc


# ---------------------------------------------------------------------------
# ⑤-2 분야 표의 '치명 | 10' 오독 — 등급과 총계를 붙여 읽는다
# ---------------------------------------------------------------------------


def test_domain_table_shows_severity_breakdown() -> None:
    """'최고 심각도 치명' 옆의 '10'이 '치명 10건'으로 읽히던 문제.

    분포는 **표의 행 안**에 있어야 한다. 절 제목에도 같은 문구가 있으므로
    행 형식까지 확인한다(변이 검사에서 실제로 빠져나갔던 지점).
    """
    report = _tiered_report()
    md, html = render_markdown(report), render_html(report)
    assert "심각도별 내역" in md and "심각도별 내역" in html
    # 4건 = 치명 1 · 높음 1 · 낮음 2, 파일 4개
    assert "| 비밀값·인증정보 노출 | 치명 | 4 | 치명 1 · 높음 1 · 낮음 2 | 4 |" in md
    assert "<td>치명 1 · 높음 1 · 낮음 2</td>" in html


def test_domain_section_heading_carries_breakdown() -> None:
    md = render_markdown(_multi_file_report())
    assert "— 6건 (낮음 6) · 파일 2개" in md


def test_domain_file_column_double_count_is_disclosed() -> None:
    """한 파일이 두 분야에 걸리면 합계가 실제 파일 수보다 크다 — 그 사실을 적는다."""
    findings = [
        _finding("database.py", 213, rule="KISA-PY-SEC-13"),      # 비밀값 분야
        _finding("database.py", 11, rule="KISA-PY-CODE-02"),      # 코드 안정성 분야
    ]
    findings[1].category = "kisa-secure-coding"
    report = ScanReport(
        target="fixture",
        summary=ScanSummary(
            finding_count=2, by_severity={"low": 2}, by_decision={"warn": 2},
            highest_severity=Severity.low,
        ),
        findings=findings,
        scanned_files=["database.py"],
    )
    for doc in (render_markdown(report), render_html(report)):
        assert "파일 열은 분야별로 셉니다" in doc
        assert "실제 파일 수(1개)" in doc


# ---------------------------------------------------------------------------
# ⑥ 의존성 수정 프롬프트 — 소스만 고치면 차단이 안 풀린다
# ---------------------------------------------------------------------------


def test_dependency_fix_prompt_lists_packages_and_reasons() -> None:
    text = _dep_fix_prompt_text(_report_with_deps())
    assert text is not None
    # HIGH·MEDIUM 뿐이므로 사다리에서 조건부 승인 — 프롬프트 머리도 그렇게 적는다.
    assert text.startswith("[조치 필요]")
    assert "pillow 12.2.0" in text and "취약점 26건" in text and "최고 HIGH" in text
    assert "pip 25.3" in text
    assert "requests" not in text          # 이상 없는 패키지는 조치 대상이 아니다
    # 권고 버전을 지어내지 않는다 — 검사 결과에 '고쳐진 버전'이 없다.
    assert "추측하지 마세요" in text


def test_dependency_fix_prompt_rendered_in_both_formats_with_warning() -> None:
    report = _report_with_deps()
    for doc in (render_markdown(report), render_html(report)):
        assert "취약·위험 패키지 2종" in doc
        assert "패키지를 빠뜨리지 마세요" in doc          # 조건부 승인 문구
        assert "패키지 블록을 빠뜨리지 마세요" not in doc   # 차단 문구는 안 나온다


def test_dependency_fix_prompt_says_block_only_when_actually_blocked() -> None:
    """차단 문구는 **진짜 차단일 때만**. 머리표도 판정을 따라간다."""
    report = _multi_file_report()
    report.dependency_audit = _dep_audit(
        _check("evil", "1.0", verdict="vulnerable", vulnerability_count=1, max_cve="CRITICAL"),
        blocked=True,
    )
    text = _dep_fix_prompt_text(report)
    assert text is not None and text.startswith("[차단]")
    for doc in (render_markdown(report), render_html(report)):
        assert "패키지 블록을 빠뜨리지 마세요" in doc


def test_fix_prompt_section_exists_even_with_no_source_findings() -> None:
    """소스 0건 + 패키지 차단 — 예전에는 프롬프트 섹션 자체가 사라졌다."""
    report = ScanReport(
        target="fixture",
        summary=ScanSummary(finding_count=0, by_severity={}, by_decision={}),
        findings=[],
        scanned_files=["hello.py"],
    )
    report.dependency_audit = _dep_audit(
        _check("pillow", "12.2.0", verdict="vulnerable", vulnerability_count=26, max_cve="HIGH"),
        blocked=True,
    )
    for doc in (render_markdown(report), render_html(report)):
        assert "수정 프롬프트" in doc
        assert "pillow 12.2.0" in doc


# ---------------------------------------------------------------------------
# ⑦ "26건이 뭔지 알 수가 없다" — 숫자만 있고 내역이 없던 결함
#
# 실측 질문: 표에 '취약·악성 3건'과 '취약점 26건'이 같이 있는데 단위가 다르다.
# 3=패키지 수(조치 단위), 26=그 패키지의 개별 권고 수. 그런데 26건의 **내역이
# 한 줄도 없었고**, 결과에도 5건만 남기고 있었다(vulns[:5] — 조용한 절단).
# ---------------------------------------------------------------------------


def _advisory(aid: str, sev: str, fixed: list[str] | None = None) -> dict:
    return {
        "id": aid, "severity": sev, "summary": f"{aid} 요약",
        "fixed_versions": fixed or [], "modified": "2026-01-01T00:00:00Z",
    }


def _vuln_check(**over) -> dict:
    base = _check(
        "pillow", "12.2.0", verdict="vulnerable", vulnerability_count=3, max_cve="HIGH",
        advisories=[
            _advisory("GHSA-aaa", "HIGH", ["12.3.0"]),
            _advisory("GHSA-bbb", "MEDIUM", ["11.4.1", "12.2.1"]),
            _advisory("GHSA-ccc", "UNKNOWN", ["12.1.5"]),
        ],
        recommended_version="12.3.0",
        registry_metadata={"latest_version": "12.3.0", "license": "MIT-CMU"},
    )
    base.update(over)
    return base


def test_advisory_detail_is_rendered_with_id_severity_and_fix() -> None:
    """무엇이 몇 건인지 — ID·심각도·해결 버전이 보여야 한다."""
    report = _multi_file_report()
    report.dependency_audit = _dep_audit(_vuln_check(), blocked=True)
    for doc in (render_markdown(report), render_html(report)):
        assert "개별 취약점 3건" in doc
        assert "GHSA-aaa" in doc and "GHSA-bbb" in doc and "GHSA-ccc" in doc
        assert "[높음]" in doc and "[보통]" in doc
        assert "미상" in doc                      # 심각도 미상을 '낮음'으로 적지 않는다
        assert "해결 12.3.0" in doc


def test_unit_note_explains_package_count_vs_advisory_count() -> None:
    """3건과 26건이 같은 화면에 있는데 단위가 다르다 — 그 사실을 적는다."""
    report = _multi_file_report()
    report.dependency_audit = _dep_audit(_vuln_check(), blocked=True)
    for doc in (render_markdown(report), render_html(report)):
        assert "숫자의 단위" in doc
        assert "패키지 수" in doc
        # 표의 **판정 칸**에도 단위가 붙어야 한다. 절 제목에도 같은 문구가 있으므로
        # 경고 기호까지 포함해 확인한다(변이 검사에서 실제로 빠져나갔던 지점).
        assert "⚠ 개별 취약점 3건" in doc


def test_upgrade_target_version_is_stated() -> None:
    report = _multi_file_report()
    report.dependency_audit = _dep_audit(_vuln_check(), blocked=True)
    md = render_markdown(report)
    assert "12.3.0 이상" in md
    prompt = _dep_fix_prompt_text(report)
    assert prompt is not None and "12.3.0 이상" in prompt


def test_unknown_fix_version_is_not_guessed() -> None:
    """고쳐진 버전을 모르는 취약점이 하나라도 있으면 목표 버전을 지어내지 않는다."""
    report = _multi_file_report()
    check = _vuln_check(
        advisories=[_advisory("GHSA-aaa", "HIGH", ["12.3.0"]), _advisory("GHSA-zzz", "HIGH")],
        recommended_version=None,
    )
    report.dependency_audit = _dep_audit(check, blocked=True)
    md = render_markdown(report)
    assert "해결 버전 미상" in md
    assert "목표 버전을 특정하지 못했습니다" in md
    assert "최신 버전은 **12.3.0**" in md          # 아는 것(최신)은 그대로 말한다
    prompt = _dep_fix_prompt_text(report)
    assert prompt is not None and "목표 버전 미상" in prompt


def test_advisory_list_folds_but_states_hidden_count() -> None:
    """길면 접되 **접은 개수를 적는다** — 조용한 절단이 이 결함의 원인이었다."""
    report = _multi_file_report()
    advs = [_advisory(f"GHSA-{i:03d}", "MEDIUM", ["9.9.9"]) for i in range(20)]
    report.dependency_audit = _dep_audit(
        _vuln_check(advisories=advs, vulnerability_count=20), blocked=True,
    )
    md = render_markdown(report)
    assert "… 외 8건" in md                        # 12건 표시 + 8건 접힘


def test_collected_fewer_than_counted_is_disclosed() -> None:
    """집계 수치보다 내역이 적으면 그 사실을 적는다 — 26이라 적고 5건만 있던 상태."""
    report = _multi_file_report()
    report.dependency_audit = _dep_audit(
        _vuln_check(vulnerability_count=26), blocked=True,
    )
    md = render_markdown(report)
    assert "집계 26건 중 3건만 내역이 수집됐습니다" in md


def test_no_dependency_prompt_when_all_packages_are_clean() -> None:
    """과잉 교정 방지 — 고칠 것이 없으면 프롬프트를 만들지 않는다."""
    report = _multi_file_report()
    report.dependency_audit = _dep_audit(_check("requests", "2.34.0"))
    assert _dep_fix_prompt_text(report) is None
    # 두 변종(차단·조건부) 모두 나오면 안 된다 — 앞말만 검사하면 조건부 변종이
    # 새어 나가도 통과한다.
    assert "빠뜨리지 마세요" not in render_markdown(report)


# ---------------------------------------------------------------------------
# ⑨ 판정 근거를 원문에서 확인할 수 있는가 — ID 만으로는 검증이 불가능하다
# ---------------------------------------------------------------------------


def _xlsx_check(**over) -> dict:
    """취약 판정 + advisory 1건짜리 체크 결과."""
    base = _check(
        "xlsx", "0.18.5",
        verdict="vulnerable", vulnerability_count=1, max_cve="HIGH",
        recommended_version=None,
        advisories=[{
            "id": "GHSA-4r6h-8v6p-xvw6", "severity": "HIGH",
            "summary": "Prototype Pollution in sheetJS",
            "fixed_versions": [], "references": ["https://cdn.sheetjs.com/advisories/x"],
        }],
    )
    base.update(over)
    return base


def test_advisory_url_only_for_well_formed_ids() -> None:
    """형태가 확실할 때만 링크를 만든다 — 죽은 주소는 근거가 아니다.

    ID 를 그대로 URL 에 이어 붙이면 ``(ID 미상)`` 같은 자리표시자나 주입 시도가
    그대로 주소가 된다. 보고서는 결재에 붙는 문서다.
    """
    from gvskb.report import advisory_url

    assert advisory_url("GHSA-4r6h-8v6p-xvw6") == \
        "https://osv.dev/vulnerability/GHSA-4r6h-8v6p-xvw6"
    assert advisory_url("CVE-2023-30533") == "https://osv.dev/vulnerability/CVE-2023-30533"
    assert advisory_url("PYSEC-2023-227") == "https://osv.dev/vulnerability/PYSEC-2023-227"
    for bad in ("(ID 미상)", "", "  ", "javascript:alert(1)", "../../etc/passwd",
                "GHSA", "http://evil.example/x"):
        assert advisory_url(bad) is None, bad


def test_report_links_each_advisory_to_its_source() -> None:
    """보고서가 권고 ID 옆에 원문 주소를 함께 낸다 — MD 와 HTML 양쪽."""
    report = _multi_file_report()
    report.dependency_audit = _dep_audit(_xlsx_check())
    md, html = render_markdown(report), render_html(report)
    url = "https://osv.dev/vulnerability/GHSA-4r6h-8v6p-xvw6"
    assert url in md
    # HTML 은 _esc 를 거치므로 본문에 박으면 클릭할 수 없는 글자가 된다.
    assert f'href="{url}"' in html


def test_no_recommended_version_still_points_at_a_fix() -> None:
    """'권고 버전 없음'이 '고칠 방법 없음'으로 읽히면 안 된다.

    실측: ``xlsx 0.18.5`` 는 npm 에 수정 버전이 없어 권고가 None 이지만, 제작사가
    자체 CDN 으로 배포를 옮겼을 뿐 **수정본은 존재한다**.
    """
    report = _multi_file_report()
    report.dependency_audit = _dep_audit(_xlsx_check())
    md = render_markdown(report)
    assert "레지스트리에 올릴 수 있는 수정 버전이 없습니다" in md
    assert "https://cdn.sheetjs.com/advisories/x" in md


def test_recommended_version_present_means_no_vendor_fallback_noise() -> None:
    """권고 버전이 있으면 제작사 안내 줄을 덧붙이지 않는다 — 과잉 교정 방지."""
    report = _multi_file_report()
    report.dependency_audit = _dep_audit(_xlsx_check(recommended_version="0.20.2"))
    md = render_markdown(report)
    assert "레지스트리에 올릴 수 있는 수정 버전이 없습니다" not in md


def test_truncated_dependencies_are_disclosed(_unused=None) -> None:
    """상한에 걸려 **보지 않은** 패키지가 있으면 보고서가 말해야 한다.

    실측: lexdiff 의 전이 의존성 906개 중 락파일 기본 상한 500 때문에 406개가
    잘렸는데, `report.py` 가 `truncated_count` 를 한 번도 읽지 않아 보고서에
    흔적이 없었다. 담당자는 "검사됨 500"이라는 **완결돼 보이는** 섹션을 결재에
    올린다 — 트리의 45% 를 안 봤다는 사실이 종이에 없다.

    `unchecked_count`(검사했으나 판정 못 함)와 구분해서 적어야 한다.
    """
    report = _multi_file_report()
    audit = _dep_audit(_check("pillow", "12.2.0"))
    audit["audits"][0].update({"truncated_count": 406, "parsed_count": 906})
    report.dependency_audit = audit
    for doc in (render_markdown(report), render_html(report)):
        assert "406" in doc and "906" in doc
        assert "검사되지 않았습니다" in doc


def test_no_truncation_means_no_banner() -> None:
    """다 봤으면 경고하지 않는다 — 없는 문제로 경고 피로를 만들지 않는다."""
    report = _multi_file_report()
    audit = _dep_audit(_check("pillow", "12.2.0"))
    audit["audits"][0].update({"truncated_count": 0, "parsed_count": 906})
    report.dependency_audit = audit
    assert "검사되지 않았습니다" not in render_markdown(report)


# ---------------------------------------------------------------------------
# 소스 파일 절단 — '열어보지도 못한 파일'을 결론 근처에서 말한다
#
# 실측(lexdiff, 2026-08-08): 568개 중 500개만 검사되고 68개가 잘렸는데, 리포트의
# 제외 요약에는 "최대 파일 수 도달 1건"으로만 나왔다. 의존성 절단(라운드13)과
# 완전히 같은 결함 — 커버리지가 깨진 사실이 종이에 없으면 결재는 그냥 통과한다.
# ---------------------------------------------------------------------------

from gvskb.report import _source_truncation_banner  # noqa: E402
from gvskb.schema import SkippedFile  # noqa: E402


def _truncated_report(missed: int = 68, limit: int = 500) -> ScanReport:
    report = _multi_file_report()
    report.skipped_files = [
        SkippedFile(path="repo", reason=f"max_files={limit} reached — {missed}개 파일이 검사되지 않았습니다"),
    ]
    return report


def test_source_truncation_banner_states_missed_and_total() -> None:
    banner = _source_truncation_banner(_truncated_report(68, 500))
    assert banner is not None
    assert "68개가 검사되지 않았습니다" in banner
    assert "568개 중 500개" in banner      # 전체를 복원해 보여준다
    assert "--max-files" in banner          # 어떻게 고치는지까지


def test_source_truncation_banner_absent_when_nothing_truncated() -> None:
    assert _source_truncation_banner(_multi_file_report()) is None


def test_source_truncation_banner_rendered_in_md_and_html() -> None:
    report = _truncated_report(68, 500)
    md, html = render_markdown(report), render_html(report)
    for doc in (md, html):
        assert "68개가 검사되지 않았습니다" in doc, doc[:200]
    assert 'class="depwarn"' in html


def test_skip_breakdown_shows_file_count_not_event_count() -> None:
    """제외 요약의 '1건'은 파일 1개가 아니라 절단 사건 1건이다.
    실제 미검사 파일 수를 같이 적지 않으면 68 누락이 1로 읽힌다."""
    md = render_markdown(_truncated_report(68, 500))
    # 제외 요약 **줄 자체**를 본다. 단순히 "68개"가 문서 어딘가에 있는지만
    # 확인하면 배너와 생략파일 목록이 이 줄을 가려, 요약을 옛 문구로 되돌려도
    # 테스트가 통과한다(변이검사에서 실제로 통과했다).
    line = next((ln for ln in md.splitlines() if "최대 파일 수에 걸려" in ln), None)
    assert line is not None, "제외 요약에 절단 줄이 없습니다"
    assert "68개 파일이 검사되지 않았습니다" in line, line
