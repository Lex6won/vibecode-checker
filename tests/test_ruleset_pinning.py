"""룰셋 버전 고정 — 게이트의 제1 조건인 재현성.

라운드 13에서 위치를 *"소스는 보조, 의존성은 게이트"* 로 정했는데, 게이트가
되려면 먼저 **어제 통과한 것이 오늘도 통과해야** 한다. 우리는 룰을 고치는 즉시
판정이 바뀌었고 그 사실이 결과 어디에도 남지 않았다.

이 파일이 지키는 것은 셋이다:
  ① 지문이 **결정적**인가 (같은 룰셋 → 언제나 같은 값)
  ② 지문이 **판정을 바꾸는 변경만** 따라가는가 (문구 수정에 흔들리면 아무도 안 올린다)
  ③ 어긋났을 때 **조용하지 않은가** (validate-rules ERROR · 리포트 배너)
"""
from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from gvskb import ruleset
from gvskb.loader import load_all_rules

_RULE = """---
id: TEST-PIN-001
title_ko: 테스트용 룰
status: approved
source_layer: baseline
sources:
  - publisher: 테스트
    document: 테스트 문서
    item: "제1절"
cwe: [CWE-79]
severity: high
decision_default: block
languages: [python]
verified_at: 2026-01-01
detection:
  patterns:
    - "eval\\\\s*\\\\("
  category: test
  why_it_matters: 테스트
  safe_fix: 쓰지 마세요
examples:
  language: python
  positive:
    - "eval(x)"
  negative:
    - "evaluate(x)"
---

## 본문
테스트 룰입니다.
"""


def _mk_rules_dir(tmp_path: Path, body: str = _RULE) -> Path:
    d = tmp_path / "rules"
    d.mkdir(parents=True, exist_ok=True)
    (d / "TEST-PIN-001.md").write_text(body, encoding="utf-8")
    # 픽스처가 실제로 로드되는지 여기서 확인한다. 룰이 0건이면 두 지문이
    # '똑같이 비어' 있어서, 지문 비교 테스트가 통과하는 것처럼 보인다
    # (실제로 `item: 1` 타입 오류로 그렇게 됐다 — 조용한 초록불).
    loaded = load_all_rules(d, strict=True)
    assert loaded, "테스트 픽스처 룰이 로드되지 않았습니다"
    return d


# ---------------------------------------------------------------------------
# ① 결정성
# ---------------------------------------------------------------------------

def test_digest_is_deterministic_and_order_independent(tmp_path: Path) -> None:
    """룰 순서가 흔들려도 같은 값이어야 한다. set 을 그대로 직렬화하면
    실행마다 값이 달라져, 잠금 파일이 매번 '드리프트'로 보인다."""
    d = _mk_rules_dir(tmp_path)
    (d / "TEST-PIN-002.md").write_text(
        _RULE.replace("TEST-PIN-001", "TEST-PIN-002"), encoding="utf-8")
    rules = load_all_rules(d)

    first = ruleset.compute_digest(rules)
    assert first == ruleset.compute_digest(list(reversed(rules)))
    assert first == ruleset.compute_digest(rules)


def test_real_ruleset_matches_its_lock() -> None:
    """저장소의 실제 룰셋이 잠금 파일과 맞는가 — 이게 깨지면 릴리스가 거짓말한다."""
    from gvskb.scanners.regex_scanner import _resolve_rules_dir

    rules_dir = _resolve_rules_dir()
    verdict = ruleset.verify_lock(load_all_rules(rules_dir), rules_dir)
    assert verdict["status"] == "ok", verdict["message"]
    assert verdict["version"]


# ---------------------------------------------------------------------------
# ② 판정을 바꾸는 변경만 따라간다
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("old, new, why", [
    ('eval\\\\s*\\\\(', 'exec\\\\s*\\\\(', "패턴"),
    ("severity: high", "severity: low", "심각도"),
    ("decision_default: block", "decision_default: warn", "판정"),
    ("languages: [python]", "languages: [javascript]", "적용 언어"),
    ("status: approved", "status: deprecated", "집행 여부"),
])
def test_digest_moves_when_verdict_changing_field_changes(
    tmp_path: Path, old: str, new: str, why: str,
) -> None:
    before = ruleset.compute_digest(load_all_rules(_mk_rules_dir(tmp_path)))
    after = ruleset.compute_digest(
        load_all_rules(_mk_rules_dir(tmp_path, _RULE.replace(old, new, 1))))
    assert before != after, f"{why} 를 바꿨는데 지문이 그대로입니다"


@pytest.mark.parametrize("old, new, why", [
    ("title_ko: 테스트용 룰", "title_ko: 이름을 바꾼 룰", "제목"),
    ("safe_fix: 쓰지 마세요", "safe_fix: 절대 쓰지 마시고 대안을 쓰세요", "조치 문구"),
    ("why_it_matters: 테스트", "why_it_matters: 아주 긴 설명으로 교체", "설명"),
    ("## 본문\n테스트 룰입니다.", "## 본문\n문서를 다듬었습니다.", "본문"),
])
def test_digest_ignores_documentation_only_changes(
    tmp_path: Path, old: str, new: str, why: str,
) -> None:
    """문구를 다듬을 때마다 버전이 흔들리면 **아무도 버전을 올리지 않게 된다.**
    그러면 이 장치 자체가 무의미해진다 — 그래서 판정에 쓰이는 필드만 본다."""
    before = ruleset.compute_digest(load_all_rules(_mk_rules_dir(tmp_path)))
    after = ruleset.compute_digest(
        load_all_rules(_mk_rules_dir(tmp_path, _RULE.replace(old, new, 1))))
    assert before == after, f"{why} 만 바꿨는데 지문이 움직였습니다"


# ---------------------------------------------------------------------------
# ③ 어긋나면 조용하지 않다
# ---------------------------------------------------------------------------

def test_lock_roundtrip_and_drift(tmp_path: Path) -> None:
    d = _mk_rules_dir(tmp_path)
    rules = load_all_rules(d)
    assert ruleset.verify_lock(rules, d)["status"] == "missing"

    ruleset.write_lock(d, version="2026.01.1",
                       digest=ruleset.compute_digest(rules), rule_count=len(rules))
    assert ruleset.verify_lock(load_all_rules(d), d)["status"] == "ok"

    # 룰만 고치고 버전은 그대로 → 드리프트
    (d / "TEST-PIN-001.md").write_text(
        _RULE.replace("severity: high", "severity: low", 1), encoding="utf-8")
    drift = ruleset.verify_lock(load_all_rules(d), d)
    assert drift["status"] == "drift"
    assert drift["version"] == "2026.01.1"
    assert "버전이 그대로" in drift["message"]


def test_validate_rules_reports_drift_as_error(tmp_path: Path) -> None:
    """별도 명령으로만 두면 아무도 안 돌린다. CI 가 이미 부르는 자리
    (`validate-rules`)에서 ERROR 로 막아야 경로가 실제로 닫힌다."""
    from gvskb import validation

    d = _mk_rules_dir(tmp_path)
    ruleset.write_lock(d, version="2026.01.1",
                       digest=ruleset.compute_digest(load_all_rules(d)), rule_count=1)
    (d / "TEST-PIN-001.md").write_text(
        _RULE.replace("decision_default: block", "decision_default: warn", 1),
        encoding="utf-8")

    report = validation.validate_rules_dir(d, today=date(2026, 1, 2))
    codes = {i["code"] for i in report["issues"]}
    assert "ruleset-digest-drift" in codes, codes
    assert report["overall"] == "error"
    assert report["summary"]["ruleset"]["status"] == "drift"


def test_validate_rules_warns_when_lock_missing(tmp_path: Path) -> None:
    """버전 선언이 아예 없는 것은 ERROR 가 아니라 WARN — 룰셋을 직접 물려 쓰는
    기관 배포(GVSKB_RULES_DIR)를 막아 버리면 안 되기 때문이다. 다만 조용하지는 않다."""
    from gvskb import validation

    report = validation.validate_rules_dir(_mk_rules_dir(tmp_path), today=date(2026, 1, 2))
    codes = {i["code"] for i in report["issues"]}
    assert "ruleset-lock-missing" in codes, codes
    assert report["overall"] == "warn"


# ---------------------------------------------------------------------------
# 리포트·상태에 각인되는가
# ---------------------------------------------------------------------------

def test_scan_report_carries_engine_and_ruleset_together() -> None:
    """엔진 코드가 바뀌어도 판정은 바뀐다 — 룰셋만 적으면 재현 가능한 것처럼
    보이는 착시가 생긴다. 그래서 **쌍으로** 노출한다."""
    from gvskb.report import render_markdown
    from gvskb.scanner import scan_code

    report = scan_code("eval(user_input)\n", filename="a.py")
    assert report.ruleset_digest and len(report.ruleset_digest) == 32
    assert report.ruleset_version
    assert report.ruleset_drift is None

    row = next(ln for ln in render_markdown(report).splitlines() if ln.startswith("| 판정 기준 |"))
    assert report.engine_version in row
    assert report.ruleset_version in row


def test_pin_mismatch_is_announced_in_report(monkeypatch: pytest.MonkeyPatch) -> None:
    from gvskb.report import render_markdown
    from gvskb.scanner import scan_code

    monkeypatch.setenv(ruleset.EXPECT_ENV, "2026.01.9")
    md = render_markdown(scan_code("x = 1\n", filename="a.py"))
    assert "고정한 룰셋과 다릅니다" in md
    assert "재현되지 않습니다" in md


def test_pin_accepts_version_or_digest_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    """CI 설정에는 사람이 읽는 버전을, 엄격한 감사에는 지문을 쓴다 —
    둘 다 받아야 실제로 쓰인다."""
    from gvskb.scanner import scan_code

    report = scan_code("x = 1\n", filename="a.py")
    for pin in (report.ruleset_version, report.ruleset_digest, report.ruleset_digest[:12]):
        monkeypatch.setenv(ruleset.EXPECT_ENV, pin)
        assert ruleset.pin_mismatch(report.ruleset_version, report.ruleset_digest) is None, pin


def test_short_pin_is_not_silently_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    """지문 앞자리 핀을 너무 짧게 허용하면 우연히 맞는다 — 8자 미만은 거절."""
    monkeypatch.setenv(ruleset.EXPECT_ENV, "4119")
    assert ruleset.pin_mismatch("2026.08.1", "41193ea9f37ff75cf4ce17ce0a124e8e") is not None


def test_server_status_exposes_ruleset_identity() -> None:
    from gvskb.diagnostics import runtime_status_for_mcp

    rs = runtime_status_for_mcp()["ruleset"]
    assert rs["status"] == "ok", rs["message"]
    assert rs["version"] and rs["digest"]
    assert rs["pin_ok"] is True
