"""룰 린터 — 실측에서 뚫린 **오탐 모양**을 룰 작성 시점에 잡는다.

라운드 10·13·14의 오탐을 하나씩 세지 않고 분해하니 소수의 *모양*으로 모였다.
그 모양을 작성 시점에 잡으면 같은 오탐이 다시 태어나지 않는다.

**린터 자신의 오탐이 가장 큰 위험이다.** 시끄러운 린터는 꺼지고, 꺼진 린터는
없는 것과 같다. 그래서 이 파일은 두 방향을 같은 무게로 고정한다:
  ① 알려진 나쁜 모양을 잡는가
  ② **정당한 모양을 잡지 않는가** (실제로 `["'](exec|eval)["']` 에서 오탐이 났다)
"""
from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from gvskb import validation

_HEAD = """---
id: TEST-LINT-001
title_ko: 린터 테스트 룰
status: approved
source_layer: baseline
sources:
  - publisher: 테스트
    document: 테스트
    item: "제1절"
cwe: [CWE-79]
severity: high
decision_default: block
languages: [javascript]
verified_at: 2026-01-01
detection:
  patterns:
    - {pattern}
  category: test
  why_it_matters: 테스트
  safe_fix: 테스트
examples:
  language: javascript
  positive:
    - "eval(x)"
  negative:
    - "safe()"
---

## 본문
"""


def _codes(tmp_path: Path, pattern: str) -> set[str]:
    d = tmp_path / "rules"
    d.mkdir(parents=True, exist_ok=True)
    (d / "TEST-LINT-001.md").write_text(_HEAD.format(pattern=pattern), encoding="utf-8")
    report = validation.validate_rules_dir(d, today=date(2026, 1, 2))
    assert report["summary"]["rules_loaded"] == 1, "픽스처 룰이 로드되지 않았습니다"
    return {i["code"] for i in report["issues"]}


# ---------------------------------------------------------------------------
# ① 경계 없는 실행 sink — 오탐 14건의 단일 원인
# ---------------------------------------------------------------------------

_BAD_SINK = (
    r'"(?i)((llm|response).*(execute|exec|eval|os\\.system)'
    r'|(execute|exec|eval|os\\.system).*(llm|response))"'
)


def test_flags_sink_tokens_without_boundary(tmp_path: Path) -> None:
    """수정 전 `GOV-LLM-OUTPUT-HANDLING-001` 의 실제 패턴."""
    assert "sink-token-without-boundary" in _codes(tmp_path, _BAD_SINK)


@pytest.mark.parametrize("pattern, why", [
    (r"'(?<![A-Za-z0-9])(?:execute|exec|eval)(?!(?-i:[a-z]))'", "좌우 경계를 붙인 형태"),
    (r"'(?:eval|exec)\\s*\\('", "호출 앵커 — 더 긴 단어에 섞일 수 없다"),
    (r"""'"(?:exec|eval|single)"'""", "따옴표 리터럴 — compile() 의 모드 인자"),
    (r"'\\b(?:eval|exec)\\b'", r"\b 경계"),
])
def test_does_not_flag_guarded_sink_tokens(tmp_path: Path, pattern: str, why: str) -> None:
    """린터의 오탐은 린터를 끄게 만든다. 따옴표 케이스는 실제로 오탐이 났다."""
    assert "sink-token-without-boundary" not in _codes(tmp_path, pattern), why


def test_does_not_flag_secret_name_lists(tmp_path: Path) -> None:
    """`password|token|secret` 은 **찾는 이름 목록**이지 실행 sink 가 아니다.
    이걸 잡으면 24건이 한꺼번에 경고로 뜬다(1차 시제품에서 실제로 그랬다)."""
    codes = _codes(tmp_path, r"'(?:password|passwd|secret|api_key)\\s*=\\s*'")
    assert "sink-token-without-boundary" not in codes


# ---------------------------------------------------------------------------
# ② 부분문자열 정화 화이트리스트 — 통과가 곧 '삭제'라 더 위험하다
# ---------------------------------------------------------------------------

def test_flags_substring_sanitizer_allowlist(tmp_path: Path) -> None:
    """수정 전 `KISA-JS-INPUT-04` 의 실제 패턴. 적대적 검증에서
    `sanitizeMaybe(h){return h.trim()}` 가 이 가드를 통과했다."""
    bad = r"'dangerouslySetInnerHTML\\s*[:=]\\s*(?!.{0,120}(?:DOMPurify|sanitize|escapeHtml))'"
    assert "sanitizer-allowlist-substring" in _codes(tmp_path, bad)


@pytest.mark.parametrize("pattern, why", [
    (r"'\\.innerHTML\\s*=\\s*(?!.{0,80}(?:DOMPurify\\.sanitize\\(|sanitiz\\w*\\s*\\())'",
     "호출 형태를 요구하는 가드"),
    (r"'\\.innerHTML\\s*=\\s*'", "가드를 아예 두지 않고 엔진에 맡긴 형태"),
])
def test_does_not_flag_call_form_or_absent_allowlist(
    tmp_path: Path, pattern: str, why: str,
) -> None:
    assert "sanitizer-allowlist-substring" not in _codes(tmp_path, pattern), why


# ---------------------------------------------------------------------------
# ③ (?i) 아래의 [a-z] — 오탐이 아니라 **미탐**을 만든다(그래서 더 조용하다)
# ---------------------------------------------------------------------------

def test_flags_lowercase_class_under_ignorecase(tmp_path: Path) -> None:
    """`(?i)…(?![a-z])` 는 대문자까지 걸러 `executeTool(llmResponse)`
    (OWASP ASI05)를 함께 죽인다."""
    bad = r"'(?i)(?<![A-Za-z0-9])(?:execute|exec)(?![a-z])'"
    assert "lowercase-class-under-ignorecase" in _codes(tmp_path, bad)


def test_does_not_flag_scoped_case_sensitive_class(tmp_path: Path) -> None:
    good = r"'(?i)(?<![A-Za-z0-9])(?:execute|exec)(?!(?-i:[a-z]))'"
    assert "lowercase-class-under-ignorecase" not in _codes(tmp_path, good)


def test_does_not_flag_lowercase_class_without_ignorecase(tmp_path: Path) -> None:
    """`(?i)` 가 없으면 `[a-z]` 는 원래 의미대로 소문자만 잡는다 — 정상이다."""
    assert "lowercase-class-under-ignorecase" not in _codes(tmp_path, r"'exec(?![a-z])'")


# ---------------------------------------------------------------------------
# 실제 룰셋이 깨끗한가 — 린터를 붙여 놓고 경고가 쌓이면 아무도 안 본다
# ---------------------------------------------------------------------------

def test_shipped_ruleset_has_no_archetype_warnings() -> None:
    """린터를 붙이면서 자기 룰 2건(`.innerHTML`·`.outerHTML` 의 부분문자열 가드)을
    실제로 찾아 고쳤다. 이 테스트는 그 상태를 유지시킨다."""
    from gvskb.scanners.regex_scanner import _resolve_rules_dir

    report = validation.validate_rules_dir(_resolve_rules_dir())
    archetypes = {"sink-token-without-boundary", "sanitizer-allowlist-substring",
                  "lowercase-class-under-ignorecase"}
    offenders = [(i["rule_id"], i["code"]) for i in report["issues"]
                 if i["code"] in archetypes]
    assert not offenders, offenders


# ---------------------------------------------------------------------------
# CI 종료코드 — 달력 때문에 켜지는 경고가 CI 를 빨갛게 만들면 안 된다
# ---------------------------------------------------------------------------

def test_archetypes_are_errors_not_warnings(tmp_path: Path) -> None:
    """archetype 은 ERROR 여야 `--fail-on error` 로 도는 CI 에서 막힌다.
    WARN 이면 CI 를 통과해 그대로 머지된다."""
    report_dir = tmp_path / "rules"
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "TEST-LINT-001.md").write_text(
        _HEAD.format(pattern=_BAD_SINK), encoding="utf-8")
    report = validation.validate_rules_dir(report_dir, today=date(2026, 1, 2))
    bad = [i for i in report["issues"] if i["code"] == "sink-token-without-boundary"]
    assert bad and bad[0]["status"] == "error", bad
    assert report["overall"] == "error"


def test_validate_rules_fail_on_error_ignores_calendar_warnings(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    """`review_due` 만료는 아무도 코드를 바꾸지 않아도 언젠가 켜진다.
    그것으로 CI 를 세우면 팀은 검사를 통째로 끈다 — 그게 최악이다."""
    import argparse

    from gvskb.cli import _cmd_validate_rules

    d = tmp_path / "rules"
    d.mkdir(parents=True, exist_ok=True)
    expired = _HEAD.format(pattern=r"'\beval\s*\('").replace(
        "verified_at: 2026-01-01", "verified_at: 2020-01-01\nreview_due: 2020-06-01")
    (d / "TEST-LINT-001.md").write_text(expired, encoding="utf-8")

    def _run(fail_on: str) -> int:
        return _cmd_validate_rules(argparse.Namespace(
            rules_dir=str(d), json=False, fail_on=fail_on))

    assert _run("warn") != 0, "만료 경고가 warn 모드에서는 잡혀야 한다"
    assert _run("error") == 0, "달력 경고가 CI 를 세우면 안 된다"
    capsys.readouterr()
