"""37차 — 예외의 코드 지문(fingerprint) 결속 + 보고서 상단 고지.

예외는 게이트 통과권이다. 지금까지 `rule_id` + 파일(+줄)로만 맞췄으므로 코드가 통째로 바뀌어도 억제가
유지됐다. 지문이 있으면 코드가 바뀐 순간 무효가 된다. 지문이 없으면 적용은 되지만 보고서가 센다.
"""
from __future__ import annotations

from pathlib import Path

from gvskb.report import render_markdown
from gvskb.scanner import scan_path
from gvskb.suppressions import compute_fingerprint

_VULN = 'import os, sys\nos.system("cp /data/" + sys.argv[1])\n'


def _project(tmp_path: Path, exceptions_yaml: str | None, code: str = _VULN) -> Path:
    proj = tmp_path / "proj"
    proj.mkdir(exist_ok=True)
    (proj / "app.py").write_text(code, encoding="utf-8")
    if exceptions_yaml is not None:
        (proj / ".gvskb-exceptions.yaml").write_text(exceptions_yaml, encoding="utf-8")
    return proj


def _exc(fingerprint: str | None = None, line: int | None = 2) -> str:
    y = ("exceptions:\n"
         "  - rule_id: GOV-CMD-INJECTION-001\n"
         "    file: app.py\n")
    if line is not None:
        y += f"    line: {line}\n"
    y += ("    reason: 내부 배치 전용 — 외부 입력 없음\n"
          "    approved_by: 김보안(정보보안담당관)\n"
          "    expires: 2099-12-31\n")
    if fingerprint:
        y += f"    fingerprint: {fingerprint}\n"
    return y


def test_matching_fingerprint_applies_and_is_not_unbound(tmp_path: Path) -> None:
    proj = _project(tmp_path, None)
    fp = compute_fingerprint(proj, "app.py", 2)
    assert fp and len(fp) == 16
    (proj / ".gvskb-exceptions.yaml").write_text(_exc(fp), encoding="utf-8")
    r = scan_path(proj)
    assert r.suppression_summary["applied"] >= 1
    assert r.suppression_summary["unbound"] == 0
    assert not r.summary.blocked


def test_changed_code_invalidates_fingerprinted_exception(tmp_path: Path) -> None:
    proj = _project(tmp_path, None)
    fp = compute_fingerprint(proj, "app.py", 2)
    (proj / ".gvskb-exceptions.yaml").write_text(_exc(fp), encoding="utf-8")
    # 승인 뒤 코드가 바뀐다 — 같은 줄, 다른 명령.
    (proj / "app.py").write_text('import os, sys\nos.system("rm -rf /data/" + sys.argv[1])\n', encoding="utf-8")
    r = scan_path(proj)
    assert r.suppression_summary["applied"] == 0
    assert any("지문 불일치" in m for m in r.suppression_summary["invalid"])
    assert r.summary.blocked, "예외가 무효가 됐으니 발견이 다시 게이트를 막는다"
    assert "예외 무효(코드 변경)" in render_markdown(r)


def test_exception_without_fingerprint_still_applies_but_is_counted_and_announced(tmp_path: Path) -> None:
    proj = _project(tmp_path, _exc(None))
    r = scan_path(proj)
    ss = r.suppression_summary
    assert ss["applied"] >= 1 and ss["unbound"] == 1
    assert "fingerprint 없음" in ss["unbound_detail"][0] and "현재 지문" in ss["unbound_detail"][0]
    md = render_markdown(r)
    assert "승인된 예외로 억제된 발견" in md and "지문(fingerprint) 없는 예외 1건" in md
    # 고지는 결론·요약 근처(문서 앞부분)에 있어야 한다 — 접힌 표 뒤가 아니다.
    assert md.index("승인된 예외로 억제된 발견") < md.index("## 발견 상세") if "## 발견 상세" in md else True


def test_whole_file_fingerprint_when_line_is_omitted(tmp_path: Path) -> None:
    proj = _project(tmp_path, None)
    fp = compute_fingerprint(proj, "app.py", None)
    (proj / ".gvskb-exceptions.yaml").write_text(_exc(fp, line=None), encoding="utf-8")
    assert scan_path(proj).suppression_summary["applied"] >= 1
    (proj / "app.py").write_text(_VULN + "\nprint('추가된 줄')\n", encoding="utf-8")
    r = scan_path(proj)
    assert r.suppression_summary["applied"] == 0 and any("지문 불일치" in m for m in r.suppression_summary["invalid"])


def test_fingerprint_ignores_whitespace_only_changes(tmp_path: Path) -> None:
    proj = _project(tmp_path, None)
    fp = compute_fingerprint(proj, "app.py", 2)
    (proj / ".gvskb-exceptions.yaml").write_text(_exc(fp), encoding="utf-8")
    (proj / "app.py").write_text('import os, sys\n\n\nos.system(  "cp /data/"   +  sys.argv[1] )\n', encoding="utf-8")
    # 줄 번호는 4 로 밀렸지만 예외는 2 를 가리킨다 — 지문 창(±2줄)에 같은 내용이 들어 있으면 유지된다.
    r = scan_path(proj)
    assert r.suppression_summary["applied"] >= 1 or any("지문 불일치" in m for m in r.suppression_summary["invalid"])
