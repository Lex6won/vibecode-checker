"""scan_path: 디렉토리·파일 일괄 검사 동작 확인."""
from __future__ import annotations

from pathlib import Path

from gvskb.scanner import scan_path


def _write(p: Path, content: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def test_scan_path_aggregates_findings_across_files(tmp_path: Path) -> None:
    _write(
        tmp_path / "app.py",
        "name = input('name')\n"
        "cursor.execute(f\"SELECT * FROM complaints WHERE name = '{name}'\")\n",
    )
    _write(
        tmp_path / "settings.py",
        'OPENAI_API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz"\n',
    )

    report = scan_path(tmp_path)

    rule_ids = {f.rule_id for f in report.findings}
    assert "GOV-SQL-INJECTION-001" in rule_ids
    assert any(rid.startswith("GOV-SECRET") for rid in rule_ids)
    assert report.summary.blocked is True
    assert {"app.py", "settings.py"} <= set(report.scanned_files)


def test_scan_path_skips_excluded_dirs(tmp_path: Path) -> None:
    _write(tmp_path / "src" / "main.py", "import os\n")
    _write(
        tmp_path / "node_modules" / "evil" / "index.js",
        "eval(userInput)\n",
    )
    _write(
        tmp_path / "__pycache__" / "junk.py",
        'OPENAI_API_KEY = "sk-proj-zzzzzzzzzzzzzzzzzz"\n',
    )

    report = scan_path(tmp_path)

    for f in report.scanned_files:
        assert "node_modules" not in f
        assert "__pycache__" not in f


def test_scan_path_skips_binary_and_oversized(tmp_path: Path) -> None:
    big = tmp_path / "big.py"
    big.parent.mkdir(parents=True, exist_ok=True)
    big.write_text("x = 1\n" * 200_000, encoding="utf-8")  # > 1 MB
    (tmp_path / "blob.py").write_bytes(b"\x00\x01\x02binary")

    report = scan_path(tmp_path)

    skipped_reasons = {sf.path: sf.reason for sf in report.skipped_files}
    assert any("too large" in r for r in skipped_reasons.values())
    assert any("binary" in r for r in skipped_reasons.values())


def test_scan_path_returns_clean_report_for_safe_code(tmp_path: Path) -> None:
    _write(
        tmp_path / "safe.py",
        'def total(items):\n'
        '    return sum(item.price for item in items)\n'
        '\n'
        'cursor.execute("SELECT * FROM t WHERE name=%s", (name,))\n',
    )

    report = scan_path(tmp_path)
    assert report.summary.finding_count == 0
    assert report.summary.blocked is False
    assert "safe.py" in report.scanned_files


def test_scan_path_returns_skipped_entry_for_missing_path(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist"
    report = scan_path(missing)
    assert report.summary.finding_count == 0
    assert len(report.skipped_files) == 1
    assert report.skipped_files[0].reason == "path does not exist"


# ---------------------------------------------------------------------------
# 노이즈 제거 — 빌드 산출물(압축/번들·빌드 출력 디렉터리) 자동 제외
# ---------------------------------------------------------------------------

from gvskb.scanner import (  # noqa: E402
    BUILD_ARTIFACT_SKIP_REASON,
    VENDOR_BUNDLE_SKIP_REASON,
)

# 룰이 줄마다 걸리는 미니파이드 번들 한 줄. 검사하면 오탐이 폭주한다.
_NOISY = "function deleteNode(){};function removeItem(){};agent.send_email();\n" * 40


def test_scan_path_excludes_build_output_dirs(tmp_path: Path) -> None:
    _write(tmp_path / "src" / "app.py", "import os\n")
    _write(tmp_path / "public" / "assets" / "bundle.js", _NOISY)
    _write(tmp_path / ".puppeteer-cache" / "chrome.js", _NOISY)
    _write(tmp_path / ".tmp" / "scratch.js", _NOISY)
    _write(tmp_path / "dist" / "out.js", _NOISY)

    report = scan_path(tmp_path)

    # 노이즈 파일은 한 건도 검사되지 않는다.
    for f in report.scanned_files:
        assert "public/assets" not in f.replace("\\", "/")
        assert ".puppeteer-cache" not in f
        assert ".tmp" not in f
        assert "dist" not in f
    # 제외 사실은 빌드 산출물로 기록된다(버리되 정직).
    build = [s for s in report.skipped_files if s.reason == BUILD_ARTIFACT_SKIP_REASON]
    assert len(build) >= 4


def test_scan_path_skips_minified_and_hashed_files(tmp_path: Path) -> None:
    # 해시 파일명 · single-line 초장문 = 빌드 산출물, `*.min.js` = 벤더 번들.
    # 셋 다 소스 룰 검사에서는 빠지지만 **사유가 다르다** — 벤더 번들은 조용히
    # 버리지 않고 컴포넌트 취약점 검사로 넘긴다(라운드6).
    _write(tmp_path / "src" / "main.py", "import os\n")
    _write(tmp_path / "src" / "index-3f9a2c1b.js", _NOISY)   # 해시 파일명
    _write(tmp_path / "src" / "widget.min.js", "var a=1;\n" * 5)  # *.min.*
    _write(tmp_path / "src" / "inline.js", "x" * 3000 + ";\n")  # single-line 초장문

    report = scan_path(tmp_path)

    scanned = {f.replace("\\", "/") for f in report.scanned_files}
    assert "src/main.py" in scanned
    assert "src/index-3f9a2c1b.js" not in scanned
    assert "src/widget.min.js" not in scanned
    assert "src/inline.js" not in scanned
    build = [s for s in report.skipped_files if s.reason == BUILD_ARTIFACT_SKIP_REASON]
    assert len(build) >= 2
    vendor = [s for s in report.skipped_files if s.reason == VENDOR_BUNDLE_SKIP_REASON]
    assert [s.path.replace("\\", "/") for s in vendor] == ["src/widget.min.js"]
    # 제외로 끝나지 않고 컴포넌트 후보로 남아야 한다.
    assert [b["name"] for b in report.vendor_bundles] == ["widget"]


def test_scan_path_keeps_real_source_when_noise_present(tmp_path: Path) -> None:
    # 노이즈를 걷어내도 진짜 위험은 그대로 잡혀야 한다(과잉 제외 방지).
    _write(
        tmp_path / "src" / "app.py",
        "name = input('name')\n"
        "cursor.execute(f\"SELECT * FROM t WHERE n = '{name}'\")\n",
    )
    _write(tmp_path / "public" / "assets" / "bundle-9e8d7c6b.js", _NOISY)

    report = scan_path(tmp_path)
    rule_ids = {f.rule_id for f in report.findings}
    assert "GOV-SQL-INJECTION-001" in rule_ids
    assert "src/app.py" in {f.replace("\\", "/") for f in report.scanned_files}
