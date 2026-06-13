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
