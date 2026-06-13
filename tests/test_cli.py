"""gvskb CLI 동작 확인 (in-process)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from gvskb import cli


def test_cli_scan_markdown_outputs_to_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text(
        "name = input('name')\n"
        "cursor.execute(f\"SELECT * FROM complaints WHERE name = '{name}'\")\n",
        encoding="utf-8",
    )
    out = tmp_path / "report.md"

    rc = cli.main(["scan", str(src), "-o", str(out)])

    assert rc == cli.EXIT_FINDINGS_BLOCK
    text = out.read_text(encoding="utf-8")
    assert "코드 보안 검사 결과" in text
    assert "GOV-SQL-INJECTION-001" in text


def test_cli_scan_json_format_to_stdout(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "safe.py").write_text('print("ok")\n', encoding="utf-8")

    rc = cli.main(["scan", str(src), "--format", "json"])

    assert rc == cli.EXIT_OK
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["summary"]["finding_count"] == 0
    assert "safe.py" in payload["scanned_files"]


def test_cli_report_renders_saved_json(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "settings.py").write_text(
        'OPENAI_API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz"\n',
        encoding="utf-8",
    )
    json_path = tmp_path / "report.json"
    md_path = tmp_path / "out.md"

    # first produce JSON via scan
    rc1 = cli.main(["scan", str(src), "--format", "json", "-o", str(json_path)])
    assert rc1 in (cli.EXIT_OK, cli.EXIT_FINDINGS_WARN, cli.EXIT_FINDINGS_BLOCK)
    # then render it
    rc2 = cli.main(["report", str(json_path), "-o", str(md_path)])
    assert rc2 == cli.EXIT_OK
    text = md_path.read_text(encoding="utf-8")
    assert "코드 보안 검사 결과" in text


def test_cli_report_missing_file(tmp_path: Path) -> None:
    rc = cli.main(["report", str(tmp_path / "no.json")])
    assert rc == cli.EXIT_NOT_FOUND
