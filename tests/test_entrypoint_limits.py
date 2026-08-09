"""사용자가 실제로 쓰는 경로의 파일 상한이 라이브러리 기본값과 **같은지** 본다.

이 파일이 생긴 이유는 실패한 수정 하나 때문이다. ``scanner.DEFAULT_MAX_FILES``
를 500 에서 20,000 으로 올리면서 정작 CLI(``cli.SCAN_MAX_FILES_DEFAULT``)와
MCP(``server.scan_path``)에 따로 적어 둔 500 을 그대로 뒀다. 라이브러리만
테스트하던 기존 테스트는 전부 통과했고, **사용자는 여전히 500 개만 검사받고
있었다** — 570개짜리 저장소에서 70개가 조용히 빠졌다.

`.innerHTML`·`.outerHTML` 을 놓친 것과 같은 모양이다. 그래서 여기서는 상수를
검사하지 않고 **진입점의 기본값**을 검사한다. 상수를 어디에 적든, 사용자가
호출하는 함수의 서명이 라이브러리와 어긋나면 실패한다.
"""

from __future__ import annotations

import inspect

import pytest

from gvskb.scanner import DEFAULT_MAX_FILES, scan_path


def test_library_default_is_not_a_toy_number() -> None:
    """상한 자체가 실무 저장소를 담을 수 있어야 한다.

    500 은 중간 규모 저장소(lexdiff 570개)에서도 걸린다. 걸리는 순간
    보고서의 '발견 0건'이 '안전'이 아니라 '못 봤다'가 되는데, 그 구분은
    담당자에게 보이지 않는다.
    """
    assert DEFAULT_MAX_FILES >= 20_000


def test_cli_default_matches_library() -> None:
    from gvskb import cli

    assert cli.SCAN_MAX_FILES_DEFAULT == DEFAULT_MAX_FILES


def test_cli_argparse_default_matches_library() -> None:
    """모듈 상수가 아니라 **파서에 실제로 박힌 값**을 본다.

    상수만 고치고 ``add_argument(default=500)`` 을 남기는 실수를 잡기 위해서다.
    """
    from gvskb import cli

    parser = cli.build_parser()
    args = parser.parse_args(["scan", "."])
    assert args.max_files == DEFAULT_MAX_FILES


def test_mcp_scan_path_default_matches_library() -> None:
    """MCP 도구 서명의 기본값. 에이전트는 대개 max_files 를 넘기지 않는다."""
    from gvskb import server

    fn = getattr(server.scan_path, "fn", server.scan_path)
    default = inspect.signature(fn).parameters["max_files"].default
    assert default == DEFAULT_MAX_FILES


def test_scan_path_signature_default_matches_library() -> None:
    assert inspect.signature(scan_path).parameters["max_files"].default == DEFAULT_MAX_FILES


@pytest.mark.parametrize("entry", ["cli", "mcp"])
def test_entrypoint_scans_past_the_old_500_cap(tmp_path, entry: str) -> None:
    """상수 비교로는 못 잡는 것 — 실제로 501번째 파일까지 검사되는가.

    기본값만 맞고 호출부가 다른 값을 넘기면 상수 테스트는 통과한다.
    그래서 파일 501개를 놓고 끝까지 읽는지 본다.
    """
    root = tmp_path / "many"
    root.mkdir()
    for i in range(501):
        (root / f"m{i:04d}.py").write_text(f"x = {i}\n", encoding="utf-8")

    if entry == "cli":
        from gvskb import cli

        args = cli.build_parser().parse_args(["scan", str(root)])
        report = scan_path(str(root), max_files=args.max_files)
    else:
        from gvskb import server

        fn = getattr(server.scan_path, "fn", server.scan_path)
        result = fn(path=str(root))
        report = result["report"] if isinstance(result, dict) and "report" in result else result
        scanned = report["scanned_files"] if isinstance(report, dict) else report.scanned_files
        assert len(scanned) == 501
        return

    assert len(report.scanned_files) == 501
    assert not [s for s in report.skipped_files if "max_files=" in s.reason]
