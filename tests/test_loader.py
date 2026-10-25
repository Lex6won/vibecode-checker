"""기본 스모크 테스트."""
from pathlib import Path

import pytest

from gvskb.loader import RuleLoadError, load_all_rules
from gvskb.schema import Rule, Severity, SourceLayer
from gvskb.search import simple_search

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


@pytest.fixture(scope="module")
def rules() -> list[Rule]:
    return load_all_rules(RULES_DIR)


def test_reference_seed_rules_present(rules):
    """The 5 original reference rules must always be loadable."""
    ids = {r.id for r in rules}
    seed_ids = {
        "OWASP-LLM-2025-01",
        "OWASP-LLM-2025-02",
        "NIS-AI-M01",
        "MOIS-49-SW-17",
        "INTEL-2026-SLOPSQUATTING",
    }
    missing = seed_ids - ids
    assert not missing, f"missing seed rules: {missing}"


# 줄 단위 regex 로는 오탐이 불가피해 **전용 엔진(AST)이 발행**하는 룰.
# patterns 를 의도적으로 비워 두며, 대신 해당 엔진의 supported_rule_ids 에 등록된다.
_ENGINE_ONLY_RULE_IDS = {
    "GOV-SQL-DDL-DYNAMIC-001",   # python-ast 가 DDL 접두사를 확인한 뒤 발행
    "GOV-SECRET-KEYFILE-001",    # scan_path 가 파일명 + 내용을 함께 보고 발행
    # 37차 — autoexec-surface 엔진(파일 이름·위치 + 구조 해석)
    "GOV-AUTOEXEC-IDE-TASK-001",
    "GOV-AUTOEXEC-AGENT-HOOK-001",
    "GOV-AGENT-CONFIG-PERMISSION-001",
    "GOV-MCP-CONFIG-001",
    "GOV-AUTOEXEC-PYTHON-STARTUP-001",
    # 37차 — hidden-text 엔진(코드포인트 단위)
    "GOV-HIDDEN-UNICODE-001",
    "GOV-BIDI-CONTROL-001",
    # 38차 — ci-workflow · npm-surface · runtime-version 판정기(구조 해석)
    "GOV-CI-PWN-REQUEST-001",
    "GOV-CI-SECRETS-DUMP-001",
    "GOV-CI-SCRIPT-INJECTION-001",
    "GOV-CI-REMOTE-EXEC-001",
    "GOV-CI-UNPINNED-ACTION-001",
    "GOV-CI-PERMISSIONS-001",
    "GOV-NPM-INSTALL-HOOK-001",
    "GOV-NPM-LOCK-SOURCE-001",
    "GOV-RUNTIME-EOL-001",
    "GOV-RUNTIME-OUTDATED-001",
    # 39차 — agent-surface 어댑터(실행 소스 행위 결합 판정)
    "GOV-AGENT-CLI-ABUSE-001",
    "GOV-AGENT-CRED-EXFIL-001",
    "GOV-AGENT-C2-CHANNEL-001",
    "GOV-AGENT-INSTRUCTION-ABUSE-001",   # autoexec-surface 수집기가 결합 판정으로 발행
    # 40차 — ecosystem-surface 수집기(Electron·VS Code 확장·Chrome 확장·MCP 서버; 구조 해석)
    "GOV-ELECTRON-WEBPREFS-001",
    "GOV-ELECTRON-IPC-BRIDGE-001",
    "GOV-ELECTRON-HARDENING-001",
    "GOV-VSCODE-EXT-TRUST-001",
    "GOV-CHROME-EXT-PERMISSION-001",
    "GOV-CHROME-EXT-HEADER-STRIP-001",
    "GOV-CHROME-EXT-MESSAGE-001",
    "GOV-MCP-SERVER-001",
    # 42차 — authz-posture 수집기(관리자 경로 보호 근거 부재 · 클라이언트 관문; 프로젝트 맥락). 테스트: test_round42_authz_posture.py
    "GOV-AUTHZ-ADMIN-POSTURE-001",
    "GOV-AUTHZ-CLIENT-GATE-001",
}


def test_scanner_builtin_rules_present_and_have_detection(rules):
    """All scanner-builtin GOV-* rules must carry a detection block (single source of truth)."""
    builtin = [r for r in rules if r.id.startswith("GOV-")]
    assert len(builtin) >= 11, f"expected at least 11 GOV-* rules, got {len(builtin)}"
    for r in builtin:
        assert r.detection is not None, f"{r.id} missing detection block"
        if r.id in _ENGINE_ONLY_RULE_IDS:
            assert not r.detection.patterns, f"{r.id} is engine-only — patterns must stay empty"
            continue
        assert r.detection.patterns, f"{r.id} has no detection patterns"


def test_engine_only_rules_are_claimed_by_an_engine():
    """전용 엔진 룰은 반드시 어떤 엔진이 발행한다고 선언돼 있어야 한다.

    선언이 없으면 patterns 도 없고 발행 주체도 없어 **영원히 침묵하는 룰**이 된다.
    """
    from gvskb.scanner import path_level_rule_ids
    from gvskb.scanners.ast_scanner import supported_rule_ids

    claimed = set(supported_rule_ids()) | set(path_level_rule_ids())
    for rule_id in _ENGINE_ONLY_RULE_IDS:
        assert rule_id in claimed, f"{rule_id} has no patterns and no engine claims it"


def test_all_rules_have_required_metadata(rules):
    for r in rules:
        assert r.title_ko
        assert r.sources, f"{r.id} has no sources"
        assert r.severity in Severity
        assert r.source_layer in SourceLayer
        assert r.verified_at is not None
        assert r.body, f"{r.id} has empty body"


def test_search_finds_prompt_injection(rules):
    hits = simple_search(rules, "프롬프트 인젝션", limit=5)
    assert any(r.id == "OWASP-LLM-2025-01" for r in hits)


def test_search_filters_by_scenario(rules):
    hits = simple_search(rules, "데이터", scenario="data-pipeline", limit=5)
    for r in hits:
        assert "data-pipeline" in r.scenarios


def test_realtime_rule_present(rules):
    rt = [r for r in rules if r.source_layer == SourceLayer.realtime]
    assert len(rt) >= 1
    assert any(r.id == "INTEL-2026-SLOPSQUATTING" for r in rt)


def test_load_all_rules_strict_raises_on_bad_rule(tmp_path: Path):
    (tmp_path / "BAD.md").write_text("no frontmatter\n", encoding="utf-8")
    with pytest.raises(RuleLoadError) as excinfo:
        load_all_rules(tmp_path, strict=True)
    assert "frontmatter not found" in str(excinfo.value)


def test_load_all_rules_non_strict_skips_bad_rule(tmp_path: Path):
    (tmp_path / "BAD.md").write_text("no frontmatter\n", encoding="utf-8")
    assert load_all_rules(tmp_path, strict=False) == []
