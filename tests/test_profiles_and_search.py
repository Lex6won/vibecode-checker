"""Stage 4 — scenario profiles + Korean synonym search + policy/audit schema."""
from __future__ import annotations

from datetime import date
from pathlib import Path

from gvskb.loader import load_all_rules
from gvskb.profiles import ProfileSpec, apply_profile, list_profiles, load_profile
from gvskb.scanner import scan_code
from gvskb.schema import AuditEvent, BypassApproval, Decision, PolicyDecision, Severity
from gvskb.search import expand_query, simple_search

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


# ---------------------------------------------------------------------------
# Profile loader + apply
# ---------------------------------------------------------------------------

def test_profile_list_includes_scenario_profiles() -> None:
    ids = set(list_profiles())
    assert {
        "public-default-strict",
        "civil-complaint-chatbot",
        "internal-db-query",
        "web-civil-service",
    } <= ids


def test_profile_load_known_scenarios() -> None:
    p = load_profile("civil-complaint-chatbot")
    assert p.profile_id == "civil-complaint-chatbot"
    assert "GOV-LLM-PII-PROMPT-001" in p.decision_overrides


def test_profile_load_unknown_returns_empty_spec() -> None:
    p = load_profile("does-not-exist")
    assert p.profile_id == "does-not-exist"
    assert p.decision_overrides == {}


def test_civil_complaint_chatbot_profile_blocks_llm_pii_path() -> None:
    code = 'prompt = f"민원인 주민번호 {citizen_rrn} 처리해줘"\n'
    r = scan_code(code, filename="bot.py", language="python", profile="civil-complaint-chatbot")
    blocked = [f for f in r.findings if f.decision == Decision.block]
    assert blocked, "civil-complaint-chatbot 프로파일은 LLM PII 경로를 block으로 끌어올려야 한다"


def test_internal_db_query_profile_blocks_sql_concat() -> None:
    code = 'cursor.execute("UPDATE board SET name=%s" % name)\n'
    r = scan_code(code, filename="ingest.py", language="python", profile="internal-db-query")
    sql = [f for f in r.findings if f.rule_id == "KISA-PY-INPUT-01"]
    assert sql and sql[0].decision == Decision.block


def test_severity_min_filter_drops_low_findings() -> None:
    """internal-db-query has severity_min=medium — low severity findings disappear."""
    # 인위적 low 룰을 만들기 어려우므로 apply_profile 단위 테스트로 검증
    from gvskb.schema import CodeLocation, Finding
    low = Finding(
        id="x", rule_id="X-LOW-1", title="t", plain_title="t",
        severity=Severity.low, decision=Decision.warn, category="x",
        location=CodeLocation(file="f", line=1), why_it_matters="",
    )
    spec = ProfileSpec(profile_id="t", severity_min="medium")
    assert apply_profile([low], spec) == []


def test_apply_profile_keeps_original_when_no_override() -> None:
    from gvskb.schema import CodeLocation, Finding
    f = Finding(
        id="x", rule_id="UNKNOWN-1", title="t", plain_title="t",
        severity=Severity.high, decision=Decision.warn, category="x",
        location=CodeLocation(file="f", line=1), why_it_matters="",
    )
    spec = ProfileSpec(profile_id="empty")
    out = apply_profile([f], spec)
    assert out == [f]


# ---------------------------------------------------------------------------
# Korean synonym expansion
# ---------------------------------------------------------------------------

def test_synonym_expansion_includes_english_and_korean() -> None:
    terms = set(expand_query("개인정보"))
    assert "개인정보" in terms
    assert "pii" in terms  # 그룹 안의 모든 동의어가 소문자로 정규화됨


def test_synonym_query_finds_korean_phrase_via_english_term() -> None:
    rules = load_all_rules(RULES_DIR)
    hits_kor = simple_search(rules, "프롬프트 인젝션", limit=5)
    hits_eng = simple_search(rules, "prompt injection", limit=5)
    # 두 질의 모두 OWASP-LLM-2025-01에 도달해야 함
    assert any(r.id == "OWASP-LLM-2025-01" for r in hits_kor)
    assert any(r.id == "OWASP-LLM-2025-01" for r in hits_eng)


def test_synonym_query_for_password_term() -> None:
    rules = load_all_rules(RULES_DIR)
    # KISA-PY-SEC-14는 "솔트 없는 해시" 룰이라 password 키워드 검색에 잡혀야 함
    hits = simple_search(rules, "password", limit=10)
    rule_ids = {r.id for r in hits}
    assert any("SEC" in rid for rid in rule_ids)


# ---------------------------------------------------------------------------
# Policy / audit schema models
# ---------------------------------------------------------------------------

def test_policy_decision_model_round_trip() -> None:
    d = PolicyDecision(
        rule_id="KISA-PY-INPUT-01", profile="internal-db-query",
        decision=Decision.block, reason="SQL 인젝션 절대 차단",
        agency="경기도", requires_approval=True,
    )
    j = d.model_dump_json()
    d2 = PolicyDecision.model_validate_json(j)
    assert d2.decision == Decision.block


def test_bypass_approval_requires_expiry() -> None:
    b = BypassApproval(
        finding_id="KISA-PY-INPUT-01:abcdef",
        rule_id="KISA-PY-INPUT-01",
        profile="internal-db-query",
        approver_role="security_manager",
        approver_id="agency-id-123",
        approved_at=date(2026, 5, 31),
        expires_at=date(2026, 6, 30),
        justification="신규 시스템 이관 기간 30일 예외",
    )
    assert b.expires_at > b.approved_at


def test_audit_event_is_hash_centric_not_raw_code() -> None:
    """감사 로그는 원문 코드와 PII를 저장하지 않아야 한다."""
    e = AuditEvent(
        event_type="block", timestamp="2026-05-31T19:00:00+09:00",
        tool="gvskb scan", profile="internal-db-query",
        rule_id="KISA-PY-INPUT-01", decision=Decision.block,
        target_hash="sha256-of-path-and-size",
        finding_id="KISA-PY-INPUT-01:abcdef",
        redacted_evidence='cursor.execute("..." % name)',
        user_role="developer", agency="경기도",
    )
    # 원문 코드 필드 자체가 없어야 함 (클래스 단에서 확인)
    fields = AuditEvent.model_fields.keys()
    assert "code" not in fields
    assert "pii" not in fields
    assert e.target_hash and e.redacted_evidence
