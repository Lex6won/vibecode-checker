"""실제 프로젝트에서 나온 오탐을 고정하는 회귀 테스트.

출처: 외부 Next.js/TypeScript 프로젝트(129파일)를 검사했을 때 16건 중 14건이
오탐이었고, 그중 critical 12건이 전부 오탐이라 배포 차단 판정까지 났다. 여기
있는 스니펫은 전부 그때 실제로 잘못 잡힌 코드다 — 임의로 만든 예시가 아니다.

같은 회귀가 다시 나면 이 파일이 먼저 깨진다.
"""
from __future__ import annotations

import pytest

from gvskb.scanner import (
    attenuate_test_path_findings,
    is_test_path,
    scan_code,
)
from gvskb.scanners.regex_scanner import (
    _rrn_checksum_ok,
    dedupe_by_group,
    evidence_for_match,
)
from gvskb.schema import Decision, Severity


def _rule_ids(code: str, *, filename: str = "<memory>", language: str | None = None) -> set[str]:
    report = scan_code(code, filename=filename, language=language,
                       collapse_duplicates=False)
    return {f.rule_id for f in report.findings}


# ---------------------------------------------------------------------------
# GOV-PII-RRN-001 — 13자리 정수를 주민등록번호로 오인
# ---------------------------------------------------------------------------

# Drizzle 마이그레이션 journal 의 Unix 밀리초 타임스탬프. 예전 패턴
# `\b\d{6}-?[1-4]\d{6}\b` 는 하이픈이 선택적이고 날짜 검증이 없어 이 값들을
# 전부 critical + block 으로 보고했다(앞 6자리를 날짜로 읽으면 "17년 84월 65일").
_TIMESTAMP_FALSE_POSITIVES = [
    '{"when": 1784654517497, "tag": "0000_bouncy_gamora"}',
    '{"when": 1784683391754, "tag": "0003_perfect_smasher"}',
    '{"when": 1784722092319, "tag": "0004_purple_swordsman"}',
    '{"when": 1784781736523, "tag": "0005_worried_whizzer"}',
]


@pytest.mark.parametrize("snippet", _TIMESTAMP_FALSE_POSITIVES)
def test_unix_millisecond_timestamp_is_not_a_resident_number(snippet: str) -> None:
    assert "GOV-PII-RRN-001" not in _rule_ids(snippet, language="python")


def test_real_resident_number_still_detected_with_hyphen() -> None:
    assert "GOV-PII-RRN-001" in _rule_ids('rrn = "900101-1234567"', language="python")


def test_documentation_placeholder_is_not_a_resident_number() -> None:
    """체커 자신의 설명도 실제 개인정보처럼 보이는 값을 남기지 않는다."""
    assert "GOV-PII-RRN-001" not in _rule_ids("# 예시 번호: YYMMDD-XXXXXXX", language="python")


def test_real_resident_number_still_detected_without_hyphen() -> None:
    # 하이픈이 없으면 검증식(mod 11)까지 통과해야 한다.
    assert "GOV-PII-RRN-001" in _rule_ids('rrn = 8203154567890', language="python")


def test_bare_13_digits_failing_checksum_is_ignored() -> None:
    # 날짜는 유효하지만(90년 01월 01일) 검증숫자가 틀린 값.
    assert "GOV-PII-RRN-001" not in _rule_ids('order_no = 9001011234560', language="python")


def test_invalid_date_is_rejected_even_when_checksum_passes() -> None:
    """날짜 검증을 **독립적으로** 고정한다.

    변이 검사에서 날짜 검증을 빼도 타임스탬프 테스트가 통과했다 — 검증식이 대신
    잡았기 때문이다. 두 층이 겹치는 건 좋지만, 그러면 날짜 층이 죽어도 아무도
    모른다. 아래 값은 앞 6자리가 "17년 84월 65일"인데 검증식은 통과한다.
    """
    assert "GOV-PII-RRN-001" not in _rule_ids('seq = 1784654000009', language="python")


def test_invalid_date_is_rejected_when_hyphenated() -> None:
    """하이픈이 있으면 검증식을 건너뛰므로 **날짜가 유일한 방어선**이다."""
    assert "GOV-PII-RRN-001" not in _rule_ids('ref = "178465-4517497"', language="python")


def test_rrn_checksum_skips_hyphenated_values() -> None:
    """하이픈이 있으면 검증식을 적용하지 않는다.

    2020.10. 뒷자리 개편 이후 번호에도 검증식이 성립한다고 단정할 근거가 없어,
    형태가 명확한 쪽(하이픈)에는 적용하지 않기로 했다 — 불확실한 규칙을 미탐
    쪽에 쓰지 않기 위해서다.
    """
    assert _rrn_checksum_ok("900101-1234567") is True     # 검증숫자 불일치지만 통과
    assert _rrn_checksum_ok("8203154567890") is True      # 하이픈 없음 + 검증식 일치
    assert _rrn_checksum_ok("1784654517497") is False     # 타임스탬프


# ---------------------------------------------------------------------------
# GOV-SECRET-APIKEY-001 — 테스트 픽스처 오탐 / SECRET_KEY 미탐
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("snippet", [
    'const base = { apiKey: "test-only-key", model: "gpt-5.6-sol" };',
    'assert.deepEqual(classroom, { classCode: "1234", joinToken: "join_old" });',
    'await rotateClassroomEntry(DB, { classCode: "9876", joinToken: "join_new" });',
])
def test_test_fixture_values_are_not_reported_as_secrets(snippet: str) -> None:
    assert "GOV-SECRET-APIKEY-001" not in _rule_ids(snippet, language="javascript")


def test_django_secret_key_is_detected() -> None:
    """예전 패턴은 키워드 바로 뒤 `[:=]` 를 요구해 SECRET_KEY 를 통째로 놓쳤다."""
    ids = _rule_ids('SECRET_KEY = "d9f2ka83jdkq0zmx84hsly26rbtv51cn"', language="python")
    assert "GOV-SECRET-APIKEY-001" in ids


def test_word_containing_test_is_still_detected() -> None:
    """테스트 픽스처 제외가 'latest' 같은 평범한 단어를 삼키면 안 된다."""
    ids = _rule_ids('password = "latestbuild9x2"', language="python")
    assert "GOV-SECRET-APIKEY-001" in ids


# ---------------------------------------------------------------------------
# GOV-LLM-PII-PROMPT-001 — 식별자 안쪽의 'openai' 오탐
# ---------------------------------------------------------------------------

def test_function_name_containing_openai_is_not_an_llm_call() -> None:
    """시크릿이 새지 '않는지' 검증하는 테스트가 개인정보 전송으로 보고됐었다."""
    snippet = (
        'await assert.rejects(requestStructuredOpenAI({ ...base, fetchImpl: async () => '
        'new Response("secret upstream body", { status: 429 }) }));'
    )
    assert "GOV-LLM-PII-PROMPT-001" not in _rule_ids(snippet, language="javascript")


def test_real_openai_call_with_pii_still_detected() -> None:
    snippet = 'resp = openai.chat.completions.create(messages=[{"content": f"주민번호 {rrn}"}])'
    assert "GOV-LLM-PII-PROMPT-001" in _rule_ids(snippet, language="python")


# ---------------------------------------------------------------------------
# 증거(evidence) — 매치 구간을 보여야 한다
# ---------------------------------------------------------------------------

def test_evidence_shows_the_match_not_the_line_start() -> None:
    """긴 줄에서 줄 앞부분만 보여주면 정탐도 오탐으로 읽힌다.

    실측: VoiceWhisper.tsx 의 빈 catch 가 300자짜리 줄 *끝*에 있어 증거에는
    `useEffect(() => { fetch("/api/voice"...` 만 찍혔다.
    """
    line = 'useEffect(() => { fetch("/api/voice").then((r) => r.json()).then(' + "x" * 200 + ' }).catch(() => {}); }, []);'
    start = line.index(".catch")
    evidence = evidence_for_match(line, start, start + len(".catch(() => {})"))
    assert ".catch(() => {})" in evidence
    assert evidence.startswith("… ")
    assert "useEffect" not in evidence


def test_short_line_evidence_is_kept_whole() -> None:
    line = '  } catch (err) {}'
    assert evidence_for_match(line, 4, len(line)).strip() == "} catch (err) {}"


def test_scan_evidence_contains_the_matched_secret_context() -> None:
    padding = "// " + "z" * 220
    line = f'const cfg = {{ {padding} , password: "hunter2plus9" }};'
    report = scan_code(line, filename="app.js", language="javascript")
    secret = [f for f in report.findings if f.rule_id == "GOV-SECRET-APIKEY-001"]
    assert secret, "hardcoded password should be detected"
    # 값은 마스킹되지만 어느 필드가 걸렸는지는 보여야 한다.
    assert "password" in secret[0].evidence


# ---------------------------------------------------------------------------
# 테스트 경로 감쇄
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path,expected", [
    ("tests/classroom-delete.test.mjs", True),
    ("src/__tests__/auth.spec.ts", True),
    ("api/test_login.py", True),
    ("lib/conftest.py", True),
    ("services/user_test.py", True),
    ("app/components/Archive.tsx", False),
    ("app/latest/page.tsx", False),      # 'latest' 는 테스트가 아니다
    ("src/contest_entry.py", False),     # 'contest' 도 아니다
    ("<memory>", False),
])
def test_is_test_path(path: str, expected: bool) -> None:
    assert is_test_path(path) is expected


def test_secret_in_test_file_is_attenuated_not_deleted() -> None:
    code = 'const cfg = { password: "Ab3xK9mQ2pR7sT1uV" };'
    report = scan_code(code, filename="tests/auth.test.mjs", language="javascript")
    secret = [f for f in report.findings if f.rule_id == "GOV-SECRET-APIKEY-001"]
    assert secret, "발견을 지우면 안 된다 — 테스트에 진짜 키를 넣는 사고도 흔하다"
    assert secret[0].severity == Severity.low
    assert secret[0].decision == Decision.warn
    assert secret[0].requires_approval_to_bypass is False
    assert secret[0].severity_adjusted and "테스트 코드 경로" in secret[0].severity_adjusted


def test_secret_in_production_file_keeps_full_severity() -> None:
    code = 'const cfg = { password: "Ab3xK9mQ2pR7sT1uV" };'
    report = scan_code(code, filename="app/config.js", language="javascript")
    secret = [f for f in report.findings if f.rule_id == "GOV-SECRET-APIKEY-001"]
    assert secret and secret[0].severity == Severity.critical
    assert secret[0].severity_adjusted is None


def test_injection_rules_are_not_attenuated_in_tests() -> None:
    """값이 아니라 *코드 모양*이 문제인 룰은 테스트 코드에서도 그대로 둔다."""
    code = 'cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)'
    findings = scan_code(code, filename="tests/test_db.py", language="python").findings
    sqli = [f for f in findings if f.rule_id == "KISA-PY-INPUT-01"]
    assert sqli and sqli[0].severity_adjusted is None


def test_attenuation_is_a_no_op_for_non_test_paths() -> None:
    code = 'password = "Ab3xK9mQ2pR7sT1uV"'
    findings = scan_code(code, filename="app/settings.py", language="python").findings
    assert attenuate_test_path_findings(findings, "app/settings.py") == findings


# ---------------------------------------------------------------------------
# 룰 간 중복 묶기
# ---------------------------------------------------------------------------

def test_overlapping_error_rules_collapse_to_one_finding() -> None:
    """KISA-JS-ERR-02 와 -03 은 같은 빈 catch 를 각각 보고했다."""
    code = 'promise.then(run).catch(() => {});'
    collapsed = scan_code(code, filename="app/x.js", language="javascript").findings
    both = scan_code(code, filename="app/x.js", language="javascript",
                     collapse_duplicates=False).findings

    def err_ids(findings):
        return sorted(f.rule_id for f in findings if f.rule_id.startswith("KISA-JS-ERR"))

    assert err_ids(both) == ["KISA-JS-ERR-02", "KISA-JS-ERR-03"]
    assert len(err_ids(collapsed)) == 1


def test_dedup_keeps_findings_without_a_group() -> None:
    code = 'password = "Ab3xK9mQ2pR7sT1uV"'
    findings = scan_code(code, filename="app/settings.py", language="python",
                         collapse_duplicates=False).findings
    assert dedupe_by_group(findings) == findings


# ---------------------------------------------------------------------------
# 리포트 묶음 — 감쇄된 발견이 진짜 발견과 한 카드로 합쳐지면 안 된다
# ---------------------------------------------------------------------------

def test_rule_groups_do_not_merge_attenuated_with_real(tmp_path) -> None:
    """같은 룰이 운영 코드에서는 치명, 테스트에서는 감쇄일 때 카드가 갈려야 한다.

    rule_id 만으로 묶으면 카드 머리의 '심각도 조정: critical → low' 가 운영 코드의
    진짜 시크릿에까지 걸린 것처럼 읽히고, decision 은 첫 발견의 것을 쓰므로
    차단이 경고로 표시된다.
    """
    from gvskb.report import _rule_groups
    from gvskb.scanner import scan_path

    (tmp_path / "app").mkdir()
    (tmp_path / "tests").mkdir()
    secret = 'SECRET_KEY = "d9f2ka83jdkq0zmx84hsly26rbtv51cn"\n'
    (tmp_path / "app" / "config.py").write_text(secret, encoding="utf-8")
    (tmp_path / "tests" / "test_config.py").write_text(secret, encoding="utf-8")

    report = scan_path(tmp_path)
    groups = [g for g in _rule_groups(report.findings)
              if g["rule_id"] == "GOV-SECRET-APIKEY-001"]
    assert len(groups) == 2, "감쇄된 발견과 진짜 발견은 다른 카드여야 한다"

    by_sev = {g["severity"]: g for g in groups}
    assert by_sev[Severity.critical]["decision"] == Decision.block
    assert by_sev[Severity.critical]["sample"].severity_adjusted is None
    assert by_sev[Severity.low]["decision"] == Decision.warn
    assert by_sev[Severity.low]["sample"].severity_adjusted


def test_rule_group_decision_matches_its_findings() -> None:
    """묶음의 decision 이 실제 구성원과 어긋나면 차단이 경고로 보인다."""
    from gvskb.report import _rule_groups
    code = 'password = "Ab3xK9mQ2pR7sT1uV5wY8"'
    findings = scan_code(code, filename="app/settings.py", language="python").findings
    for group in _rule_groups(findings):
        assert {f.decision for f in group["findings"]} == {group["decision"]}
        assert {f.severity for f in group["findings"]} == {group["severity"]}


# ---------------------------------------------------------------------------
# 시크릿 이름 넓히기의 부작용 — 시크릿을 '가리키는' 이름은 시크릿이 아니다
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("snippet", [
    'token_endpoint = "https://auth.acme.invalid/oauth/token"',
    'token_url = "https://idp.acme.invalid/token"',
    'secret_name = "prod-db-credential"',
    'password_field = "user_password"',
    'api_key_header = "X-Api-Key-Value"',
    'password_hint = "생일 8자리를 입력하세요"',
    'secret_keystore = "/etc/ssl/keystore.jks"',
])
def test_names_that_reference_a_secret_are_not_secrets(snippet: str) -> None:
    """SECRET_KEY 미탐을 고치며 뒷마디를 아무 단어나 받았다가 전부 오탐이 됐다."""
    assert "GOV-SECRET-APIKEY-001" not in _rule_ids(snippet, language="python")


@pytest.mark.parametrize("snippet", [
    'SECRET_KEY = "d9f2ka83jdkq0zmx84hsly26rbtv51cn"',
    'JWT_SECRET_KEY = "Ab3xK9mQ2pR7sT1uV5wY8zC4dE6f"',
    'API_TOKEN_SECRET = "Zq4mN8vB2xK6pL9rT3wY7cE1"',
    'DB_PASSWORD = "P4ssw0rdLongEnough"',
])
def test_suffixed_secret_names_are_still_detected(snippet: str) -> None:
    assert "GOV-SECRET-APIKEY-001" in _rule_ids(snippet, language="python")


# ---------------------------------------------------------------------------
# KISA-PY-INPUT-03 — 고정 경로 open 이 '경로 조작'으로 차단되던 문제
#
# 출처: 백테스트 파이프라인(semi_fable5) 검사에서 8건이 전부 이 형태였고,
# 모두 '높음·차단'이라 정상 프로젝트의 배포 판정이 막혔다.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("snippet", [
    'with open(os.path.join(DATA_DIR, "meta.json"), "w", encoding="utf-8") as f:',
    'with open(os.path.join(DATA_DIR, "params.json"), "r", encoding="utf-8") as f:',
    'open(os.path.join(BASE_DIR, "config", "app.json"))',
    "open(os.path.join(DATA_DIR,'meta.json'))",
    'return send_file(os.path.join(EXPORT_DIR, "report.pdf"))',
])
def test_constant_path_join_is_not_path_traversal(snippet: str) -> None:
    """조각이 전부 문자열 리터럴이면 경로가 동적이지 않다."""
    assert "KISA-PY-INPUT-03" not in _rule_ids(snippet, language="python")


@pytest.mark.parametrize("snippet", [
    "with open(os.path.join(UPLOAD_DIR, filename)) as f:",
    'with open(os.path.join(BASE_DIR, "sub", user_name)) as f:',
    'with open(os.path.join(BASE_DIR, f"{report_id}.json")) as f:',
    "return send_file(os.path.join(EXPORT_DIR, requested))",
    'data = open(request.args["path"]).read()',
])
def test_dynamic_path_join_is_still_detected(snippet: str) -> None:
    """반대 방향 고정 — 변수·f-string이 섞이면 여전히 잡아야 한다."""
    assert "KISA-PY-INPUT-03" in _rule_ids(snippet, language="python")


def test_path_rule_whitespace_lookahead_actually_narrows() -> None:
    """전방탐색 밖에 `\\s*` 를 두면 0글자로 백트래킹해 공백이 '따옴표 아님'으로
    통과한다 — 아무것도 좁혀지지 않은 채 '수정 완료'가 되는 함정이다."""
    import re
    broken = re.compile(r'open\s*\(\s*os\.path\.join\s*\([^)]*,\s*(?!["\'])')
    fixed = re.compile(r'open\s*\(\s*os\.path\.join\s*\([^)]*,(?!\s*["\'])')
    line = 'open(os.path.join(DATA_DIR, "meta.json"), "w")'
    assert broken.search(line), "이 형태가 예전에 통과하던 것을 고정해 둔다"
    assert not fixed.search(line)


# ---------------------------------------------------------------------------
# GOV-SECRET-APIKEY-001 — 환경변수·템플릿 주입 표기
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("snippet", [
    'DB_PASSWORD = "${DB_PASSWORD}"',
    'api_key = "${CIVIL_AI_API_KEY}"',
    'VAULT_SECRET = "{{ vault_secret }}"',
    'DEPLOY_TOKEN = "%DEPLOY_TOKEN%"',
])
def test_env_placeholder_is_not_a_secret(snippet: str) -> None:
    """비밀값을 코드에 두지 '않았다'는 증거를 차단하고 있었다."""
    assert "GOV-SECRET-APIKEY-001" not in _rule_ids(snippet, language="python")


@pytest.mark.parametrize("snippet", [
    'password = "pa%ss%word12"',      # 소문자 %..% 는 실제 비밀번호일 수 있다
    'password = "P4ss$WORD123x"',     # 맨몸 $ 는 제외하지 않는다
    'SECRET_KEY = "d9f2ka83jdkq0zmx84hsly26rbtv51cn"',
])
def test_real_secret_with_special_chars_still_detected(snippet: str) -> None:
    """`%VAR%` 제외가 실제 비밀번호를 삼키면 안 된다.

    `(?i)` 가 패턴 전역이라 `[A-Z_]` 만 쓰면 소문자까지 먹어 실제로 미탐이 났다.
    `(?-i:...)` 로 그 구간만 대소문자를 되살린다.
    """
    assert "GOV-SECRET-APIKEY-001" in _rule_ids(snippet, language="python")


# ---------------------------------------------------------------------------
# GOV-PII-RRN-001 — 실수 소수부의 우연한 일치
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("snippet", [
    '{"sharpe": 12.9001011234568, "trades": 418}',   # 유효 날짜 + 검증식까지 통과
    '{"avg_win": 294.4441521234567}',                # 실측(semi_fable5)
    "score = 9001011234568.75",
])
def test_number_inside_a_decimal_is_not_a_resident_number(snippet: str) -> None:
    """`\\b` 만으로는 부족하다 — 소수점이 단어 경계라 소수부가 후보가 된다.

    실측값이 지금까지 안 걸린 건 날짜가 '84월'이라 운이 좋았을 뿐이고,
    유효 날짜를 심자 즉시 '치명·차단'으로 재현됐다.
    """
    assert "GOV-PII-RRN-001" not in _rule_ids(snippet, language="python")


def test_bare_resident_number_still_detected_next_to_delimiters() -> None:
    """반대 방향 고정 — 숫자열의 일부가 아니면 그대로 잡아야 한다."""
    assert "GOV-PII-RRN-001" in _rule_ids("rrn = 8203154567890", language="python")
    assert "GOV-PII-RRN-001" in _rule_ids('{"rrn": 8203154567890}', language="python")


def test_hyphenated_resident_number_keeps_no_boundary_guard() -> None:
    """하이픈 형태에는 가드를 걸지 않는다 — 문장 끝 마침표에서 미탐이 난다."""
    assert "GOV-PII-RRN-001" in _rule_ids("주민번호는 900101-1234568.", language="python")


def test_dedup_choice_is_stable() -> None:
    code = 'promise.then(run).catch(() => {});'
    picks = {
        tuple(sorted(
            f.rule_id for f in
            scan_code(code, filename="app/x.js", language="javascript").findings
        ))
        for _ in range(5)
    }
    assert len(picks) == 1, "같은 입력에 매번 같은 룰이 남아야 리포트가 재현된다"
