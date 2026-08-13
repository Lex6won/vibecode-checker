"""실행 위험과 노출 위험은 다른 규칙을 따른다 — 언어 범위와 안내문 감쇄.

실사용 제보에서 시작했다.

> *"적대적 검증 중 체커가 새 YAML 문구를 LLM 출력 실행 위험으로 오탐 차단했는데,
> 문장형 설명을 구조화 필드로 바꿔 제거했습니다."*

**진짜 피해는 차단이 아니라 그다음이다** — 담당자가 도구를 통과시키려고
문서를 고쳤다. 도구가 사람의 글을 왜곡한 것이다.

확인하다 보니 결함이 하나가 아니었다.

| | 결함 | 어떻게 드러났나 |
|---|---|---|
| A | 보안 안내문이 자기가 금지한 토큰 때문에 차단됨 | 제보 |
| B | 주민번호·API키·내부망 IP 가 `.ts`·`.go`·`.cs`·`.php` 에서 **미탐** | A 를 조사하다 발견 |
| C | 노출 카테고리 집합이 두 모듈에 복제돼 **둘 다** 내부망이 빠짐 | B 를 고치자 차단 48건 발생 |
| D | 시크릿 룰이 TS 객체 리터럴 `access_token: accessToken` 을 차단 | B 를 고치자 발생 |

B 가 가장 무거웠다. 공공 웹앱의 주력 언어가 TypeScript 인데 **주민등록번호를
한 번도 검사하지 않고 있었다.**
"""

from __future__ import annotations

import pytest

from gvskb.scanner import scan_code
from gvskb.schema import EXPOSURE_CATEGORIES


def _find(code: str, filename: str):
    return scan_code(code, filename=filename).findings


def _ids(code: str, filename: str) -> set[str]:
    return {f.rule_id for f in _find(code, filename)}


def _decisions(code: str, filename: str, rule_id: str) -> set[str]:
    return {f.decision.value for f in _find(code, filename) if f.rule_id == rule_id}


# ---------------------------------------------------------------------------
# B — 노출 위험은 언어를 가리지 않는다
# ---------------------------------------------------------------------------

_EVERY_LANGUAGE = ["py", "js", "ts", "tsx", "mts", "java", "go", "rs", "cs",
                   "php", "rb", "kt", "swift", "sql", "yaml", "json"]


@pytest.mark.parametrize("ext", _EVERY_LANGUAGE)
@pytest.mark.parametrize("code, rule", [
    ('const rrn = "900101-1234567";', "GOV-PII-RRN-001"),
    ('const phone = "010-9876-5432";', "GOV-PII-PHONE-001"),
    ('const API_KEY = "sk-proj-Ab3xK9mQ2pR7sT1uV5wY8zC4";', "GOV-SECRET-APIKEY-001"),
    ('const host = "10.10.20.5";', "GOV-INTERNAL-NET-001"),
])
def test_exposure_rules_run_in_every_language(ext: str, code: str, rule: str) -> None:
    """주민등록번호는 Go 로 적으나 Rust 로 적으나 주민등록번호다.

    실측(2026-08-09): 이 넷 중 셋이 `.ts`·`.tsx`·`.go`·`.cs`·`.php` 에서
    **한 번도 돌지 않았다.** 값의 모양만 보는 룰에 언어 제한을 단 것 자체가
    잘못된 설계였다.
    """
    assert rule in _ids(code, f"a.{ext}"), f".{ext} 에서 {rule} 이 돌지 않는다"


def test_no_exposure_rule_restricts_javascript_without_typescript() -> None:
    """이 구멍이 **다섯 번** 났다 — 같은 모양을 기계로 훑는다.

    TypeScript 는 JavaScript 의 상위집합이라 'JS 에는 맞고 TS 에는 안 맞는'
    룰은 존재할 수 없다. 목록에 javascript 만 있으면 그것은 의도가 아니라
    빠뜨린 것이다.
    """
    from pathlib import Path

    from gvskb.loader import load_all_rules

    broken, checked = [], 0
    for rule in load_all_rules(Path(__file__).resolve().parent.parent / "rules"):
        # **패턴이 있는 룰만** 본다. 패턴 없는 룰은 검색·참조용 문서라
        # languages 가 필터로 쓰이지 않는다(74건). 그것까지 세면 고칠 수 없는
        # 실패가 무더기로 나오고, 고칠 수 없는 실패는 검사를 끄게 만든다.
        if not (rule.detection and rule.detection.patterns):
            continue
        checked += 1
        langs = {str(x) for x in (rule.languages or [])}
        if "javascript" in langs and "typescript" not in langs:
            broken.append(f"{rule.id}: {sorted(langs)}")
    assert checked >= 50, f"검사한 룰이 {checked}개뿐 — 스윕이 헛돌고 있다"
    assert not broken, "javascript 는 있고 typescript 가 없는 룰:\n  " + "\n  ".join(broken)


# ---------------------------------------------------------------------------
# C — 노출 카테고리 집합은 한 곳에서만 정의한다
# ---------------------------------------------------------------------------

def test_exposure_category_set_is_defined_once() -> None:
    """같은 목록을 두 곳에 적으면 언젠가 어긋난다 — 실제로 어긋났다.

    주석 건너뛰기 예외와 테스트 경로 감쇄 대상이 각각 따로 적혀 있었고,
    **둘 다** ``public-sector-internal`` 이 빠져 있었다. 그래서 테스트
    픽스처의 사설 IP 48건이 '차단'으로 올라왔다.
    """
    from gvskb.scanner import _VALUE_BASED_CATEGORIES
    from gvskb.scanners.regex_scanner import _COMMENT_SKIP_EXEMPT_CATEGORIES

    assert _VALUE_BASED_CATEGORIES is EXPOSURE_CATEGORIES
    assert _COMMENT_SKIP_EXEMPT_CATEGORIES is EXPOSURE_CATEGORIES
    assert "public-sector-internal" in EXPOSURE_CATEGORIES


def test_private_ip_in_test_fixture_is_attenuated_not_blocked() -> None:
    """레이트리밋 테스트의 `192.168.1.1` 은 우리 기관 내부 호스트가 아니다."""
    assert _decisions("const result = checkRateLimit('192.168.1.1', false)",
                      "__tests__/middleware.test.ts", "GOV-INTERNAL-NET-001") == {"warn"}


def test_private_ip_in_production_code_still_blocks() -> None:
    assert _decisions('const DB_HOST = "10.10.20.5";', "src/db.ts",
                      "GOV-INTERNAL-NET-001") == {"block"}


# ---------------------------------------------------------------------------
# D — 값이 키 이름 그 자체면 변수 참조다
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("code, why", [
    ("  access_token: accessToken", "TS 객체 리터럴 — 실측 오탐"),
    ("  api_key: apiKey", "같은 모양"),
    ("  password: password", "자기반복 — 플레이스홀더 계열"),
    ("  refresh_token: refreshToken", "같은 모양"),
])
def test_value_equal_to_its_own_key_is_not_a_secret(code: str, why: str) -> None:
    """실제 비밀값이 자기 키 이름과 같을 수는 없다 — 진짜를 가릴 위험이 없다."""
    assert "GOV-SECRET-APIKEY-001" not in _ids(code, "gmailClient.ts"), why


@pytest.mark.parametrize("code, why", [
    ("  api_key: Ab3xK9mQ2pR7sT1uV5wY", "값이 키와 다르다 — 진짜 후보"),
    ("DB_PASSWORD=gg2026Secure", "설정 파일 표준"),
    ("spring.datasource.password=gg2026Secure", "점 있는 키"),
])
def test_self_reference_guard_does_not_swallow_real_secrets(code: str, why: str) -> None:
    assert "GOV-SECRET-APIKEY-001" in _ids(code, "app.yaml"), why


# ---------------------------------------------------------------------------
# A — "하지 마세요"라고 말하는 줄
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("code, why", [
    ("description: LLM 응답을 그대로 실행(execute)하지 말고 검증하세요", "제보된 바로 그 모양"),
    ('note: "The model response must never be passed to eval()"', "영문 금지문"),
    ("guidance: innerHTML 로 response 를 렌더링하지 마세요", "한국어 금지문"),
    ("desc: eval() 사용 금지", "짧은 금지문"),
    ("safe_fix: LLM 출력은 execute 하기 전에 검증하세요 — 직접 실행 금지", "룰 파일 본문"),
])
def test_security_guidance_prose_is_attenuated_not_blocked(code: str, why: str) -> None:
    """도구가 **자기가 하라고 쓴 문장**을 막으면 안 된다.

    제보자는 차단을 피하려고 문장형 설명을 구조화 필드로 바꿨다 —
    도구가 사람의 문서를 고치게 만든 것이 이 결함의 진짜 피해다.
    """
    fs = _find(code, "policy.yaml")
    assert fs, "발견 자체를 지우지는 않는다 — 낮출 뿐이다"
    assert all(f.decision.value != "block" for f in fs), why
    assert all(f.severity_adjusted for f in fs), "낮춘 사유가 보고서에 남아야 한다"


@pytest.mark.parametrize("code, filename, why", [
    ('  "prepare": "node -e \\"require(\'child_process\').exec(cmd)\\""',
     "package.json", "npm 라이프사이클 스크립트 — 실제 공급망 위험"),
    ("  run: os.system(user_input)", "workflow.yml", "CI 워크플로에 박힌 명령 실행"),
    ("exec(llm_response)", "app.py", "LLM 출력 직접 실행"),
    ("os.system(model_output.strip())", "app.py", "LLM 출력 셸 실행"),
    ("element.innerHTML = llmResponse", "app.ts", "LLM 출력 DOM 삽입"),
])
def test_real_execution_risk_still_blocks(code: str, filename: str, why: str) -> None:
    """데이터 파일이라고 실행형 룰을 통째로 끄면 이것들을 놓친다.

    처음에 그렇게 설계하려다 실측에서 걸렸다 — `package.json` 의 npm 스크립트와
    CI 워크플로의 `run:` 은 **데이터 파일에 담긴 실행 코드**다.
    """
    assert any(f.decision.value == "block" for f in _find(code, filename)), why


@pytest.mark.parametrize("code, rule, why", [
    ('password = "hunter2plus9"  # 절대 하드코딩하지 마세요', "GOV-SECRET-APIKEY-001",
     "하지 말라고 적어 뒀어도 비밀번호는 그대로 노출돼 있다"),
    ('rrn = "900101-1234567"  # 개인정보 금지', "GOV-PII-RRN-001",
     "의도가 위험을 지우지 못한다"),
    ('host = "10.10.20.5"  # 외부에 노출하지 말 것', "GOV-INTERNAL-NET-001",
     "같은 논리"),
])
def test_prohibition_phrases_do_not_soften_exposure_risk(
    code: str, rule: str, why: str,
) -> None:
    """**노출 위험에는 안내문 감쇄를 적용하지 않는다.**"""
    assert _decisions(code, "app.py", rule) == {"block"}, why


def test_prohibition_attenuation_never_deletes() -> None:
    """감쇄는 삭제가 아니다. 판단이 틀렸을 때 위험이 사라지면 안 된다."""
    code = "os.system(cmd)  # 하지 말 것"
    fs = _find(code, "app.py")
    assert fs, "안내문처럼 보인다고 지우면 놓친 사실이 아무 데도 안 남는다"
    assert all(f.severity_adjusted for f in fs)


@pytest.mark.parametrize("code, why", [
    ("// IPv4-mapped IPv6 (::ffff:10.0.0.1) → 내장 IPv4로 재검사", "실측 오탐 — 표기법 설명"),
    ('assert.equal(isPrivateIp("::ffff:192.168.1.1"), true)', "표기법 테스트"),
])
def test_ipv4_mapped_ipv6_notation_is_not_an_internal_host(code: str, why: str) -> None:
    """실제 설정에는 맨몸 IPv4 로 적지 `::ffff:` 표기를 쓰지 않는다.

    소스에 이 모양으로 나오면 주소가 아니라 **표기법을 설명하는 문장**이다.
    내부망 룰을 주석에서도 보게 바꾸자(노출 위험이므로 옳다) 바로 걸렸다.
    """
    assert "GOV-INTERNAL-NET-001" not in _ids(code, "src/watch.ts"), why


def test_plain_private_ip_in_a_comment_is_still_caught() -> None:
    """`::ffff:` 제외가 주석 속 진짜 내부 주소까지 삼키면 안 된다.

    주석에 적힌 내부망 주소는 **여전히 내부 구조 노출**이다 — 그래서 내부망을
    노출 카테고리에 넣어 주석에서도 보게 했다.
    """
    assert "GOV-INTERNAL-NET-001" in _ids("// 운영 DB 는 10.10.20.5 에 있다", "src/db.ts")


@pytest.mark.parametrize("code, filename", [
    ("el.innerHTML = data  // avoid", "app.ts"),
    ("el.innerHTML = data  // avoid ", "app.ts"),
    ("os.system(cmd)  # never", "app.py"),
    ("os.system(cmd)  # never do this", "app.py"),
])
def test_prohibition_match_does_not_depend_on_trailing_whitespace(
    code: str, filename: str,
) -> None:
    """같은 모양이 **뒤 공백 유무**로 다르게 판정되면 안 된다.

    처음에 `avoid\s`·`never\s` 로 적었더니 줄 끝에 온 `// avoid` 가 매치되지
    않아, 판정이 보이지 않는 문자에 좌우됐다. 적대적 검증에서 잡혔다.
    """
    fs = _find(code, filename)
    assert fs, "발견을 지우지는 않는다"
    assert all(f.decision.value != "block" for f in fs)
    assert all(f.severity_adjusted for f in fs)


# ---------------------------------------------------------------------------
# E — TypeScript 를 열자 드러난 자리: JS 표준 컬렉션과 이름이 겹치는 API
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("code, want_hit, why", [
    ("tools.delete(basic)", False, "Set.prototype.delete — 실측 오탐"),
    ("tools.has(name)", False, "Set.has"),
    ("toolkit.add(x)", False, "Set.add"),
    ("toolbar.remove()", False, "UI 요소 제거"),
    ("tools.deleteFile(path)", True, "이름이 더 붙은 파괴적 호출"),
    ("toolRegistry.removeUser(uid)", True, "같은 이유"),
    ("tools.dropTable('users')", True, "DB drop"),
    ("agent.delete(resource)", True, "에이전트의 맨몸 delete 는 실제 자원 삭제"),
    ("mcpClient.delete(path)", True, "같은 이유"),
])
def test_tool_collection_methods_are_not_agent_authority(
    code: str, want_hit: bool, why: str,
) -> None:
    """`tools` 는 흔히 `Set<string>` 이고 `.delete()` 는 집합 연산이다.

    이 룰은 이미 DOM API(`removeItem`·`removeChild`)를 빼고 있었는데 JS 표준
    **컬렉션** API 는 빠져 있었다 — 같은 부류의 형제 자리다. TypeScript 를
    검사 대상에 넣자마자 실측에서 차단으로 올라왔다.
    """
    hit = "GOV-AGENT-EXCESSIVE-AUTHORITY-001" in _ids(code, "a.ts")
    assert hit is want_hit, why
