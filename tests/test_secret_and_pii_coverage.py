"""비밀값·개인정보 탐지 범위 — 실측으로 드러난 구멍 여섯 개.

사용자가 *"실제 비번이나 아이디 등 위험한 내용을 제대로 탐지하는지 확인하고
싶다"* 고 물어 28가지를 직접 돌려 본 결과다(2026-08-08). 잡는다고 믿고 있던
것 중 다섯 가지를 못 잡고 있었고, 안 잡아야 할 것 하나를 잡고 있었다.

**모든 항목을 미탐/오탐 짝으로 둔다.** 비밀값 룰은 한 방향으로만 손보면
반드시 반대쪽이 무너진다 — 이 파일 자체가 그 증거다(S1 을 넣자마자
`password = getpass.getpass()` 라는 *모범 사례*를 차단했다).
"""
from __future__ import annotations

import pytest

from gvskb.scanner import scan_code

_SECRET_RULES = {"GOV-SECRET-APIKEY-001", "KISA-PY-SEC-06", "KISA-JS-SEC-06",
                 "KISA-PY-SEC-13", "KISA-JS-SEC-13"}


def _hits(code: str, filename: str) -> set[str]:
    return {f.rule_id for f in scan_code(code, filename=filename).findings}


def _secret_hit(code: str, filename: str = "a.py") -> bool:
    return bool(_hits(code, filename) & _SECRET_RULES)


# ---------------------------------------------------------------------------
# S1 — 설정 파일의 따옴표 **없는** 비밀번호
#
# 모든 비밀번호 룰이 값에 따옴표를 요구했다. 그런데 `.env`·`.properties`·YAML 은
# 따옴표 없이 쓰는 것이 표준이다 — 공공 Java/Spring 프로젝트에서 비밀번호가
# 가장 흔히 노출되는 자리가 통째로 비어 있었다.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("code, filename, why", [
    ("spring.datasource.password=gg2026Secure", "application.properties", "Spring 표준"),
    ("DB_PASSWORD=gg2026Secure", ".env", ".env 대문자"),
    ("db.password = Adm1n2026Prod", "application.properties", "점 있는 키 + 공백"),
    ("password: gg2026Secure", "config.yaml", "YAML 콜론"),
    ("JWT_SECRET=aVeryLongSigningKey2026", ".env", "서명키"),
    ("api_key=AIzaSyD1234567890abcdef", ".env", "공백 없는 소문자 키"),
    ("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfi", ".env", "AWS 키"),
    ("DB_PASSWORD=gg2026Secure   # 운영 DB", ".env", "뒤따르는 주석"),
])
def test_unquoted_config_secret_is_detected(code: str, filename: str, why: str) -> None:
    assert _secret_hit(code, filename), why


@pytest.mark.parametrize("code, why", [
    ("password = getpass.getpass()", "비밀번호를 **올바르게 읽는** 코드"),
    ("password = input('pw: ')", "입력받기"),
    ("password = os.environ.get('DB_PW')", "환경변수 읽기"),
    ("password = settings.DB_PASSWORD", "설정 객체 참조"),
    ("password = user_input", "변수 대입"),
    ("    google_api_key=GEMINI_API_KEY,", "파이썬 키워드 인자(실측 오탐)"),
    # 위 한 줄은 **두 가드가 동시에** 막는다(쉼표 · 대문자 상수). 그래서
    # 한쪽만 지워도 통과한다 — 층 가림. 각 가드를 홀로 시험하는 줄을 둔다.
    ("    api_key=someValue123,", "쉼표 가드 단독 — 소문자 인자"),
    ("    api_key=GEMINI_API_KEY", "대문자 상수 가드 단독 — 쉼표 없음"),
    # 괄호 가드 단독. 쉼표는 값 문자집합에서도 빠져 있어 두 겹으로 막히므로,
    # 괄호만으로 갈리는 줄이 따로 있어야 그 가드가 실제로 시험된다.
    ("API_KEY=load_key()", "괄호 가드 단독 — 대문자 키 + 호출"),
])
def test_code_that_handles_secrets_correctly_is_not_flagged(code: str, why: str) -> None:
    """모범 사례를 차단하면 담당자는 도구를 끈다 — 오탐 중에서도 최악이다.
    S1 1차 시안이 실제로 이 여섯 중 둘을 차단했다."""
    assert not _secret_hit(code), why


@pytest.mark.parametrize("code, why", [
    ("DB_PASSWORD=${DB_PASSWORD}", "변수 참조 — 비밀을 코드에 두지 않았다는 증거"),
    ("DB_PASSWORD=$DB_PASSWORD", "맨몸 변수 참조"),
    ("DB_PASSWORD=%DB_PASSWORD%", "윈도우 변수"),
    ("password: {{ vault_password }}", "템플릿"),
    ("PASSWORD=YOUR_PASSWORD_HERE", "플레이스홀더"),
    ("PASSWORD=CHANGEME", "플레이스홀더"),
    ("PASSWORD=abc", "너무 짧음"),
    ("token_endpoint=https://auth.example.kr/token", "엔드포인트 — 비밀을 *가리키는* 이름"),
])
def test_config_placeholders_are_not_flagged(code: str, why: str) -> None:
    assert not _secret_hit(code, ".env"), why


# ---------------------------------------------------------------------------
# S4 — 플레이스홀더 오탐 (형제 룰끼리 가드가 어긋나 있었다)
# ---------------------------------------------------------------------------

def test_placeholder_value_is_not_blocked_by_any_password_rule() -> None:
    """`GOV-SECRET-APIKEY-001` 은 진작 플레이스홀더 가드가 있었는데
    `KISA-PY-SEC-06` 만 없어서 `PASSWORD = "YOUR_PASSWORD_HERE"` 가
    **치명·차단**이었다. 안내용 템플릿을 배포 차단하면 도구가 꺼진다."""
    assert not _secret_hit('PASSWORD = "YOUR_PASSWORD_HERE"')
    assert not _secret_hit('SECRET_KEY = "CHANGEME_BEFORE_DEPLOY"')
    assert not _secret_hit('DB_PASSWORD = "<your-password>"')
    # 반대 방향 — 진짜 값은 계속 잡는다
    assert _secret_hit('PASSWORD = "P@ssw0rd!2026"')


# ---------------------------------------------------------------------------
# S6 — 벤더 접두사 토큰. 접두사가 곧 신원이라 변수명이 없어도 잡는다.
#
# **접두사를 소스에 통째로 적지 않는다.** GitHub 푸시 보호가 이 파일을 실제
# 유출로 판단해 푸시를 거부한다(실측 2026-08-09 — 룰 파일 주석과 인계 문서에
# 이미 적혀 있던 함정을 그대로 밟았다). 런타임에 이어 붙이면 검사 대상 값은
# 똑같으면서 파일에는 리터럴이 남지 않는다.
# ---------------------------------------------------------------------------

def _tok(prefix: str, body: str) -> str:
    """벤더 접두사 토큰을 **런타임에** 조립한다(파일에 리터럴을 남기지 않는다)."""
    return prefix + body


@pytest.mark.parametrize("code, why", [
    (_tok("ghp" + "_", "16C7e42F292c6912E7710c838347Ae178B4a1b2c3d"), "GitHub PAT"),
    ('headers = {"Authorization": "Bearer '
     + _tok("ghp" + "_", "16C7e42F292c6912E7710c838347Ae178B4a1b") + '"}',
     "변수명 없이 문자열로만 박힌 자리"),
    (_tok("glpat" + "-", "Ab3xK9mQ2pR7sT1uV5wY"), "GitLab PAT"),
    (_tok("npm" + "_", "abcdefghijklmnopqrstuvwxyz0123456789"), "npm 토큰"),
    ("-----BEGIN RSA PRIVATE KEY-----", "소스에 붙여 넣은 개인키"),
])
def test_vendor_prefix_tokens_are_detected(code: str, why: str) -> None:
    assert "GOV-SECRET-APIKEY-001" in _hits(code, "a.py"), why


def test_prefix_lookalikes_are_not_flagged() -> None:
    """자릿수를 함께 요구하지 않으면 평범한 식별자가 걸린다."""
    assert not _secret_hit(_tok("ghp" + "_", "handler = build()"))
    assert not _secret_hit(_tok("npm" + "_", "install_flag = True"))


# ---------------------------------------------------------------------------
# S2·S3 — 주석. 두 위험을 갈라서 다룬다.
#
#   실행 위험: 주석은 살아있는 코드가 아니다 → 건너뛴다
#   노출 위험: 주석에 적힌 비밀·개인정보는 그대로 유출이다 → 잡는다
#
# 이 둘을 한 규칙으로 다루던 것이 결함이었다.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("code, filename, why", [
    ("// eval(userInput)", "a.js", "한 줄 주석"),
    ("/*\n  eval(userInput)\n*/", "a.js", "블록 주석"),
    ("/**\n * 이렇게 쓰지 마세요: eval(userInput)\n */", "a.js", "JSDoc"),
    ("# eval(user_input)", "a.py", "파이썬 주석"),
    ('def f():\n    """예시: eval(x) 는 위험합니다"""\n    return 1', "a.py", "독스트링"),
    ("<!--\n  <script>alert(1)</script>\n-->", "a.html", "HTML 주석"),
])
def test_dangerous_code_inside_comments_is_skipped(code: str, filename: str, why: str) -> None:
    """주석 속 '이렇게 쓰지 마세요' 예시를 위반으로 올리면 안 된다."""
    ids = _hits(code, filename)
    assert not (ids & {"KISA-JS-INPUT-02", "KISA-JS-API-02", "KISA-PY-INPUT-02",
                       "KISA-JS-INPUT-04"}), f"{why}: {ids}"


def test_real_code_after_a_jsdoc_block_is_still_scanned() -> None:
    """블록 주석 상태가 새어 나가 뒤따르는 진짜 코드까지 건너뛰면 안 된다."""
    assert "KISA-JS-INPUT-04" in _hits("/**\n * 설명\n */\nel.innerHTML = userInput\n", "a.js")


@pytest.mark.parametrize("code, filename, why", [
    ("// const API_KEY = 'sk-proj-abcdefghijklmnopqrstuvwxyz1234'", "a.js", "한 줄 주석 속 키"),
    ("/**\n * const API_KEY = 'sk-proj-abcdefghijklmnopqrstuvwxyz1234'\n */", "a.js", "JSDoc 속 키"),
    ("/**\n * 운영 DB: id=admin  pw=Adm1n2026Prod\n */", "a.js", "JSDoc 속 비밀번호(S3)"),
    ("# 기본 관리자 password = P@ssw0rd2026", "a.py", "파이썬 주석 속 비밀번호"),
])
def test_credentials_inside_comments_are_still_detected(
    code: str, filename: str, why: str,
) -> None:
    assert _secret_hit(code, filename), why


@pytest.mark.parametrize("code, filename, why", [
    ("# 테스트 대상자 주민번호 900101-1234567", "a.py", "파이썬 주석 속 주민번호"),
    ("// 테스트 900101-1234567", "a.js", "JS 주석 속 주민번호"),
    ("/**\n * 테스트 900101-1234567\n */", "a.js", "JSDoc 속 주민번호"),
])
def test_personal_data_inside_comments_is_detected(code: str, filename: str, why: str) -> None:
    """주석에 적힌 주민등록번호는 **여전히 개인정보 유출**이다. 커밋되면 이력에
    영구히 남는다. '주석은 살아있는 코드가 아니다'는 실행 위험에는 맞지만
    노출 위험에는 맞지 않는다."""
    assert "GOV-PII-RRN-001" in _hits(code, filename), why


@pytest.mark.parametrize("code, why", [
    ("// HWP 구조: Root/BodyText/Section0, Root/DocInfo, Root/BinData/BIN0001 등", "경로 나열"),
    (" * 예약어(over/root/of) 를 필러로 가린 사본", "산문 + 괄호"),
    (" * requireAiAuth 최상단에 `if (process.env.APP_SECRET && req.get('x-s'))`", "주석 속 코드 인용"),
    ("// 예: config.password = process.env.DB_PW", "어디서 읽는지 적은 주석 — 모범 사례"),
    ("/** @param {string} password - 사용자 비밀번호 */", "JSDoc 파라미터 설명"),
    ("// 비밀번호 정책은 8자 이상입니다", "값 없는 안내문"),
    # 코드 인용 차단의 **고유** 효과. `.*` 로 되돌리면 중괄호 안의
    # `password: "..."` 까지 훑어 걸린다 — 위 세 줄만으로는 그 차이가 안 드러난다.
    ('// 예시: fetch(url, {headers: {password: "abc12345"}})', "주석 속 코드 예시"),
    ("// 예시 fetch(url) 호출 뒤 password = abc12345", "훑기가 괄호를 넘어야 닿는 값"),
    ("// `initDb()` 를 부른 뒤 password = abc12345 로 접속", "백틱 코드 인용 뒤의 값"),
])
def test_prose_and_code_quotes_in_comments_are_not_flagged(code: str, why: str) -> None:
    """JSDoc 은 파이썬 `#` 주석과 달리 **코드 예시를 자주 담는다.**
    첫 세 개는 실측에서 실제로 걸렸던 오탐이다."""
    assert "KISA-JS-SEC-13" not in _hits(code, "a.ts"), why


# ---------------------------------------------------------------------------
# S5 — 개인정보 확대(휴대전화·카드번호)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("code, why", [
    ('phone = "010-9876-5432"', "하이픈 있는 휴대전화"),
    ('CONTACT = "01098765432"', "하이픈 없는 휴대전화"),
    ('old_phone = "011-234-5678"', "구 식별번호"),
])
def test_contact_pii_is_detected(code: str, why: str) -> None:
    assert "GOV-PII-PHONE-001" in _hits(code, "a.py"), why


@pytest.mark.parametrize("ext", ["py", "ts", "mts", "js", "java", "sql", "md", "yaml"])
def test_phone_rule_runs_in_every_language(ext: str) -> None:
    """언어 목록에 구멍이 있으면 그 확장자에서는 룰이 **아예 돌지 않는다**.

    실제로 이 룰의 ``languages`` 에 typescript 가 없어 ``.ts`` 프로젝트에서
    한 건도 걸리지 않았고, 그 빈자리를 메우려고 만든 중복 룰이 같은 줄에
    두 건씩 발행하고 있었다. 개인정보는 언어를 가리지 않는다.
    """
    assert "GOV-PII-PHONE-001" in _hits('phone = "010-9876-5432"', f"a.{ext}"), ext


def test_phone_rule_has_no_duplicate_twin() -> None:
    """같은 일을 하는 룰이 둘이면 담당자는 한 줄을 두 번 고친다.

    ``GOV-PII-CONTACT-001`` 은 이 룰과 완전히 겹쳐 삭제했다. 되살아나면
    실패한다 — 룰 린터의 중복 커버리지 검사와 짝을 이루는 명시적 못이다.
    """
    from gvskb.scanners.regex_scanner import RULES

    ids = {r["rule_id"] for r in RULES}
    assert "GOV-PII-CONTACT-001" not in ids, "삭제한 중복 룰이 되살아났다"

    hits = _hits('phone = "010-9876-5432"', "a.ts")
    phone_rules = [r for r in hits if "PHONE" in r or "CONTACT" in r]
    assert phone_rules == ["GOV-PII-PHONE-001"], f"전화번호를 보는 룰이 둘 이상: {phone_rules}"


# ---------------------------------------------------------------------------
# 카드번호 — 전화번호와 **룰을 나눈** 이유가 검증기에 있다
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("code, why", [
    ('card = "4532015112830366"', "Luhn 통과 Visa"),
    ('CARD_NO = "4532-0151-1283-0366"', "하이픈 구분"),
])
def test_card_number_is_detected(code: str, why: str) -> None:
    assert "GOV-PII-CARD-001" in _hits(code, "a.py"), why


@pytest.mark.parametrize("code, why", [
    ('order_no = "4123456789012345"', "Luhn 실패 — 이 룰의 존재 이유"),
    ('trace_id = "5412751234123456"', "Luhn 실패"),
    ('test_card = "4111-1111-1111-1111"', "카드사 공식 테스트 번호"),
    ("timestamp = 1784654517497", "타임스탬프"),
])
def test_card_lookalikes_are_not_flagged(code: str, why: str) -> None:
    assert "GOV-PII-CARD-001" not in _hits(code, "a.py"), why


def test_phone_rule_does_not_require_luhn() -> None:
    """검증기는 **룰 단위**로 걸린다. 카드용 Luhn 을 전화번호 룰에 함께 걸면
    정상 번호의 90%를 놓친다 — 그래서 두 룰로 나눴다. 처음에 한 룰로 묶었다가
    검증기가 아무 데도 안 걸리는 **죽은 코드**가 됐고 테스트가 그것을 드러냈다."""
    from gvskb.scanners.regex_scanner import RULES, _luhn_ok

    by_id = {r["rule_id"]: r for r in RULES}
    assert _luhn_ok in by_id["GOV-PII-CARD-001"]["validators"], "카드 룰에 Luhn 이 없다"
    assert _luhn_ok not in by_id["GOV-PII-PHONE-001"]["validators"], \
        "전화번호 룰에 Luhn 이 걸리면 정상 번호의 90%를 놓친다"
    # Luhn 을 통과하지 못하는 평범한 전화번호도 잡혀야 한다
    assert not _luhn_ok("01098765432")
    assert "GOV-PII-PHONE-001" in _hits('phone = "010-9876-5432"', "a.py")


@pytest.mark.parametrize("code, why", [
    ('phone = "010-1234-5678"', "국내 안내문의 사실상 표준 예시 번호"),
    ('phone = "010-0000-0000"', "명백한 더미"),
    ('test_card = "4111-1111-1111-1111"', "카드 브랜드 공식 테스트 번호"),
    ("timestamp = 1784654517497", "Unix 밀리초"),
    ('version = "1.0.10"', "버전 문자열"),
    ('order_id = "20260808-0001"', "주문번호"),
])
def test_contact_pii_placeholders_are_not_flagged(code: str, why: str) -> None:
    """대표 예시 번호까지 잡으면 README·기획서마다 경고가 뜬다."""
    assert "GOV-PII-PHONE-001" not in _hits(code, "a.py"), why


def test_phone_pii_blocks_in_production_code() -> None:
    """운영 코드의 휴대전화번호는 **차단**한다.

    한때 ``warn`` 으로 낮추자는 안이 있었다 — "형태만으로는 더미인지 알 수 없다".
    채택하지 않은 이유는 이 패턴이 대표번호(02·1588)가 아니라 **이동통신
    식별번호만** 본다는 것이다. 운영 코드에 박힌 010 번호는 거의 언제나 실존
    개인의 번호이고, 커밋되면 Git 이력에 영구히 남는다.
    """
    fs = [f for f in scan_code('CONTACT = "010-9876-5432"', filename="app.py").findings
          if f.rule_id == "GOV-PII-PHONE-001"]
    assert fs, "운영 코드의 실제 형태 번호를 놓쳤다"
    assert all(str(f.decision.value) == "block" for f in fs)


def test_phone_pii_is_attenuated_inside_tests() -> None:
    """오탐이 몰리는 자리는 테스트 픽스처다. 거기서는 차단이 아니라 검토 요청.

    ``block`` 을 유지할 수 있는 근거가 이것이다 — 확신 없이 배포를 막으면
    담당자가 도구를 끄는데, 그 상황을 감쇄가 대신 받아 준다.
    """
    fs = [f for f in scan_code('const phone = "010-9876-5432"',
                               filename="tests/fill.test.ts").findings
          if f.rule_id == "GOV-PII-PHONE-001"]
    assert fs, "테스트 경로라고 발견을 지우면 안 된다 — 낮출 뿐이다"
    assert all(str(f.decision.value) == "warn" for f in fs)
    assert all(str(f.severity.value) == "low" for f in fs)
    assert all(f.severity_adjusted for f in fs), "낮춘 사실을 보고서에 남겨야 한다"


# ---------------------------------------------------------------------------
# Luhn 검증기 — 카드번호 룰의 근거
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value, ok", [
    ("4111111111111111", True),
    ("5105105105105100", True),
    ("4111-1111-1111-1111", True),
    ("4111111111111112", False),      # 마지막 자리 하나만 틀림
    ("1234567890123456", False),      # 임의 16자리
    ("12345", False),                 # 너무 짧음
])
def test_luhn_validator(value: str, ok: bool) -> None:
    from gvskb.scanners.regex_scanner import _luhn_ok

    assert _luhn_ok(value) is ok, value
