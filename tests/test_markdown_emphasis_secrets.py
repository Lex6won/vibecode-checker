"""마크다운 강조(`**`)와 비밀값 — 두 방향을 같은 무게로 고정한다.

사용자가 물었다. *"AI 코딩툴은 강조할 때 `**` 를 쓰던데, 그건 위험 요소가
아니잖아? 겹치는 건가?"*

**답의 절반은 '겹치지 않는다'였다** — `**` 자체는 어떤 룰의 패턴에도 없고,
`***` 는 이미 플레이스홀더(마스킹 표시)로 제외된다. 오탐은 없었다.

**나머지 절반이 문제였다.** 강조가 키 이름을 감싸면 `키워드 다음 구분자`
모양이 끊겨 **다섯 형태가 통째로 미탐**이었다. 강조를 떼면 전부 잡히던
것들이라, 이건 새 탐지 영역이 아니라 이미 보기로 한 것을 못 보고 있던 자리다.

이 파일은 그 두 방향을 함께 못 박는다. 미탐을 메우려다 `2 ** 10` 이나
`**kwargs` 를 잡기 시작하면 고친 것보다 잃는 것이 크다.
"""

from __future__ import annotations

import pytest

from gvskb.scanner import scan_code


def _hits(code: str, filename: str) -> set[str]:
    return {f.rule_id for f in scan_code(code, filename=filename).findings}


# ---------------------------------------------------------------------------
# ① 강조가 감싼 비밀값은 잡는다 — 강조를 떼면 잡히던 것들
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("code, filename, why", [
    ('**password** = "P@ssw0rd2026x"', "a.py", "따옴표 대입"),
    ('**api_key**: "Ab3xK9mQ2pR7sT1u"', "a.yaml", "YAML 콜론"),
    ("**DB_PASSWORD**=gg2026Secure", "a.env", "대문자 키 · 공백 없는 ="),
    ("**DB_PASSWORD** = gg2026Secure", "a.env", "대문자 키 · 공백 있는 ="),
    ("**spring.datasource.password**=gg2026Secure", "app.properties", "점 있는 키"),
    ("# **password** = P@ssw0rd2026", "a.py", "파이썬 주석"),
    ("# **비밀번호**: Adm1n2026Prod", "a.py", "한국어 키워드"),
    ("// **pw** = Adm1n2026Prod", "a.js", "JS 주석"),
    ("/** 운영 DB: **id**=admin **pw**=Adm1n2026Prod */", "a.ts", "JSDoc"),
])
def test_emphasised_secret_is_still_detected(code: str, filename: str, why: str) -> None:
    assert _hits(code, filename), why


@pytest.mark.parametrize("plain, bold, filename", [
    ('password = "supersecretvalue123"', '**password** = "supersecretvalue123"', "a.py"),
    ("DB_PASSWORD=gg2026Secure", "**DB_PASSWORD**=gg2026Secure", "a.env"),
    ("# password = P@ssw0rd2026", "# **password** = P@ssw0rd2026", "a.py"),
])
def test_emphasis_does_not_change_the_verdict(plain: str, bold: str, filename: str) -> None:
    """강조는 서식이지 의미가 아니다. 같은 줄이면 같은 판정이 나와야 한다."""
    assert _hits(plain, filename) == _hits(bold, filename)


# ---------------------------------------------------------------------------
# ② 강조 자체는 위험이 아니다 — 넓힌 자리에서 정상 코드가 걸리면 안 된다
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("code, filename, why", [
    # 파이썬 거듭제곱·언팩 — `**` 를 받아들이면서 가장 위험해진 자리
    ("x = 2 ** 10", "a.py", "거듭제곱"),
    ("strength = base ** password_rounds", "a.py", "변수명에 password + 거듭제곱"),
    ("cost = 2 ** SECRET_ROUNDS", "a.py", "대문자 상수 + 거듭제곱"),
    ("password **= 2", "a.py", "거듭제곱 대입 연산자 — 짝 강제가 막는 자리"),
    ("api_key **= factor", "a.py", "거듭제곱 대입 연산자"),
    ("client = Vendor(**config)", "a.py", "딕셔너리 언팩"),
    ("def f(*args, **kwargs): pass", "a.py", "가변 인자"),
    ("send(**{'api_key': key})", "a.py", "언팩 + 리터럴 키"),
    # 강조된 안내문 — 값이 없다
    ("# **중요**: 반드시 확인하세요", "a.py", "강조된 안내"),
    ("# **API 키**는 발급받아 넣으세요", "a.py", "값 없는 안내"),
    ("// **주의** 토큰을 커밋하지 마세요", "a.js", "강조된 경고"),
    ("* **password**: 8자 이상으로 설정하세요", "a.js", "정책 안내문"),
    ("/** **secret** 은 환경변수로 옮길 것 */", "a.ts", "할 일 메모"),
    # 짝이 안 맞는 강조
    ("**password = notreallyaseparator", "a.py", "여는 강조만"),
])
def test_emphasis_alone_is_not_a_risk(code: str, filename: str, why: str) -> None:
    assert not _hits(code, filename), f"{why}: {_hits(code, filename)}"


# ---------------------------------------------------------------------------
# ③ 강조를 받아들여도 기존 제외는 그대로 — 특히 모범 사례
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("code, filename, why", [
    ('**api_key** = "YOUR_KEY_HERE"', "a.py", "플레이스홀더"),
    ('**password** = "XXXXXXXXXXXX"', "a.py", "X 반복"),
    ('**api_key** = "<your-api-key>"', "a.py", "꺾쇠 플레이스홀더"),
    ("**DB_PASSWORD**=${DB_PASSWORD}", "a.env", "환경변수 참조 — 비밀을 코드에 두지 않은 증거"),
    ("PASSWORD = '***'", "a.py", "마스킹 표시"),
    ("**PASSWORD**='***'", "a.py", "강조 + 마스킹 표시"),
    ("**password** = getpass.getpass()", "a.py", "비밀번호를 올바르게 읽는 코드"),
])
def test_exclusions_still_apply_under_emphasis(code: str, filename: str, why: str) -> None:
    """**모범 사례를 막는 것이 오탐 중에서도 최악이다.** 담당자는 그 순간 도구를 끈다."""
    assert not _hits(code, filename), f"{why}: {_hits(code, filename)}"


# ---------------------------------------------------------------------------
# ④ 남아 있는 구멍 — 알고 두는 것과 모르고 두는 것은 다르다
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("code, why", [
    ("- **password**: `gg2026Secure`", "값이 백틱 안 — 따옴표 문자로 안 봄"),
    ("| **DB_PASSWORD** | gg2026Secure |", "마크다운 표 — 키·값 구분자가 없음"),
])
def test_known_remaining_gaps_in_markdown_documents(code: str, why: str) -> None:
    """문서 안의 비밀값에는 아직 못 보는 모양이 남아 있다.

    백틱을 따옴표로 받아들이고 표 셀을 구분자로 보는 것은 **다른 archetype**
    이라 같이 처리하지 않았다. 여기 적어 두는 이유는, 나중에 이 테스트가
    실패하면 그건 회귀가 아니라 **개선**이라는 표시를 남기기 위해서다.
    """
    assert not _hits(code, "README.md"), f"구멍이 메워졌다 — 이 테스트를 위로 옮기세요 ({why})"


# ---------------------------------------------------------------------------
# ⑤ 형제 자리 — 사람은 고르게 고치지 않는다. 기계로 훑는다.
# ---------------------------------------------------------------------------

def test_no_rule_loses_its_own_example_under_emphasis() -> None:
    """모든 룰의 positive 예시에 강조를 씌워 판정이 뒤집히는 곳을 찾는다.

    이 검사를 만든 이유가 곧 이 검사의 이력이다. 강조 허용을 손으로 넣다가
    **세 번 어긋났다** — GOV-SECRET-APIKEY-001 을 고치고 주석 룰 둘을 빠뜨렸고,
    그걸 고치고 KISA-PY-SEC-06 을 빠뜨렸다. 마지막 하나는 이 파일의 다른
    테스트가 잡았고, 그래서 손으로 찾기를 그만두고 기계에 맡겼다.

    새 자격증명 룰이 들어올 때 같은 구멍을 안고 태어나면 여기서 걸린다.
    """
    import re
    from pathlib import Path

    from gvskb.loader import load_all_rules

    # **컴파일된 RULES 가 아니라 원본 룰**을 읽는다. 처음에 이 스윕을
    # `regex_scanner.RULES` 로 짰다가 0개를 검사하고 "이상 없음"을 냈다 —
    # 컴파일 결과에는 examples 가 남지 않기 때문이다. 그래서 아래 `checked`
    # 하한 단언이 있다: **검사를 안 하고 통과하는 것이 가장 나쁜 통과다.**
    rules = load_all_rules(Path(__file__).resolve().parent.parent / "rules")

    ext_of = {
        "python": "py", "javascript": "js", "typescript": "ts", "java": "java",
        "yaml": "yaml", "toml": "toml", "sql": "sql", "html": "html",
    }
    key_re = re.compile(
        r"(?i)\b(api[_-]?key|secret[_-]?key|secret|password|passwd|pwd|token|"
        r"access[_-]?key|auth[_-]?token|db[_-]?pass(?:word)?|비밀번호|암호|"
        r"userid|username|user_id|admin_id|admin_pw|pw|id)\b"
    )

    def emphasise(line: str) -> str | None:
        """구분자 바로 앞의 키워드 하나만 `**` 로 감싼다."""
        for m in key_re.finditer(line):
            rest = line[m.end():]
            if re.match(r"\s*[:=]", rest):
                return f"{line[:m.start()]}**{m.group(0)}**{rest}"
        return None

    broken: list[str] = []
    checked = 0
    for rule in rules:
        if rule.detection is None or not rule.detection.patterns or rule.examples is None:
            continue
        # **비밀값 룰만 본다.** 강조는 사람이 *글로 적을 때* 쓰는 서식이라,
        # 자격증명을 문서·주석에 적어 두는 자리에서만 나타난다. 스윕을 전체
        # 룰로 열면 SQL 문자열 안(`SET **password**=?`)이나 파이썬 키워드
        # 인자(`filter(**id**=…)`) 처럼 강조가 있을 수 없는 자리가 무더기로
        # 걸린다 — 고칠 수 없는 실패는 검사를 끄게 만든다.
        if rule.detection.category != "secret-scanning":
            continue
        langs = [str(x) for x in (rule.languages or [])]
        ext = ext_of.get(langs[0], "py") if langs else "py"
        fn = f"probe.{ext}"
        for src in rule.examples.positive:
            bold = emphasise(src)
            if bold is None:
                continue
            checked += 1
            if rule.id in _hits(src, fn) and rule.id not in _hits(bold, fn):
                broken.append(f"{rule.id}: {src!r} → {bold!r}")

    assert checked >= 8, f"검사한 예시가 {checked}개뿐 — 스윕이 헛돌고 있다"
    assert not broken, "강조를 씌우면 자기 예시를 놓치는 룰:\n  " + "\n  ".join(broken)
