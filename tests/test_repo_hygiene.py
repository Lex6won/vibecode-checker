"""저장소 위생 가드 — 기관 식별자가 추적 파일·커밋 메시지에 남지 못하게 막는다.

왜 필요한가(실측): 지난 세션에 감사 대상 기관의 기본 계정 문자열을 **두 번 놓칠
뻔했고 둘 다 사람 눈으로 잡았다**. 사람 눈은 세 번째에 놓친다. 이 저장소는 MIT
공개 저장소라 한 번 푸시되면 회수할 수 없으므로, 실패를 사람이 아니라 CI 에 둔다.

무엇을 막는가 — 세 가지 부류:

1. **기관 도메인** (``*.go.kr``) — 공개 참조처·합성 예제만 허용목록으로 통과시키고
   나머지는 전부 실패한다. 새 ``go.kr`` 호스트를 넣으려면 허용목록에 이름을 적어야
   하므로, 기관 도메인 유입이 **눈에 보이는 행위**가 된다.
2. **시·군·구 실명** — 한글 실명과 로마자 표기 양쪽. 실측 유출은 로마자
   (``…시 개인키 파일명``)로 새어 나갔다.
3. **기본 비밀번호 문자열** — 감사 현장에서 실제로 본 계정 문자열. 룰·예제에는
   합성 문자열(``P@ssw0rd`` 등)만 쓴다.

가드가 자기 자신을 잡지 않게 하는 방법: 비밀번호 목록은 **조각으로 나눠** 두어
소스에 원문이 없다(이 파일도 검사 대상이다). 반면 기관명 목록은 원문이 있어야
하므로, **기관명 검사에 한해** 이 파일 하나만 예외로 둔다(``_NAME_SCAN_EXEMPT``).
예외가 조용히 늘어나지 못하도록 그 크기를 테스트가 고정한다.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

# 기관명 검사만 면제되는 경로 — 목록 원문을 담아야 하는 이 파일 하나뿐이다.
# 도메인·비밀번호 검사는 이 파일에도 그대로 적용된다.
_NAME_SCAN_EXEMPT = frozenset({"tests/test_repo_hygiene.py"})

# 이력 재작성(docs 인계 §C) 전까지 남아 있는 과거 커밋. 새 커밋은 예외가 없다.
# 재작성 후에는 SHA 가 바뀌므로 이 목록은 자연히 빈 목록이 된다.
_PENDING_HISTORY_REWRITE: frozenset[str] = frozenset({
    # 커밋 메시지 본문에 감사 대상 기관의 개인키 파일명(도메인 포함)이 들어 있다.
    # 이미 공개 원격에 푸시된 커밋이라 amend 로 지울 수 없다 — 이력 재작성 대상.
    # 이 가드가 처음 잡아낸 실제 유출이며, 재작성 후 이 항목을 지운다.
    "97e6ef7c38869252fc1fa3a28cd3ef9542df5aed",
})

_BINARY_SUFFIXES = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".pdf", ".zip", ".gz",
    ".whl", ".xlsx", ".hwp", ".hwpx", ".pptx", ".docx", ".pyc", ".woff", ".woff2",
})

# ---------------------------------------------------------------------------
# 1) 기관 도메인 — 기본 차단 + 명시 허용목록
# ---------------------------------------------------------------------------

# 호스트 라벨이 **하나 이상** 있어야 한다. 맨 `go.kr` 은 기관을 식별하지 않으며
# (문서에서 규칙 자체를 설명할 때 쓴다), 신원은 앞 라벨에서 나온다.
_GO_KR = re.compile(r"(?<![A-Za-z0-9.-])(?:[A-Za-z0-9-]+\.)+go\.kr", re.IGNORECASE)

#: 통과시킬 ``go.kr`` 호스트(접미사 일치). 두 종류만 허용한다:
#: (a) 누구나 쓰는 공개 참조처, (b) 문서·룰의 합성 예제 호스트.
#: 여기에 없는 호스트는 **감사 대상 기관의 도메인일 수 있다**고 보고 실패시킨다.
_ALLOWED_GO_KR = (
    # (a) 공개 참조처 — 법령·지침·공공데이터
    "law.go.kr",
    "mois.go.kr",
    "pipc.go.kr",
    "aikorea.go.kr",
    "data.go.kr",
    "juso.go.kr",
    "kisa.go.kr",
    # 발행 기관의 **공개** 포털(README 에 이미 공개된 소속). 감사 대상이 아니다.
    "gg.go.kr",
    # (b) 합성 예제 호스트 — 룰 문서·테스트에서만 쓴다
    "example.go.kr",
    "myservice.go.kr",
    "someservice.go.kr",
    "partner.go.kr",
)


def _domain_allowed(host: str) -> bool:
    host = host.lower().rstrip(".")
    return any(host == allowed or host.endswith("." + allowed) for allowed in _ALLOWED_GO_KR)


# ---------------------------------------------------------------------------
# 2) 시·군·구 실명 — 한글 + 로마자
# ---------------------------------------------------------------------------

_KOREAN_NAMES = (
    "수원시", "성남시", "의정부시", "안양시", "부천시", "광명시", "평택시", "동두천시",
    "안산시", "고양시", "과천시", "구리시", "남양주시", "오산시", "시흥시", "군포시",
    "의왕시", "하남시", "용인시", "파주시", "이천시", "안성시", "김포시", "화성시",
    "양주시", "포천시", "여주시", "연천군", "가평군", "양평군", "광주시",
)

_ROMAN_NAMES = (
    "suwon", "seongnam", "uijeongbu", "anyang", "bucheon", "gwangmyeong", "pyeongtaek",
    "dongducheon", "ansan", "goyang", "gwacheon", "guri", "namyangju", "osan", "siheung",
    "gunpo", "uiwang", "hanam", "yongin", "paju", "icheon", "anseong", "gimpo",
    "hwaseong", "yangju", "pocheon", "yeoju", "yeoncheon", "gapyeong", "yangpyeong",
)

_KOREAN_NAME_RE = re.compile("|".join(_KOREAN_NAMES))
_ROMAN_NAME_RE = re.compile(
    r"(?<![a-z])(?:" + "|".join(_ROMAN_NAMES) + r")(?![a-z])", re.IGNORECASE
)
# ○○시청·군청·구청·도청 — 목록에 없는 기관도 형태로 잡는다.
_OFFICE_RE = re.compile(r"[가-힣]{2,4}(?:시청|군청|구청|도청)")


# ---------------------------------------------------------------------------
# 3) 기본 비밀번호 문자열
# ---------------------------------------------------------------------------

#: 조각으로 나눠 둔다 — 이 파일도 검사 대상이라 원문을 적으면 자기 자신에 걸린다.
#: (감사 현장에서 실제로 본 문자열 + 국내 공공 시스템에 흔한 기본값)
_PASSWORD_FRAGMENTS = (
    ("admin", "1234"),
    ("admin", "123!"),
    ("manager", "1234"),
    ("qwer", "1234"),
    ("test", "1234"),
    ("1q2w", "3e4r"),
    ("passw", "ord1234"),
)
_DEFAULT_PASSWORDS = tuple("".join(parts) for parts in _PASSWORD_FRAGMENTS)
_PASSWORD_RE = re.compile("|".join(re.escape(p) for p in _DEFAULT_PASSWORDS), re.IGNORECASE)


# ---------------------------------------------------------------------------
# 스캔
# ---------------------------------------------------------------------------

Violation = tuple[str, str]  # (부류, 실제로 걸린 문자열)


def scan_text(text: str, *, check_names: bool = True) -> list[Violation]:
    """텍스트 한 덩어리에서 기관 식별자를 찾는다. 파일·커밋 메시지 공용."""
    found: list[Violation] = []
    for m in _GO_KR.finditer(text):
        if not _domain_allowed(m.group(0)):
            found.append(("기관 도메인", m.group(0)))
    for m in _PASSWORD_RE.finditer(text):
        found.append(("기본 비밀번호", m.group(0)))
    if check_names:
        for regex, kind in (
            (_KOREAN_NAME_RE, "시·군 실명"),
            (_ROMAN_NAME_RE, "시·군 실명(로마자)"),
            (_OFFICE_RE, "기관 명칭"),
        ):
            for m in regex.finditer(text):
                found.append((kind, m.group(0)))
    return found


def _git(*args: str) -> str:
    try:
        proc = subprocess.run(
            ["git", *args], cwd=REPO_ROOT, capture_output=True, text=True,
            encoding="utf-8", errors="replace", check=False,
        )
    except OSError as exc:  # pragma: no cover - git 없는 환경
        pytest.skip(f"git 실행 불가: {exc}")
    if proc.returncode != 0:  # pragma: no cover - 저장소가 아닌 경우
        pytest.skip(f"git {' '.join(args)} 실패: {proc.stderr.strip()}")
    return proc.stdout


@pytest.fixture(scope="module")
def tracked_files() -> list[str]:
    if not (REPO_ROOT / ".git").exists():  # pragma: no cover - sdist 배포본
        pytest.skip("git 체크아웃이 아닙니다 — 저장소 위생 검사 대상 아님")
    return [line for line in _git("ls-files").splitlines() if line.strip()]


def _read_text(path: Path) -> str | None:
    """텍스트면 내용, 바이너리·읽기 실패면 None."""
    if path.suffix.lower() in _BINARY_SUFFIXES:
        return None
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in raw[:4096]:
        return None
    return raw.decode("utf-8", errors="replace")


def test_tracked_files_have_no_institution_identifiers(tracked_files: list[str]) -> None:
    """추적 파일에 기관 도메인·시군 실명·기본 비밀번호가 있으면 실패한다."""
    problems: list[str] = []
    for rel in tracked_files:
        path = REPO_ROOT / rel
        if not path.is_file():
            continue  # 추적돼 있으나 작업 트리에 없는 경우(삭제 대기)
        text = _read_text(path)
        if text is None:
            continue
        for kind, hit in scan_text(text, check_names=rel not in _NAME_SCAN_EXEMPT):
            problems.append(f"{rel}: [{kind}] {hit}")
    assert not problems, (
        "추적 파일에 기관 식별자가 있습니다 — 공개 저장소에 올라가면 회수할 수 없습니다:\n  "
        + "\n  ".join(sorted(set(problems)))
        + "\n\n합성 예제로 바꾸거나, 공개 참조처라면 _ALLOWED_GO_KR 에 근거와 함께 추가하세요."
    )


def test_commit_messages_have_no_institution_identifiers() -> None:
    """커밋 메시지에 기관 식별자가 있으면 실패한다 — 파일만 지워서는 사라지지 않는다."""
    if not (REPO_ROOT / ".git").exists():  # pragma: no cover - sdist 배포본
        pytest.skip("git 체크아웃이 아닙니다")
    raw = _git("log", "--format=%H%x1f%B%x1e")
    problems: list[str] = []
    for entry in raw.split("\x1e"):
        entry = entry.strip("\n")
        if not entry.strip():
            continue
        sha, _, message = entry.partition("\x1f")
        sha = sha.strip()
        if sha in _PENDING_HISTORY_REWRITE:
            continue
        for kind, hit in scan_text(message):
            problems.append(f"{sha[:12]}: [{kind}] {hit}")
    assert not problems, (
        "커밋 메시지에 기관 식별자가 있습니다:\n  "
        + "\n  ".join(sorted(set(problems)))
        + "\n\n아직 푸시 전이라면 메시지를 고쳐 커밋하세요(git commit --amend). "
        "이미 푸시된 과거 이력이면 이력 재작성 대상이며, 그때까지만 "
        "_PENDING_HISTORY_REWRITE 에 SHA 를 근거와 함께 남깁니다."
    )


# ---------------------------------------------------------------------------
# 가드 자체가 작동하는지 — 저장소가 깨끗해도 탐지력이 살아 있어야 한다
# ---------------------------------------------------------------------------

def test_guard_detects_synthetic_violations() -> None:
    """세 부류 모두 실제로 잡히는지. 문자열은 런타임에 조립해 자기 자신에 걸리지 않게 한다."""
    domain = "minwon." + "somecity" + ".go.kr"
    password = "admin" + "1234"
    korean = "시" + "흥시"
    roman = "sihe" + "ung"
    office = "가상" + "구청"  # 목록에 없는 기관도 '○○구청' 형태로 잡는다

    kinds = {kind for kind, _ in scan_text(f"DB={password} host={domain}")}
    assert "기관 도메인" in kinds
    assert "기본 비밀번호" in kinds

    assert [k for k, _ in scan_text(korean)] == ["시·군 실명"]
    assert [k for k, _ in scan_text(roman)] == ["시·군 실명(로마자)"]
    assert [k for k, _ in scan_text("우리" + "구청 담당자")][0] == "기관 명칭"
    assert scan_text(office)


def test_allowlisted_public_domains_pass() -> None:
    """공개 참조처는 통과해야 한다 — 경고 피로로 가드가 꺼지는 것이 더 위험하다."""
    for host in ("www.law.go.kr", "apis.data.go.kr", "api.example.go.kr"):
        assert not scan_text(host), f"{host} 가 오탐으로 걸렸습니다"


def test_unlisted_go_kr_host_fails() -> None:
    """허용목록에 없는 go.kr 은 통과하면 안 된다 — 기본은 차단이다."""
    assert scan_text("https://" + "portal.newcity" + ".go.kr/login")


def test_bare_go_kr_is_not_an_identifier() -> None:
    """맨 `go.kr` 은 기관을 식별하지 않는다 — 규칙을 설명하는 문서가 자기 규칙에 걸리면 안 된다.

    실측: 이 가드를 설명하는 CHANGELOG 문장(`*.go.kr`)이 첫 실행에서 걸렸다.
    라벨이 하나라도 붙으면 다시 잡힌다.
    """
    assert not scan_text("기관 도메인(*." + "go.kr" + ") 을 막는다")
    assert scan_text("x." + "go.kr")


def test_roman_name_requires_word_boundary() -> None:
    """로마자 이름이 다른 단어 안에 묻혀 오탐을 내지 않아야 한다."""
    assert not scan_text("configuring")  # 'guri' 를 포함하지만 단어가 아니다
    assert not scan_text("transposant")


def test_name_scan_exemption_stays_narrow() -> None:
    """기관명 검사 면제는 가드 파일 하나뿐 — 예외가 늘면 가드가 아니라 구멍이 된다."""
    assert _NAME_SCAN_EXEMPT == frozenset({"tests/test_repo_hygiene.py"})
    # 면제된 파일에서도 도메인·비밀번호는 여전히 잡힌다.
    hits = scan_text("admin" + "1234", check_names=False)
    assert [k for k, _ in hits] == ["기본 비밀번호"]
