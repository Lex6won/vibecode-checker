"""숨은 문자 검사 — 에디터·diff·사람 눈에 보이지 않는 유니코드로 숨긴 코드·지시.

왜 필요한가(37차, 2026-10-24)
----------------------------
2025-10 ~ 2026-04 OpenVSX 확장 공급망 사고(GlassWorm 계열)는 **변형 선택자(U+FE00~)·태그
블록(U+E0000~)** 같은 '폭 0' 문자에 페이로드를 인코딩해 숨겼다. 코드 리뷰어도 diff 뷰어도
기존 스캐너도 그 줄을 "빈 줄" 또는 "정상 문자열"로 봤다. 같은 수법은 에이전트 지시 파일
(CLAUDE.md 등)에 사람 눈에 안 보이는 지시를 넣는 데도 쓰인다.

CVE-2021-42574(Trojan Source)의 **양방향 제어 문자**(U+202A~202E, U+2066~2069)는 소스의
표시 순서와 컴파일 순서를 다르게 만든다 — 주석으로 보이는 것이 코드로 실행된다.

둘 다 **바이트(코드포인트) 단위**로 봐야 하고, 룰 정규식(줄 단위 문자열 패턴)으로는
"보이지 않는다"는 성질 때문에 사람이 패턴을 쓸 수 없다. 그래서 전용 엔진이다.

판정 원칙
---------
- 한 파일에 한 룰당 **발견 1건** — 수백 개가 들어 있어도 1건에 개수·첫 위치를 적는다.
  (숨긴 쪽은 많이 넣는다. 건수대로 올리면 보고서가 그 파일로 뒤덮인다.)
- 증거에 **숨은 문자 자체를 싣지 않는다** — 코드포인트 이름(`U+200B`)만 적는다. 보고서를
  다시 스캔할 때 자기 증거를 다시 잡는 자기 참조를 막고, 보고서가 페이로드 운반체가 되는
  것을 막는다.
- 정상 용례는 **문맥으로** 뺀다: 이모지 뒤 U+FE0F, 한자(CJK) 뒤 이체자 선택자, 아랍·인도
  계열 문자 사이의 ZWJ/ZWNJ, 이모지 결합용 ZWJ, 파일 맨 앞 BOM. 한국어(한글 영역)는 이런
  문자를 쓰지 않으므로 공공기관 소스에서 오탐 여지가 거의 없다.
- 확신도는 **confirmed** — 문자가 있다는 사실 자체가 판정이며 출처 추적이 필요 없다.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..schema import Finding
from .base import ScannerAdapter
from .regex_scanner import build_finding, lookup_rule

HIDDEN_RULE_ID = "GOV-HIDDEN-UNICODE-001"
BIDI_RULE_ID = "GOV-BIDI-CONTROL-001"
CATEGORY = "hidden-code"

# --- 양방향 제어: 예외 없이 전부 ------------------------------------------------
_BIDI = frozenset(range(0x202A, 0x202F)) | frozenset(range(0x2066, 0x206A))

# --- 폭 0 / 보이지 않는 문자 ------------------------------------------------------
_ZERO_WIDTH_ALWAYS = frozenset({
    0x200B,  # ZERO WIDTH SPACE
    0x2060,  # WORD JOINER
    0x2061, 0x2062, 0x2063, 0x2064,  # 보이지 않는 수학 연산자
    0x180E,  # MONGOLIAN VOWEL SEPARATOR(폐기된 폭 0)
    0x00AD,  # SOFT HYPHEN
    0x034F,  # COMBINING GRAPHEME JOINER
    0x061C,  # ARABIC LETTER MARK(폭 0 — 아랍 문맥 밖에서는 은닉용)
    0x115F, 0x1160,  # HANGUL CHOSEONG/JUNGSEONG FILLER — 한글 음절 조합용 채움 문자. 완성형 한글
                     # 소스에는 나오지 않으며 공백처럼 보여 식별자·문자열 은닉에 쓰인다.
    0x3164,  # HANGUL FILLER — 같은 성질(호환 영역)
    0xFFA0,  # HALFWIDTH HANGUL FILLER
})
_ZWNJ, _ZWJ = 0x200C, 0x200D
_BOM = 0xFEFF
_TAG_BLOCK = range(0xE0000, 0xE0080)          # TAGS — 현재 이모지 깃발 서브태그 외 용도 없음
_VS_BASIC = range(0xFE00, 0xFE10)             # VARIATION SELECTOR-1..16
_VS_SUPP = range(0xE0100, 0xE01F0)            # VARIATION SELECTOR-17..256 (한자 이체자용)

# 이모지 깃발 서브태그 시퀀스([검은 깃발 + 태그 문자 g,b,e,n,g + 취소 태그] 잉글랜드 등)는 U+1F3F4 뒤에 태그 문자가 오고 U+E007F 로 끝난다.
_BLACK_FLAG = 0x1F3F4
_CANCEL_TAG = 0xE007F
_KEYCAP = 0x20E3                               # COMBINING ENCLOSING KEYCAP — 1️⃣ 의 세 번째 문자


def _is_cjk(cp: int) -> bool:
    return (
        0x4E00 <= cp <= 0x9FFF or 0x3400 <= cp <= 0x4DBF or 0xF900 <= cp <= 0xFAFF
        or 0x20000 <= cp <= 0x323AF or 0x2E80 <= cp <= 0x2FDF   # 부수·강희 부수
        or 0x3000 <= cp <= 0x303F                                # CJK 기호·구두점(々 등)
    )


def _is_emoji_like(cp: int) -> bool:
    return (
        0x1F000 <= cp <= 0x1FAFF or 0x2600 <= cp <= 0x27BF or 0x2300 <= cp <= 0x23FF
        or 0x2B00 <= cp <= 0x2BFF or 0x2190 <= cp <= 0x21FF or 0x25A0 <= cp <= 0x25FF
        or cp in {0x00A9, 0x00AE, 0x203C, 0x2049, 0x2122, 0x2139, 0x24C2, 0x3030, 0x303D, 0x3297, 0x3299}
        or 0x30 <= cp <= 0x39 or cp in {0x23, 0x2A}            # 키캡 베이스(0-9 # *)
        or 0x1F3FB <= cp <= 0x1F3FF                            # 피부색 수정자
        or cp == _ZWJ                                          # 이모지 시퀀스 중간의 ZWJ 뒤 VS
    )


def _needs_joiner(cp: int) -> bool:
    """ZWJ/ZWNJ 가 **문자 모양을 바꾸는** 문자 체계인가 — 아랍·시리아·인도·동남아 계열."""
    return (
        0x0600 <= cp <= 0x06FF or 0x0750 <= cp <= 0x077F or 0x08A0 <= cp <= 0x08FF   # 아랍
        or 0xFB50 <= cp <= 0xFDFF or 0xFE70 <= cp <= 0xFEFE                           # 아랍 표현형
        or 0x0700 <= cp <= 0x074F                                                     # 시리아
        or 0x0780 <= cp <= 0x07BF                                                     # 타나
        or 0x0900 <= cp <= 0x0DFF                                                     # 데바나가리~싱할라
        or 0x1000 <= cp <= 0x109F or 0x1780 <= cp <= 0x17FF                           # 미얀마·크메르
        or 0x0F00 <= cp <= 0x0FFF or 0x1800 <= cp <= 0x18AF                           # 티베트·몽골
        or 0xA980 <= cp <= 0xA9DF or 0x1B00 <= cp <= 0x1B7F                           # 자바·발리
        or 0x1F000 <= cp <= 0x1FAFF or 0x2600 <= cp <= 0x27BF                         # 이모지 시퀀스
        or 0x1F3FB <= cp <= 0x1F3FF or 0x2640 <= cp <= 0x2642 or cp == 0x2695        # 수정자·성별·직업
        or cp in _VS_BASIC                                                            # 👨‍❤️‍👨 처럼 VS 뒤 ZWJ
    )


@dataclass
class _Tally:
    count: int = 0
    first_line: int = 0
    names: dict[str, int] = field(default_factory=dict)

    def add(self, cp: int, line_no: int) -> None:
        if self.count == 0:
            self.first_line = line_no
        self.count += 1
        key = f"U+{cp:04X}"
        self.names[key] = self.names.get(key, 0) + 1


def _classify(text: str) -> tuple[_Tally, _Tally]:
    """텍스트 전체를 한 번 훑어 (숨은 문자, 양방향 제어) 집계를 돌려준다."""
    hidden, bidi = _Tally(), _Tally()
    line_no = 1
    n = len(text)
    in_flag_tag = False
    for i, ch in enumerate(text):
        cp = ord(ch)
        if cp == 0x0A:
            line_no += 1
            in_flag_tag = False
            continue
        if cp < 0x00AD:
            continue
        prev = ord(text[i - 1]) if i > 0 else -1
        nxt = ord(text[i + 1]) if i + 1 < n else -1

        if cp in _BIDI:
            bidi.add(cp, line_no)
            continue
        if cp == _BOM:
            if i != 0:
                hidden.add(cp, line_no)
            continue
        if cp in _ZERO_WIDTH_ALWAYS:
            hidden.add(cp, line_no)
            continue
        if cp == _ZWNJ or cp == _ZWJ:
            if not (_needs_joiner(prev) or _needs_joiner(nxt)):
                hidden.add(cp, line_no)
            continue
        if cp in _TAG_BLOCK:
            if prev == _BLACK_FLAG:
                in_flag_tag = True
            if in_flag_tag:
                if cp == _CANCEL_TAG:
                    in_flag_tag = False
                continue
            hidden.add(cp, line_no)
            continue
        if cp in _VS_BASIC:
            # FE0E/FE0F 는 이모지 표시 선택자, FE00~FE0D 는 한자·수학 기호 이체자 선택자.
            if cp >= 0xFE0E:
                # 뒤에 U+20E3(키캡 테두리)가 오면 키캡 시퀀스다 — 앞 글자가 숫자가 아니어도 정상.
                # 실측(2026-10-24, 챗봇 UI): 정규식 `[1-9]️⃣` 에서 FE0F 의 앞 글자가 `]` 였다.
                if not (_is_emoji_like(prev) or _is_cjk(prev) or nxt == _KEYCAP):
                    hidden.add(cp, line_no)
            elif not (_is_cjk(prev) or 0x2200 <= prev <= 0x2BFF):
                hidden.add(cp, line_no)
            continue
        if cp in _VS_SUPP:
            if not _is_cjk(prev):
                hidden.add(cp, line_no)
            continue
    return hidden, bidi


def _evidence(t: _Tally, what: str) -> str:
    top = sorted(t.names.items(), key=lambda kv: (-kv[1], kv[0]))[:4]
    parts = " · ".join(f"{k}×{v}" for k, v in top)
    more = f" 외 {len(t.names) - len(top)}종" if len(t.names) > len(top) else ""
    return f"{what} {t.count}개 — {parts}{more} (첫 위치 {t.first_line}행; 문자 자체는 보고서에 싣지 않음)"


def scan_hidden_text(text: str, *, filename: str = "<memory>") -> list[Finding]:
    """숨은 문자·양방향 제어 발견. 룰 카드가 없으면(룰셋 제외 환경) 빈 목록."""
    if not text:
        return []
    # 빠른 길: 모든 문자가 U+00AD 미만이면 볼 것이 없다(대부분의 소스 파일).
    if max(map(ord, text), default=0) < 0x00AD:
        return []
    hidden, bidi = _classify(text)
    out: list[Finding] = []
    if hidden.count:
        rule = lookup_rule(HIDDEN_RULE_ID)
        if rule is not None:
            out.append(build_finding(
                rule, filename=filename, line_no=hidden.first_line,
                evidence=_evidence(hidden, "보이지 않는 문자"), engine="hidden-text",
                confidence="confirmed",
            ))
    if bidi.count:
        rule = lookup_rule(BIDI_RULE_ID)
        if rule is not None:
            out.append(build_finding(
                rule, filename=filename, line_no=bidi.first_line,
                evidence=_evidence(bidi, "양방향 제어 문자"), engine="hidden-text",
                confidence="confirmed",
            ))
    return out


class HiddenTextScanner(ScannerAdapter):
    """`_ADAPTERS` 에 등록되는 엔진 — 모든 텍스트 파일, 언어 무관."""

    name = "hidden-text"

    def scan(
        self,
        code: str,
        *,
        filename: str = "<memory>",
        language: str | None = None,
        scenario: str | None = None,
        profile: str = "public-default-strict",
        categories: set[str] | None = None,
    ) -> list[Finding]:
        if categories and CATEGORY not in categories:
            return []
        # 예외는 삼키지 않는다 — scan_code 가 엔진 실패로 기록해 '돌지 않은 검사'를 남긴다.
        return scan_hidden_text(code, filename=filename)
