"""37차 — 숨은 문자(보이지 않는 유니코드·양방향 제어) 엔진.

GlassWorm(2025-10~2026-04) 수법: 변형 선택자·태그 블록·제로폭 문자에 코드를 숨긴다. Trojan Source
(CVE-2021-42574): 양방향 제어로 표시 순서와 실행 순서를 다르게 만든다. 둘 다 코드포인트 단위 검사.

이 파일의 fixture 는 전부 ``chr()`` 로 조립한다 — 테스트 소스 자체에 숨은 문자가 들어 있으면
이 엔진이 이 파일을 잡고(개밥먹기 2026-10-24 실측), diff 뷰어에서도 보이지 않는다.
"""
from __future__ import annotations

from pathlib import Path

from gvskb.scanner import scan_code, scan_path
from gvskb.scanners.hidden_text import BIDI_RULE_ID, HIDDEN_RULE_ID, scan_hidden_text


def H(*cps: int) -> str:
    """코드포인트 → 문자열. 테스트 소스에 보이지 않는 문자를 직접 쓰지 않기 위한 조립기."""
    return "".join(chr(c) for c in cps)


ZWSP, ZWNJ, ZWJ, WJ, SHY, BOM = H(0x200B), H(0x200C), H(0x200D), H(0x2060), H(0x00AD), H(0xFEFF)
VS16, KEYCAP, HANGUL_FILLER = H(0xFE0F), H(0x20E3), H(0x3164)
RLO, LRI, PDI = H(0x202E), H(0x2066), H(0x2069)


def _ids(code: str, filename: str = "a.js") -> set[str]:
    return {f.rule_id for f in scan_code(code, filename=filename).findings}


# --- 잡아야 하는 것 ---------------------------------------------------------------

def test_zero_width_space_in_string_is_confirmed_block() -> None:
    r = scan_code(f'const p = "ab{ZWSP}cd{ZWSP}ef";\n', filename="a.js")
    hits = [f for f in r.findings if f.rule_id == HIDDEN_RULE_ID]
    assert len(hits) == 1
    f = hits[0]
    assert f.confidence == "confirmed" and f.decision.value == "block" and f.engine == "hidden-text"
    assert "U+200B" in f.evidence and "×2" in f.evidence
    # 증거에 숨은 문자 자체가 실리지 않는다 — 보고서가 페이로드 운반체가 되면 안 된다.
    assert ZWSP not in f.evidence


def test_variation_selector_payload_without_emoji_base() -> None:
    payload = "x" + "".join(chr(0xFE00 + i % 16) for i in range(40))
    assert HIDDEN_RULE_ID in _ids(f'const s = "{payload}";\n')


def test_tag_block_characters_outside_flag_sequence() -> None:
    hidden = "".join(chr(0xE0061 + i) for i in range(10))
    assert HIDDEN_RULE_ID in _ids(f"// {hidden}\nrun();\n")


def test_one_finding_per_file_even_with_hundreds_of_hidden_chars() -> None:
    code = "\n".join(f'const v{i} = "a{ZWSP}{WJ}b";' for i in range(200)) + "\n"
    hits = [f for f in scan_code(code, filename="a.js").findings if f.rule_id == HIDDEN_RULE_ID]
    assert len(hits) == 1
    assert hits[0].location.line == 1 and "400개" in hits[0].evidence


def test_soft_hyphen_and_hangul_filler_are_hidden() -> None:
    assert HIDDEN_RULE_ID in _ids(f"sudo{SHY} apt install x\n", "run.sh")
    assert HIDDEN_RULE_ID in _ids(f"admin{HANGUL_FILLER} = True\n", "a.py")


def test_bidi_override_is_block() -> None:
    code = f'if level != "user{RLO} {LRI}// admin{PDI} {LRI}":\n    pass\n'
    r = scan_code(code, filename="auth.py")
    hits = [f for f in r.findings if f.rule_id == BIDI_RULE_ID]
    assert len(hits) == 1 and hits[0].decision.value == "block" and hits[0].confidence == "confirmed"
    assert "U+202E" in hits[0].evidence


def test_bom_in_the_middle_is_hidden_but_leading_bom_is_fine() -> None:
    assert HIDDEN_RULE_ID in _ids(f'a = 1\nb = "{BOM}"\n', "a.py")
    assert HIDDEN_RULE_ID not in _ids(f"{BOM}a = 1\n", "a.py")


# --- 잡지 말아야 하는 것(정상 용례) -------------------------------------------------

def test_emoji_presentation_selector_is_fine() -> None:
    check, heart = H(0x2705), H(0x2764)
    assert _ids(f'const ok = "완료 {check}{VS16} 처리 {heart}{VS16}";\n') == set()


def test_keycap_and_skin_tone_sequences_are_fine() -> None:
    thumbs, skin = H(0x1F44D), H(0x1F3FD)
    assert _ids(f'const k = "1{VS16}{KEYCAP} {thumbs}{skin}";\n') == set()


def test_keycap_inside_regex_char_class_is_fine() -> None:
    # 실측(2026-10-24, 공공 챗봇 UI QuestionView.tsx:152): `[1-9]️⃣` — 키캡의 FE0F 앞 글자가 `]`.
    # 첫 실측 비교에서 이 한 줄이 새 발견으로 올라왔다(오탐). 뒤에 U+20E3 이 오면 키캡이다.
    code = (f"// Step process (1{VS16}{KEYCAP}, 2{VS16}{KEYCAP}, etc.)\n"
            f"const m = line.match(/^([1-9]{VS16}{KEYCAP})\\s*(.+)/);\n")
    assert _ids(code, "QuestionView.tsx") == set()


def test_zwj_emoji_sequence_is_fine() -> None:
    man, woman, girl, heart = H(0x1F468), H(0x1F469), H(0x1F467), H(0x2764)
    family = f"{man}{ZWJ}{woman}{ZWJ}{girl}"
    couple = f"{woman}{ZWJ}{heart}{VS16}{ZWJ}{man}"
    assert _ids(f'const f = "{family} {couple}";\n') == set()


def test_flag_tag_sequence_is_fine() -> None:
    england = H(0x1F3F4, 0xE0067, 0xE0062, 0xE0065, 0xE006E, 0xE0067, 0xE007F)
    assert _ids(f'const flag = "{england}";\n') == set()


def test_arabic_and_devanagari_joiners_are_fine() -> None:
    arabic = H(0x0646, 0x0627) + ZWNJ + H(0x0628, 0x0627)
    devanagari = H(0x0915, 0x094D) + ZWJ + H(0x0937)
    assert _ids(f'name = "{arabic}"\n', "a.py") == set()
    assert _ids(f'w = "{devanagari}"\n', "a.py") == set()


def test_cjk_ideographic_variation_selector_is_fine() -> None:
    assert _ids(f's = "{H(0x8FBB, 0xE0100)} {H(0x5944, 0xFE00)}"\n', "a.py") == set()


def test_plain_korean_source_is_clean() -> None:
    code = (
        "# 민원 처리 — 담당자 확인 후 저장\n"
        'label = "접수 완료 · 처리 중"\n'
        "def 저장(값):\n    return 값\n"
    )
    assert scan_hidden_text(code, filename="minwon.py") == []


def test_this_test_file_contains_no_hidden_characters() -> None:
    """개밥먹기 — fixture 를 chr() 로 조립했으므로 이 파일 자체는 깨끗해야 한다."""
    assert scan_hidden_text(Path(__file__).read_text(encoding="utf-8"), filename=__file__) == []


# --- 파일 경로에서도 돈다 -------------------------------------------------------------

def test_scan_path_runs_hidden_text_on_source_files(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(f'const p = "a{ZWSP}b";\n', encoding="utf-8")
    r = scan_path(tmp_path)
    assert any(f.rule_id == HIDDEN_RULE_ID and f.location.file == "app.js" for f in r.findings)
    assert "hidden-text" in r.engines.used


def test_hidden_text_is_not_inline_ignorable(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(f'// gvskb: ignore\nconst p = "a{ZWSP}b";\n', encoding="utf-8")
    r = scan_path(tmp_path)
    assert any(f.rule_id == HIDDEN_RULE_ID for f in r.findings)
