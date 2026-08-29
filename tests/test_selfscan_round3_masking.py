"""자기검사(2026-08-29) 3차 — 증거 마스킹 사각지대.

보고서에 원문이 그대로 실리던 모양들(실측): `SECRET_KEY`·`SIGNING_KEY`·`JWT_SECRET_KEY`
(접미 `_KEY`), `비밀번호 =`, `**password** =`(마크다운 강조), DB URL 자격증명, JWT,
카드번호. 보고서는 결재 첨부·감사로그로 남으므로 여기가 뚫리면 도구가 유출본을 한 벌
더 만든다.
"""
from __future__ import annotations

import pytest

from gvskb.scanners.regex_scanner import evidence_is_masked, redact_evidence

_LEAKS = [
    ('SECRET_KEY = "d9f2ka83jdkq0zmx84hsly26rbtv51cn"', "d9f2ka83jdkq0zmx84hsly26rbtv51cn"),
    ('JWT_SECRET_KEY = "Ab3xK9mQ2pR7sT1uV5wY8zC4dE6f"', "Ab3xK9mQ2pR7sT1uV5wY8zC4dE6f"),
    ('SIGNING_KEY = "Zq8pL2mN4vB6xC9dF1gH3jK5"', "Zq8pL2mN4vB6xC9dF1gH3jK5"),
    ('비밀번호 = "P@ssw0rd!2026"', "P@ssw0rd!2026"),
    ('**password** = "P@ssw0rd2026x"', "P@ssw0rd2026x"),
    ('DATABASE_URL = "postgres://admin:p4ssFAKE@db.internal:5432/app"', "p4ssFAKE"),
    ('JWT_SAMPLE = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmYWtlIn0.FAKEFAKEFAKEFAKEFAKEFAKEFAKE"',
     "eyJzdWIiOiJmYWtlIn0.FAKEFAKEFAKEFAKEFAKEFAKEFAKE"),
    ('card = "4532015112830366"', "4532015112830366"),
    ("card = '4532-0151-1283-0366'", "0151-1283"),
]


@pytest.mark.parametrize("line, secret", _LEAKS)
def test_previously_leaking_shapes_are_masked(line: str, secret: str) -> None:
    out = redact_evidence(line)
    assert secret not in out, out
    assert evidence_is_masked(out), out


def test_passwords_including_korean_are_masked_whole() -> None:
    assert redact_evidence('비밀번호 = "P@ssw0rd!2026"').endswith('"[마스킹]"')
    assert redact_evidence('db.password = "hunter2plus9"').endswith('"[마스킹]"')


def test_key_name_survives_for_identification() -> None:
    out = redact_evidence('SECRET_KEY = "d9f2ka83jdkq0zmx84hsly26rbtv51cn"')
    assert out.startswith("SECRET_KEY = ")


# ── 적대: 가리면 안 되는 것 ──────────────────────────────────────────────────

@pytest.mark.parametrize("line", [
    'url = "https://api.example.com/v1/token/refresh"',                 # 경로 안의 token 단어
    'commit = "3f9a2c1b7e5d4a6b8c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b"',  # 해시
    'PUBLIC_KEY = "abc"',
    'greeting = "hello world"',
    'timestamp = "2026-08-29T16:35:00+09:00"',
    'order_no = "4532-2026-0829"',                                      # 카드 모양 아님
])
def test_non_secrets_are_left_alone(line: str) -> None:
    assert redact_evidence(line) == line


def test_rrn_and_phone_shapes_unchanged() -> None:
    assert redact_evidence('rrn = "900101-1234567"') == 'rrn = "900101-1******"'
    assert redact_evidence('phone = "010-1234-5678"') == 'phone = "010-****-5678"'
