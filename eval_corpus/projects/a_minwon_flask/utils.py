# 의도적 취약 샘플 — 운영 배포 금지.
import random


def make_session_token() -> str:
    return str(random.random())  # A-10 weak random token


def safe_int(value: str) -> int:
    try:
        return int(value)
    except:  # A-11 bare except swallow
        pass
    return 0
