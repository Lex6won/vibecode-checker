# 경계 프로브: alias import 우회 — 미탐 예상 (탐지 한계 측정용)
from os import system as run_cmd


def cleanup(fname: str) -> None:
    run_cmd("del " + fname)  # H-01 aliased os.system
