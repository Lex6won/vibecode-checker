# 경계 프로브: 간접 eval — 미탐 예상 (탐지 한계 측정용)
import builtins


def run_expr(user_input: str):
    f = eval  # noqa  # H-02 eval alias assignment (호출 아님)
    return f(user_input)  # H-02 indirect call


def run_expr2(user_input: str):
    g = getattr(builtins, "ev" + "al")  # H-03 obfuscated getattr eval
    return g(user_input)
