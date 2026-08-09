"""Python 상수 바인딩 추론 — "이 변수는 개발자가 박은 값뿐인가"를 판별한다.

왜 필요한가(실측 근거): 아래 코드는 f-string 으로 SQL 을 만들지만 **사용자
입력이 닿을 수 없다**. 삽입되는 ``col``·``dfn`` 은 바로 위 리터럴 리스트에서만
나오기 때문이다::

    for col, dfn in [('처리상태', 'INTEGER DEFAULT 0'), ('접수번호', 'TEXT')]:
        c.execute(f'ALTER TABLE 민원 ADD COLUMN {col} {dfn}')

테인트 추적이 이걸 구분하지 못하면 "사용자 입력이 SQL 에 들어간다"는 **사실과
다른 critical 경보**가 뜬다(공공기관 대상 도구에서 오탐은 신뢰를 직접 깎는다).

이 모듈은 한 스코프 안에서 **증명 가능하게 상수인 이름**만 모은다. 판단이
애매하면 상수로 보지 않는다(보수적 — 놓칠지언정 거짓 안심은 주지 않는다).

인정하는 상수 바인딩:

- ``x = "리터럴"`` / 숫자 / True·None — 그리고 그 이름에 **다른 대입이 없을 때**
- ``for x in ['a', 'b']`` / ``for k, v in [('a','b'), ...]`` — 리터럴 이터러블 순회
- ``x = ['a', 'b']`` 같은 리터럴 컨테이너 — ``.append``/``.extend`` 인자가
  전부 리터럴일 때만 유지(하나라도 동적이면 즉시 실격)

전 구간을 미리 훑은 뒤 판정하므로, 뒤쪽에서 동적 값이 대입되면 앞에서도
상수로 보지 않는다(순서 무관 안전).
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field


@dataclass
class ConstEnv:
    """스코프 단위 상수 판정 결과."""

    names: set[str] = field(default_factory=set)        # 값이 상수인 이름
    containers: set[str] = field(default_factory=set)   # 원소가 전부 리터럴인 리스트/튜플

    def is_const_name(self, name: str) -> bool:
        return name in self.names


def _is_literal(node: ast.AST | None) -> bool:
    """리터럴(상수/리터럴 컬렉션/리터럴만의 f-string)인가."""
    if node is None:
        return False
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return all(_is_literal(e) for e in node.elts)
    if isinstance(node, ast.Dict):
        return all(_is_literal(k) for k in node.keys) and all(_is_literal(v) for v in node.values)
    if isinstance(node, ast.JoinedStr):
        # 삽입 필드가 전부 상수인 f-string 은 사실상 리터럴.
        return all(
            not isinstance(v, ast.FormattedValue) or isinstance(v.value, ast.Constant)
            for v in node.values
        )
    if isinstance(node, ast.UnaryOp):      # -1 같은 형태
        return _is_literal(node.operand)
    if isinstance(node, ast.BinOp):        # 'a' + 'b' 처럼 리터럴끼리 결합
        return _is_literal(node.left) and _is_literal(node.right)
    return False


def _iter_names(target: ast.AST) -> list[str]:
    """대입 대상에서 이름들을 뽑는다(튜플 언패킹 포함)."""
    out: list[str] = []
    if isinstance(target, ast.Name):
        out.append(target.id)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for e in target.elts:
            out.extend(_iter_names(e))
    return out


def _literal_iterable_elements_are_literal(node: ast.AST) -> bool:
    """``for x in <여기>`` 의 이터러블이 리터럴 원소만 담고 있는가."""
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return all(_is_literal(e) for e in node.elts)
    return False


def _walk_scope(stmts: list[ast.stmt]) -> list[ast.stmt]:
    """중첩 블록(if/for/while/with/try)까지 펼치되 def/class 는 넘지 않는다."""
    out: list[ast.stmt] = []
    stack = list(stmts)
    while stack:
        s = stack.pop()
        out.append(s)
        if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue  # 별도 스코프 — 여기서 판단하지 않는다
        for fld in ("body", "orelse", "finalbody"):
            blk = getattr(s, fld, None)
            if isinstance(blk, list):
                stack.extend(blk)
        for h in getattr(s, "handlers", []) or []:
            if isinstance(h, ast.ExceptHandler):
                stack.extend(h.body)
    return out


def collect_constants(stmts: list[ast.stmt]) -> ConstEnv:
    """스코프 전체를 훑어 상수로 증명되는 이름·컨테이너를 반환한다.

    2단계로 판정한다:

    1. 리터럴 대입·리터럴 이터러블 순회로 **즉시 상수**인 이름을 모은다.
    2. 나머지 이름은 **고정점 반복**으로 승격한다 — 예컨대
       ``where = ("WHERE " + " AND ".join(conds)) if conds else ""`` 는
       ``conds`` 가 리터럴 컨테이너로 확정된 뒤에야 상수임을 알 수 있다.
       더 이상 승격이 없을 때까지 반복하므로 선언 순서에 영향받지 않는다.
    """
    const_candidates: set[str] = set()
    container_candidates: set[str] = set()
    mutable_const_candidates: set[str] = set()  # 가변 컨테이너 — 변형 없을 때만 상수
    disqualified: set[str] = set()          # 값 자체가 상수가 아님
    container_disqualified: set[str] = set()  # 컨테이너 원소가 리터럴이 아님
    # 이름 → 대입된 값 노드들(고정점 재평가용). 하나라도 상수가 아니면 실격.
    assignments: dict[str, list[ast.AST]] = {}

    flat = _walk_scope(stmts)

    for s in flat:
        # 1) 일반 대입
        if isinstance(s, (ast.Assign, ast.AnnAssign)):
            targets = s.targets if isinstance(s, ast.Assign) else [s.target]
            value = s.value
            names: list[str] = []
            for t in targets:
                names.extend(_iter_names(t))
            for n in names:
                # 튜플 언패킹(a, b = f())은 값 노드를 이름별로 나눌 수 없으므로
                # 리터럴이 아닌 한 재평가 대상에서 제외한다(보수적).
                single_target = len(names) == 1
                if isinstance(value, (ast.List, ast.Set, ast.Dict)):
                    # **가변** 컨테이너 — 빈 리스트도 리터럴로 보이지만 이후
                    # append 로 동적 값이 들어올 수 있다. 상수 확정은 변형
                    # 검사(5단계) 이후로 미룬다.
                    container_candidates.add(n)
                    mutable_const_candidates.add(n)
                    if not _is_literal(value):
                        container_disqualified.add(n)
                        disqualified.add(n)
                elif _is_literal(value):
                    const_candidates.add(n)
                    if isinstance(value, ast.Tuple):   # 불변 — 변형될 일이 없다
                        container_candidates.add(n)
                else:
                    disqualified.add(n)
                    container_disqualified.add(n)   # 동적 값 재대입 — 컨테이너 자격도 상실
                    if single_target and value is not None:
                        assignments.setdefault(n, []).append(value)
        # 2) 증강 대입은 항상 실격(값이 바뀔 수 있음)
        elif isinstance(s, ast.AugAssign):
            for n in _iter_names(s.target):
                disqualified.add(n)
                assignments.pop(n, None)      # 재평가 대상에서 완전히 제외
                assignments[n] = [s.value, ast.Name(id="__aug__", ctx=ast.Load())]
        # 3) for 루프 변수 — 리터럴 이터러블 순회면 상수
        elif isinstance(s, (ast.For, ast.AsyncFor)):
            names = _iter_names(s.target)
            if _literal_iterable_elements_are_literal(s.iter):
                const_candidates.update(names)
            else:
                for n in names:
                    disqualified.add(n)
                    assignments[n] = [ast.Name(id="__loop__", ctx=ast.Load())]
        # 4) with ... as x / except ... as e — 동적으로 본다
        elif isinstance(s, (ast.With, ast.AsyncWith)):
            for item in s.items:
                if item.optional_vars is not None:
                    for n in _iter_names(item.optional_vars):
                        disqualified.add(n)
                        assignments[n] = [ast.Name(id="__with__", ctx=ast.Load())]

    # 5) 컨테이너에 동적 값이 들어가면 실격 — 스코프 전체에서 append/extend 확인
    for s in flat:
        for node in ast.walk(s):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                continue
            base = node.func.value
            if not isinstance(base, ast.Name) or base.id not in container_candidates:
                continue
            attr = node.func.attr
            if attr in {"append", "insert"}:
                args = node.args[1:] if attr == "insert" else node.args
                if not all(_is_literal(a) for a in args):
                    container_disqualified.add(base.id)
            elif attr == "extend":
                if not all(_literal_iterable_elements_are_literal(a) or _is_literal(a)
                           for a in node.args):
                    container_disqualified.add(base.id)
            elif attr in {"__setitem__", "update"}:
                container_disqualified.add(base.id)

    # 6) 함수 인자로 넘겨 변형될 수 있는 컨테이너도 보수적으로 실격
    for s in flat:
        for node in ast.walk(s):
            if not isinstance(node, ast.Call):
                continue
            # obj.method(container) — join/format 같은 읽기 전용은 예외로 둔다
            readonly = (
                isinstance(node.func, ast.Attribute)
                and node.func.attr in {"join", "format", "count", "index"}
            )
            if readonly:
                continue
            for a in node.args:
                if isinstance(a, ast.Name) and a.id in container_candidates:
                    container_disqualified.add(a.id)

    # 가변 컨테이너는 **변형이 없을 때만** 상수로 인정한다.
    safe_mutables = mutable_const_candidates - container_disqualified
    env = ConstEnv(
        names=(const_candidates | safe_mutables) - disqualified,
        containers=container_candidates - container_disqualified,
    )

    # 7) 고정점 반복 — 확정된 상수·컨테이너에 기대어 상수임이 드러나는 이름을
    #    승격한다(예: where = "WHERE " + " AND ".join(conds)).
    for _ in range(5):   # 실무 코드에서 5단계면 충분하고, 무한 루프를 막는다
        promoted = False
        for name, values in assignments.items():
            if name in env.names or not values:
                continue
            if all(expr_is_constant(v, env) for v in values):
                env.names.add(name)
                promoted = True
        if not promoted:
            break

    return env


def expr_is_constant(node: ast.AST, env: ConstEnv) -> bool:
    """이 표현식이 (상수 환경 기준) 상수로 평가되는가.

    ``' AND '.join(conds)`` 처럼 **리터럴만 담긴 컨테이너를 읽는 호출**도 상수로
    본다 — 실측에서 이 형태가 WHERE 절 조립의 전형이었고, 값은 전부 파라미터
    바인딩으로 넘어가고 있었다.
    """
    if _is_literal(node):
        return True
    if isinstance(node, ast.Name):
        return node.id in env.names
    if isinstance(node, ast.JoinedStr):
        return all(
            not isinstance(v, ast.FormattedValue) or expr_is_constant(v.value, env)
            for v in node.values
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return expr_is_constant(node.left, env) and expr_is_constant(node.right, env)
    if isinstance(node, ast.IfExp):
        return expr_is_constant(node.body, env) and expr_is_constant(node.orelse, env)
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "join":
            base_ok = expr_is_constant(func.value, env)
            arg_ok = all(
                (isinstance(a, ast.Name) and a.id in env.containers) or expr_is_constant(a, env)
                for a in node.args
            )
            return base_ok and arg_ok and bool(node.args)
        if isinstance(func, ast.Attribute) and func.attr == "format":
            return expr_is_constant(func.value, env) and all(
                expr_is_constant(a, env) for a in node.args
            )
    return False


# ---------------------------------------------------------------------------
# 모듈 단위 매개변수 상수 증명 — 스코프 안만 봐서는 절대 알 수 없는 것
# ---------------------------------------------------------------------------
#
# 실측(2026-08-09, koica-reg-mcp):
#
#     def _bump(conn, table, key_col, key, now):
#         conn.execute(f"INSERT INTO {table}({key_col}, ...) VALUES(?, ?, ?)", (key, now, now))
#     ...
#     _bump(conn, "tool_usage", "tool", tool, now)      # 호출부 넷 전부 리터럴
#
# 값(`key`·`now`)은 전부 `?` 바인딩이고 f-string 이 끼워 넣는 것은 **테이블·컬럼
# 이름뿐**인데, 그 둘은 모듈 안 모든 호출부에서 문자열 리터럴이다. 스코프 안만
# 보는 상수 판정으로는 매개변수의 출처를 알 수 없어 '치명·차단'이 됐다.
#
# SQL 식별자는 파라미터 바인딩으로 넘길 수 없으므로 f-string 조립 자체는
# 정당한 패턴이다. 위험한 것은 **거기에 들어오는 값이 외부 입력일 때**뿐이다.


def _param_names(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    a = fn.args
    return [p.arg for p in (*a.posonlyargs, *a.args)]


def literal_only_parameters(tree: ast.AST) -> dict[str, set[str]]:
    """모듈 내 **모든 호출부가 문자열 리터럴을 넘기는** 매개변수를 함수별로 모은다.

    반환: ``{함수이름: {매개변수이름, ...}}``

    소리(soundness)를 지키기 위해 아래를 전부 요구한다.

    - 함수 이름이 ``_`` 로 시작한다(모듈 사설). 공개 함수는 다른 모듈에서
      부를 수 있어 이 모듈만 봐서는 증명이 되지 않는다.
    - 같은 이름의 함수 정의가 모듈에 **하나뿐**이다(재정의·오버라이드 배제).
    - 함수 이름이 호출 이외의 자리에 **값으로 등장하지 않는다**
      (``h = _bump`` · ``register(_bump)`` 처럼 넘겨지면 간접 호출을 놓친다).
    - 호출부가 **한 곳 이상** 있고, 그 전부가 해당 자리에 문자열 리터럴을 준다.
    - ``*args``/``**kwargs`` 로 넘기는 호출부가 하나라도 있으면 그 함수는 통째로
      포기한다 — 무엇이 어디로 가는지 알 수 없다.

    조건을 하나라도 못 채우면 그 매개변수는 **증명 실패**로 두고 예전처럼
    동적으로 본다. 증명하지 못한 것을 안전하다고 말하지 않는다.
    """
    defs: dict[str, list[ast.FunctionDef | ast.AsyncFunctionDef]] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            defs.setdefault(node.name, []).append(node)

    candidates = {
        name: fns[0] for name, fns in defs.items()
        if name.startswith("_") and len(fns) == 1
    }
    if not candidates:
        return {}

    # 이름이 값으로 새어 나가면 포기한다.
    for node in ast.walk(tree):
        if not isinstance(node, ast.Name) or isinstance(node.ctx, ast.Store):
            continue
        if node.id not in candidates:
            continue
        parent_is_callee = False
        for outer in ast.walk(tree):
            if isinstance(outer, ast.Call) and outer.func is node:
                parent_is_callee = True
                break
        if not parent_is_callee:
            candidates.pop(node.id, None)

    result: dict[str, set[str]] = {}
    for name, fn in candidates.items():
        params = _param_names(fn)
        if not params:
            continue
        calls = [
            n for n in ast.walk(tree)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == name
        ]
        if not calls:
            continue
        if any(
            any(isinstance(a, ast.Starred) for a in c.args)
            or any(kw.arg is None for kw in c.keywords)
            for c in calls
        ):
            continue

        literal: set[str] = set()
        for idx, param in enumerate(params):
            ok = True
            for call in calls:
                if idx < len(call.args):
                    given = call.args[idx]
                else:
                    given = next((kw.value for kw in call.keywords if kw.arg == param), None)
                    if given is None:
                        # 기본값에 기댄 호출 — 기본값이 리터럴이어야 인정한다.
                        defaults = fn.args.defaults
                        offset = len(params) - len(defaults)
                        given = defaults[idx - offset] if idx >= offset else None
                if not (isinstance(given, ast.Constant) and isinstance(given.value, str)):
                    ok = False
                    break
            if ok:
                literal.add(param)
        if literal:
            result[name] = literal
    return result
