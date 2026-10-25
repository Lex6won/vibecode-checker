"""JS/TS 구조 해석 엔진(ts-structure, 45차 · C 결정 B) — **선택 설치**.

`pip install vibecode-checker[ts]` 로 `tree-sitter`·`tree-sitter-javascript`·`tree-sitter-typescript` 가 있을 때만
가동한다. 없으면 어댑터가 스스로 꺼지고(`is_available`), 보고서에는 "미가동" 배너만 남으며 판정은 현행
js-taint·regex 와 **똑같다**(판정 불가로 떨어뜨리지 않는다 — Semgrep 과 같은 보조 등급).

첫 판의 범위는 좁다. 줄 기반 엔진이 **글자 모양 때문에** 놓치는 것만 구조로 본다.
- 계산된 속성으로 가린 전역 eval: `window["ev" + "al"](x)` · `globalThis['eval'](x)` (경계 프로브 H-07)
- 이름에 담은 eval/Function: `const f = eval; f(x)` · `const F = Function; new F(x)`
- TS 문법(`as`·`!`·제네릭)이 끼어도 같은 구조로 읽힌다.
발견은 기존 룰 id(KISA-JS-INPUT-02)로 내고, 같은 줄의 regex 발견과는 dedup 으로 합쳐진다.
"""
from __future__ import annotations

from ..schema import Finding
from .base import ScannerAdapter
from .regex_scanner import InlineIgnores, build_finding, lookup_rule, redact_evidence

ENGINE = "ts-structure"
RULE_CODE_EXEC = "KISA-JS-INPUT-02"
_JS_SUFFIXES = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts")
_JS_LANGS = {"javascript", "typescript", "js", "ts"}
_GLOBALS = {"window", "globalThis", "self", "global"}
_EXEC_NAMES = {"eval", "Function"}
_MAX_BYTES = 1_500_000


def _load_languages() -> dict | None:
    """tree-sitter 와 언어 팩을 가져온다. 하나라도 없으면 None(엔진 꺼짐)."""
    try:
        import tree_sitter_javascript as tsjs
        import tree_sitter_typescript as tsts
        from tree_sitter import Language, Parser
    except Exception:  # noqa: BLE001 — 미설치·바이너리 불일치 모두 '없음'
        return None
    try:
        return {
            "Parser": Parser,
            "js": Language(tsjs.language()),
            "ts": Language(tsts.language_typescript()),
            "tsx": Language(tsts.language_tsx()),
        }
    except Exception:  # noqa: BLE001
        return None


def _text(node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", "replace")


def _folded_str(node, src: bytes) -> str | None:
    """문자열 리터럴 또는 문자열 리터럴끼리의 `+` 결합을 접은 값."""
    if node is None:
        return None
    t = node.type
    if t == "string":
        inner = [c for c in node.children if c.type == "string_fragment"]
        if not inner:
            return "" if _text(node, src) in ('""', "''", "``") else None
        return "".join(_text(c, src) for c in inner)
    if t == "template_string":
        if any(c.type == "template_substitution" for c in node.children):
            return None
        return "".join(_text(c, src) for c in node.children if c.type == "string_fragment")
    if t == "parenthesized_expression" and node.named_child_count == 1:
        return _folded_str(node.named_children[0], src)
    if t in ("as_expression", "non_null_expression", "satisfies_expression") and node.named_child_count >= 1:
        return _folded_str(node.named_children[0], src)
    if t == "binary_expression":
        op = node.child_by_field_name("operator")
        if op is not None and _text(op, src) == "+":
            left = _folded_str(node.child_by_field_name("left"), src)
            right = _folded_str(node.child_by_field_name("right"), src)
            if left is not None and right is not None:
                return left + right
    return None


def _unwrap(node):
    """TS 캐스트·괄호를 벗긴다 — `(eval as any)(x)` · `f!(x)`."""
    while node is not None and node.type in ("parenthesized_expression", "as_expression", "non_null_expression",
                                             "satisfies_expression", "type_assertion") and node.named_child_count >= 1:
        node = node.named_children[-1] if node.type == "type_assertion" else node.named_children[0]
    return node


def _is_global_exec_lookup(node, src: bytes) -> bool:
    """`window["ev"+"al"]` · `globalThis.eval` 처럼 전역 객체에서 eval/Function 을 꺼내는 식인가."""
    node = _unwrap(node)
    if node is None:
        return False
    if node.type == "subscript_expression":
        obj = _unwrap(node.child_by_field_name("object"))
        idx = node.child_by_field_name("index")
        return obj is not None and obj.type in ("identifier", "this") and _text(obj, src) in _GLOBALS | {"this"} \
            and _folded_str(idx, src) in _EXEC_NAMES
    if node.type == "member_expression":
        obj = _unwrap(node.child_by_field_name("object"))
        prop = node.child_by_field_name("property")
        return obj is not None and obj.type == "identifier" and _text(obj, src) in _GLOBALS \
            and prop is not None and _text(prop, src) in _EXEC_NAMES
    return False


def _walk(node):
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.children))


def analyze(code: str, *, filename: str, languages: dict) -> list[tuple[int, str, str]]:
    """(줄 번호, 근거, 확신도) 목록. 파서가 돌아가는 환경에서만 호출된다."""
    src = code.encode("utf-8")
    low = filename.lower()
    lang = languages["tsx"] if low.endswith(".tsx") else languages["ts"] if low.endswith((".ts", ".mts", ".cts")) else languages["js"]
    tree = languages["Parser"](lang).parse(src)
    root = tree.root_node

    # 1차: eval/Function 을 담은 이름
    aliases: set[str] = set()
    for n in _walk(root):
        if n.type == "variable_declarator":
            name, value = n.child_by_field_name("name"), _unwrap(n.child_by_field_name("value"))
            if name is None or value is None or name.type != "identifier":
                continue
            if (value.type == "identifier" and _text(value, src) in _EXEC_NAMES) or _is_global_exec_lookup(value, src):
                aliases.add(_text(name, src))
    # 2차: 호출
    out: list[tuple[int, str, str]] = []
    for n in _walk(root):
        if n.type not in ("call_expression", "new_expression"):
            continue
        fn = _unwrap(n.child_by_field_name("function") if n.type == "call_expression" else n.child_by_field_name("constructor"))
        if fn is None:
            continue
        line = n.start_point[0] + 1
        raw_fn = n.child_by_field_name("function") if n.type == "call_expression" else n.child_by_field_name("constructor")
        if _is_global_exec_lookup(fn, src):
            out.append((line, "전역 객체에서 계산된 이름으로 꺼낸 eval/Function 호출(구조 해석)", "likely"))
        elif fn.type == "identifier" and _text(fn, src) in aliases:
            out.append((line, f"`{_text(fn, src)}` 는 eval/Function 의 별칭 — 이름을 바꿔 가린 코드 실행(구조 해석)", "likely"))
        elif fn.type == "identifier" and _text(fn, src) in _EXEC_NAMES and raw_fn is not None and raw_fn.type != "identifier":
            # `(eval as any)(x)` · `(eval)(x)` — 캐스트·괄호로 감싸 줄 기반 패턴을 피한 직접 호출
            out.append((line, "캐스트·괄호로 감싼 eval/Function 직접 호출(구조 해석)", "likely"))
    return out


class TsStructureScanner(ScannerAdapter):
    name = ENGINE

    def __init__(self) -> None:
        self._langs: dict | None = None
        self._checked = False

    def is_available(self) -> bool:
        if not self._checked:
            self._langs = _load_languages()
            self._checked = True
        return self._langs is not None

    def scan(self, code: str, *, filename: str = "<memory>", language: str | None = None,
             scenario: str | None = None, profile: str = "public-default-strict",
             categories: set[str] | None = None) -> list[Finding]:
        low = filename.lower()
        if not (low.endswith(_JS_SUFFIXES) or (language or "").lower() in _JS_LANGS):
            return []
        if categories and "injection" not in categories and "code-exec" not in categories:
            return []
        if len(code) > _MAX_BYTES or not self.is_available():
            return []
        rule = lookup_rule(RULE_CODE_EXEC)
        if rule is None:
            return []
        ignores = InlineIgnores(code, "javascript")
        lines = code.split("\n")
        out: list[Finding] = []
        for line, why, conf in analyze(code, filename=filename, languages=self._langs or {}):
            if ignores.suppresses(line, RULE_CODE_EXEC, conf):
                continue
            snippet = lines[line - 1].strip() if 0 < line <= len(lines) else ""
            out.append(build_finding(rule, filename=filename, line_no=line,
                                     evidence=redact_evidence(f"{snippet[:120]} — {why}"), engine=ENGINE, confidence=conf))
        return out
