"""tree-sitter 파서 공용 모듈 — `ts-structure` 와 `js-flow` 가 같은 파일을 두 번 파싱하지 않게 한다.

선택 설치(`pip install vibecode-checker[ts]`)다. 언어 팩이 하나라도 없으면 :func:`load_languages` 가 None 이고,
:func:`parse` 도 None 을 돌려준다(엔진이 스스로 꺼진다).

**직전 결과 하나를 캐시한다.** 열쇠는 (내용 바이트의 해시, 문법)이다. 파일 이름으로 잡지 않는다 — `scan_code` 의 기본
이름은 `<memory>` 이고, 시험은 같은 이름을 되풀이해 쓰고, HTML 은 원문과 스크립트 사본을 같은 이름으로 두 번 돌린다.
캐시와 파서는 스레드마다 따로 둔다(점검 서버가 요청을 여러 스레드에서 처리할 수 있다).
"""
from __future__ import annotations

import hashlib
import threading

_TS_SUFFIXES = (".ts", ".mts", ".cts")

_languages: dict | None = None
_languages_checked = False
_local = threading.local()


def load_languages() -> dict | None:
    """tree-sitter 와 언어 팩을 가져온다. 하나라도 없으면 None(엔진 꺼짐). 한 번만 시도한다."""
    global _languages, _languages_checked
    if _languages_checked:
        return _languages
    try:
        import tree_sitter_javascript as tsjs
        import tree_sitter_typescript as tsts
        from tree_sitter import Language, Parser
    except Exception:  # noqa: BLE001 — 미설치·바이너리 불일치 모두 '없음'
        _languages, _languages_checked = None, True
        return None
    try:
        _languages = {
            "Parser": Parser,
            "js": Language(tsjs.language()),
            "ts": Language(tsts.language_typescript()),
            "tsx": Language(tsts.language_tsx()),
        }
    except Exception:  # noqa: BLE001
        _languages = None
    _languages_checked = True
    return _languages


def grammar_for(filename: str) -> str:
    """파일 이름으로 문법을 고른다 — `.tsx` → tsx, `.ts`·`.mts`·`.cts` → ts, 그 밖(스크립트 사본 포함) → js."""
    low = filename.lower()
    if low.endswith(".tsx"):
        return "tsx"
    return "ts" if low.endswith(_TS_SUFFIXES) else "js"


def text(node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", "replace")


def unwrap(node):
    """TS 캐스트·괄호를 벗긴다 — `(eval as any)(x)` · `f!(x)` · `<T>x` · `x satisfies T`."""
    while node is not None and node.type in ("parenthesized_expression", "as_expression", "non_null_expression",
                                             "satisfies_expression", "type_assertion") and node.named_child_count >= 1:
        node = node.named_children[-1] if node.type == "type_assertion" else node.named_children[0]
    return node


def walk(node):
    """재귀 없이 앞에서부터 모든 노드를 돈다."""
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.children))


def _parser(grammar: str, languages: dict):
    parsers = getattr(_local, "parsers", None)
    if parsers is None:
        parsers = _local.parsers = {}
    p = parsers.get(grammar)
    if p is None:
        p = parsers[grammar] = languages["Parser"](languages[grammar])
    return p


def parse(code: str, filename: str):
    """``(root_node, src_bytes)`` — 언어 팩이 없으면 None. 같은 내용·같은 문법이면 직전 결과를 그대로 준다."""
    languages = load_languages()
    if languages is None:
        return None
    src = code.encode("utf-8")
    grammar = grammar_for(filename)
    key = (hashlib.blake2b(src, digest_size=16).digest(), len(src), grammar)
    cached = getattr(_local, "last", None)
    if cached is not None and cached[0] == key:
        return cached[2].root_node, cached[1]
    tree = _parser(grammar, languages).parse(src)
    _local.last = (key, src, tree)        # 나무를 붙잡아 둔다 — 노드는 나무가 살아 있는 동안만 쓸 수 있다
    return tree.root_node, src
