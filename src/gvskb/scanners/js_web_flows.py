"""JS·TS 서버 코드에서 웹 요청 값이 **변수·같은 파일의 함수를 거쳐** 닿는 흐름 — 서버 대리 요청 · 파일 경로 · 리다이렉트 · 명령.

실측(2026-11-21 말뭉치 `l_remote_unauth_2026`): `axios.get(req.query.url)` 처럼 한 줄에 출처와 호출이 함께 있으면 줄 단위
정규식이 잡지만, `const value = req.query.url; axios.get(value)` 처럼 변수 하나만 거치면 전부 놓쳤다. 범위·가림·구조분해·콜백을
빠짐없이 봐야 아래 원칙이 성립하므로 tree-sitter 구문 트리 위에서 이름을 선언에 묶고 대입을 따라간다(엔진 `js-flow`).

**원칙 — Python 판(`py_web_flows`)과 같다. 그 값이 다른 데 쓰인 적이 없을 때만, '유력(검토)'으로 보고한다.**

요청 값, 거기서 나온 값, 그 값을 들여다본 변수를 한 묶음으로 본다. 묶음의 어느 하나라도 "해가 없다고 분명히 아는 쓰임" 밖에서
한 번이라도 쓰였으면 보고하지 않는다. 그 쓰임이 검사인지는 판단하지 않는다 — 모르는 함수에 넘겼다, 비교했다, 객체의 키로 썼다,
조건식에 넣었다 → 전부 침묵이다. 같은 요청 필드는 읽는 방식이 달라도(`req.query.url`·`req.query['url']`·`const { url } = req.query`)
하나의 열쇠로 보고, 쓰임은 **파일 전체**에서 찾는다. "검사로 인정되는 모양"의 목록은 두지 않는다. 늘리는 것은 "해가 없는 쓰임"의
목록뿐이다: 다른 이름에 담기·이어 붙이기, 값이 있는지만 보고 없으면 끝내기, 기록 남기기, `res.json(…)` 으로 돌려주기, 위험한 자리 그 자체,
값을 그대로 옮기는 것으로 아는 호출(`String`·`trim`·`path.join` 등).

근거를 '확인됨'이 아니라 '유력'으로 내는 까닭: 이 분석이 말할 수 있는 것은 "검사를 못 봤다"이지 "검사가 없다"가 아니다.

출처는 **구조로 확인된** 요청 객체뿐이다: `express()`·`Router()`·`new Koa()`·`new Hono()`·`fastify()` 등의 결과를 담은 이름에
등록한 라우트 처리 함수의 첫 매개변수, 또는 express·fastify·koa·hono 에서 가져온 요청 형으로 표기한 매개변수. 이름이 `req` 라는
것만으로는 인정하지 않는다. 응답 객체도 같다(그 바로 다음 매개변수, 그 값을 그대로 넘겨받은 같은 파일 함수의 매개변수).

**그래서 놓치는 것**: 검사처럼 보이지만 검사가 아닌 코드, 다른 파일로 넘어가는 흐름, 객체 속성에 담아 둔 값, 콜백 매개변수로
넘어가는 흐름, 알 수 없는 함수의 반환값, 같은 이름의 필드를 다른 함수가 들여다본 경우, 검증 미들웨어가 걸린 라우트(전부 침묵).
"""
from __future__ import annotations

import re

from ._ts_parse import text as _text
from ._ts_parse import unwrap as _unwrap
from .regex_scanner import redact_evidence

RULE_SSRF = "KISA-JS-INPUT-12"
RULE_PATH = "KISA-JS-INPUT-03"
RULE_REDIRECT = "KISA-JS-INPUT-07"
RULE_CMD = "KISA-JS-INPUT-05"
EMITTED_RULE_IDS = (RULE_SSRF, RULE_PATH, RULE_REDIRECT, RULE_CMD)
CONFIDENCE = "likely"                 # "검사를 못 봤다" — 사람이 확인할 발견이다(모듈 설명 참고)

REQ = "REQ"                           # 요청 필드 열쇠의 뿌리 — `REQ[query.url]` · 그릇 `REQ[query]` · 요청 객체 통째 `REQ`
MAX_BYTES = 512 * 1024                # 이보다 큰 파일은 보지 않는다
_BUDGET = 1_500_000                   # 한 파일에서 보는 노드 조각 수의 한도(Python 판과 같다) — 넘으면 이 분석만 건너뛴다
_MAX_HOPS = 1                         # 같은 파일 함수 요약으로 잇는 단계 수(W1-a: 1단계 — 호출부 → 함수 안의 위험한 자리)
_MAX_ROUNDS = 4
_PARTS_LIMIT = 400                    # 이보다 긴 연결식은 앞부분만 본다

#: 이 모듈을 가져온 파일만 본다(서버 프레임워크 표지).
FRAMEWORK_MODULES = frozenset({
    "express", "koa", "@koa/router", "koa-router", "fastify", "hono", "@hapi/hapi", "restify", "polka",
    "next", "next/server", "next/navigation", "@nestjs/common",
})
#: 파싱 전에 거르는 글자 표지 — 표지가 없는 파일(라이브러리·브라우저 코드 대부분)은 파서도 부르지 않는다.
FRAMEWORK_IMPORT_RE = re.compile(
    r"""(?:\brequire\s*\(\s*|\bfrom\s*|\bimport\s*\(?\s*)['"](?:node:)?"""
    r"""(?:express|koa|@koa/router|koa-router|fastify|hono|@hapi/hapi|restify|polka|next|next/server|next/navigation"""
    r"""|@nestjs/common)['"]""",
)

_FUNC_TYPES = frozenset({"function_declaration", "generator_function_declaration", "function_expression", "function",
                         "generator_function", "arrow_function", "method_definition"})
_FUNC_DECL_TYPES = frozenset({"function_declaration", "generator_function_declaration"})
_CLASS_TYPES = frozenset({"class_declaration", "abstract_class_declaration", "class"})
_SKIP_TYPES = frozenset({
    "comment", "html_comment", "hash_bang_line", "type_annotation", "type_arguments", "type_parameters",
    "interface_declaration", "type_alias_declaration", "ambient_declaration", "enum_declaration", "predefined_type",
    "type_identifier", "regex", "property_identifier", "private_property_identifier", "statement_identifier",
    "import_statement", "abstract_method_signature", "method_signature", "index_signature",
})
_WRAPPERS = frozenset({"parenthesized_expression", "as_expression", "non_null_expression", "satisfies_expression",
                       "type_assertion"})
_KEYED_TYPES = frozenset({"identifier", "shorthand_property_identifier", "member_expression", "subscript_expression",
                          "call_expression"})

_MODULE_ALIASES = {"fs/promises": "fs.promises", "path/posix": "path", "path/win32": "path"}

# ── 출처 ─────────────────────────────────────────────────────────────────────
_ROUTE_METHODS = frozenset({"get", "post", "put", "patch", "delete", "del", "all", "head", "options", "use"})
#: 이 호출의 결과가 담긴 이름이 프레임워크 객체다(라우트를 등록하는 쪽).
_FW_CALLS = {
    "express": "express", "express.Router": "express", "polka": "express", "restify.createServer": "express",
    "fastify": "fastify", "fastify.fastify": "fastify", "fastify.default": "fastify",
}
_FW_NEW = {"koa": "koa", "@koa/router": "koa", "koa-router": "koa", "hono.Hono": "hono", "express.Router": "express"}
#: 매개변수 형 표기로 인정하는 요청 형(그 모듈에서 가져온 것일 때만).
_TYPED_REQUESTS = {
    "express.Request": "express", "fastify.FastifyRequest": "fastify", "koa.Context": "koa",
    "koa.ParameterizedContext": "koa", "hono.Context": "hono",
}
_EXPRESS_FIELDS = frozenset({"query", "body", "params", "headers", "cookies", "signedCookies"})
_KOA_FIELDS = frozenset({"query", "params", "headers", "header"})
_KOA_REQUEST_FIELDS = frozenset({"query", "body", "headers", "header"})
#: 응답 객체에서 이어 부르는 것(같은 응답 객체를 돌려준다) — `res.status(302).redirect(u)`.
_RES_CHAIN = frozenset({"status", "set", "header", "type", "cookie", "clearCookie", "append", "vary", "code", "headers"})

# ── 4-7 핸들러·파일 단위 침묵 ───────────────────────────────────────────────
_NEUTRAL_NAMES = frozenset({
    "cors", "helmet", "morgan", "cookieParser", "compression", "rateLimit", "rateLimiter", "slowDown", "session",
    "expressSession", "bodyParser", "json", "urlencoded", "static", "raw", "text", "csrf", "csurf", "serveStatic", "koaBody",
})
_NEUTRAL_MODULES = frozenset({
    "cors", "helmet", "morgan", "cookie-parser", "compression", "express-rate-limit", "express-session", "body-parser",
    "csurf", "express-slow-down", "serve-static", "serve-favicon", "koa-bodyparser", "@koa/bodyparser", "@koa/cors", "koa-body",
    "koa-helmet", "koa-logger", "koa-static", "koa-compress", "hono/logger", "hono/cors", "hono/secure-headers",
    "hono/compress", "hono/etag", "hono/pretty-json", "hono/timing", "hono/request-id",
})
_UPLOAD_METHODS = frozenset({"single", "array", "fields", "none", "any"})
_FASTIFY_HOOK_KEYS = frozenset({"preHandler", "onRequest", "preValidation", "preParsing"})
#: URL 원문을 읽는 필드 — 쿼리 전체를 읽은 것으로 본다(쓰임 전용 열쇠 `REQ[query]`, 출처는 아니다).
_URL_FIELDS = {
    "express": frozenset({"url", "originalUrl", "_parsedUrl"}),
    "fastify": frozenset({"url", "originalUrl"}),
    "koa": frozenset({"url", "originalUrl", "querystring", "search", "href"}),
}
#: 경로를 읽는 필드 — 경로 매개변수 전체를 읽은 것으로 본다(쓰임 전용 열쇠 `REQ[params]`).
_PATH_FIELDS = {
    "express": frozenset({"path"}),
    "fastify": frozenset({"routerPath", "routeOptions"}),
    "koa": frozenset({"path"}),
}
#: 응답 객체에 값을 싣지만 해가 없다고 아는 메서드 — 내려받기 이름·헤더·형식.
_RES_HARMLESS = frozenset({"json", "attachment", "set", "setHeader", "type"})
#: import 로 확인하면 투명하게 보는 비동기 래퍼 모듈 — `asyncHandler(async (req, res) => …)`.
_ASYNC_WRAPPER_MODULES = frozenset({"express-async-handler", "express-async-wrap", "@awaitjs/express",
                                    "express-promise-wrap", "async-handler"})
_MOUNT_METHODS = frozenset({"routes", "allowedMethods", "middleware"})

# ── 흐름 ─────────────────────────────────────────────────────────────────────
#: 값을 그대로 옮기는 것으로 아는 호출(전체 이름) — 묶음을 유지하고 쓰임으로 치지 않는다.
_PASS_ALL_ARGS = frozenset({"path.join", "path.resolve", "path.normalize", "path.posix.join", "path.posix.resolve",
                            "path.win32.join", "path.win32.resolve", "Object.assign"})
_PASS_FIRST_ARG = frozenset({"String", "decodeURIComponent", "decodeURI", "JSON.stringify"})
_PASS_METHODS_NOARG = frozenset({"toString", "trim"})
_LOG_METHODS = frozenset({"log", "info", "debug", "warn", "error", "trace", "fatal"})
_LOG_OWNER_RE = re.compile(r"(?i)(?:log|logger|debug)$")
_LOG_PASS_TYPES = frozenset({"arguments", "template_substitution", "template_string", "binary_expression", "pair",
                             "object", "array", "parenthesized_expression", "as_expression", "non_null_expression"})
#: 아직 호스트가 끝나지 않은 접두 — `""`·`"http://"`·`"https://api-"`·`"//"`. 이 뒤에 붙는 값이 호스트를 정한다.
_OPEN_AUTHORITY_RE = re.compile(r"^(?:(?:[A-Za-z][A-Za-z0-9+.\-]*:)?//[^/?#\s]*|[A-Za-z][A-Za-z0-9+.\-]*:/?)$")

# ── 닿는 자리 ────────────────────────────────────────────────────────────────
_HTTP_VERBS = ("get", "post", "put", "patch", "delete", "head", "options")
_SSRF_FIRST = frozenset(
    {"node-fetch", "cross-fetch", "isomorphic-fetch", "undici.fetch", "undici.request", "axios", "got", "ky", "request",
     "superagent", "http.get", "http.request", "https.get", "https.request"}
    | {f"{lib}.{verb}" for lib in ("axios", "got", "ky", "request", "superagent", "needle") for verb in _HTTP_VERBS}
    | {"request.del", "superagent.del"},
)
_SSRF_CONFIG = frozenset({"axios.request"})
_FS_METHODS = ("readFile", "readFileSync", "createReadStream", "createWriteStream", "writeFile", "writeFileSync",
               "appendFile", "appendFileSync", "unlink", "unlinkSync", "rm", "rmSync", "readdir", "readdirSync", "stat",
               "statSync")
_PATH_SINKS = frozenset(f"{mod}.{m}" for mod in ("fs", "fs.promises", "fs-extra", "graceful-fs") for m in _FS_METHODS)
_EXEC_SINKS = frozenset({"child_process.exec", "child_process.execSync"})
_SPAWN_SINKS = frozenset({"child_process.spawn", "child_process.spawnSync"})
_EXEC_FILE_SINKS = frozenset({"child_process.execFile", "child_process.execFileSync"})
_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh"})


class _OutOfBudget(Exception):
    """한 파일에 쓸 일의 양을 넘었다."""


class _Unresolvable(Exception):
    """이 파일의 이름을 풀 수 없다(`eval`·`with`) — 이 분석을 통째로 건너뛴다."""


def _named(node) -> list:
    return [c for c in node.named_children if c.type != "comment"] if node is not None else []


def _field(node, name: str):
    return node.child_by_field_name(name) if node is not None else None


def _str_value(node, src: bytes) -> str | None:
    """문자열 리터럴(치환 없는 템플릿 포함)의 값. 아니면 None."""
    n = _unwrap(node)
    if n is None:
        return None
    if n.type == "string" or (n.type == "template_string" and not any(c.type == "template_substitution" for c in n.children)):
        return "".join(_text(c, src) for c in n.named_children if c.type in ("string_fragment", "escape_sequence"))
    return None


def _walk_nodes(node):
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(n.children)


def _callee(call):
    """호출 대상 — TS 문법은 `await axios.get<T>(x)` 의 `await` 를 함수 자리에 붙여 읽는다."""
    f = _unwrap(_field(call, "function"))
    while f is not None and f.type == "await_expression" and _named(f):
        f = _unwrap(_named(f)[0])
    return f


def _args(call) -> list:
    a = _field(call, "arguments")
    return _named(a) if a is not None and a.type == "arguments" else []


def _ancestors(key: str) -> list[str]:
    """열쇠를 감싸는 그릇들 — `REQ[query.url]` → [`REQ[query]`, `REQ`]."""
    if not key.startswith(REQ + "["):
        return []
    inner = key[len(REQ) + 1:-1].split(".")
    return [f"{REQ}[{'.'.join(inner[:i])}]" for i in range(len(inner) - 1, 0, -1)] + [REQ]


def _extend(key: str, path) -> str | None:
    if not path:
        return key
    if not key.startswith(REQ + "["):
        return None
    return key[:-1] + "." + ".".join(path) + "]"


def _is_statement(t: str) -> bool:
    return t.endswith(("_statement", "_declaration")) or t in ("statement_block", "program", "switch_case", "switch_default")


class _Groups:
    """서로 이어진 값들의 묶음 — 값에서 나온 값, 값을 들여다본 결과."""

    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        root = x
        while self.parent.get(root, root) != root:
            root = self.parent[root]
        while self.parent.get(x, x) != root:
            self.parent[x], x = root, self.parent[x]
        return root

    def link(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[ra] = rb


class _Binding:
    """선언 하나 — 같은 이름이라도 범위가 다르면 다른 선언이다(가림)."""

    __slots__ = ("id", "key", "name", "kind", "func", "writes", "init", "path")

    def __init__(self, bid: int, name: str, kind: str, func: int) -> None:
        self.id = bid
        self.key = f"B{bid}"
        self.name = name
        self.kind = kind                 # var·let·const·param·function·fname·class·import·catch
        self.func = func                 # 선언한 함수 노드의 id(최상위는 0)
        self.writes: list[int] = []      # 다시 대입한 자리가 속한 함수 노드의 id
        self.init = None                 # (값 노드, 구조분해 경로 | None) — 선언과 함께 대입된 값


class _Lex:
    __slots__ = ("parent", "names", "func", "func_node")

    def __init__(self, parent: _Lex | None, func_node) -> None:
        self.parent = parent
        self.names: dict[str, _Binding] = {}
        self.func_node = func_node
        self.func = func_node.id if func_node is not None else 0


def _func_lex(lex: _Lex) -> _Lex:
    """`var` 가 올라가는 범위 — 가장 가까운 함수(또는 최상위)."""
    cur = lex
    while cur.parent is not None and cur.parent.func == cur.func:
        cur = cur.parent
    return cur


def _param_nodes(fn) -> list:
    single = _field(fn, "parameter")
    if single is not None:
        return [single]
    return _named(_field(fn, "parameters"))


def _param_parts(p):
    """매개변수 노드 → (패턴, 기본값)."""
    t = p.type
    if t in ("required_parameter", "optional_parameter"):
        return _field(p, "pattern"), _field(p, "value")
    if t == "assignment_pattern":
        return _field(p, "left"), _field(p, "right")
    if t in ("identifier", "object_pattern", "array_pattern", "rest_pattern"):
        return p, None
    return None, None


def _pattern_items(pattern, src: bytes):
    """패턴 → ([(이름 노드, 경로 | None, 나머지인가)], [기본값·계산된 키 식]). 경로 None 은 위치를 모른다(배열·계산된 키)."""
    items: list = []
    exprs: list = []
    stack = [(pattern, ())]
    while stack:
        n, path = stack.pop()
        if n is None:
            continue
        t = n.type
        if t in ("identifier", "shorthand_property_identifier_pattern"):
            items.append((n, path, False))
        elif t == "object_pattern":
            for c in _named(n):
                ct = c.type
                if ct == "shorthand_property_identifier_pattern":
                    items.append((c, None if path is None else (*path, _text(c, src)), False))
                elif ct == "pair_pattern":
                    key, val = _field(c, "key"), _field(c, "value")
                    kname = None
                    if key is not None and key.type == "property_identifier":
                        kname = _text(key, src)
                    elif key is not None and key.type in ("string", "number"):
                        kname = _str_value(key, src) if key.type == "string" else _text(key, src)
                    elif key is not None:
                        exprs.append(key)
                    stack.append((val, None if path is None or kname is None else (*path, kname)))
                elif ct == "object_assignment_pattern":
                    left, right = _field(c, "left"), _field(c, "right")
                    if right is not None:
                        exprs.append(right)
                    if left is not None and left.type == "shorthand_property_identifier_pattern":
                        items.append((left, None if path is None else (*path, _text(left, src)), False))
                    else:
                        stack.append((left, None))
                elif ct == "rest_pattern":
                    inner = _named(c)
                    if inner and inner[0].type == "identifier":
                        items.append((inner[0], path, True))
                    elif inner:
                        stack.append((inner[0], None))
        elif t == "array_pattern":
            for c in _named(n):
                stack.append((c, None))
        elif t == "assignment_pattern":
            right = _field(n, "right")
            if right is not None:
                exprs.append(right)
            stack.append((_field(n, "left"), path))
        elif t == "rest_pattern":
            inner = _named(n)
            if inner:
                stack.append((inner[0], None))
        elif t in _WRAPPERS:
            inner = _named(n)
            if inner:
                stack.append((inner[0], path))
    return items, exprs


class _ReqInfo:
    __slots__ = ("kind", "constrained")

    def __init__(self, kind: str, constrained: frozenset[str]) -> None:
        self.kind = kind
        self.constrained = constrained


class _Context:
    """파일 하나에서 미리 알아 두는 것 — 이름과 선언, 프레임워크 객체, 요청·응답 객체, 같은 파일 함수와 그 요약."""

    def __init__(self, root, src: bytes) -> None:
        self.root = root
        self.src = src
        self.budget = _BUDGET
        self.parents: dict[int, object] = {}
        self.calls: list = []                              # 파일의 모든 호출 노드
        self.assigns: list = []                            # 파일의 모든 대입 식
        self.bindings: list[_Binding] = []
        self.reads: dict[int, _Binding] = {}               # 읽는 자리의 이름 노드 → 선언
        self.write_refs: dict[int, _Binding] = {}          # 대입하는 자리의 이름 노드 → 선언
        self.decl: dict[int, _Binding] = {}                # 선언하는 자리의 이름 노드 → 선언
        self.params: dict[int, list] = {}                  # 함수 노드 → 자리마다 선언(구조분해·나머지는 None)
        self.param_patterns: dict[int, dict[int, list]] = {}   # 함수 노드 → 자리 → [(선언, 경로)] (구조분해한 매개변수)
        self.param_types: dict[int, dict[int, object]] = {}    # 함수 노드 → 자리 → 형 노드
        self.opaque: set[int] = set()                      # 풀 수 없는 선언(다른 함수에서 다시 대입, `arguments`)
        self.imports: dict[int, str] = {}                  # 선언 → 가져온 모듈 경로(`child_process.exec`)
        self.import_names: dict[str, str] = {}             # 최상위에서 가져온 이름 → 모듈 경로(형 표기 풀이용)
        self.fw: dict[int, str] = {}                       # 프레임워크 객체 선언 → 종류
        self.reqs: dict[int, _ReqInfo] = {}                # 요청 객체 선언
        self.resps: dict[int, str] = {}                    # 응답 객체 선언 → 종류
        self.aliases: dict[int, str] = {}                  # 한 번만 대입된 이름 → 그것이 가리키는 요청 필드 열쇠
        self.handlers: dict[int, bool] = {}                # 라우트 처리 함수 노드 → 보고해도 되는가(모르는 미들웨어가 없다)
        self.funcs: dict[int, object] = {}                 # 같은 파일 함수 선언 → 함수 노드
        self.func_of_node: dict[int, int] = {}             # 함수 노드 → 그 선언
        self.summaries: dict[int, tuple[frozenset, frozenset, frozenset]] = {}
        self.param_sources: dict[int, dict[int, tuple[bool, int]]] = {}
        self.collected: dict[int, dict[int, tuple[bool, int]]] = {}
        self.request_used: set[str] = set()
        self.request_used_next: set[str] = set()
        self.hits: list[tuple[str, int]] = []
        self.units: list = []
        self.uses: list[tuple[bool, list, str]] = []       # `app.use(…)` — (경로 인자가 있는가, 나머지 인자, 종류)
        self.root_gated: dict[int, list] = {}              # sendFile·download 호출 → 뿌리(root) 옵션 값들
        self.member_writes: dict[int, list] = {}           # 선언 → 나중에 `x.root = 값` 으로 대입한 값들
        self.dropped = False                               # 모르는 `app.use(…)` 가 있다 — 파일 전체를 버린다
        self._struct: dict[int, tuple | None] = {}
        self._full: dict[int, str | None] = {}
        self._sink: dict[int, tuple | None] = {}

    def spend(self, amount: int = 1) -> None:
        self.budget -= amount
        if self.budget < 0:
            raise _OutOfBudget

    def text(self, node) -> str:
        return _text(node, self.src)

    def parent(self, node):
        return self.parents.get(node.id)

    # ── 1. 노드 색인 · 범위와 선언 ─────────────────────────────────────────────

    def index(self) -> None:
        stack = [self.root]
        parents = self.parents
        calls = self.calls
        while stack:
            n = stack.pop()
            self.spend()
            if n.type == "call_expression":
                calls.append(n)
            elif n.type == "assignment_expression":
                self.assigns.append(n)
            for c in n.children:
                parents[c.id] = n
                stack.append(c)
        calls.sort(key=lambda c: c.start_byte)

    def _declare(self, lex: _Lex, ident, kind: str) -> _Binding:
        name = self.text(ident)
        b = lex.names.get(name)
        if b is not None:
            b.writes.append(lex.func)                      # 같은 범위에서 다시 선언 — 한 번만 대입된 이름이 아니다
        else:
            b = _Binding(len(self.bindings), name, kind, lex.func)
            self.bindings.append(b)
            lex.names[name] = b
        self.decl[ident.id] = b
        return b

    def scopes(self) -> None:
        """이름을 쓰는 자리를 가장 가까운 선언에 묶는다(가림을 지킨다). 선언을 먼저 다 모은 뒤 푼다(끌어올림)."""
        src = self.src
        program = _Lex(None, None)
        refs: list = []                                    # (이름 노드, 범위, 대입인가)
        stack: list = [(0, self.root, program, None)]
        while stack:
            op, node, lex, extra = stack.pop()
            self.spend()
            if node is None:
                continue
            t = node.type
            if op == 1:                                    # 선언 패턴
                kind, elex, init = extra
                items, exprs = _pattern_items(node, src)
                for ident, path, _rest in items:
                    b = self._declare(lex, ident, kind)
                    if init is not None:
                        b.init = (init, path)
                for e in exprs:
                    stack.append((0, e, elex, None))
                continue
            if op == 2:                                    # 대입 대상
                if t in ("identifier", "shorthand_property_identifier_pattern"):
                    refs.append((node, lex, True))
                elif t in ("object_pattern", "array_pattern"):
                    for c in _named(node):
                        ct = c.type
                        if ct == "pair_pattern":
                            stack.append((2, _field(c, "value"), lex, None))
                            key = _field(c, "key")
                            if key is not None and key.type == "computed_property_name":
                                stack.append((0, key, lex, None))
                        elif ct == "object_assignment_pattern":
                            stack.append((2, _field(c, "left"), lex, None))
                            stack.append((0, _field(c, "right"), lex, None))
                        else:
                            stack.append((2, c, lex, None))
                elif t == "assignment_pattern":
                    stack.append((2, _field(node, "left"), lex, None))
                    stack.append((0, _field(node, "right"), lex, None))
                elif t == "rest_pattern" or t in _WRAPPERS:
                    for c in _named(node):
                        stack.append((2, c, lex, None))
                else:
                    stack.append((0, node, lex, None))     # `obj.k = v` — 그릇을 읽는다
                continue
            if op == 3:                                    # 매개변수
                fn, idx = extra
                pattern, default = _param_parts(node)
                slots = self.params.setdefault(fn.id, [])
                while len(slots) <= idx:
                    slots.append(None)
                if node.type in ("required_parameter", "optional_parameter"):
                    note = _field(node, "type")
                    if note is not None:
                        self.param_types.setdefault(fn.id, {})[idx] = note
                if pattern is None:
                    continue
                if default is not None:
                    stack.append((0, default, lex, None))
                if pattern.type == "identifier":
                    slots[idx] = self._declare(lex, pattern, "param")
                    continue
                items, exprs = _pattern_items(pattern, src)
                pats = self.param_patterns.setdefault(fn.id, {}).setdefault(idx, [])
                for ident, path, rest in items:
                    b = self._declare(lex, ident, "param")
                    pats.append((b, None if rest else path))
                for e in exprs:
                    stack.append((0, e, lex, None))
                continue
            # op == 0: 일반 노드
            if t in _SKIP_TYPES and t != "import_statement":
                continue
            if t in _FUNC_TYPES:
                name = _field(node, "name")
                if t in _FUNC_DECL_TYPES and name is not None:
                    b = self._declare(lex, name, "function")
                    b.init = (node, ())
                flex = _Lex(lex, node)
                if t in ("function_expression", "function", "generator_function") and name is not None:
                    self._declare(flex, name, "fname")
                if t == "method_definition" and name is not None and name.type == "computed_property_name":
                    stack.append((0, name, lex, None))
                body = _field(node, "body")
                if body is not None and body.type == "statement_block":
                    for c in reversed(_named(body)):
                        stack.append((0, c, flex, None))
                elif body is not None:
                    stack.append((0, body, flex, None))
                for i, p in enumerate(_param_nodes(node)):
                    stack.append((3, p, flex, (node, i)))
                continue
            if t in ("class_declaration", "abstract_class_declaration"):
                name = _field(node, "name")
                if name is not None:
                    self._declare(lex, name, "class")
                for c in reversed(_named(node)):
                    if name is None or c.id != name.id:
                        stack.append((0, c, lex, None))
                continue
            if t in ("statement_block", "switch_body"):
                blex = _Lex(lex, lex.func_node)
                for c in reversed(_named(node)):
                    stack.append((0, c, blex, None))
                continue
            if t == "for_in_statement":
                blex = _Lex(lex, lex.func_node)
                kind = _field(node, "kind")
                left = _field(node, "left")
                if kind is not None:
                    k = self.text(kind)
                    stack.append((1, left, _func_lex(blex) if k == "var" else blex, (k, blex, None)))
                else:
                    stack.append((2, left, blex, None))
                stack.append((0, _field(node, "right"), blex, None))
                stack.append((0, _field(node, "body"), blex, None))
                continue
            if t == "for_statement":
                blex = _Lex(lex, lex.func_node)
                for c in reversed(_named(node)):
                    stack.append((0, c, blex, None))
                continue
            if t == "catch_clause":
                clex = _Lex(lex, lex.func_node)
                param = _field(node, "parameter")
                if param is not None:
                    stack.append((1, param, clex, ("catch", clex, None)))
                body = _field(node, "body")
                for c in reversed(_named(body)):
                    stack.append((0, c, clex, None))
                continue
            if t in ("lexical_declaration", "variable_declaration"):
                k = "var" if t == "variable_declaration" else self.text(node.children[0])
                tgt = _func_lex(lex) if k == "var" else lex
                for d in _named(node):
                    if d.type != "variable_declarator":
                        stack.append((0, d, lex, None))
                        continue
                    value = _field(d, "value")
                    stack.append((1, _field(d, "name"), tgt, (k, lex, value)))
                    if value is not None:
                        stack.append((0, value, lex, None))
                continue
            if t == "import_statement":
                self._import(node, program)
                continue
            if t in ("assignment_expression", "augmented_assignment_expression"):
                stack.append((2, _field(node, "left"), lex, None))
                stack.append((0, _field(node, "right"), lex, None))
                continue
            if t == "update_expression":
                arg = _field(node, "argument")
                stack.append((2, arg, lex, None))
                stack.append((0, arg, lex, None))
                continue
            if t in ("identifier", "shorthand_property_identifier"):
                refs.append((node, lex, False))
                continue
            if t == "with_statement":
                raise _Unresolvable
            for c in reversed(node.named_children):
                stack.append((0, c, lex, None))
        # 푼다
        for node, lex, is_write in refs:
            self.spend()
            name = self.text(node)
            cur: _Lex | None = lex
            b = None
            while cur is not None:
                b = cur.names.get(name)
                if b is not None:
                    break
                cur = cur.parent
            if b is None:
                if is_write:
                    continue
                p = self.parent(node)
                if name == "eval" and p is not None and p.type == "call_expression":
                    raise _Unresolvable                    # 직접 eval — 이 파일의 이름을 풀 수 없다
                if name == "arguments":
                    self._arguments_used(lex)
                continue
            if is_write:
                b.writes.append(lex.func)
                self.write_refs[node.id] = b
            else:
                self.reads[node.id] = b
        for b in self.bindings:
            if any(w != b.func for w in b.writes):
                self.opaque.add(b.id)                      # 다른 함수(클로저)에서 다시 대입 — 언제 무엇인지 모른다
        for n in self.assigns:
            left = _unwrap(_field(n, "left"))
            if left is None or left.type not in ("member_expression", "subscript_expression"):
                continue
            obj = _unwrap(_field(left, "object"))
            prop = _field(left, "property") if left.type == "member_expression" else _field(left, "index")
            name = (self.text(prop) if prop is not None and prop.type == "property_identifier"
                    else _str_value(prop, self.src))
            if name == "root" and obj is not None and obj.type == "identifier" and obj.id in self.reads:
                self.member_writes.setdefault(self.reads[obj.id].id, []).append(_field(n, "right"))

    def _arguments_used(self, lex: _Lex) -> None:
        """`arguments` 를 쓰는 함수의 매개변수는 풀 수 없다(화살표 함수는 바깥 함수의 것을 쓴다)."""
        fn = lex.func_node
        while fn is not None and fn.type == "arrow_function":
            p = self.parent(fn)
            while p is not None and p.type not in _FUNC_TYPES:
                p = self.parent(p)
            fn = p
        if fn is None:
            return
        for b in self.params.get(fn.id, []):
            if b is not None:
                self.opaque.add(b.id)
        for pats in self.param_patterns.get(fn.id, {}).values():
            for b, _ in pats:
                self.opaque.add(b.id)

    def _import(self, node, program: _Lex) -> None:
        module = _str_value(_field(node, "source"), self.src)
        if module is None:
            return
        module = self._norm_module(module)
        for clause in _named(node):
            if clause.type != "import_clause":
                continue
            for c in _named(clause):
                if c.type == "identifier":
                    self._import_binding(program, c, module)
                elif c.type == "namespace_import":
                    for ident in _named(c):
                        if ident.type == "identifier":
                            self._import_binding(program, ident, module)
                elif c.type == "named_imports":
                    for spec in _named(c):
                        if spec.type != "import_specifier":
                            continue
                        name, alias = _field(spec, "name"), _field(spec, "alias")
                        if name is None:
                            continue
                        imported = _str_value(name, self.src) if name.type == "string" else self.text(name)
                        self._import_binding(program, alias or name, f"{module}.{imported}")

    def _import_binding(self, program: _Lex, ident, path: str) -> None:
        b = self._declare(program, ident, "import")
        self.imports[b.id] = path
        self.import_names[self.text(ident)] = path

    @staticmethod
    def _norm_module(module: str) -> str:
        if module.startswith("node:"):
            module = module[5:]
        return _MODULE_ALIASES.get(module, module)

    def module_of(self, node) -> str | None:
        """`require('m')`·`require('m').a.b` 이면 그 모듈 경로."""
        n = _unwrap(node)
        props: list[str] = []
        while n is not None and n.type == "member_expression":
            prop = _field(n, "property")
            if prop is None or prop.type != "property_identifier":
                return None
            props.append(self.text(prop))
            n = _unwrap(_field(n, "object"))
        if n is None or n.type != "call_expression":
            return None
        f = _callee(n)
        args = _args(n)
        if f is None or f.type != "identifier" or self.text(f) != "require" or f.id in self.reads or len(args) != 1:
            return None
        module = _str_value(args[0], self.src)
        if module is None:
            return None
        return ".".join([self._norm_module(module), *reversed(props)])

    def full_name(self, node) -> str | None:
        """호출 대상의 전체 이름 — 가져온 이름은 모듈 경로로(`exec` → `child_process.exec`), 전역은 이름 그대로.
        같은 파일에서 선언한 이름(가져온 것이 아닌)은 None."""
        if node is None:
            return None
        cached = self._full.get(node.id, 0)
        if cached != 0:
            return cached
        out: str | None = None
        n = _unwrap(node)
        props: list[str] = []
        ok = True
        while n is not None and n.type == "member_expression":
            prop = _field(n, "property")
            if prop is None or prop.type != "property_identifier":
                ok = False
                break
            props.append(self.text(prop))
            n = _unwrap(_field(n, "object"))
        if ok and n is not None:
            base: str | None = None
            if n.type == "identifier":
                b = self.reads.get(n.id)
                if b is None:
                    base = self.text(n)
                elif b.id in self.imports:
                    base = self.imports[b.id]
            elif n.type == "call_expression":
                base = self.module_of(n)
            if base is not None:
                out = ".".join([base, *reversed(props)])
        self._full[node.id] = out
        return out

    # ── 2. 가져온 모듈 · 같은 파일 함수 · 프레임워크 객체 · 라우트 ─────────────

    def prepare_names(self) -> None:
        for b in self.bindings:
            if b.init is None or b.writes:
                continue
            value, path = b.init
            if b.kind == "function":
                self.funcs[b.id] = value
                continue
            if path is None or b.kind not in ("const", "let", "var"):
                continue
            module = self.module_of(value)
            if module is not None:
                self.imports[b.id] = ".".join([module, *path])
                continue
            v = _unwrap(value)
            if not path and v is not None and v.type in ("arrow_function", "function_expression", "function"):
                self.funcs[b.id] = v
                continue
            if not path and v is not None and v.type in ("call_expression", "new_expression"):
                callee = _unwrap(_field(v, "function" if v.type == "call_expression" else "constructor"))
                name = self.module_of(callee) if callee is not None and callee.type == "call_expression" \
                    else self.full_name(callee)
                kind = (_FW_CALLS if v.type == "call_expression" else _FW_NEW).get(name or "")
                if kind is not None:
                    self.fw[b.id] = kind
        self.func_of_node = {fn.id: bid for bid, fn in self.funcs.items()}

    def _function_value(self, node):
        n = _unwrap(node)
        if n is None:
            return None
        if n.type in _FUNC_TYPES:
            return n
        if n.type == "call_expression" and len(_args(n)) == 1 and self._is_async_wrapper(_callee(n)):
            inner = _unwrap(_args(n)[0])                   # `asyncHandler(async (req, res) => …)` — 투명한 래퍼
            return inner if inner is not None and inner.type in _FUNC_TYPES else None
        if n.type == "identifier":
            b = self.reads.get(n.id)
            if b is not None:
                return self.funcs.get(b.id)
        return None

    def _is_async_wrapper(self, callee) -> bool:
        """잘 알려진 비동기 래퍼(import 로 확인) 또는 같은 파일의 `(fn) => (req, res, next) => …fn(req, res, next)…` 모양."""
        if callee is None:
            return False
        for bid in self.bindings_of_import(callee):
            if self.imports[bid].split(".")[0] in _ASYNC_WRAPPER_MODULES or self.imports[bid] in _ASYNC_WRAPPER_MODULES:
                return True
        if callee.type != "identifier":
            return False
        b = self.reads.get(callee.id)
        outer = self.funcs.get(b.id) if b is not None else None
        outer_slots = self.params.get(outer.id, []) if outer is not None else []
        if outer is None or len(outer_slots) != 1 or outer_slots[0] is None:
            return False
        body = _unwrap(_field(outer, "body"))
        if body is not None and body.type == "statement_block":
            stmts = _named(body)
            body = _unwrap(_named(stmts[0])[0]) if len(stmts) == 1 and stmts[0].type == "return_statement" \
                and _named(stmts[0]) else None
        if body is None or body.type not in _FUNC_TYPES:
            return False
        inner_slots = [x for x in self.params.get(body.id, []) if x is not None]
        if not inner_slots:
            return False
        fn_param = outer_slots[0]
        passes = False
        for n in _walk_nodes(body):
            if n.type == "identifier" and self.reads.get(n.id) is inner_slots[0]:
                parent = self.parent(n)
                call = self.parent(parent) if parent is not None and parent.type == "arguments" else None
                callee_n = _callee(call) if call is not None and call.type == "call_expression" else None
                if callee_n is None or callee_n.type != "identifier" or self.reads.get(callee_n.id) is not fn_param:
                    return False                           # 요청 객체를 넘기는 것 말고 다른 데 쓴다 — 모르는 래퍼
                passes = True
        return passes

    def _route_owner(self, call) -> tuple[str, bool, str] | None:
        """`<fw>.get(경로, …, 함수)` 면 (종류, 경로 인자가 있는가, 메서드)."""
        f = _callee(call)
        if f is None or f.type != "member_expression":
            return None
        prop = _field(f, "property")
        method = self.text(prop) if prop is not None else ""
        if method not in _ROUTE_METHODS:
            return None
        obj = _unwrap(_field(f, "object"))
        has_path = True
        for _ in range(16):                                # `router.route('/x').get(a).post(b)`·`app.get(…).post(…)`
            if obj is None:
                return None
            if obj.type == "identifier":
                b = self.reads.get(obj.id)
                kind = self.fw.get(b.id) if b is not None else None
                return (kind, has_path, method) if kind is not None else None
            created = self._fw_kind_of_value(obj)
            if created is not None:
                return created, has_path, method           # `polka().get(…)`·`express().get(…)` — 담지 않고 바로 붙였다
            if obj.type != "call_expression":
                return None
            of = _callee(obj)
            if of is None or of.type != "member_expression":
                return None
            oprop = _field(of, "property")
            oname = self.text(oprop) if oprop is not None else ""
            if oname == "route":
                has_path = False
            elif oname not in _ROUTE_METHODS:
                return None
            obj = _unwrap(_field(of, "object"))
        return None

    def _fw_kind_of_value(self, v) -> str | None:
        """`express()`·`express.Router()`·`polka()`·`new Koa()`·`require('express')()` 이면 프레임워크 종류."""
        if v is None or v.type not in ("call_expression", "new_expression"):
            return None
        callee = _unwrap(_field(v, "function" if v.type == "call_expression" else "constructor"))
        if callee is None:
            return None
        name = self.module_of(callee) if callee.type == "call_expression" else self.full_name(callee)
        return (_FW_CALLS if v.type == "call_expression" else _FW_NEW).get(name or "")

    def _param_hook(self, call) -> None:
        """`router.param('file', check)` — 그 경로 매개변수는 다른 함수가 먼저 들여다본다(쓰인 것이다)."""
        f = _callee(call)
        if f is None or f.type != "member_expression":
            return
        prop = _field(f, "property")
        obj = _unwrap(_field(f, "object"))
        if prop is None or self.text(prop) != "param" or obj is None or obj.type != "identifier":
            return
        b = self.reads.get(obj.id)
        if b is None or b.id not in self.fw:
            return
        args = _args(call)
        name = _str_value(args[0], self.src) if args else None
        self.request_used.add(f"{REQ}[params.{name}]" if name else f"{REQ}[params]")

    def _is_path_arg(self, node) -> bool:
        """경로 인자인가 — 문자열·템플릿·정규식·그 배열, 또는 문자열로 한 번만 대입된 이름(`app.use(API_PREFIX, router)`)."""
        n = _unwrap(node)
        if n is None:
            return False
        if n.type in ("string", "template_string", "regex"):
            return True
        if n.type == "array":
            return all(c.type in ("string", "regex", "template_string") for c in _named(n))
        if n.type == "identifier":
            b = self.reads.get(n.id)
            init = _unwrap(b.init[0]) if b is not None and b.init is not None and not b.writes and b.init[1] == () else None
            return init is not None and init.type in ("string", "template_string")
        return False

    def routes(self) -> None:
        """라우트 등록에서 요청·응답 객체를 찾는다. `<obj>` 는 프레임워크 객체로 확인된 이름이어야 한다."""
        for call in self.calls:
            self.spend()
            self._param_hook(call)
            if self._route_object(call) or self._hook(call):
                continue
            owner = self._route_owner(call)
            if owner is None:
                continue
            kind, has_path, method = owner
            args = _args(call)
            if method == "use":
                with_path = bool(args) and self._is_path_arg(args[0])
                rest = args[1:] if with_path else args
                self.uses.append((with_path, rest, kind))
                for a in rest:
                    self._register_middlewares(a, kind)
                continue
            route = None
            if has_path:
                if len(args) < 2 or self._function_value(args[0]) is not None:
                    continue
                route, args = args[0], args[1:]
            if not args:
                continue
            fn = self._function_value(args[-1])
            if fn is None:
                continue
            for m in args[:-1]:
                self._register_middlewares(m, kind)
            reportable = all(self.middleware_ok(m, kind) for m in args[:-1])
            constrained = frozenset(re.findall(r":(\w+)\(", _str_value(route, self.src) or "")) if route is not None \
                else frozenset()
            self._register(fn, kind, constrained)
            self.handlers[fn.id] = self.handlers.get(fn.id, True) and reportable
        # 형 표기로 인정하는 요청 객체 — `function convert(req: Request, res: Response)`(express 에서 가져온 형)
        for fn_id, notes in self.param_types.items():
            for idx, note in notes.items():
                kind = _TYPED_REQUESTS.get(self._type_name(note) or "")
                if kind is None:
                    continue
                slots = self.params.get(fn_id, [])
                req = slots[idx] if idx < len(slots) else None
                if req is not None and req.id not in self.reqs:
                    self.reqs[req.id] = _ReqInfo(kind, frozenset())
                    res = req if kind in ("koa", "hono") else (slots[idx + 1] if idx + 1 < len(slots) else None)
                    if res is not None:
                        self.resps.setdefault(res.id, kind)
        # 응답 객체를 그대로 넘겨받은 같은 파일 함수의 매개변수 — `helper(res, value)`
        for _ in range(_MAX_HOPS):
            found: dict[int, str] = {}
            for call in self.calls:
                f = _callee(call)
                b = self.reads.get(f.id) if f is not None and f.type == "identifier" else None
                fn = self.funcs.get(b.id) if b is not None else None
                if fn is None:
                    continue
                slots = self.params.get(fn.id, [])
                for i, a in enumerate(_args(call)):
                    if a.type == "spread_element":
                        break
                    a = _unwrap(a)
                    ab = self.reads.get(a.id) if a is not None and a.type == "identifier" else None
                    if ab is not None and ab.id in self.resps and i < len(slots) and slots[i] is not None:
                        found.setdefault(slots[i].id, self.resps[ab.id])
            if all(k in self.resps for k in found):
                break
            for k, v in found.items():
                self.resps.setdefault(k, v)
        self._aliases()
        # 파일 단위 침묵 — 모르는 `app.use(…)`
        for with_path, rest, _kind in self.uses:
            for a in rest:
                if not self._mount_ok(a, with_path) and not self.middleware_ok(a, _kind):
                    self.dropped = True

    def _register_middlewares(self, node, kind: str) -> None:
        """함수 미들웨어(인라인·같은 파일 함수·그 배열·Koa use)의 첫 매개변수도 요청 객체로 본다.

        미들웨어가 무엇을 검사하는지는 판단하지 않는다 — 그 안에서 요청 필드를 쓴 것이 파일 전체의 그 필드 쓰임으로 잡혀,
        같은 필드(열쇠)의 흐름만 침묵시킨다(원칙 4). `req.url`·`req.path` 같은 원문을 쓰면 쿼리·경로 매개변수 전체가 쓰인 것이다.
        """
        n = _unwrap(node)
        if n is None:
            return
        if n.type == "array":
            for e in _named(n):
                self._register_middlewares(e, kind)
            return
        fn = self._function_value(n)
        if fn is None or len(self.params.get(fn.id, [])) >= 4:
            return                                         # 오류 처리기(err, req, res, next) — 첫 매개변수가 요청이 아니다
        self._register(fn, kind, frozenset())
        self.handlers.setdefault(fn.id, True)

    def _hook(self, call) -> bool:
        """Fastify `fastify.addHook('onRequest' | 'preHandler' | …, fn)` — 훅 함수도 요청 출처로 등록한다."""
        f = _callee(call)
        if f is None or f.type != "member_expression":
            return False
        prop = _field(f, "property")
        obj = _unwrap(_field(f, "object"))
        if prop is None or self.text(prop) != "addHook" or obj is None:
            return False
        kind = self.fw.get(self.reads[obj.id].id) if obj.type == "identifier" and obj.id in self.reads \
            else self._fw_kind_of_value(obj)
        if kind != "fastify":
            return False
        args = _args(call)
        if len(args) >= 2:
            self._register_middlewares(args[1], "fastify")
        return True

    def _route_object(self, call) -> bool:
        """Fastify `fastify.route({ method, url, handler })`. 처리 함수 말고 다른 열쇠(schema·preHandler 등)가 있으면
        무엇을 거르는지 모르므로 그 처리 함수는 보고하지 않는다."""
        f = _callee(call)
        if f is None or f.type != "member_expression":
            return False
        prop = _field(f, "property")
        obj = _unwrap(_field(f, "object"))
        if prop is None or self.text(prop) != "route" or obj is None or obj.type != "identifier":
            return False
        b = self.reads.get(obj.id)
        args = _args(call)
        if b is None or self.fw.get(b.id) != "fastify" or len(args) != 1 or _unwrap(args[0]).type != "object":
            return False
        opts = _unwrap(args[0])
        handler = self._prop_value(opts, "handler")
        fn = self._function_value(handler) if handler is not None else None
        if fn is None:
            return True
        keys = set()
        for c in _named(opts):
            key = _field(c, "key") if c.type == "pair" else (c if c.type == "shorthand_property_identifier" else None)
            keys.add(self.text(key) if key is not None and key.type in ("property_identifier", "shorthand_property_identifier")
                     else "?")
        reportable = keys <= {"method", "url", "path", "handler"}
        self._register(fn, "fastify", frozenset())
        self.handlers[fn.id] = self.handlers.get(fn.id, True) and reportable
        return True

    def _aliases(self) -> None:
        """한 번만 대입된 이름이 요청 필드나 그 그릇을 그대로 가리키면 그 열쇠로 본다.

        `const q = req.query`·`const { url, ...rest } = req.query`·`const body = { ...req.body }`·`const data = req.body || {}` —
        이름이 달라도 같은 값이다. 여러 번 대입되는 이름은 그때그때 따라간다.
        """
        ordered = sorted((b for b in self.bindings if b.init is not None and not b.writes and b.id not in self.opaque
                          and b.kind in ("const", "let", "var") and b.init[1] is not None),
                         key=lambda b: b.init[0].start_byte if b.init[0] is not None else 0)
        for _ in range(2):                                 # 별칭의 별칭
            for b in ordered:
                if b.id in self.aliases:
                    continue
                value, path = b.init
                v = _unwrap(value)
                for _ in range(4):
                    if v is None:
                        break
                    if v.type == "binary_expression" and self.text(_field(v, "operator")) in ("||", "??") \
                            and _unwrap(_field(v, "right")) is not None \
                            and _unwrap(_field(v, "right")).type in ("object", "array", "string"):
                        v = _unwrap(_field(v, "left"))          # `req.body || {}`
                    elif v.type == "await_expression" and _named(v):
                        v = _unwrap(_named(v)[0])                   # `const { url } = await c.req.json()`
                    elif v.type == "object" and len(_named(v)) == 1 and _named(v)[0].type == "spread_element":
                        v = _unwrap(_named(_named(v)[0])[0]) if _named(_named(v)[0]) else None    # `{ ...req.body }`
                    elif v.type == "call_expression" and self.full_name(_callee(v)) == "Object.assign" \
                            and len(_args(v)) == 2 and _unwrap(_args(v)[0]).type == "object" \
                            and not _named(_unwrap(_args(v)[0])):
                        v = _unwrap(_args(v)[1])                # `Object.assign({}, req.body)`
                    else:
                        break
                if v is None or v.type not in _KEYED_TYPES:
                    continue
                s = self.struct(v)
                key = None
                if s is None or s[0] == "skip":
                    continue
                if s[0] == "req":
                    key = _extend(s[1], path)
                elif s[0] == "reqobj":
                    info = self.reqs[s[1].id]
                    key = self._field_key(info.kind, path, info.constrained) if path else None
                elif s[0] == "bind" and s[1].id in self.aliases:
                    base = _extend(self.aliases[s[1].id], s[2])
                    key = _extend(base, path) if base is not None else None
                if key is not None:
                    self.aliases[b.id] = key

    def _type_name(self, note) -> str | None:
        n = _named(note)[0] if note is not None and note.type == "type_annotation" and _named(note) else note
        if n is not None and n.type == "generic_type":
            n = _field(n, "name") or (_named(n)[0] if _named(n) else None)
        if n is None:
            return None
        if n.type == "type_identifier":
            return self.import_names.get(self.text(n))
        if n.type == "nested_type_identifier":
            parts = self.text(n).split(".")
            base = self.import_names.get(parts[0])
            return ".".join([base, *parts[1:]]) if base is not None else None
        return None

    def _register(self, fn, kind: str, constrained: frozenset[str]) -> None:
        slots = self.params.get(fn.id, [])
        req = slots[0] if slots else None
        if req is not None:
            self.reqs.setdefault(req.id, _ReqInfo(kind, constrained))
        else:                                              # `({ query }, res) => …` — 요청 객체를 매개변수에서 바로 풀었다
            for b, path in self.param_patterns.get(fn.id, {}).get(0, []):
                key = self._field_key(kind, path, constrained) if path else None
                if key is not None and not b.writes:
                    self.aliases.setdefault(b.id, key)
        res = slots[0] if kind in ("koa", "hono") else (slots[1] if len(slots) > 1 else None)
        if res is not None:
            self.resps.setdefault(res.id, kind)

    @staticmethod
    def _raw_use(kind: str, path) -> str | None:
        """URL 원문(`req.url`·`ctx.querystring`·`c.req.url`)·경로(`req.path`·`ctx.path`)를 읽는 자리면 그 쓰임 열쇠."""
        path = list(path)
        raw = False                                        # 프레임워크 밑의 원래 요청 객체(`ctx.req`·`request.raw`·`c.req.raw`)
        if kind == "hono":
            if path[:1] != ["req"]:
                return None
            path = path[1:]
            if path[:1] == ["raw"]:
                path, raw = path[1:], True
            if path[:1] == ["url"]:
                return f"{REQ}[query]"
            if path[:1] == ["path"]:
                return f"{REQ}[params]"
            return REQ if raw and path else None
        if kind == "koa" and path[:1] == ["request"]:
            path = path[1:]
        if (kind == "fastify" and path[:1] == ["raw"]) or (kind == "koa" and path[:1] == ["req"]):
            path, raw = path[1:], True
        if not path:
            return REQ if raw else None
        if path[0] in _URL_FIELDS.get(kind, ()) or raw and path[0] in ("url", "originalUrl"):
            return f"{REQ}[query]"
        if path[0] in _PATH_FIELDS.get(kind, ()):
            return f"{REQ}[params]"
        if path[0] == "rawBody":
            return f"{REQ}[body]"                          # 본문 원문
        if path[0] in ("hostname", "host"):
            return f"{REQ}[headers.host]"
        if raw:
            return REQ                                     # 원래 요청 객체의 다른 자리 — 무엇을 읽는지 모른다
        return None

    @staticmethod
    def _field_key(kind: str, path, constrained: frozenset[str] = frozenset()) -> str | None:
        """요청 객체에서 읽는 경로 → 열쇠. 요청 필드가 아니면(`req.user`·`req.ip`) None."""
        path = list(path)
        if not path:
            return None
        if kind in ("express", "fastify"):
            if path[0] not in _EXPRESS_FIELDS:
                return None
        elif kind == "koa":
            if path[0] == "request":
                path = path[1:]
                if not path or path[0] not in _KOA_REQUEST_FIELDS:
                    return None
            elif path[0] not in _KOA_FIELDS:
                return None
            if path[0] == "header":
                path[0] = "headers"
        else:
            return None
        if path[0] == "params" and len(path) > 1 and path[1] in constrained:
            return None                                    # `'/:id(\\d+)'` — 경로 제약이 값을 좁혔다
        return f"{REQ}[{'.'.join(path)}]"

    # ── 4-7 미들웨어 ─────────────────────────────────────────────────────────

    def _callee_ok(self, call) -> bool:
        from .authz_posture import _GUARD_NAME

        f = _callee(call)
        if f is None:
            return False
        raw = self.text(f)
        if _GUARD_NAME.search(raw):
            return True
        full = self.full_name(f) or ""
        if full in ("express.json", "express.urlencoded", "express.static", "express.raw", "express.text")                 or full.startswith("restify.plugins."):
            return True                                    # 본문·질의 해석기 — 값을 거르지 않는다
        for b in self.bindings_of_import(f):
            if self.imports[b].split(".")[0] in _NEUTRAL_MODULES or self.imports[b] in _NEUTRAL_MODULES:
                return True
        if f.type == "member_expression":
            prop = self.text(_field(f, "property")) if _field(f, "property") is not None else ""
            if prop in _UPLOAD_METHODS:
                return True                                # `upload.single('file')`
            obj = _unwrap(_field(f, "object"))
            ob = self.reads.get(obj.id) if obj is not None and obj.type == "identifier" else None
            if ob is not None and ob.id in self.fw and prop in _MOUNT_METHODS:
                return True                                # `app.use(router.routes())`
        last = raw.rsplit(".", 1)[-1]
        return last in _NEUTRAL_NAMES

    def _is_imported(self, node) -> bool:
        """호출 대상의 뿌리가 `require`·`import` 로 가져온 모듈인가."""
        n = _unwrap(node)
        while n is not None and n.type == "member_expression":
            n = _unwrap(_field(n, "object"))
        if n is not None and n.type == "call_expression":
            return self.module_of(n) is not None
        return bool(self.bindings_of_import(node))

    def bindings_of_import(self, node) -> list[int]:
        n = _unwrap(node)
        while n is not None and n.type == "member_expression":
            n = _unwrap(_field(n, "object"))
        b = self.reads.get(n.id) if n is not None and n.type == "identifier" else None
        return [b.id] if b is not None and b.id in self.imports else []

    def _fastify_route_options_ok(self, opts, kind: str) -> bool:
        """Fastify 라우트 옵션 — 훅 함수(preHandler 등)만 있으면 등록해 필드별로 세고, 그 밖의 열쇠(schema 등)는 모른다."""
        ok = True
        for c in _named(opts):
            key = _field(c, "key") if c.type == "pair" else None
            name = self.text(key) if key is not None and key.type == "property_identifier" else "?"
            if name in _FASTIFY_HOOK_KEYS:
                self._register_middlewares(_field(c, "value"), kind)
                v = _unwrap(_field(c, "value"))
                fns = _named(v) if v is not None and v.type == "array" else [v]
                ok = ok and all(self._function_value(x) is not None for x in fns)
            elif name != "config":
                ok = False
        return ok

    def middleware_ok(self, node, kind: str = "express") -> bool:
        """인증으로 아는 이름이거나 입력과 무관하다고 아는 미들웨어인가 — 아니면 검증 미들웨어일 수 있다."""
        from .authz_posture import _GUARD_NAME

        n = _unwrap(node)
        if n is None:
            return False
        if n.type == "array":
            return all(self.middleware_ok(e, kind) for e in _named(n))
        if n.type in _FUNC_TYPES:
            return True                                    # 첫 매개변수를 요청 출처로 등록했다 — 쓰임은 필드별로 센다
        if n.type == "object" and kind == "fastify":
            return self._fastify_route_options_ok(n, kind)
        if n.type == "call_expression":
            return self._callee_ok(n)
        if n.type == "identifier":
            b = self.reads.get(n.id)
            if b is not None and b.id in self.funcs:
                return True                                # 같은 파일 함수 미들웨어 — 필드별로 센다
            if b is not None and b.init is not None and not b.writes and b.init[1] == ():
                init = _unwrap(b.init[0])
                if init is not None and init.type == "call_expression":
                    return self._callee_ok(init)           # `const limiter = rateLimit({…}); app.use(limiter)`
            raw = self.text(n)
            return bool(_GUARD_NAME.search(raw)) or raw in _NEUTRAL_NAMES
        if n.type == "member_expression":
            raw = self.text(n)
            return bool(_GUARD_NAME.search(raw)) or raw.rsplit(".", 1)[-1] in _NEUTRAL_NAMES
        return False

    def _mount_ok(self, node, with_path: bool) -> bool:
        """라우터 붙이기 — `app.use('/api', router)`·`app.use(require('./routes'))`·4개짜리 오류 처리기."""
        n = _unwrap(node)
        if n is None:
            return False
        if n.type == "identifier":
            b = self.reads.get(n.id)
            if b is not None and b.id in self.fw:
                return True
            if b is not None and b.id in self.imports:
                return with_path or "rout" in b.name.lower()
            return False
        if n.type == "call_expression" and self.module_of(n) is not None:
            return True
        if n.type in _FUNC_TYPES:
            return len(self.params.get(n.id, [])) >= 4
        return False

    # ── 3. 식의 구조(상태와 무관한 부분 — 노드마다 한 번만 계산) ───────────────

    def struct(self, node):
        """None · ("req", 열쇠) · ("reqobj", 선언) · ("bind", 선언, 경로) · ("skip",) — skip 은 요청 객체의 필드가 아닌 것."""
        nid = node.id
        if nid in self._struct:
            return self._struct[nid]
        out = self._compute_struct(node)
        self._struct[nid] = out
        return out

    def _compute_struct(self, n):
        t = n.type
        if t in ("identifier", "shorthand_property_identifier"):
            b = self.reads.get(n.id)
            if b is None:
                return None
            return ("reqobj", b) if b.id in self.reqs else ("bind", b, ())
        if t in ("member_expression", "subscript_expression"):
            path: list[str] = []
            cur = n
            while cur is not None and cur.type in ("member_expression", "subscript_expression"):
                if cur.type == "member_expression":
                    prop = _field(cur, "property")
                    if prop is None or prop.type not in ("property_identifier", "private_property_identifier"):
                        return None
                    path.append(self.text(prop))
                else:
                    idx = _unwrap(_field(cur, "index"))
                    sv = self.text(idx) if idx is not None and idx.type == "number" else _str_value(idx, self.src)
                    if sv is None:
                        return None                        # `req.query[k]` — 그릇을 모르는 열쇠로 들여다봤다
                    path.append(sv)
                cur = _unwrap(_field(cur, "object"))
            path.reverse()
            if cur is None or cur.type != "identifier":
                return None
            b = self.reads.get(cur.id)
            if b is None:
                return None
            if b.id in self.reqs:
                if len(path) > 2 and path[-1] == "length":
                    return None                            # `req.query.url.length` — 필드의 길이를 본 것이다
                info = self.reqs[b.id]
                use = self._raw_use(info.kind, path)
                if use is not None:
                    return ("use", use)
                key = self._field_key(info.kind, path, info.constrained)
                return ("req", key) if key is not None else ("skip",)
            return ("bind", b, tuple(path))
        if t == "call_expression":
            f = _callee(n)
            if f is None or f.type != "member_expression":
                return None
            prop = _field(f, "property")
            m = self.text(prop) if prop is not None else ""
            obj = _unwrap(_field(f, "object"))
            args = _args(n)
            arg = _str_value(args[0], self.src) if len(args) == 1 else None
            if obj is not None and obj.type == "identifier":
                b = self.reads.get(obj.id)
                info = self.reqs.get(b.id) if b is not None else None
                if info is not None and m in ("get", "header") and info.kind in ("express", "koa") and arg is not None:
                    return ("req", f"{REQ}[headers.{arg.lower()}]")      # `req.get('x-url')`
                if info is not None and m in ("get", "header") and info.kind in ("express", "koa"):
                    return ("use", f"{REQ}[headers]")              # `req.get(name)` — 열쇠를 모른다
                if info is not None and m == "param" and info.kind == "express":
                    return ("use", REQ)                            # `req.param(x)` — 경로·본문·질의 어디서든 읽는다
            if obj is not None and obj.type == "member_expression":
                base = _unwrap(_field(obj, "object"))
                oprop = _field(obj, "property")
                oname = self.text(oprop) if oprop is not None else ""
                b = self.reads.get(base.id) if base is not None and base.type == "identifier" else None
                info = self.reqs.get(b.id) if b is not None else None
                if info is not None and info.kind == "hono" and oname == "req":
                    field = {"query": "query", "queries": "query", "param": "params", "header": "headers"}.get(m)
                    if field is not None and arg is not None:
                        return ("req", f"{REQ}[{field}.{arg.lower() if field == 'headers' else arg}]")
                    if field in ("query", "params") and not args:
                        return ("req", f"{REQ}[{field}]")
                    if m in ("json", "parseBody", "formData") and not args:
                        return ("req", f"{REQ}[body]")             # `await c.req.json()`
                    if field is not None:
                        return ("use", f"{REQ}[{field}]")          # `c.req.query(k)` — 열쇠를 모른다
                if info is not None and info.kind == "koa" and oname == "cookies" and m == "get" and arg is not None:
                    return ("req", f"{REQ}[cookies.{arg}]")
            return None
        return None

    def resp_kind(self, node) -> str | None:
        n = _unwrap(node)
        for _ in range(8):
            if n is None:
                return None
            if n.type == "identifier":
                b = self.reads.get(n.id)
                return self.resps.get(b.id) if b is not None else None
            if n.type != "call_expression":
                return None
            f = _callee(n)
            prop = _field(f, "property") if f is not None and f.type == "member_expression" else None
            if prop is None or self.text(prop) not in _RES_CHAIN:
                return None
            n = _unwrap(_field(f, "object"))
        return None

    def sink(self, call) -> tuple[str, list, bool] | None:
        """이 호출이 위험한 자리면 (룰 ID, 봐야 할 인자들, 주소인가)."""
        nid = call.id
        if nid in self._sink:
            return self._sink[nid]
        out = self._compute_sink(call)
        self._sink[nid] = out
        return out

    def _prop_value(self, obj, name: str):
        for c in _named(obj):
            if c.type == "pair":
                key = _field(c, "key")
                kname = self.text(key) if key is not None and key.type == "property_identifier" \
                    else _str_value(key, self.src) if key is not None else None
                if kname == name:
                    return _field(c, "value")
            elif c.type == "shorthand_property_identifier" and self.text(c) == name:
                return c
        return None

    def _compute_sink(self, call):
        f = _callee(call)
        args = _args(call)
        if f is None or not args:
            return None
        if f.type == "member_expression":
            prop = _field(f, "property")
            m = self.text(prop) if prop is not None else ""
            rk = self.resp_kind(_field(f, "object"))
            if rk is not None:
                if m == "redirect":
                    target = args[1] if len(args) >= 2 and _unwrap(args[0]).type == "number" else args[0]
                    return RULE_REDIRECT, [target], True
                if m in ("sendFile", "download") and rk in ("express", "fastify"):
                    state, root = self._root_option(m, args)
                    if state == "unknown":
                        return None                        # 옵션을 모른다 — 모르면 침묵
                    if state == "root":
                        self.root_gated[call.id] = root    # 뿌리 값이 요청 값일 때만 보고한다(_record_call)
                        return RULE_PATH, [args[0], *root], False
                    return RULE_PATH, [args[0]], False
                return None
        full = self.full_name(f)
        if full is None:
            return None
        if full != "fetch" and not self._is_imported(f):
            return None                                    # import 를 확인하지 못한 `exec(…)`·`request(…)` 는 싱크가 아니다
        first = _unwrap(args[0])
        if full == "fetch" or full in _SSRF_FIRST:
            if first is not None and first.type == "object":
                url = self._prop_value(first, "url")
                return (RULE_SSRF, [url], True) if url is not None else None
            return RULE_SSRF, [args[0]], True
        if full in _SSRF_CONFIG:
            url = self._prop_value(first, "url") if first is not None and first.type == "object" else None
            return (RULE_SSRF, [url], True) if url is not None else None
        if full == "needle" and len(args) >= 2:
            return RULE_SSRF, [args[1]], True
        if full in _PATH_SINKS:
            return RULE_PATH, [args[0]], False
        if full in _EXEC_SINKS:
            return RULE_CMD, [args[0]], False
        if full in _SPAWN_SINKS | _EXEC_FILE_SINKS:
            shell_arg = self._shell_dash_c(args)
            if shell_arg is not None:
                return RULE_CMD, [shell_arg], False        # `spawn('sh', ['-c', 'ls ' + dir])` — 셸이 명령 문자열을 읽는다
        if full in _SPAWN_SINKS:
            opts = next((_unwrap(a) for a in args[1:3] if _unwrap(a).type == "object"), None)
            shell = self._prop_value(opts, "shell") if opts is not None else None
            if shell is not None and _unwrap(shell).type not in ("false", "null", "undefined", "number") \
                    and _str_value(shell, self.src) != "":
                targets = [args[0]]
                if len(args) > 1 and _unwrap(args[1]).type != "object":
                    targets.append(args[1])
                return RULE_CMD, targets, False
        return None

    def _later_roots(self, node) -> list:
        """옵션을 담은 이름에 나중에 대입한 뿌리 값들 — `opts.root = req.query.d`."""
        n = _unwrap(node)
        out: list = []
        for _ in range(4):
            if n is None or n.type != "identifier":
                return out
            b = self.reads.get(n.id)
            if b is None:
                return out
            for call_or_assign in self.member_writes.get(b.id, ()):
                out.append(call_or_assign)
            if b.init is None or b.writes or b.init[1] != ():
                return out
            n = _unwrap(b.init[0])
        return out

    def _object_of(self, node):
        """옵션 자리의 값이 객체 리터럴이면 그 객체(한 번만 담은 이름을 따라간다). 콜백이면 "fn", 모르면 None."""
        n = _unwrap(node)
        for _ in range(4):
            if n is None:
                return None
            if n.type in _FUNC_TYPES:
                return "fn"
            if n.type == "object":
                return n
            if n.type != "identifier":
                return None
            b = self.reads.get(n.id)
            if b is None:
                return None
            if b.id in self.funcs:
                return "fn"
            if b.init is None or b.writes or b.init[1] != ():
                return None
            n = _unwrap(b.init[0])
        return None

    def _root_option(self, method: str, args) -> tuple[str, object]:
        """`res.sendFile(p, [옵션], [fn])`·`res.download(p, [이름], [옵션], [fn])` 의 뿌리(root) 옵션.

        ("none", None) — 뿌리가 없다고 확실히 안다(옵션 없음·콜백·root 없는 객체·root 가 undefined·null·''·'/').
        ("root", 값 노드) — 뿌리가 있다. 그 값이 요청 값이면 경로를 사용자가 정하는 것이라 보고하고, 아니면 침묵한다.
        ("unknown", None) — 옵션을 모른다(다른 변수·펼친 객체가 root 를 덮을 수 있다) → 침묵.
        """
        rest = args[1:]
        if method == "download":                           # 둘째 자리는 내려받을 이름일 수 있다 — 객체일 때만 옵션이다
            cands = [a for a in rest[:2] if self._object_of(a) not in (None, "fn")]
            if not cands:
                return "none", None
            opts = self._object_of(cands[0])
        else:
            if not rest:
                return "none", None
            opts = self._object_of(rest[0])
            if opts == "fn":
                return "none", None
            if opts is None:
                return "unknown", None
            cands = [rest[0]]
        root = None
        root_index = -1
        kids = _named(opts)
        for i, c in enumerate(kids):
            key = _field(c, "key") if c.type == "pair" else (c if c.type == "shorthand_property_identifier" else None)
            if key is not None and (self.text(key) if key.type != "string" else _str_value(key, self.src)) == "root":
                root, root_index = (_field(c, "value") if c.type == "pair" else c), i
        if any(c.type == "spread_element" for c in kids[root_index + 1:]):
            return "unknown", None                         # `{ root: X, ...OPTS }`·`{ ...BASE_OPTS }` — 펼친 쪽이 root 를 정할 수 있다
        later = self._later_roots(cands[0])
        if later:
            return "root", ([root] if root is not None else []) + later     # `opts.root = req.query.d` — 어느 값이든 될 수 있다
        if root is None:
            return "none", None
        v = _unwrap(root)
        lit = _str_value(v, self.src)
        if v is not None and (v.type in ("undefined", "null") or lit in ("", "/")
                              or v.type == "identifier" and self.text(v) == "undefined" and v.id not in self.reads):
            return "none", None                            # 뿌리가 없는 것과 같다
        return "root", [root]

    def _shell_dash_c(self, args):
        """첫 인자가 셸이고 인자 배열의 `-c`(cmd 는 `/c`) 다음 원소면 그 원소 — 명령 문자열이다."""
        shell = _str_value(args[0], self.src) if args else None
        if shell is None or shell.replace("\\", "/").rsplit("/", 1)[-1].lower() not in _SHELLS:
            return None
        arr = _unwrap(args[1]) if len(args) > 1 else None
        if arr is None or arr.type != "array":
            return None
        elems = _named(arr)
        for i, e in enumerate(elems[:-1]):
            if (_str_value(e, self.src) or "").lower() in ("-c", "/c", "-command"):
                return elems[i + 1]
        return None

    def local_callee(self, call):
        """같은 파일 함수를 부르는 호출이면 (선언 id, 매개변수 자리들)."""
        f = _callee(call)
        if f is None or f.type != "identifier":
            return None
        b = self.reads.get(f.id)
        if b is None or b.id not in self.funcs:
            return None
        return b.id, self.params.get(self.funcs[b.id].id, [])

    def reportable_at(self, node) -> bool:
        """이 자리를 감싸는 가장 안쪽 라우트 처리 함수에 모르는 미들웨어가 걸려 있지 않은가."""
        p = self.parent(node)
        while p is not None:
            if p.id in self.handlers:
                return self.handlers[p.id]
            p = self.parent(p)
        return True

    # ── 4. 분석 단위 ─────────────────────────────────────────────────────────

    def collect_units(self) -> None:
        """분석할 단위 — 최상위 문장들, 그리고 다른 함수 안에 들어 있지 않은 함수들(안쪽 함수는 같은 단위에서 본다)."""
        units: list = [self.root]
        stack = [self.root]
        while stack:
            n = stack.pop()
            for c in n.named_children:
                if c.type in _FUNC_TYPES:
                    units.append(c)
                elif c.type not in _SKIP_TYPES:
                    stack.append(c)
        self.units = units


class _Unit:
    """분석 단위 하나 — 최상위 함수(안쪽 함수 포함) 또는 최상위 문장들."""

    def __init__(self, cx: _Context, fn, *, probe: bool = False) -> None:
        self.cx = cx
        self.fn = fn
        self.module = fn.type == "program"
        self.probe = probe
        self.taint: dict[str, bool] = {}       # 지금 요청 값이 남아 있는 선언 열쇠 → 값의 맨 앞까지 요청 값인가
        self.depth: dict[str, int] = {}        # 그 값이 같은 파일 함수를 몇 단계 거쳐 왔는가
        self.ever: set[str] = set()            # 한 번이라도 요청 값이었던 선언
        self.views: set[str] = set()           # 요청 값을 들여다본 결과를 담은 선언
        self.groups = _Groups()
        self.seen: set[str] = set()
        self.sinks: list = []
        self.calls: list = []
        self.returns: list = []
        self.only_inside: list[tuple[str, set[int]]] = []
        self.nested = 0

    # ── 식이 어떤 값인가 ────────────────────────────────────────────────────

    def key_of(self, node, *, census: bool = False) -> str | None:
        n = _unwrap(node)
        if n is None or n.type not in _KEYED_TYPES:
            return None
        s = self.cx.struct(n)
        if s is None:
            return None
        tag = s[0]
        if tag == "req":
            return s[1]
        if tag in ("reqobj", "use"):
            return (REQ if tag == "reqobj" else s[1]) if census else None   # 쓰임으로만 센다 — 출처는 아니다
        if tag == "skip":
            return None
        b, path = s[1], s[2]
        alias = self.cx.aliases.get(b.id)
        if alias is not None:
            if path and path[-1] == "length":
                return None                                # `url.length` — 값의 길이를 본 것이다(쓰임에서 따로 본다)
            return _extend(alias, path)
        if path:
            return None                                    # 값의 속성 — 무엇인지 모른다
        k = b.key
        if k in self.taint or census and (k in self.ever or k in self.views):
            return k
        return None

    def carries(self, key: str) -> bool:
        return key.startswith(REQ) or key in self.taint

    def leads(self, key: str) -> bool:
        return True if key.startswith(REQ) else self.taint.get(key, True)

    def _depth_of(self, key: str) -> int:
        return 0 if key.startswith(REQ) else self.depth.get(key, 0)

    def children(self, node) -> list | None:
        """값에 요청 값이 **그대로 남을 수 있는** 하위 식. None 이면 끊긴다(모르는 것은 끊는다)."""
        cx = self.cx
        n = _unwrap(node)
        if n is None:
            return None
        t = n.type
        if t == "call_expression":
            f = _callee(n)
            args = _args(n)
            if f is None:
                return None
            if f.type == "identifier":
                local = cx.local_callee(n)
                if local is not None:
                    bid, slots = local
                    summary = cx.summaries.get(bid)
                    if summary is None:
                        return None
                    kept = []
                    for i, a in enumerate(args):
                        if a.type == "spread_element":
                            break
                        if i < len(slots) and slots[i] is not None and slots[i].id in summary[1]:
                            kept.append(a)
                    return kept
            full = cx.full_name(f)
            if full in _PASS_ALL_ARGS:
                return [a for a in args if a.type != "spread_element"]
            if full in _PASS_FIRST_ARG:
                return args[:1]
            if f.type == "member_expression":
                prop = _field(f, "property")
                m = cx.text(prop) if prop is not None else ""
                if (m in _PASS_METHODS_NOARG and not args) or (m == "join" and len(args) <= 1):
                    return [_field(f, "object")]
            return None
        if t == "await_expression":
            return _named(n)
        if t == "ternary_expression":
            return [_field(n, "consequence"), _field(n, "alternative")]
        if t == "binary_expression":
            op = _field(n, "operator")
            o = cx.text(op) if op is not None else ""
            if o in ("+", "||", "??"):
                return [_field(n, "left"), _field(n, "right")]
            if o == "&&":
                return [_field(n, "right")]
            return None
        if t == "template_string":
            return [c for c in n.named_children if c.type == "template_substitution"]
        if t in ("template_substitution", "spread_element", "array"):
            return _named(n)
        if t == "object":
            out = []
            for c in _named(n):
                if c.type == "pair":
                    out.append(_field(c, "value"))
                elif c.type in ("shorthand_property_identifier", "spread_element"):
                    out.append(c)
            return out
        if t == "sequence_expression":
            kids = _named(n)
            return kids[-1:]
        return None

    def reach(self, node, *, lead_only: bool = False) -> set[str]:
        """이 식의 값에 남는 요청 값들의 열쇠. 비어 있으면 닿지 않는다."""
        found: set[str] = set()
        stack = [node]
        while stack:
            n = stack.pop()
            if n is None:
                continue
            self.cx.spend()
            key = self.key_of(n)
            if key is not None:
                if self.carries(key) and (not lead_only or self.leads(key)):
                    found.add(key)
                    self.seen.add(key)
                continue
            kids = self.children(n)
            if kids:
                stack.extend(kids)
        return found

    def occurrences(self, node, *, skip_sinks: bool = False, skip_functions: bool = False):
        """식 안에서 따라가는 값이 나오는 자리 — (그 자리의 가장 바깥 식, 열쇠). 안쪽 함수(콜백)까지 전부 본다."""
        cx = self.cx
        stack = [node]
        while stack:
            n = stack.pop()
            if n is None:
                continue
            cx.spend()
            t = n.type
            if t in _SKIP_TYPES:
                continue
            if skip_functions and t in _FUNC_TYPES:
                continue
            if t in _KEYED_TYPES:
                if skip_sinks and t == "call_expression" and cx.sink(n) is not None:
                    continue
                s = cx.struct(n)
                if s is not None:
                    if s[0] == "skip":
                        continue
                    key = self.key_of(n, census=True)
                    if key is not None:
                        self.seen.add(key)
                        yield n, key
                        continue
                if t == "call_expression":
                    f = _field(n, "function")
                    uf = _callee(n)
                    if uf is not None and uf.type == "member_expression":
                        recv = _unwrap(_field(uf, "object"))
                        rs = cx.struct(recv) if recv is not None and recv.type in _KEYED_TYPES else None
                        if rs is None or rs[0] != "reqobj":
                            stack.append(_field(uf, "object"))     # 메서드 이름은 값이 아니다
                        # 요청 객체의 메서드를 부른 것(`c.text(…)`·`ctx.throw(…)`)은 요청 값을 쓴 것이 아니다
                    elif uf is not None and uf.type != "identifier":
                        stack.append(f)
                    if skip_sinks:
                        kept = self._looked_at_args(n)
                        if kept is not None:
                            stack.extend(kept)
                            continue
                    stack.append(_field(n, "arguments"))
                    continue
                if t == "member_expression":
                    stack.append(_field(n, "object"))
                    continue
            stack.extend(n.named_children)

    def _looked_at_args(self, call) -> list | None:
        """같은 파일 함수 호출에서 그 함수가 **들여다보는** 인자만(매개변수를 다른 데 쓰거나 돌려주는 것).

        매개변수를 위험한 자리에만 넣는 함수의 결과는 그 값을 들여다본 결과가 아니다 —
        `const html = await grab(req.query.src)` 의 `html` 은 `grab` 안 `fetch(u)` 의 응답이다. 모르면 None(전부 본다).
        """
        cx = self.cx
        local = cx.local_callee(call)
        if local is None:
            return None
        bid, slots = local
        summary = cx.summaries.get(bid)
        if summary is None:
            return None
        kept = []
        for i, a in enumerate(_args(call)):
            param = slots[i] if i < len(slots) else None
            if a.type == "spread_element" or param is None or param.id in summary[0] or param.id in summary[1]:
                kept.append(a)
        return kept

    def mentions(self, node) -> set[str]:
        """이 식 어디에든 나오는 따라가는 값. 위험한 자리에 넣은 것은 뺀다. 함수 값의 본문은 보지 않는다 —
        `const show = (req, res) => …` 의 `show` 는 요청 값을 들여다본 결과가 아니다."""
        return {key for _, key in self.occurrences(node, skip_sinks=True, skip_functions=True)}

    # ── 주소의 호스트 자리 ──────────────────────────────────────────────────

    def _ordered_parts(self, node) -> list:
        """문자열 조립을 앞에서부터 — `"a" + b` · 템플릿. 상수 조각은 문자열로."""
        out: list = []
        todo = [node]
        src = self.cx.src
        while todo and len(out) < _PARTS_LIMIT:
            n = todo.pop()
            if isinstance(n, str):
                out.append(n)
                continue
            n = _unwrap(n)
            if n is None:
                continue
            if n.type == "binary_expression" and self.cx.text(_field(n, "operator")) == "+":
                todo += [_field(n, "right"), _field(n, "left")]
            elif n.type == "template_string":
                seq: list = []
                for c in n.named_children:
                    if c.type in ("string_fragment", "escape_sequence"):
                        seq.append(_text(c, src))
                    elif c.type == "template_substitution":
                        inner = _named(c)
                        if inner:
                            seq.append(inner[0])
                todo += reversed(seq)
            else:
                sv = _str_value(n, src)
                out.append(sv if sv is not None else n)
        return out

    def destination(self, node, *, slash_is_open: bool = False) -> set[str]:
        """요청 값이 주소의 **호스트 자리**까지 정하면 그 값들. 앞에 다른 것이 붙어 있으면(고정 주소·경로·상수 접두) 비어 있다."""
        cx = self.cx
        n = _unwrap(node)
        if n is None:
            return set()
        if n.type == "call_expression":
            local = cx.local_callee(n)
            if local is not None:
                bid, slots = local
                summary = cx.summaries.get(bid)
                if summary is None:
                    return set()
                out: set[str] = set()
                for i, a in enumerate(_args(n)):
                    if a.type == "spread_element":
                        break
                    if i < len(slots) and slots[i] is not None and slots[i].id in summary[2]:
                        out |= self.destination(a)
                return out
        if n.type == "await_expression":
            inner = _named(n)
            return self.destination(inner[0], slash_is_open=slash_is_open) if inner else set()
        text = ""
        parts = self._ordered_parts(n)
        for i, part in enumerate(parts):
            if isinstance(part, str):
                text += part
                continue
            if text and not _OPEN_AUTHORITY_RE.match(text) and not (slash_is_open and text == "/"):
                return set()                               # `'https://api.example/items/' + x`·`'?page=' + x`
            found = self.reach(part, lead_only=True)
            if not found and not text and not self.reach(part):
                nxt = parts[i + 1] if i + 1 < len(parts) else None
                if isinstance(nxt, str) and nxt.startswith("://"):
                    text = "x"                             # `${scheme}://${host}/…` — 앞 조각은 스킴이다
                    continue
            return found
        return set()

    # ── 쓰임이 해롭지 않은가 ─────────────────────────────────────────────────

    def _is_log_call(self, call) -> bool:
        f = _callee(call)
        if f is None or f.type != "member_expression":
            return False
        prop = _field(f, "property")
        if prop is None or self.cx.text(prop) not in _LOG_METHODS:
            return False
        obj = _unwrap(_field(f, "object"))
        if obj is None:
            return False
        if obj.type == "identifier" and self.cx.text(obj) == "console" and obj.id not in self.cx.reads:
            return True
        last = self.cx.text(obj).rsplit(".", 1)[-1]
        return bool(_LOG_OWNER_RE.search(last)) and obj.type in ("identifier", "member_expression")

    def _inside_log(self, occ) -> bool:
        """기록 문장 — `logger.info('fetch', { url })`·`console.log(`… ${url}`)`."""
        cx = self.cx
        up = occ
        while True:
            p = cx.parent(up)
            if p is None or _is_statement(p.type):
                return False
            if p.type == "call_expression":
                if self._is_log_call(p):
                    gp = cx.parent(p)
                    while gp is not None and gp.type in ("await_expression", "parenthesized_expression"):
                        gp = cx.parent(gp)
                    return gp is not None and gp.type == "expression_statement"
                if cx.full_name(_callee(p)) not in _PASS_FIRST_ARG:
                    return False
            elif p.type not in _LOG_PASS_TYPES:
                return False
            up = p

    def _terminates(self, stmt) -> bool:
        """이 문장(블록)이 끝나면 뒤 문장으로 이어지지 않는가 — `return`·`throw`·`continue`·`break`."""
        s = stmt
        while s is not None and s.type == "statement_block":
            kids = _named(s)
            if not kids:
                return False
            s = kids[-1]
        return s is not None and s.type in ("return_statement", "throw_statement", "continue_statement", "break_statement")

    def _presence(self, cur, p, positive: bool, key: str) -> bool:
        """값이 있는지만 본 조건 — **없으면 끝내는** 것은 해롭지 않다. 있으면 끝내는 분기는 적어 둔다(그 밖은 빈 값)."""
        if p.type == "if_statement":
            branch = _field(p, "consequence") if positive else None
            if not positive:
                alt = _field(p, "alternative")
                branch = _named(alt)[0] if alt is not None and _named(alt) else None
            if branch is not None and self._terminates(branch):
                ids: set[int] = set()
                stack = [branch]
                while stack:
                    n = stack.pop()
                    ids.add(n.id)
                    stack.extend(n.children)
                self.only_inside.append((key, ids))
            return True
        return True

    def is_harmless(self, occ, *, view: bool, key: str) -> bool:
        """따라가는 값이 이 자리에서 **해롭지 않다고 분명히 아는** 방식으로 쓰였는가. 모르면 False."""
        cx = self.cx
        if self._inside_log(occ):
            return True
        cur = occ
        shaped = False                      # 이어 붙이기·감싸기를 거쳤다 — 그 결과를 조건에 쓰면 값을 본 것이다
        positive = True                     # 조건이 참이면 값이 있다는 뜻인가
        while True:
            cx.spend()
            p = cx.parent(cur)
            if p is None:
                return True
            t = p.type
            if t in ("expression_statement", "return_statement", "throw_statement"):
                return True                                # 그냥 계산·돌려주기·오류로 내보내기
            if t in _WRAPPERS or t == "await_expression":
                cur = p
                continue
            if t == "variable_declarator":
                v = _field(p, "value")
                return v is not None and v.id == cur.id    # 다른 이름에 담기(흐름으로 따라간다)
            if t in ("assignment_expression", "augmented_assignment_expression"):
                right, left = _field(p, "right"), _unwrap(_field(p, "left"))
                if right is None or right.id != cur.id or left is None:
                    return False
                if left.type == "member_expression" and t == "assignment_expression":
                    prop = _field(left, "property")
                    obj = _unwrap(_field(left, "object"))
                    return prop is not None and cx.text(prop) == "root" and obj is not None and obj.type == "identifier" \
                        and obj.id in cx.reads and cx.reads[obj.id].id in cx.member_writes   # `opts.root = v` — 뿌리로 따라간다
                return left.type == "identifier"
            if t == "for_in_statement":
                right = _field(p, "right")
                return right is not None and right.id == cur.id
            if t in ("if_statement", "while_statement", "do_statement", "for_statement"):
                cond = _field(p, "condition")
                if cond is None or cond.id != cur.id:
                    return False
                return not view and not shaped and self._presence(cur, p, positive, key)
            if t == "ternary_expression":
                cond = _field(p, "condition")
                if cond is not None and cond.id == cur.id:
                    return not view and not shaped
                cur = p
                continue
            if t == "unary_expression":
                op = cx.text(_field(p, "operator"))
                if op == "!":
                    cur, positive = p, not positive
                    continue
                if op == "typeof":
                    gp = cx.parent(p)
                    if gp is None or gp.type != "binary_expression" or view or shaped:
                        return False
                    o = cx.text(_field(gp, "operator"))
                    other = _field(gp, "right") if _field(gp, "left").id == p.id else _field(gp, "left")
                    lit = _str_value(other, cx.src)
                    if o not in ("===", "==", "!==", "!=") or lit is None:
                        return False
                    present_when_true = (lit != "undefined") == (o in ("===", "=="))
                    cur, positive = gp, positive == present_when_true
                    continue
                return False
            if t == "binary_expression":
                o = cx.text(_field(p, "operator"))
                if o == "+":
                    cur, shaped = p, True
                    continue
                if o in ("||", "??", "&&"):
                    cur = p
                    continue
                if o in ("===", "==", "!==", "!="):
                    left, right = _field(p, "left"), _field(p, "right")
                    other = right if left is not None and left.id == cur.id else left
                    ou = _unwrap(other)
                    if ou is not None and (ou.type in ("null", "undefined") or _str_value(ou, cx.src) == ""
                                           or ou.type == "identifier" and cx.text(ou) == "undefined"
                                           and ou.id not in cx.reads):
                        if view or shaped:
                            return False
                        cur, positive = p, positive == (o in ("!==", "!="))      # `x == null`·`x !== ''`
                        continue
                return False
            if t in ("template_substitution", "template_string"):
                if t == "template_string":
                    gp = cx.parent(p)
                    args = _field(gp, "arguments") if gp is not None and gp.type == "call_expression" else None
                    if args is not None and args.id == p.id:
                        return False                       # 태그드 템플릿 — 모르는 함수에 넘겼다
                    shaped = True
                cur = p
                continue
            if t in ("array", "spread_element", "object"):
                cur, shaped = p, True
                continue
            if t == "pair":
                v = _field(p, "value")
                if v is None or v.id != cur.id:
                    return False                           # 계산된 키 — 객체의 키로 썼다
                cur = p
                continue
            if t == "sequence_expression":
                kids = _named(p)
                if kids and kids[-1].id != cur.id:
                    return True                            # 버려지는 값
                cur = p
                continue
            if t == "arguments":
                call = cx.parent(p)
                if call is None or call.type != "call_expression":
                    if call is not None and call.type == "new_expression" and cx.parent(call) is not None \
                            and cx.parent(call).type == "throw_statement":
                        return True                        # `throw new Error(`bad ${x}`)`
                    return False
                verdict = self._call_arg(call, cur)
                if verdict is None:
                    cur, shaped = call, True
                    continue
                return verdict
            if t == "member_expression":
                obj = _field(p, "object")
                if obj is None or obj.id != cur.id:
                    return False
                prop = _field(p, "property")
                m = cx.text(prop) if prop is not None else ""
                gp = cx.parent(p)
                if gp is not None and gp.type == "call_expression" and _field(gp, "function").id == p.id:
                    if cx.sink(gp) is not None:
                        return True                        # 위험한 자리의 받는 쪽
                    kids = self.children(gp)
                    if kids is not None and any(k is not None and k.id == cur.id for k in kids):
                        if m != "trim":
                            shaped = True
                        cur = gp
                        continue
                    return False                           # `x.startsWith(…)`·`x.includes(…)` — 값을 봤다
                if m == "length" and gp is not None and gp.type == "binary_expression" and not view and not shaped:
                    o = cx.text(_field(gp, "operator"))
                    other = _field(gp, "right") if _field(gp, "left").id == p.id else _field(gp, "left")
                    if o in ("===", "==", "!==", "!=") and other is not None and cx.text(other) == "0":
                        cur, positive = gp, positive == (o in ("!==", "!="))     # `x.length === 0`
                        continue
                return False
            return False

    def _call_arg(self, call, cur) -> bool | None:
        """호출의 인자로 쓰였다 — True(해롭지 않다)·False(쓰였다)·None(결과에 값이 남는다 — 결과가 어디에 쓰이는지 본다)."""
        cx = self.cx
        if cx.sink(call) is not None:
            return True                                    # 위험한 자리 그 자체(다른 인자 포함)
        local = cx.local_callee(call)
        if local is not None:
            bid, slots = local
            idx = None
            for i, a in enumerate(_args(call)):
                if a.type == "spread_element":
                    return False
                if a.id == cur.id:
                    idx = i
                    break
            summary = cx.summaries.get(bid)
            param = slots[idx] if idx is not None and idx < len(slots) else None
            if param is None or summary is None or param.id in summary[0]:
                return False                               # 그 함수가 값을 다른 데 쓴다(검사일 수 있다)
            if param.id in summary[1]:
                return None                                # 반환값에 남는다
            return True
        f = _callee(call)
        if f is not None and f.type == "member_expression":
            prop = _field(f, "property")
            if prop is not None and cx.text(prop) in _RES_HARMLESS and cx.resp_kind(_field(f, "object")) is not None:
                return True                                # `res.json({ … })`·`ctx.attachment(name)`·`res.set(h, v)` — 응답에 싣기
        kids = self.children(call)
        if kids is not None and any(k is not None and k.id == cur.id for k in kids):
            return None
        return False

    # ── 대입 ─────────────────────────────────────────────────────────────────

    def _bind(self, bindings: list[_Binding], value, *, keep: bool = False) -> None:
        """대입 — 요청 값이 남으면 그 이름도 요청 값, 아니면 끊는다. 값을 들여다본 결과면 '본 것'으로 이어 둔다."""
        cx = self.cx
        bindings = [b for b in bindings if b.id not in cx.aliases]
        if not bindings or value is None:
            return
        found = self.reach(value)
        if found:
            leads = bool(self.destination(value))
            d = min(self._depth_of(k) for k in found)
            for b in bindings:
                k = b.key
                self.taint[k] = self.taint[k] if keep and k in self.taint else leads
                self.depth[k] = min(d, self.depth.get(k, d)) if keep else d
                self.ever.add(k)
                for key in found:
                    self.groups.link(k, key)
            return
        seen = self.mentions(value)
        for b in bindings:
            k = b.key
            if seen:
                self.views.add(k)
                for key in seen:
                    self.groups.link(k, key)
            if not keep:
                self.taint.pop(k, None)

    def _bind_declarator(self, d) -> None:
        cx = self.cx
        name, value = _field(d, "name"), _field(d, "value")
        if name is None:
            return
        if name.type == "identifier":
            b = cx.decl.get(name.id)
            if b is None:
                return
            if value is None:
                self.taint.pop(b.key, None)
            else:
                self._bind([b], value)
            return
        if value is None:
            return
        items, _ = _pattern_items(name, cx.src)
        bare = _unwrap(value)
        while bare is not None and bare.type == "await_expression" and _named(bare):
            bare = _unwrap(_named(bare)[0])
        base = self.key_of(bare)
        for ident, path, rest in items:
            b = cx.decl.get(ident.id)
            if b is None or b.id in cx.aliases:
                continue
            k = b.key
            if path is not None and not rest and base is not None and base.startswith(REQ):
                fk = _extend(base, path)
                if fk is not None:
                    self.taint[k] = True
                    self.depth[k] = 0
                    self.ever.add(k)
                    self.groups.link(k, fk)
                    self.seen.add(fk)
                    continue
            seen = self.mentions(value)
            if seen:
                self.views.add(k)
                for key in seen:
                    self.groups.link(k, key)
            self.taint.pop(k, None)

    def _bind_assignment(self, node) -> None:
        cx = self.cx
        left, right = _unwrap(_field(node, "left")), _field(node, "right")
        if left is None or right is None:
            return
        if left.type == "identifier":
            b = cx.write_refs.get(left.id)
            if b is not None:
                self._bind([b], right, keep=node.type == "augmented_assignment_expression")
            return
        if left.type in ("object_pattern", "array_pattern"):
            items, _ = _pattern_items(left, cx.src)
            seen = self.mentions(right) | self.reach(right)
            for ident, _path, _rest in items:
                b = cx.write_refs.get(ident.id)
                if b is None or b.id in cx.aliases:
                    continue
                if seen:
                    self.views.add(b.key)
                    for key in seen:
                        self.groups.link(b.key, key)
                self.taint.pop(b.key, None)

    # ── 한 단위 걷기(분기마다 지금의 값을 따로 본다) ─────────────────────────

    def _snapshot(self):
        return dict(self.taint), dict(self.depth)

    def _restore(self, state) -> None:
        self.taint, self.depth = dict(state[0]), dict(state[1])

    def _merge(self, states) -> None:
        """갈라졌던 경로를 합친다 — 어느 경로로든 요청 값이면 요청 값."""
        taint: dict[str, bool] = {}
        depth: dict[str, int] = {}
        for t, d in states:
            for k, lead in t.items():
                taint[k] = taint.get(k, False) or lead
                depth[k] = min(depth.get(k, d.get(k, 0)), d.get(k, 0))
        self.taint, self.depth = taint, depth

    def _process(self, roots) -> tuple[list, list]:
        """이 문장에서 계산하는 식 — 위험한 자리와 같은 파일 함수 호출을 적는다. 돌려주는 값: (안쪽 함수들, 대입 식들)."""
        cx = self.cx
        fns: list = []
        assigns: list = []
        stack = list(reversed([r for r in roots if r is not None]))
        while stack:
            n = stack.pop()
            cx.spend()
            t = n.type
            if t in _FUNC_TYPES:
                fns.append(n)
                continue
            if t in _CLASS_TYPES:
                body = _field(n, "body")
                fns.extend(m for m in _named(body) if m.type == "method_definition")
                continue
            if t in _SKIP_TYPES:
                continue
            if t in ("assignment_expression", "augmented_assignment_expression"):
                assigns.append(n)
            elif t == "call_expression":
                self._record_call(n)
            stack.extend(reversed(n.named_children))
        return fns, assigns

    def _record_call(self, call) -> None:
        cx = self.cx
        found = cx.sink(call)
        if found is not None:
            rule, targets, address = found
            roots = cx.root_gated.get(call.id)
            if roots is not None and not any(self.reach(r) for r in roots):
                return                                     # 뿌리 폴더가 상수·모르는 값 — 그 밖으로 못 나간다
            keys: set[str] = set()
            for tg in targets:
                keys |= self.destination(tg, slash_is_open=rule == RULE_REDIRECT) if address else self.reach(tg)
            if keys:
                self.sinks.append((rule, call, keys))
            return
        local = cx.local_callee(call)
        if local is None:
            return
        bid, slots = local
        for i, a in enumerate(_args(call)):
            if a.type == "spread_element":
                break
            if i >= len(slots) or slots[i] is None:
                continue
            keys = self.reach(a)
            if keys:
                depth = min(self._depth_of(k) for k in keys) + 1
                self.calls.append((bid, slots[i].id, keys, bool(self.destination(a)), depth, call))

    def _statement(self, st):
        """문장 하나 — 하위 블록·안쪽 함수는 ("block", 문장들)·("fn", 함수)로 요청한다(재귀 없이)."""
        cx = self.cx
        cx.spend()
        t = st.type
        if t in _FUNC_DECL_TYPES:
            if not self.module:
                yield ("fn", st)
            return
        if t in ("class_declaration", "abstract_class_declaration"):
            if not self.module:
                for m in _named(_field(st, "body")):
                    if m.type == "method_definition":
                        yield ("fn", m)
            return
        if t == "statement_block":
            yield ("block", _named(st))
            return
        if t == "labeled_statement":
            yield ("block", [_field(st, "body")])
            return
        if t == "export_statement":
            decl = _field(st, "declaration")
            if decl is not None:
                yield ("block", [decl])
                return
        roots: list = []
        if t in ("expression_statement", "return_statement", "throw_statement", "export_statement"):
            roots = _named(st)
        elif t in ("lexical_declaration", "variable_declaration"):
            roots = [d for d in _named(st) if d.type == "variable_declarator"]
        elif t == "if_statement" or t in ("while_statement", "do_statement"):
            roots = [_field(st, "condition")]
        elif t == "for_statement":
            roots = [_field(st, "initializer"), _field(st, "condition"), _field(st, "increment")]
        elif t == "for_in_statement":
            roots = [_field(st, "right")]
        elif t == "switch_statement":
            roots = [_field(st, "value")]
        fns, assigns = self._process(roots)
        if t == "return_statement" and not self.nested and roots:
            keys = self.reach(roots[0])
            if keys:
                self.returns.append((keys, bool(self.destination(roots[0]))))
        if t in ("lexical_declaration", "variable_declaration"):
            for d in roots:
                self._bind_declarator(d)
        if t == "for_statement":
            init = _field(st, "initializer")
            if init is not None and init.type in ("lexical_declaration", "variable_declaration"):
                for d in _named(init):
                    if d.type == "variable_declarator":
                        self._bind_declarator(d)
        for a in sorted(assigns, key=lambda a: a.start_byte):
            self._bind_assignment(a)
        if not self.module:
            for f in fns:
                yield ("fn", f)
        if t == "if_statement":
            start = self._snapshot()
            ends = []
            alt = _field(st, "alternative")
            for blk in (_field(st, "consequence"), _named(alt)[0] if alt is not None and _named(alt) else None):
                self._restore(start)
                if blk is not None:
                    yield ("block", [blk])
                if blk is None or not self._terminates(blk):
                    ends.append(self._snapshot())
            self._merge(ends or [start])
        elif t in ("for_statement", "for_in_statement", "while_statement", "do_statement"):
            start = self._snapshot()
            if t == "for_in_statement":
                left = _field(st, "left")
                op = _field(st, "operator")
                is_of = op is not None and cx.text(op) == "of"
                for ident, _p, _r in (_pattern_items(left, cx.src)[0] if left is not None else []):
                    b = cx.decl.get(ident.id) or cx.write_refs.get(ident.id)
                    if b is None:
                        continue
                    if is_of:
                        self._bind([b], _field(st, "right"))
                    else:
                        self.taint.pop(b.key, None)
            body = _field(st, "body")
            yield ("block", [body])
            yield ("block", [body])                        # 두 번 돌려 고정점을 근사한다
            self._merge([start, self._snapshot()])
        elif t == "try_statement":
            start = self._snapshot()
            body = _field(st, "body")
            yield ("block", [body])
            ends = [] if self._terminates(body) else [self._snapshot()]
            handler = _field(st, "handler")
            if handler is not None:
                self._restore(start)
                hbody = _field(handler, "body")
                yield ("block", [hbody])
                if not self._terminates(hbody):
                    ends.append(self._snapshot())
            self._merge(ends or [start])
            fin = _field(st, "finalizer")
            if fin is not None:
                yield ("block", [_field(fin, "body")])
        elif t == "switch_statement":
            start = self._snapshot()
            ends = []
            has_default = False
            for case in _named(_field(st, "body")):
                if case.type not in ("switch_case", "switch_default"):
                    continue
                has_default = has_default or case.type == "switch_default"
                self._restore(start)
                value = _field(case, "value")
                if value is not None:
                    self._process([value])
                body = [c for c in _named(case) if value is None or c.id != value.id]
                yield ("block", body)
                last = body[-1] if body else None
                if last is None or last.type not in ("return_statement", "throw_statement", "continue_statement"):
                    ends.append(self._snapshot())
            if not has_default:
                ends.append(start)
            self._merge(ends or [start])

    def _block(self, stmts):
        for st in stmts:
            if st is not None and st.type != "comment":
                yield ("stmt", st)

    def _nested(self, fn):
        """안쪽 함수 — 바깥 값을 본다. 콜백 매개변수로 넘어가는 흐름은 따라가지 않는다. 실행되지 않을 수도 있어 되돌린다."""
        saved = self._snapshot()
        self.nested += 1
        body = _field(fn, "body")
        if body is not None and body.type == "statement_block":
            yield ("block", _named(body))
        elif body is not None:
            fns, assigns = self._process([body])
            for a in sorted(assigns, key=lambda a: a.start_byte):
                self._bind_assignment(a)
            for f in fns:
                yield ("fn", f)
        self.nested -= 1
        self._restore(saved)

    def _run(self, stmts) -> None:
        """하위 블록 요청을 명시적 스택으로 처리한다 — 깊은 중첩에서도 재귀 한도에 걸리지 않는다."""
        stack = [self._block(stmts)]
        while stack:
            try:
                req = next(stack[-1])
            except StopIteration:
                stack.pop()
                continue
            kind, payload = req
            if kind == "stmt":
                stack.append(self._statement(payload))
            elif kind == "block":
                stack.append(self._block(payload))
            elif kind == "fn":
                stack.append(self._nested(payload))
            if len(stack) > 100_000:
                raise _OutOfBudget

    def _initial_taint(self) -> None:
        cx = self.cx
        if self.module:
            return
        slots = cx.params.get(self.fn.id, [])
        if self.probe:
            for b in slots:
                if b is not None and b.id not in cx.reqs and b.id not in cx.resps:
                    self.taint[b.key] = True
                    self.depth[b.key] = 0
                    self.ever.add(b.key)
            return
        bid = cx.func_of_node.get(self.fn.id)
        for pid, (lead, depth) in cx.param_sources.get(bid, {}).items() if bid is not None else ():
            k = cx.bindings[pid].key
            self.taint[k] = lead
            self.depth[k] = depth
            self.ever.add(k)

    def _used_groups(self) -> set[str]:
        """다른 데 쓰인 값들의 묶음 — 해롭지 않다고 아는 쓰임이 아니면 전부 센다(안쪽 함수 포함)."""
        used: set[str] = set()
        if self.module:
            targets = _named(self.fn)
        else:
            targets = [self.fn]
        for target in targets:
            for occ, key in self.occurrences(target, skip_functions=self.module):
                is_view = key in self.views and key not in self.ever
                if not self.is_harmless(occ, view=is_view, key=key):
                    used.add(self.groups.find(key))
        return used

    def _is_unused(self, keys: set[str], used: set[str], at=None) -> bool:
        """이 값들이(그릇을 포함해) 어디에도 쓰이지 않았는가 — 이 단위와, 요청 필드라면 파일 전체에서."""
        cx = self.cx
        find = self.groups.find
        known = self.seen | self.ever | self.views
        for key in keys:
            family = {key} | {k for k in known if find(k) == find(key)}
            family |= {k for k in known if any(a in family for a in _ancestors(k))}
            for member in family:
                if member.startswith("B") and int(member[1:]) in cx.opaque:
                    return False
                for k in (member, *_ancestors(member)):
                    if find(k) in used or k in cx.request_used:
                        return False
            for other, inside in self.only_inside:
                if find(other) == find(key) and (at is None or at.id not in inside):
                    return False
        return True

    def analyse(self) -> None:
        cx = self.cx
        self._initial_taint()
        if self.module:
            self._run(_named(self.fn))
        else:
            body = _field(self.fn, "body")
            if body is not None and body.type == "statement_block":
                self._run(_named(body))
            elif body is not None:                         # 화살표 함수의 식 본문 — 그 값이 반환값이다
                fns, assigns = self._process([body])
                keys = self.reach(body)
                if keys:
                    self.returns.append((keys, bool(self.destination(body))))
                for a in sorted(assigns, key=lambda a: a.start_byte):
                    self._bind_assignment(a)
                stack = [self._nested(f) for f in reversed(fns)]
                while stack:
                    try:
                        kind, payload = next(stack[-1])
                    except StopIteration:
                        stack.pop()
                        continue
                    if kind == "fn":
                        stack.append(self._nested(payload))
                    elif kind == "block":
                        self._run(payload)
        used = self._used_groups()
        for key in self.seen:                              # 이 단위가 들여다본 요청 필드는 파일 전체에 알린다
            if key.startswith(REQ) and self.groups.find(key) in used:
                cx.request_used_next.add(key)
        if self.probe:
            bid = cx.func_of_node[self.fn.id]
            find = self.groups.find
            slots = [b for b in cx.params.get(self.fn.id, []) if b is not None]
            cx.summaries[bid] = (
                frozenset(b.id for b in slots if find(b.key) in used or b.id in cx.opaque),
                frozenset(b.id for b in slots for keys, _ in self.returns if any(find(k) == find(b.key) for k in keys)),
                frozenset(b.id for b in slots for keys, lead in self.returns if lead and any(find(k) == find(b.key) for k in keys)),
            )
            return
        for rule, call, keys in self.sinks:
            if self._is_unused(keys, used, call) and cx.reportable_at(call):
                cx.hits.append((rule, call.start_point[0] + 1))
        for callee, param, keys, leads, depth, call in self.calls:
            if depth > _MAX_HOPS or not self._is_unused(keys, used) or not cx.reportable_at(call):
                continue
            mine = cx.collected.setdefault(callee, {})
            old = mine.get(param)
            mine[param] = (leads or (old[0] if old else False), min(depth, old[1]) if old else depth)


def has_framework_marker(code: str) -> bool:
    """서버 프레임워크를 가져오는 글자가 있는가 — 파서를 부르기 전에 거른다."""
    return bool(FRAMEWORK_IMPORT_RE.search(code))


def scan_js_flows(root, src: bytes, filename: str, *, strict: bool = False) -> list[tuple[str, int, str, str]]:
    """``(rule_id, line_no, evidence, confidence)`` — 서버 프레임워크를 쓰는 JS·TS 파일에서만.

    이 분석이 실패하거나 일의 양 한도를 넘어도 같은 파일의 다른 분석은 계속돼야 하므로 빈 결과를 돌려준다(일부만 본 결과는
    내지 않는다). 파일이 너무 크거나 구문 트리에 오류·빠진 노드가 하나라도 있으면 통째로 건너뛴다 — 요청 필드의 쓰임은 파일
    전체에서 보는데, 다른 함수의 파싱 오류가 쓰임을 가리면 그것이 오탐이 된다. ``strict`` 는 시험용 — 실패를 그대로 드러낸다.
    """
    del filename                                           # 언어 선택은 파싱할 때 끝났다(자리를 맞춰 둔다)
    if root is None or len(src) > MAX_BYTES or root.has_error:
        return []
    if not FRAMEWORK_IMPORT_RE.search(src.decode("utf-8", "replace")):
        return []
    try:
        cx = _Context(root, src)
        cx.index()
        cx.scopes()
        cx.prepare_names()
        cx.routes()
        if cx.dropped or not (cx.reqs or cx.aliases):
            return []
        cx.collect_units()
        for _ in range(3):                                 # 함수가 함수를 부르는 겹까지 요약이 자리 잡을 때까지
            before = dict(cx.summaries)
            for bid, fn in cx.funcs.items():
                _Unit(cx, fn, probe=True).analyse()
            if cx.summaries == before:
                break
        for _ in range(_MAX_ROUNDS):                       # 호출부 → 함수 + 파일 전체에서 쓰인 요청 필드가 자리 잡을 때까지
            cx.collected = {}
            cx.hits = []
            cx.request_used_next = set()
            for unit in cx.units:
                _Unit(cx, unit).analyse()
            merged = {k: dict(v) for k, v in cx.param_sources.items()}
            for name, params in cx.collected.items():
                mine = merged.setdefault(name, {})
                for pid, (lead, depth) in params.items():
                    old = mine.get(pid)
                    mine[pid] = (lead or (old[0] if old else False), min(depth, old[1]) if old else depth)
            stable = merged == cx.param_sources and cx.request_used_next <= cx.request_used
            cx.param_sources = merged
            cx.request_used |= cx.request_used_next
            if stable:
                break
    except _Unresolvable:
        return []                               # `eval`·`with` — 이름을 풀 수 없는 파일(오류가 아니다)
    except (RecursionError, _OutOfBudget):
        if strict:
            raise
        return []
    except Exception:                           # noqa: BLE001 — 격리가 목적이다(위 설명)
        if strict:
            raise
        return []
    lines = src.split(b"\n")
    out = set()
    for rule, line in cx.hits:
        raw = lines[line - 1].decode("utf-8", "replace").strip() if 1 <= line <= len(lines) else ""
        out.add((rule, line, redact_evidence(raw[:200]), CONFIDENCE))
    return sorted(out, key=lambda h: (h[1], h[0]))
