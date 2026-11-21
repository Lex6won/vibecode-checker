"""웹 요청 값이 **변수·함수를 거쳐** 닿는 흐름 — SSRF · 템플릿 삽입 · 경로 조작 · 열린 리다이렉트.

실측(2026-11-21 말뭉치 `l_remote_unauth_2026`): 한 줄에 출처와 호출이 함께 있으면 잡지만
(`requests.get(request.args['url'])`), 변수 하나만 거치면(`url = request.args['url']; requests.get(url)`)
전부 놓쳤다. 줄 단위 정규식으로는 볼 수 없는 자리라 구문 트리에서 대입을 따라간다.

**원칙 — 그 값이 다른 데 쓰인 적이 없을 때만, '유력(검토)'으로 보고한다.**

요청 값이 위험한 자리에 닿더라도, 그 값이나 거기서 나온 값·그 값을 들여다본 결과가 조건문·비교·조회·모르는 함수에
한 번이라도 쓰였으면 보고하지 않는다. 그것이 검사인지 아닌지는 판단하지 않는다. 같은 요청 필드는 읽는 방식이 달라도
(`request.args["x"]`·`request.values.get("x")`·별칭·사본) 하나로 보고, 쓰임은 **파일 전체**에서 찾는다 — 요청 전 훅이나
다른 함수가 그 필드를 들여다봤으면 핸들러에서도 쓰인 것이다.

근거를 '확인됨'이 아니라 '유력'으로 내는 까닭: 이 분석이 말할 수 있는 것은 "검사를 못 봤다"이지 "검사가 없다"가 아니다.
독립 적대적 검증을 네 차례 거쳤고, 코드를 읽고 쓰는 상대는 매번 이 파일만으로는 알 수 없는 안전한 코드를 만들어 냈다
(다른 파일의 확인 함수, 프레임워크가 보장하는 형, 권한 클래스).

해롭지 않다고 **분명히 아는** 쓰임만 예외다: 다른 이름에 담기·이어 붙이기, 값이 있는지 확인하고 없으면 끝내기,
열쇠가 있는지 확인, 파일이 있는지 확인(`os.path.exists` — `../../etc/passwd` 도 있다), 길이, 기록 남기기,
응답·오류 응답에 돌려주기, 위험한 자리 그 자체.

출처는 웹 요청뿐이다(요청 객체의 필드, 라우트 매개변수, 그 값을 그대로 넘겨받은 같은 파일 함수의 매개변수). 웹 프레임워크를
쓰지 않는 파일은 보지 않는다. 대상이 아닌 것: 숫자로 변환된 값, 문자열이 아닌 형으로 선언된 매개변수·모델 필드,
조회 열쇠로만 쓰인 값, 호스트가 고정된 주소, 올린 파일 객체(그 `filename` 만 값이다), 잘라 내거나 바꿔 쓴 값
(`.replace(…)`·`.split(…)`·`[:2]`), 데코레이터·의존성·클래스 훅이 걸린 핸들러의 경로 매개변수.

**그래서 놓치는 것**: 검사처럼 보이지만 검사가 아닌 코드(`.endswith(".pdf")` 만 확인하고 경로에 쓰기), 다른 파일로 넘어가는
흐름, 객체 속성에 담아 둔 값, 알 수 없는 함수의 반환값, 같은 이름의 필드를 다른 함수가 검사한 경우.
"""
from __future__ import annotations

import ast
import re
import string

from .py_const import is_numeric_cast
from .regex_scanner import redact_evidence

RULE_SSRF = "KISA-PY-INPUT-12"
RULE_TEMPLATE = "KISA-PY-INPUT-04"
RULE_PATH = "KISA-PY-INPUT-03"
RULE_REDIRECT = "KISA-PY-INPUT-07"
EMITTED_RULE_IDS = (RULE_SSRF, RULE_TEMPLATE, RULE_PATH, RULE_REDIRECT)
CONFIDENCE = "likely"                 # "검사를 못 봤다" — 사람이 확인할 발견이다(모듈 설명 참고)

REQ, UPLOAD = "REQ", "UPLOAD"         # 요청 필드·올린 파일의 열쇠 뿌리(읽는 방식과 무관하게 하나로)

_WEB_FRAMEWORKS = frozenset({
    "flask", "django", "fastapi", "starlette", "sanic", "bottle", "aiohttp", "tornado", "rest_framework", "quart",
    "falcon", "pyramid", "litestar", "chalice", "werkzeug", "flask_restful", "flask_restx", "ninja",
})
_TEST_TOOLS = frozenset({"unittest", "mock", "pytest"})
#: 요청 객체에서 값을 읽는 속성. 경로 매개변수(`view_args`·`path_params`·`match_info`)는 변환기가 좁혔을 수 있어 뺐다.
_REQUEST_FIELDS_RE = re.compile(
    r"^(?:request|req|self\.request|flask\.request)\.(?:args|form|forms|json|values|data|headers|cookies|get_json|get_data"
    r"|GET|POST|body|META|COOKIES|query_params|params|query|rel_url\.query|media|arguments|query_arguments|body_arguments)$",
)
_REQUEST_FILES_RE = re.compile(r"^(?:request|req|self\.request|flask\.request)\.(?:files|FILES)$")
#: 열쇠를 인자로 받아 값을 돌려주는 요청 메서드 — `self.get_argument("u")`·`req.get_param("u")`.
_REQUEST_GETTER_RE = re.compile(
    r"^(?:self\.(?:get_argument|get_arguments|get_query_argument|get_query_arguments|get_body_argument|get_body_arguments)"
    r"|req\.get_param(?:_as_\w+)?)$",
)
_ROUTE_DECORATOR_RE = re.compile(r"(?:^|\.)(?:route|get|post|put|patch|delete|api_route|websocket)$")
#: 그 자체로 값을 안전하게 만드는 함수 — 결과는 요청 값이 아니다.
_SANITIZERS = frozenset({"secure_filename", "basename", "safe_join", "url_for", "uuid4", "unsign"})
#: 요청 값이 그대로 결과에 남는 함수(문자열·경로·목록 조립). 그 밖의 함수 호출 결과는 요청 값으로 보지 않는다.
_PASS_FUNCS = frozenset({
    "str", "repr", "format", "bytes", "dict", "list", "tuple", "set", "frozenset", "Path", "PurePath", "PurePosixPath",
    "PureWindowsPath", "join", "abspath", "normpath", "realpath", "expanduser", "expandvars", "unquote", "unquote_plus",
    "urljoin", "fspath", "copy", "deepcopy", "enumerate", "sorted", "reversed", "zip", "iter", "next", "escape", "dirname",
})
#: 값을 그대로 둔 채 모양만 바꾸는 메서드 — 받는 쪽의 값이 결과에 남는다. 잘라 내거나 바꿔 쓰는 것(`replace`·`split`)은 아니다.
_PASS_METHODS = frozenset({
    "strip", "lstrip", "rstrip", "lower", "upper", "title", "format", "encode", "decode", "join", "joinpath",
    "with_name", "with_suffix", "resolve", "absolute", "expanduser", "as_posix", "copy", "get_json", "json", "to_dict",
    "dict", "model_dump", "items", "values", "keys", "format_map",
})
_ARG_PASS_METHODS = frozenset({"format", "join", "joinpath", "format_map"})   # 인자도 결과에 남는다
_DECODERS = frozenset({"loads", "load", "safe_load", "json_decode", "full_load"})
_DATA_MODULES = frozenset({"json", "simplejson", "orjson", "ujson", "yaml", "tomllib", "msgpack", "tornado", "escape"})
_PATH_MODULES = frozenset({"os", "posixpath", "ntpath", "urllib"})
_PATH_CLASSES = frozenset({"Path", "PurePath", "PurePosixPath", "PureWindowsPath"})
#: 쓰여도 해롭지 않다고 분명히 아는 호출 — 길이, 파일이 있는지·종류, 디렉터리 만들기, 기록, 응답·오류 응답 만들기, 저장.
_HARMLESS_CALLS = frozenset({
    "print", "repr",
    "debug", "info", "warning", "warn", "error", "exception", "critical", "log",
    "jsonify", "JSONResponse", "JsonResponse", "make_response", "render_template", "Response", "HttpResponse", "HTMLResponse",
    "PlainTextResponse", "json_response", "write", "finish", "flash",
    "abort", "HTTPException", "Http404", "HTTPError", "NotFound", "BadRequest", "HttpResponseNotFound", "HttpResponseBadRequest",
    "append", "extend", "add", "insert", "update", "setdefault", "save", "read", "seek", "close", "set_header",
})
#: 파일이 있는지·종류를 보는 호출 — 경로 모듈의 것일 때만(`r.exists(key)`·`storage.exists(name)` 는 등록 여부 검사다).
_EXISTENCE_CALLS = frozenset({
    "exists", "lexists", "isfile", "isdir", "islink", "getsize", "getmtime", "getctime", "getatime", "stat", "access",
    "makedirs", "mkdir", "guess_type",
})
_PATH_OWNERS = frozenset({"os", "posixpath", "ntpath", "path", "mimetypes", "shutil", "pathlib"})
#: 기록 문장 안에서 값을 감싸도 되는 호출 — 그 밖의 호출(`checked(name)`)은 검사일 수 있다.
_LOG_WRAPPERS = frozenset({"urlparse", "urlsplit", "len", "str", "repr", "basename", "quote", "join", "format"})
_LOG_METHODS = frozenset({"debug", "info", "warning", "warn", "error", "exception", "critical", "log", "print"})
_STORE_METHODS = frozenset({"append", "extend", "add", "insert", "update", "setdefault"})
_SHALLOW_VIEWS = frozenset({"len", "exists", "lexists", "isfile", "isdir", "is_file", "is_dir", "getsize", "getmtime", "stat"})
_INERT_PARAM_NAMES = frozenset({
    "self", "cls", "request", "req", "response", "resp", "db", "session", "background_tasks", "current_user", "user",
    "websocket", "ws", "ctx", "context", "settings", "config",
})
_WRAPPER_RE = re.compile(r"^(?:typing\.)?(?:Optional|Annotated|Union)\[\s*")
#: 이름 그대로 써도 요청 값인 형 — 문자열과 주소. 그 밖의 형(숫자·열거형·모르는 클래스)은 요청 값으로 보지 않는다.
_STRING_ANNOTATION_RE = re.compile(
    r"^(?:typing\.)?(?:str|bytes|Any|AnyStr|EmailStr|HttpUrl|AnyUrl|AnyHttpUrl|IPvAnyAddress"
    r"|(?:list|List|set|Set|tuple|Tuple|Sequence|dict|Dict|Mapping)(?:\[[\s\w.,]*\b(?:str|Any)\s*\])?)$",
)
_UPLOAD_ANNOTATION_RE = re.compile(r"(?:^|\.)(?:UploadFile|FileStorage|UploadedFile)$")
_REQUEST_ANNOTATION_RE = re.compile(r"(?:^|\.)(?:Request|HttpRequest|WSGIRequest)$")
_CONSTRAINT_RE = re.compile(
    r"\b(?:AfterValidator|BeforeValidator|PlainValidator|WrapValidator|StringConstraints|constr|Depends|Security)\s*\(\s*[^)\s]"
    r"|\b(?:Field|Query|Path|Body|Form|Header|Cookie)\s*\([^()]*\b(?:pattern|regex|max_length|min_length|ge|gt|le|lt|enum)\s*=",
)
#: 입력과 무관하다고 아는 데코레이터 — 그 밖의 데코레이터가 붙은 핸들러의 매개변수는 무엇을 거쳤는지 모른다.
_NEUTRAL_DECORATOR_RE = re.compile(
    r"(?i)^(?:(?:\w+_)?(?:login|auth|jwt|token|permission|permissions|role|roles|admin|user|staff|superuser)_required"
    r"|requires_auth|authenticated|verify_jwt_in_request|cache\w*|cached|memoize|never_cache|limit|limiter\w*|ratelimit"
    r"|throttle\w*|csrf_exempt|csrf_protect|ensure_csrf_cookie|exempt|cross_origin|cors|wraps|transaction|atomic|api_view"
    r"|require_(?:http_methods|GET|POST|safe)|staticmethod|classmethod|property|override|abstractmethod|action"
    r"|authentication_classes|permission_classes|renderer_classes|parser_classes)$",
)
#: 값을 좁히거나 찾아오는 의존성 이름 — `Depends(verify_name)`·`Depends(load_document)`.
_INSPECTING_DEPENDENCY_RE = re.compile(r"(?i)valid|verify|check|ensure|require|allow|guard|sanit|parse|load|resolve|lookup|fetch|or_404")
_AUTH_DEPENDENCY_RE = re.compile(r"(?i)token|auth|user|login|jwt|session|api_key|credential|permission|role|admin|db|settings|config")
_CLASS_HOOKS = frozenset({"prepare", "dispatch", "initial", "before_request", "get_permissions", "check_permissions"})
_CLASS_HOOK_ATTRS = frozenset({"decorators", "method_decorators"})
_ANGLE_PARAM_RE = re.compile(r"<(?:(\w+)(\([^)]*\))?:)?(\w+)>")
_BRACE_PARAM_RE = re.compile(r"\{(\w+)(?::[^}]*)?\}")
_OPEN_CONVERTERS = frozenset({"", "string", "path", "str"})      # 이 밖의 변환기(int·uuid·any·직접 만든 것)는 값을 좁힌다
_HTTP_VERBS = frozenset({"get", "post", "put", "patch", "delete", "head", "options"})
_HTTP_CLIENT_CTOR_RE = re.compile(r"^(?:requests\.(?:Session|session)|httpx\.(?:Async)?Client|aiohttp\.ClientSession)$")
_HTTP_CLIENT_ANNOTATION_RE = re.compile(r"(?:^|\.)(?:AsyncClient|Client|ClientSession)$|^requests\.Session$")
#: 아직 호스트가 끝나지 않은 접두 — `""`·`"http://"`·`"https://api-"`·`"//"`. 이 뒤에 붙는 값이 호스트를 정한다.
_OPEN_AUTHORITY_RE = re.compile(r"^(?:(?:[A-Za-z][A-Za-z0-9+.\-]*:)?//[^/?#\s]*|[A-Za-z][A-Za-z0-9+.\-]*:/?)$")
_PERCENT_FIELD_RE = re.compile(r"%(?:\((\w+)\))?[#0\- +]*\d*(?:\.\d+)?[sdrfxieg]")
_REDIRECT_RE = re.compile(
    r"(?:^|\.)(?:redirect|RedirectResponse|HttpResponseRedirect|HttpResponsePermanentRedirect|HTTPFound|HTTPSeeOther"
    r"|HTTPMovedPermanently|HTTPTemporaryRedirect)$",
)
_FILE_RESPONSE_RECEIVERS = frozenset({"send_file", "FileResponse", "flask", "responses", "fastapi", "starlette", "quart", "web"})
_REDIRECT_RECEIVERS = frozenset({"flask", "self", "django", "shortcuts", "responses", "starlette", "fastapi", "http", "quart", "web"})
_KEY_LIKE_RE = re.compile(r"\w+")
_ROOT_RE = re.compile(r"^[A-Za-z_]\w*")
_TAIL_RE = re.compile(r"(?:\[[^\[\]]*\]|\.\w+)$")
_PARTS_LIMIT = 400                   # 이보다 긴 연결식은 앞부분만 본다
_BUDGET = 1_500_000                  # 한 파일에서 보는 식 조각 수의 한도(수만 줄짜리 생성 코드 대비) — 넘으면 이 분석만 건너뛴다


class _OutOfBudget(Exception):
    """한 파일에 쓸 일의 양을 넘었다."""


def _dotted(node: ast.AST | None) -> str | None:
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return None


def _call_name(call: ast.AST) -> str:
    """호출 이름의 마지막 마디 — `os.path.basename(x)` → ``basename``, `v.validate(x)` → ``validate``."""
    func = getattr(call, "func", None)
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return ""


def _unwrap(node: ast.AST | None) -> ast.AST | None:
    while isinstance(node, ast.Await):
        node = node.value
    return node


def _call_args(call: ast.Call) -> list[ast.AST]:
    return [*call.args, *(kw.value for kw in call.keywords)]


def _is_numeric(node: ast.AST) -> bool:
    """숫자(또는 문자열이 아닌 것)로 바꾼 값 — `int(x)`·`args.get("n", type=int)`·`args.get("n", 1, int)`."""
    if not isinstance(node, ast.Call):
        return False
    if is_numeric_cast(node):
        return True
    if isinstance(node.func, ast.Attribute) and node.func.attr in {"get", "getlist"}:
        kind = next((kw.value for kw in node.keywords if kw.arg == "type"), node.args[2] if len(node.args) > 2 else None)
        return kind is not None and (_dotted(kind) or "") not in {"", "str"}
    return False


def _const_lookup(node: ast.AST) -> tuple[ast.AST, object] | None:
    """`x["k"]`·`x.get("k")`·`x.getlist("k")` 이면 (그릇 식, 열쇠)."""
    if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant):
        return node.value, node.slice.value
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {"get", "getlist", "pop"} \
            and node.args and isinstance(node.args[0], ast.Constant) and not _is_numeric(node):
        return node.func.value, node.args[0].value
    return None


def _ancestors(key: str) -> list[str]:
    """열쇠를 감싸는 그릇들 — `REQ['a']['b']` → [`REQ['a']`, `REQ`]."""
    out: list[str] = []
    while True:
        m = _TAIL_RE.search(key)
        if m is None:
            return out
        key = key[:m.start()]
        out.append(key)


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


class _Context:
    def __init__(self, source_lines: list[str], aliases: dict[str, str]) -> None:
        self.source_lines = source_lines
        self.aliases = aliases
        self.parents: dict[ast.AST, ast.AST] = {}
        self.funcs: dict[str, list[str]] = {}              # 같은 파일의 함수(메서드 제외) → 매개변수
        self.methods: dict[str, list[str]] = {}            # 메서드(이름이 하나뿐인 것) → self 를 뺀 매개변수
        self.decorated: set[str] = set()                   # 데코레이터가 붙은 함수·메서드 — 인자가 무엇을 거치는지 모른다
        #: 함수·메서드가 매개변수를 어떻게 다루는가 — (다른 데 쓰는 것, 반환값에 남는 것, 그중 맨 앞까지 남는 것).
        self.summaries: dict[str, tuple[set[str], set[str], set[str]]] = {}
        self.enums: set[str] = set()
        self.models: dict[str, dict[str, str]] = {}        # 모델 클래스 → 필드의 종류("*" 는 모델 전체를 보는 코드가 있음)
        self.type_aliases: dict[str, str] = {}             # `Slug = Annotated[str, …]`·`Name = constr(…)`
        self.module_clients: set[str] = set()
        self.module_shadowed: set[str] = set()
        self.request_imports: set[str] = set()             # 웹 프레임워크에서 가져온 요청 객체 이름(`from flask import request`)
        self.hook_checked: set[str] = set()                # 라우터·앱 수준 의존성이 받는 매개변수 이름
        self.path_hook = False                             # 요청 전 훅이 경로 매개변수를 본다
        self.hooked_classes: set[int] = set()              # 클래스 수준 훅·데코레이터가 있는 클래스의 메서드들
        #: 파일 어디서든 다른 데 쓰인 요청 필드(읽는 방식과 무관한 열쇠). `REQ` 가 있으면 요청 그릇째 쓰였다.
        self.request_used: set[str] = set()
        self.request_used_next: set[str] = set()
        #: 함수 이름 → 호출자가 깨끗한 요청 값을 넘긴 매개변수. 값은 (닿는 것, 그중 맨 앞까지 요청 값인 것).
        self.param_sources: dict[str, tuple[set[str], set[str]]] = {}
        self.collected: dict[str, tuple[set[str], set[str]]] = {}
        self.hits: list[tuple[str, int, str, str]] = []
        self.budget = _BUDGET
        self.frameworks: set[str] = set()

    def spend(self, amount: int = 1) -> None:
        self.budget -= amount
        if self.budget < 0:
            raise _OutOfBudget

    def resolve(self, dotted: str | None) -> str:
        if not dotted:
            return ""
        head, _, rest = dotted.partition(".")
        base = self.aliases.get(head)
        if base is None or base == head:
            return dotted
        return f"{base}.{rest}" if rest else base


class _Scope:
    """가장 바깥 함수 하나(또는 모듈 최상위)의 분석 — 안쪽 함수는 같은 스코프에서 본다."""

    def __init__(self, cx: _Context) -> None:
        self.cx = cx
        self.taint: dict[str, bool] = {}       # 지금 요청 값이 남아 있는 이름 → 값의 맨 앞까지 요청 값인가
        self.clean: set[str] = set()           # 지금 요청 값이 아닌 것으로 덮어쓴 필드 열쇠(`payload["callback"] = CONST`)
        self.ever: set[str] = set()            # 한 번이라도 요청 값이었던 이름
        self.views: set[str] = set()           # 요청 값을 들여다본 결과를 담은 이름
        self.objects: dict[str, str | None] = {}   # 클래스형 매개변수 → 모델 이름(정의를 모르면 None — 올린 파일 등)
        self.alias: dict[str, str] = {}        # 한 번만 대입되는 이름 → 그것이 가리키는 열쇠(`data = request.get_json()` → REQ)
        self.groups = _Groups()
        self.seen: set[str] = set()            # 이 스코프에서 나온 모든 열쇠
        self.clients: set[str] = set()
        self.requests: set[str] = set()        # 이 스코프에서 웹 요청 객체인 이름
        self.sinks: list[tuple[str, ast.Call, set[str]]] = []
        self.calls: list[tuple[str, str, set[str], bool]] = []
        self.returns: list[tuple[set[str], bool]] = []
        self.only_inside: list[tuple[str, set[int]]] = []   # (열쇠, 그 값이 비어 있지 않은 채로 닿는 유일한 분기의 노드들)
        self.route_params: set[str] = set()    # 라우트 매개변수 — 같은 이름의 요청 필드이기도 하다(FastAPI 질의 매개변수)
        self.reportable = True                 # 이 핸들러의 요청 본문을 봐도 되는가(모르는 데코레이터가 없다)
        self.path_inspected = False            # 핸들러가 요청 경로 전체(`request.path`)를 조건에 썼다

    # ── 식이 어떤 값인가 ────────────────────────────────────────────────────

    def _request_root(self, node: ast.AST) -> str | None:
        """요청 객체에서 읽는 식이면 그 뿌리 열쇠 — 필드 그릇은 ``REQ``, 올린 파일 그릇은 ``UPLOAD``."""
        d = _dotted(node)
        if not d:
            return None
        head = d.split(".")[0]
        if head in {"request", "req"} and head not in self.requests:
            return None                                # 웹 요청이 아닌 다른 것에 붙은 이름
        if _REQUEST_FILES_RE.match(d):
            return UPLOAD
        return REQ if _REQUEST_FIELDS_RE.match(d) else None

    def key_of(self, node: ast.AST, *, census: bool = False) -> str | None:
        """이 식이 따라가는 값이면 그 열쇠. 같은 요청 필드는 읽는 방식이 달라도 같은 열쇠다.

        ``census`` 면 지금은 요청 값이 아니어도 한 번이라도 따라간 이름·들여다본 결과를 포함한다.
        """
        suffix: list[str] = []
        cur = node
        if _is_numeric(cur):
            return None
        while True:
            step = _const_lookup(cur)
            if step is None:
                break
            cur = step[0]
            suffix.append(f"[{step[1]!r}]")
        tail = "".join(reversed(suffix))
        if isinstance(cur, ast.Name):
            if cur.id in self.alias:
                return self.alias[cur.id] + tail
            known = cur.id in self.taint or census and (cur.id in self.ever or cur.id in self.views or cur.id in self.objects)
            return cur.id + tail if known else None
        if isinstance(cur, ast.Attribute):
            root = self._request_root(cur)
            if root is not None:
                return root + tail                     # `request.args['next']` → REQ['next']
            attrs: list[str] = []
            base = cur
            while isinstance(base, ast.Attribute):
                attrs.append(base.attr)
                base = base.value
            inner = self.key_of(base, census=census) if not isinstance(base, ast.Name) else None
            if isinstance(base, ast.Name) and (base.id in self.objects or self.alias.get(base.id, "").startswith(UPLOAD)):
                inner = self.alias.get(base.id, base.id)
            if inner is not None and (inner.startswith(UPLOAD) or _ROOT_RE.match(inner).group(0) in self.objects):
                return inner + "".join("." + a for a in reversed(attrs)) + tail     # `body.url`·`upload.filename`
            return None
        if isinstance(cur, ast.Call) and len(cur.args) == 1 and _call_name(cur) in _DECODERS | {"dict"}:
            # 풀어 읽기만 하는 것(`json.loads`·`dict`)일 때만 — `Schema().load(…)` 는 검사하는 호출이다
            owner = set(self.cx.resolve(_dotted(cur.func)).split("."))
            plain = _call_name(cur) == "dict" and isinstance(cur.func, ast.Name) or bool(owner & _DATA_MODULES)
            if plain and self.key_of(cur.args[0], census=census) == REQ:
                return REQ + tail                      # `json.loads(request.body)['feed']`·`dict(request.args)['x']`
        if isinstance(cur, ast.Call) and isinstance(cur.func, ast.Attribute) and not cur.args \
                and cur.func.attr in {"to_dict", "dict", "copy"}:
            inner = self.key_of(cur.func.value, census=census)
            if inner is not None and inner.startswith(REQ):
                return inner + tail                    # `request.form.to_dict()['kind']`
        if isinstance(cur, ast.Call) and isinstance(cur.func, ast.Attribute):
            d = _dotted(cur.func) or ""
            if _REQUEST_GETTER_RE.match(d) and (d.split(".")[0] != "req" or "req" in self.requests):
                arg = cur.args[0] if cur.args else None
                return REQ + (f"[{arg.value!r}]" if isinstance(arg, ast.Constant) else "") + tail
            if self._request_root(cur.func) == REQ and not cur.args:
                return REQ + tail                      # `request.get_json()['url']`
        return None

    def carries(self, key: str) -> bool:
        """이 열쇠의 값에 **지금** 요청 값이 그대로 남아 있는가."""
        if key in self.clean or any(a in self.clean for a in _ancestors(key)):
            return False
        root = _ROOT_RE.match(key).group(0)
        if root == UPLOAD:
            return key.endswith(".filename")               # 올린 파일은 객체다 — 보낸 쪽이 적은 이름만 값이다
        if root == REQ:
            return True
        if root in self.objects:
            attrs = key[len(root):].split("[")[0].strip(".").split(".")
            model = self.objects[root]
            if not attrs or attrs == [""] or root not in self.taint:
                return False
            if model is None:
                return attrs == ["filename"]           # 정의를 모르는 클래스 — 올린 파일의 이름만 안다
            kind = model
            for attr in attrs:
                kind = self.cx.models.get(kind, {}).get(attr, "")
            return kind == "string"                    # 모델 필드는 문자열로 선언된 것만
        return root in self.taint

    def leads(self, key: str) -> bool:
        root = _ROOT_RE.match(key).group(0)
        return self.taint.get(root, True)

    def children(self, node: ast.AST) -> list[ast.AST] | None:
        """`node` 의 값에 요청 값이 **그대로 남을 수 있는** 하위 식. None 이면 끊긴다(모르는 것은 끊는다)."""
        cx = self.cx
        if isinstance(node, ast.Call):
            if _is_numeric(node):
                return None
            name = _call_name(node)
            func = node.func
            if name in _SANITIZERS or (name == "loads" and re.search(r"(?i)sign|serializ", _dotted(func) or "")):
                return None
            if isinstance(func, ast.Attribute):
                owner = cx.resolve(_dotted(func.value)).split(".") if _dotted(func.value) else []
                if name in _DECODERS:
                    return _call_args(node) if set(owner) & _DATA_MODULES else None
                if name in _PASS_FUNCS and owner and owner[0] in _PATH_MODULES:
                    return _call_args(node)            # `os.path.join(BASE, x)`·`urllib.parse.urljoin(a, b)`
                if name in _ARG_PASS_METHODS:
                    return [func.value, *_call_args(node)]
                if name in {"get", "pop", "getlist"}:
                    return [func.value]                # `data.get(key)` — 그릇에서 꺼낸 것
                if name in _PASS_METHODS and not (name in {"strip", "lstrip", "rstrip"} and node.args):
                    return [func.value]
                return None
            if isinstance(func, ast.Name):
                summary = cx.summaries.get(func.id) if func.id in cx.funcs else None
                if summary is not None:                # 같은 파일 함수 — 반환값에 남는 매개변수만
                    params = cx.funcs[func.id]
                    kept = [a for i, a in enumerate(node.args) if i < len(params) and params[i] in summary[1]]
                    return kept + [kw.value for kw in node.keywords if kw.arg in summary[1]]
                full = cx.resolve(func.id)
                last = full.rsplit(".", 1)[-1]
                if last in _PASS_FUNCS or (last in _DECODERS and set(full.split(".")) & _DATA_MODULES):
                    return _call_args(node)
            return None
        if isinstance(node, ast.IfExp):
            return [node.body, node.orelse]
        if isinstance(node, ast.BoolOp):
            # `a and b` 의 값은 b 이거나 거짓인 a(빈 값)다. `a or b` 는 어느 쪽이든 될 수 있다
            return [node.values[-1]] if isinstance(node.op, ast.And) else list(node.values)
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            return [node.elt]                          # 원소가 값이다 — 돌리는 대상은 `for` 변수 대입으로 따라간다
        if isinstance(node, ast.BinOp):
            return [node.left, node.right] if isinstance(node.op, (ast.Add, ast.Div, ast.Mod)) else None
        if isinstance(node, (ast.JoinedStr, ast.FormattedValue, ast.Tuple, ast.List, ast.Set, ast.Starred, ast.NamedExpr,
                             ast.Await)):
            return list(ast.iter_child_nodes(node))
        if isinstance(node, ast.Dict):
            return [v for v in node.values if v is not None]
        return None                                    # 잘라 내기·속성 읽기·비교·람다·그 밖 — 모르는 것은 따라가지 않는다

    def reach(self, node: ast.AST, *, lead_only: bool = False) -> set[str]:
        """이 식의 값에 남는 요청 값들의 열쇠. 비어 있으면 닿지 않는다."""
        found: set[str] = set()
        stack = [node]
        while stack:
            n = stack.pop()
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

    def occurrences(self, node: ast.AST, *, skip_sinks: bool = False):
        """식 안에서 따라가는 값이 나오는 자리 — (그 자리의 가장 바깥 식, 열쇠)."""
        stack = [node]
        while stack:
            n = stack.pop()
            self.cx.spend()
            if isinstance(n, ast.Name) and not isinstance(n.ctx, ast.Load):
                continue
            if skip_sinks and isinstance(n, ast.Call) and self.sink(n) is not None:
                continue
            if isinstance(n, ast.expr):
                key = self.key_of(n, census=True)
                if key is not None:
                    self.seen.add(key)
                    yield n, key
                    continue
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
                stack.append(n.func.value)             # 메서드 이름은 값이 아니다
                stack.extend(_call_args(n))
            elif isinstance(n, ast.Call) and isinstance(n.func, ast.Name):
                stack.extend(_call_args(n))
            elif not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                stack.extend(ast.iter_child_nodes(n))

    def mentions(self, node: ast.AST) -> set[str]:
        """이 식 어디에든 나오는 따라가는 값 — 값을 옮기지 않아도 '들여다본' 것을 잇는 데 쓴다.

        위험한 자리에 넣은 것은 뺀다 — `resp = requests.get(url)` 의 `resp` 는 `url` 을 들여다본 결과가 아니다.
        """
        return {key for _, key in self.occurrences(node, skip_sinks=True)}

    # ── 주소의 호스트 자리 ──────────────────────────────────────────────────

    def destination(self, node: ast.AST, *, slash_is_open: bool = False) -> set[str]:
        """요청 값이 주소의 **호스트 자리**까지 정하면 그 값들. 앞에 다른 것이 붙어 있으면(고정 주소·경로·상수 접두) 비어 있다.

        ``slash_is_open``: 리다이렉트에서 `"/" + x` 는 `x="/evil.example"` 이면 `//evil.example` 이 된다.
        """
        node = _unwrap(node)
        cx = self.cx
        if isinstance(node, ast.Call) and _call_name(node) == "urljoin" and len(node.args) == 2:
            # 둘째가 절대 주소면 첫째를 버린다. 둘째의 맨 앞이 요청 값이 아니면 호스트는 첫째가 정한다
            return self.destination(node.args[1]) or self.destination(node.args[0])
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in cx.summaries \
                and node.func.id in cx.funcs:
            params, leading = cx.funcs[node.func.id], cx.summaries[node.func.id][2]
            args = [a for i, a in enumerate(node.args) if i < len(params) and params[i] in leading]
            args += [kw.value for kw in node.keywords if kw.arg in leading]
            return set().union(*(self.destination(a) for a in args)) if args else set()
        text = ""
        parts = _ordered_parts(node)
        for i, part in enumerate(parts):
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                text += part.value
                continue
            if text and not _OPEN_AUTHORITY_RE.match(text) and not (slash_is_open and text == "/"):
                return set()                           # `"https://api.example/items/" + x`·`"?page=" + x`·`"users/" + x`
            found = self.reach(part, lead_only=True)
            if not found and not text and not self.reach(part):
                nxt = parts[i + 1] if i + 1 < len(parts) else None
                if isinstance(nxt, ast.Constant) and isinstance(nxt.value, str) and nxt.value.startswith("://"):
                    text = "x"                         # `f"{scheme}://{host}/…"` — 앞 조각은 스킴이다
                    continue
            return found
        return set()

    # ── 위험한 자리 ─────────────────────────────────────────────────────────

    def sink(self, call: ast.Call) -> tuple[str, ast.AST, bool] | None:
        """이 호출이 위험한 자리면 (룰 ID, 봐야 할 인자, 주소인가)."""
        cx = self.cx
        raw = _dotted(call.func)
        name = cx.resolve(raw)
        func = call.func
        last = name.rsplit(".", 1)[-1]
        url: ast.AST | None = None
        if re.match(r"^(?:requests|httpx)\.(?:get|post|put|patch|delete|head|options)$", name) \
                or re.match(r"^urllib\.request\.(?:urlopen|Request)$", name):
            url = _arg(call, 0, "url")
        elif re.match(r"^(?:requests|httpx)\.(?:request|stream)$", name):
            url = _arg(call, 1, "url")
        elif isinstance(func, ast.Attribute) and (
                isinstance(func.value, ast.Name) and func.value.id in self.clients
                or isinstance(func.value, ast.Call) and _HTTP_CLIENT_CTOR_RE.match(cx.resolve(_dotted(func.value.func)))):
            if func.attr in _HTTP_VERBS:
                url = _arg(call, 0, "url")
            elif func.attr in {"request", "stream"}:
                url = _arg(call, 1, "url")
        if url is not None:
            return RULE_SSRF, url, True
        if last == "render_template_string" or name == "jinja2.Template" \
                or (isinstance(func, ast.Attribute) and func.attr == "from_string"
                    and (re.search(r"(?i)env|jinja", _dotted(func.value) or "")
                         or isinstance(func.value, ast.Call) and _call_name(func.value) == "Environment")):
            template = _arg(call, 0, "source")
            return (RULE_TEMPLATE, template, False) if template is not None else None
        if name in {"open", "io.open", "codecs.open", "builtins.open", "os.remove", "os.unlink"} \
                or (last in {"send_file", "FileResponse"} and (raw or "").split(".")[0] in _FILE_RESPONSE_RECEIVERS):
            path = _arg(call, 0, "file", "path", "path_or_file")
            return (RULE_PATH, path, False) if path is not None else None
        if isinstance(func, ast.Attribute) and func.attr in {"read_text", "read_bytes", "write_text", "write_bytes", "unlink"}:
            return RULE_PATH, func.value, False        # `(BASE / name).read_text()` — pathlib 로 연다
        if isinstance(func, ast.Attribute) and func.attr == "open" and (
                isinstance(func.value, ast.BinOp) and isinstance(func.value.op, ast.Div)
                or isinstance(func.value, ast.Call) and _call_name(func.value) in _PATH_CLASSES):
            return RULE_PATH, func.value, False
        if raw and _REDIRECT_RE.search(name) and ("." not in raw or raw.split(".")[0] in _REDIRECT_RECEIVERS):
            target = _arg(call, 0, "url", "location", "to")
            return (RULE_REDIRECT, target, True) if target is not None else None
        return None


def _arg(call: ast.Call, index: int, *keywords: str) -> ast.AST | None:
    """위치 인자가 먼저다 — `FileResponse(path, filename=…)` 의 `filename` 은 내려받을 이름이지 경로가 아니다."""
    if index < len(call.args):
        return None if any(isinstance(a, ast.Starred) for a in call.args[:index + 1]) else call.args[index]
    for kw in call.keywords:
        if kw.arg in keywords:
            return kw.value
    return None


def _format_parts(template: str, call: ast.Call) -> list[ast.AST] | None:
    """`"{base}/items/{id}".format(id=x, base=B)` 를 **자리 순서**로."""
    out: list[ast.AST] = []
    auto = 0
    keywords = {kw.arg: kw.value for kw in call.keywords if kw.arg}
    try:
        fields = list(string.Formatter().parse(template))
    except ValueError:
        return None
    for literal, field, _, _ in fields:
        if literal:
            out.append(ast.Constant(value=literal))
        if field is None:
            continue
        head = re.split(r"[.\[]", field, maxsplit=1)[0]
        if head == "":
            index, auto = auto, auto + 1
        elif head.isdigit():
            index = int(head)
        else:
            index = None
        value = keywords.get(head) if index is None else (call.args[index] if index < len(call.args) else None)
        if value is None or isinstance(value, ast.Starred):
            return None
        out.append(value)
    return out


def _percent_parts(template: str, right: ast.AST) -> list[ast.AST] | None:
    values = list(right.elts) if isinstance(right, ast.Tuple) else [right]
    named = {k.value: v for k, v in zip(right.keys, right.values) if isinstance(k, ast.Constant)} \
        if isinstance(right, ast.Dict) else None
    out: list[ast.AST] = []
    pos = index = 0
    for m in _PERCENT_FIELD_RE.finditer(template):
        if m.start() > pos:
            out.append(ast.Constant(value=template[pos:m.start()]))
        pos = m.end()
        if m.group(1) is not None:
            value = named.get(m.group(1)) if named is not None else None
        else:
            value = values[index] if named is None and index < len(values) else None
            index += 1
        if value is None:
            return None
        out.append(value)
    if pos < len(template):
        out.append(ast.Constant(value=template[pos:]))
    return out


def _ordered_parts(node: ast.AST) -> list[ast.AST]:
    """문자열 조립을 앞에서부터 — `"a" + b`·f-string·`T % b`·`T.format(b)`·`sep.join([a, b])`·`BASE / "x" / y`."""
    out: list[ast.AST] = []
    todo = [node]
    while todo and len(out) < _PARTS_LIMIT:
        n = todo.pop()
        if isinstance(n, ast.BinOp) and isinstance(n.op, (ast.Add, ast.Div)):
            todo += [n.right, n.left]
        elif isinstance(n, ast.JoinedStr):
            todo += [v.value if isinstance(v, ast.FormattedValue) else v for v in reversed(n.values)]
        elif isinstance(n, ast.BinOp) and isinstance(n.op, ast.Mod):
            parts = _percent_parts(n.left.value, n.right) \
                if isinstance(n.left, ast.Constant) and isinstance(n.left.value, str) else None
            rest = list(n.right.elts) if isinstance(n.right, ast.Tuple) else [n.right]
            todo += reversed(parts if parts is not None else [n.left, *rest])      # `URL_TEMPLATE % x` — 틀이 맨 앞
        elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "format":
            receiver = n.func.value
            parts = _format_parts(receiver.value, n) \
                if isinstance(receiver, ast.Constant) and isinstance(receiver.value, str) else None
            todo += reversed(parts if parts is not None else [receiver, *_call_args(n)])
        elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "join" \
                and len(n.args) == 1 and isinstance(n.args[0], (ast.List, ast.Tuple)) and n.args[0].elts:
            # `"/".join([BASE, x])`·`sep.join([self._url, query])` — 첫 원소가 맨 앞이다(실측: jupyter_server 의 리다이렉트)
            seq: list[ast.AST] = []
            for i, elt in enumerate(n.args[0].elts):
                if i:
                    seq.append(n.func.value)
                seq.append(elt)
            todo += reversed(seq)
        else:
            out.append(n)
    return out


# ── 쓰임이 해롭지 않은가 ─────────────────────────────────────────────────────

def _terminates(body: list[ast.stmt]) -> bool:
    """이 블록이 끝나면 뒤 문장으로 이어지지 않는가 — `return`·`raise`·`continue`·`abort(…)`."""
    if not body:
        return False
    last = body[-1]
    if isinstance(last, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
        return True
    value = _unwrap(last.value) if isinstance(last, ast.Expr) else None
    return isinstance(value, ast.Call) and bool(re.search(r"(?i)abort|exit|fail|raise", _call_name(value)))


def _presence_test_is_harmless(cur: ast.AST, positive: bool, sc: _Scope, key: str) -> bool:
    """값이 있는지만 본 조건 — **없으면 끝내는** 것은 해롭지 않다.

    **있으면 끝내는** 조건(`if url: return fetch(url)`)은 그 분기 밖에서 값이 비어 있다는 뜻이다 — 분기 안의 위험한
    자리만 값이 있는 채로 닿는다. 그 분기를 적어 두고, 밖에 있는 위험한 자리는 보고하지 않는다.
    """
    p = sc.cx.parents.get(cur)
    if isinstance(p, ast.Assert):
        return positive
    if isinstance(p, ast.If):
        branch = p.body if positive else p.orelse
        if _terminates(branch):
            sc.only_inside.append((key, {id(n) for s in branch for n in ast.walk(s)}))
        return True
    return isinstance(p, (ast.While, ast.IfExp, ast.comprehension))


def _is_harmless_use(node: ast.AST, sc: _Scope, *, view: bool, key: str = "") -> bool:
    """따라가는 값이 이 자리에서 **해롭지 않다고 분명히 아는** 방식으로 쓰였는가. 모르면 False.

    ``view``(들여다본 결과)는 조건에 쓰이기만 해도 검사일 수 있다 — `m = re.fullmatch(…); if not m: abort()`.
    """
    cx = sc.cx
    parents = cx.parents
    cur = node
    shaped = False                      # 이어 붙이기·감싸기를 거쳤다 — 그 결과를 조건에 쓰면 값을 본 것이다
    positive = True                     # 조건이 참이면 값이 있다(참)는 뜻인가
    up = parents.get(cur)
    while up is not None and not isinstance(up, ast.stmt):
        if isinstance(up, ast.Call):
            if _call_name(up) in _LOG_METHODS and isinstance(parents.get(up), ast.Expr):
                return True                              # 기록 문장 — `logger.info("…", urlparse(url).hostname)`
            if _call_name(up) not in _LOG_WRAPPERS:
                break                                    # 기록 문장 안이라도 모르는 호출을 거치면 따로 본다
        up = parents.get(up)
    while True:
        p = parents.get(cur)
        if p is None or isinstance(p, (ast.Return, ast.Expr, ast.Yield, ast.YieldFrom, ast.Await, ast.withitem, ast.Raise)):
            return True                                  # 돌려주기·그냥 계산·오류로 내보내기
        if isinstance(p, ast.Call) and isinstance(parents.get(p), ast.Raise) and p.func is not cur:
            return True                                  # `raise web.HTTPNotFound(text=f"{name} not found")`
        if isinstance(p, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.For, ast.AsyncFor)):
            return True                                  # 다른 이름에 담기·돌리기
        if isinstance(p, ast.comprehension):
            if any(cur is c for c in p.ifs):
                return not view and not shaped
            return True
        if isinstance(p, (ast.If, ast.While, ast.Assert)) or isinstance(p, ast.IfExp) and p.test is cur:
            return not view and not shaped and _presence_test_is_harmless(cur, positive, sc, key)
        if isinstance(p, ast.IfExp):
            cur = p
            continue
        if isinstance(p, ast.UnaryOp) and isinstance(p.op, ast.Not):
            cur, positive = p, not positive
            continue
        if isinstance(p, ast.BoolOp):
            cur = p
            continue
        if isinstance(p, ast.Compare):
            if view or shaped:
                return False
            if len(p.ops) == 1 and isinstance(p.ops[0], (ast.Is, ast.IsNot, ast.Eq, ast.NotEq)) and p.left is cur \
                    and isinstance(p.comparators[0], ast.Constant) and p.comparators[0].value in (None, ""):
                # `x is None`·`x is not None`·`x == ""`·`x != ""` — 값이 있는지 본 것이다
                cur, positive = p, positive == isinstance(p.ops[0], (ast.IsNot, ast.NotEq))
                continue
            left = p.left
            return len(p.ops) == 1 and isinstance(p.ops[0], (ast.In, ast.NotIn)) and p.comparators[0] is cur \
                and isinstance(left, ast.Constant) and isinstance(left.value, str) \
                and bool(_KEY_LIKE_RE.fullmatch(left.value))     # `"url" in data` — 열쇠가 있는지
        if isinstance(p, ast.keyword):
            cur = p
            continue
        if isinstance(p, ast.Call):
            if p.func is cur:
                return False
            name = _call_name(p)
            if sc.sink(p) is not None:
                return True                              # 위험한 자리 그 자체(다른 인자 포함)
            local = _local_callee(p, cx)
            if local is not None:
                callee, params = local
                param = _param_for(p, cur, params)
                summary = cx.summaries.get(callee)
                if param is None or summary is None or param in summary[0] or callee in cx.decorated:
                    return False                         # 그 함수가 값을 다른 데 쓴다(검사일 수 있다)
                if param in summary[1]:
                    cur, shaped = p, True                # 반환값에 남는다
                    continue
                return True
            if name == "len":
                # `len(x) > 255` 는 길이 제한, `len(x) != 1`·`== 36` 은 값의 모양을 본 것이다
                outer = parents.get(p)
                return not (isinstance(outer, ast.Compare) and any(isinstance(op, (ast.Eq, ast.NotEq)) for op in outer.ops))
            if name in _EXISTENCE_CALLS:
                owner = cx.resolve(_dotted(p.func.value)).split(".") if isinstance(p.func, ast.Attribute) else []
                return isinstance(p.func, ast.Name) or bool(set(owner) & _PATH_OWNERS)
            if name in _HARMLESS_CALLS:
                return True
            kids = sc.children(p)
            if (kids is not None and any(k is cur for k in kids)) or name in _SANITIZERS:
                cur, shaped = p, True                    # `os.path.join(BASE, x)`·`str(x)`·`basename(x)` — 결과가 어디에 쓰이는지 본다
                continue
            return False
        if isinstance(p, ast.Attribute):
            gp = parents.get(p)
            if isinstance(gp, ast.Call) and gp.func is p:
                if p.attr in _HARMLESS_CALLS or p.attr in _EXISTENCE_CALLS or p.attr in {"is_file", "is_dir", "is_symlink"} \
                        or sc.sink(gp) is not None:
                    return True                          # `target.exists()`·`f.save(path)`·위험한 자리의 받는 쪽
                kids = sc.children(gp)
                if kids is not None and any(k is cur for k in kids):
                    if p.attr not in {"strip", "lstrip", "rstrip", "lower", "upper"}:
                        shaped = True
                    cur = gp
                    continue
                return False                             # `x.startswith(…)` — 값을 봤다
            return False                                 # 속성 읽기 — 무엇인지 모른다
        if isinstance(p, ast.Subscript):
            if p.value is cur:
                if isinstance(p.ctx, ast.Store):
                    return True                          # `opts["url"] = v`
                return False                             # `x[0]`·`x[:2]` — 잘라 냈다
            return isinstance(p.ctx, ast.Store)          # `out[x] = v` 는 담기, `TABLE[x]` 는 찾아본 것이다
        if isinstance(p, ast.NamedExpr):
            cur = p                                      # `(url := …)` — 담기. 그 식을 조건에 쓰면 참·거짓만 본 것이다
            continue
        if isinstance(p, (ast.BinOp, ast.JoinedStr, ast.FormattedValue, ast.Tuple, ast.List, ast.Set, ast.Dict, ast.Starred,
                          ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            cur, shaped = p, True
            continue
        return False


def _local_callee(call: ast.Call, cx: _Context) -> tuple[str, list[str]] | None:
    if isinstance(call.func, ast.Name) and call.func.id in cx.funcs:
        return call.func.id, cx.funcs[call.func.id]
    if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name) and call.func.value.id in {"self", "cls"} \
            and call.func.attr in cx.methods:
        return call.func.attr, cx.methods[call.func.attr]
    return None


def _param_for(call: ast.Call, arg: ast.AST, params: list[str]) -> str | None:
    """호출의 이 인자(또는 그 키워드)가 받는 매개변수 이름. 모르면 None."""
    for i, a in enumerate(call.args):
        if isinstance(a, ast.Starred):
            return None
        if a is arg:
            return params[i] if i < len(params) else None
    for kw in call.keywords:
        if kw is arg or kw.value is arg:
            return kw.arg if kw.arg in params else None
    return None


# ── 한 스코프 걷기(분기마다 지금의 값을 따로 본다) ───────────────────────────

def _stmt_roots(stmt: ast.stmt) -> list[ast.AST]:
    from .ast_scanner import _stmt_roots as roots

    out = roots(stmt)
    if isinstance(stmt, ast.Match):
        out = [*out, stmt.subject]
    return out


def _is_ignored(line: str, rule_id: str) -> bool:
    from .regex_scanner import line_ignores_rule

    return line_ignores_rule(line, rule_id, "python")


def _store_names(target: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(target) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}


def _bind(sc: _Scope, names: set[str], value: ast.AST, *, keep: bool = False) -> None:
    """대입 — 요청 값이 남으면 그 이름도 요청 값, 아니면 끊는다. 값을 들여다본 결과면 '본 것'으로 이어 둔다.

    ``keep``: 더하는 대입(`url += x`·`names.append(x)`·`opts["k"] = x`)이라 남아 있던 값을 지우지 않는다.
    """
    value = _unwrap(value)
    names = {n for n in names if n not in sc.alias}      # 별칭은 가리키는 열쇠로 따라간다
    if not names:
        return
    if not keep:                                         # 통째로 다시 대입하면 필드에 대해 알던 것은 지운다
        sc.clean = {k for k in sc.clean if _ROOT_RE.match(k).group(0) not in names}
    if isinstance(value, ast.Dict) and not keep:
        for name in names:                               # `opts = {"url": CONST, …}` — 상수로 채운 필드는 요청 값이 아니다
            for k, v in zip(value.keys, value.values):
                if isinstance(k, ast.Constant) and v is not None and not sc.reach(v):
                    sc.clean.add(f"{name}[{k.value!r}]")
    found = sc.reach(value)
    if found:
        leads = bool(sc.destination(value))
        for name in names:
            sc.taint[name] = sc.taint[name] if keep and name in sc.taint else leads
            sc.ever.add(name)
            for key in found:
                sc.groups.link(name, key)
        return
    probe = value.operand if isinstance(value, ast.UnaryOp) else value
    seen = set() if isinstance(probe, ast.Call) and _call_name(probe) in _SHALLOW_VIEWS else sc.mentions(value)
    for name in names:
        if seen:                                         # 있는지·길이만 본 결과는 '본 것'이 아니다
            sc.views.add(name)
            for key in seen:
                sc.groups.link(name, key)
        if not keep:
            sc.taint.pop(name, None)                     # 다른 값으로 덮어썼다


def _bind_targets(sc: _Scope, targets: list[ast.AST], value: ast.AST) -> None:
    """`a, b = x, y` 는 짝끼리. `opts["url"] = v` 는 그릇에 담는다."""
    for target in targets:
        if isinstance(target, (ast.Tuple, ast.List)) and isinstance(value, (ast.Tuple, ast.List)) \
                and len(target.elts) == len(value.elts) and not any(isinstance(e, ast.Starred) for e in (*target.elts, *value.elts)):
            for t, v in zip(target.elts, value.elts):
                _bind_targets(sc, [t], v)
        elif isinstance(target, ast.Subscript):
            key = sc.key_of(target, census=True) if isinstance(target.slice, ast.Constant) else None
            if key is None and isinstance(target.slice, ast.Constant) and isinstance(target.value, ast.Name):
                key = f"{target.value.id}[{target.slice.value!r}]"     # 아직 요청 값이 아닌 그릇의 필드
            reaches = bool(sc.reach(value))
            if key is not None:                          # `payload["callback"] = CONST` 는 그 필드를 요청 값이 아니게 한다
                (sc.clean.discard if reaches else sc.clean.add)(key)
            if reaches and isinstance(target.value, ast.Name):
                _bind(sc, {target.value.id}, value, keep=True)
        else:
            _bind(sc, _store_names(target), value)


def _snapshot(sc: _Scope) -> tuple[dict[str, bool], set[str]]:
    return dict(sc.taint), set(sc.clean)


def _restore(sc: _Scope, state: tuple[dict[str, bool], set[str]]) -> None:
    sc.taint, sc.clean = dict(state[0]), set(state[1])


def _merge(sc: _Scope, states: list[tuple[dict[str, bool], set[str]]]) -> None:
    """갈라졌던 경로를 합친다 — 어느 경로로든 요청 값이면 요청 값, 모든 경로에서 덮어썼어야 덮어쓴 것이다."""
    taint: dict[str, bool] = {}
    for t, _ in states:
        for name, lead in t.items():
            taint[name] = taint.get(name, False) or lead
    sc.taint = taint
    sc.clean = set.intersection(*(c for _, c in states)) if states else set()


def _branches(sc: _Scope, blocks: list[list[ast.stmt]], *, may_skip: bool) -> None:
    """블록들 가운데 하나를 지난다. ``may_skip`` 이면 어느 것도 안 지날 수 있다."""
    start = _snapshot(sc)
    ends: list[tuple[dict[str, bool], set[str]]] = [start] if may_skip else []
    for block in blocks:
        _restore(sc, start)
        _walk(sc, block)
        if not _terminates(block):
            ends.append(_snapshot(sc))
    _merge(sc, ends or [start])


def _walk(sc: _Scope, stmts: list[ast.stmt]) -> None:
    cx = sc.cx
    for stmt in stmts:
        cx.spend()
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            saved = _snapshot(sc)                        # 안쪽 함수는 바깥 변수를 본다. 매개변수는 가린다
            for p in _params(stmt):
                sc.taint.pop(p, None)
            _walk(sc, stmt.body)
            _restore(sc, saved)
            continue
        if isinstance(stmt, ast.ClassDef):
            continue
        roots = _stmt_roots(stmt)
        shadow: dict[str, bool | None] = {}              # 컴프리헨션 변수는 그 식 안에서만 산다
        for root in roots:
            for n in ast.walk(root):
                if isinstance(n, ast.NamedExpr) and isinstance(n.target, ast.Name):
                    _bind(sc, {n.target.id}, n.value)
                elif isinstance(n, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
                    for gen in n.generators:
                        for name in _store_names(gen.target):
                            shadow.setdefault(name, sc.taint.get(name))
                        _bind(sc, _store_names(gen.target), gen.iter)
        for root in roots:
            for n in ast.walk(root):
                if not isinstance(n, ast.Call):
                    continue
                found = sc.sink(n)
                if found is not None:
                    rule_id, arg, is_address = found
                    keys = sc.destination(arg, slash_is_open=rule_id == RULE_REDIRECT) if is_address else sc.reach(arg)
                    if keys:
                        sc.sinks.append((rule_id, n, keys))
                    continue
                local = _local_callee(n, cx)
                if local is not None:
                    callee, params = local
                    for arg in _call_args(n):
                        param = _param_for(n, arg, params)
                        keys = sc.reach(arg) if param is not None else set()
                        if keys:
                            sc.calls.append((callee, param, keys, bool(sc.destination(arg))))
        if isinstance(stmt, ast.Return) and stmt.value is not None:
            keys = sc.reach(stmt.value)
            if keys:
                sc.returns.append((keys, bool(sc.destination(stmt.value))))
        # 대입 — 컴프리헨션 변수가 살아 있는 동안에 본다(`urls = [u.strip() for u in …]`)
        if isinstance(stmt, ast.Assign):
            _bind_targets(sc, stmt.targets, stmt.value)
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            _bind_targets(sc, [stmt.target], stmt.value)
        elif isinstance(stmt, ast.AugAssign):
            _bind(sc, _store_names(stmt.target), stmt.value, keep=True)
        elif isinstance(stmt, ast.Expr):
            call = _unwrap(stmt.value)
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name) \
                    and call.func.attr in _STORE_METHODS:
                for arg in _call_args(call):             # `names.append(v)`
                    if sc.reach(arg):
                        _bind(sc, {call.func.value.id}, arg, keep=True)
        for name, before in shadow.items():
            if before is None:
                sc.taint.pop(name, None)
            else:
                sc.taint[name] = before
        # 하위 블록
        if isinstance(stmt, ast.If):
            _branches(sc, [stmt.body, stmt.orelse], may_skip=False)
        elif isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
            start = _snapshot(sc)
            if not isinstance(stmt, ast.While):
                it = _unwrap(stmt.iter)
                if isinstance(it, ast.Call) and _call_name(it) == "enumerate" and it.args \
                        and isinstance(stmt.target, ast.Tuple) and len(stmt.target.elts) == 2:
                    _bind(sc, _store_names(stmt.target.elts[0]), ast.Constant(value=0))    # 번호는 요청 값이 아니다
                    _bind(sc, _store_names(stmt.target.elts[1]), it.args[0])
                else:
                    _bind(sc, _store_names(stmt.target), stmt.iter)
            _walk(sc, stmt.body)
            _merge(sc, [start, _snapshot(sc)])           # 한 번도 안 돌 수 있다
            _walk(sc, stmt.orelse)
        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            for item in stmt.items:
                if item.optional_vars is not None:
                    _bind(sc, _store_names(item.optional_vars), ast.Constant(value=None))
            _walk(sc, stmt.body)
        elif isinstance(stmt, ast.Try) or stmt.__class__.__name__ == "TryStar":
            start = _snapshot(sc)
            _walk(sc, [*stmt.body, *stmt.orelse])
            ends = [] if _terminates([*stmt.body, *stmt.orelse]) else [_snapshot(sc)]
            for handler in stmt.handlers:
                _restore(sc, start)
                _walk(sc, handler.body)
                if not _terminates(handler.body):
                    ends.append(_snapshot(sc))
            _merge(sc, ends or [start])
            _walk(sc, stmt.finalbody)
        elif isinstance(stmt, ast.Match):
            _branches(sc, [case.body for case in stmt.cases], may_skip=True)


def _aliases(sc: _Scope, fn: ast.AST, body: list[ast.stmt]) -> None:
    """한 번만 대입되는 이름이 요청 필드나 그 그릇을 그대로 가리키면 그 열쇠로 본다.

    `args = request.args`·`data = request.get_json() or {}`·`params = body.copy()`·`nxt = request.args.get("next")`·
    `for job in jobs` — 이름이 달라도 같은 값이다. 여러 번 대입되는 이름은 그때그때 따라간다.
    """
    counts: dict[str, int] = {}
    nodes = [n for s in body for n in ast.walk(s)]
    for n in nodes:
        if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
            counts[n.id] = counts.get(n.id, 0) + 1
        elif isinstance(n, ast.arg):
            counts[n.arg] = counts.get(n.arg, 0) + 2     # 안쪽 함수의 매개변수와 겹치는 이름은 별칭으로 삼지 않는다
    if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
        for p in _params(fn):
            counts[p] = counts.get(p, 0) + 1
    single = {name for name, count in counts.items() if count == 1}
    pairs: list[tuple[ast.Name, ast.AST, bool]] = []
    for n in sorted((n for n in nodes if isinstance(n, (ast.Assign, ast.For, ast.AsyncFor))),
                    key=lambda n: (n.lineno, n.col_offset)):
        target = n.targets[0] if isinstance(n, ast.Assign) and len(n.targets) == 1 else getattr(n, "target", None)
        value = n.value if isinstance(n, ast.Assign) else n.iter
        loop = not isinstance(n, ast.Assign)
        if isinstance(target, ast.Tuple) and isinstance(value, ast.Tuple) and len(target.elts) == len(value.elts) and not loop:
            pairs += [(a, b, False) for a, b in zip(target.elts, value.elts) if isinstance(a, ast.Name)]
        elif isinstance(target, ast.Name):
            pairs.append((target, value, loop))
    bound: dict[str, set[str | None]] = {}
    for target, value, loop in pairs:
        if target.id in single:
            continue
        key = sc.key_of(_unwrap(value), census=True)
        bound.setdefault(target.id, set()).add(key if key == REQ and not loop else None)
    for name, keys in bound.items():
        if keys == {REQ} and counts.get(name, 0) == len([1 for a, _, _ in pairs if a.id == name]):
            sc.alias[name] = REQ                         # 어느 분기로 와도 요청 그릇이다
    for target, value, loop in pairs:
        if target.id not in single:
            continue
        value = _unwrap(value)
        if isinstance(value, ast.BoolOp) and isinstance(value.op, ast.Or) and len(value.values) == 2 \
                and isinstance(value.values[1], (ast.Constant, ast.Dict, ast.List)):
            value = value.values[0]                      # `request.get_json() or {}`
        if isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute) and value.func.attr == "copy" and not value.args:
            value = value.func.value
        elif isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id == "dict" and len(value.args) == 1:
            value = value.args[0]
        key = sc.key_of(value, census=True)
        if key is None:
            continue
        root = _ROOT_RE.match(key).group(0)
        if root in {REQ, UPLOAD} or root in single and root not in sc.objects:
            sc.alias[target.id] = key + ("[*]" if loop else "")


def _used_groups(sc: _Scope, body: list[ast.stmt]) -> set[str]:
    """다른 데 쓰인 값들의 묶음 — 해롭지 않다고 아는 쓰임이 아니면 전부 센다."""
    cx = sc.cx
    used: set[str] = set()
    for stmt in body:
        for node in ast.walk(stmt):
            if not isinstance(node, ast.expr) or isinstance(cx.parents.get(node), (ast.expr, ast.keyword, ast.comprehension)):
                continue                                 # 문장에 바로 달린 식에서만 내려간다(겹쳐 세지 않게)
            for occ, key in sc.occurrences(node):
                root = _ROOT_RE.match(key).group(0)
                is_view = root in sc.views and root not in sc.ever and root not in sc.objects and root not in sc.alias
                if not _is_harmless_use(occ, sc, view=is_view, key=key):
                    used.add(sc.groups.find(key))
    return used


def _is_unused(sc: _Scope, keys: set[str], used: set[str], at: ast.AST | None = None) -> bool:
    """이 값들이(그릇을 포함해) 어디에도 쓰이지 않았는가 — 이 스코프와, 요청 필드라면 파일 전체에서.

    ``at``(위험한 자리)이 '값이 있으면 끝내는' 분기 밖이면 그 값은 비어 있다 — 쓰인 것으로 본다.
    """
    request_used = sc.cx.request_used
    find = sc.groups.find
    known = sc.seen | sc.ever | sc.views
    for key in keys:
        # 같은 묶음(이 값에서 나온 값·들여다본 결과·유래한 요청 필드)과, 그릇이라면 그 안의 필드까지 본다
        family = {key} | {k for k in known if find(k) == find(key)}
        family |= {k for k in known if any(a in family for a in _ancestors(k))}
        for member in family:
            for k in (member, *_ancestors(member)):
                if find(k) in used or k in request_used:
                    return False
                if k in sc.route_params and (f"{REQ}[{k!r}]" in request_used or REQ in request_used):
                    return False                         # 다른 함수(미들웨어·훅)가 같은 이름의 요청 필드를 들여다봤다
            if not sc.reportable and member.startswith((REQ, UPLOAD)):
                return False                             # 이 핸들러의 요청 본문은 데코레이터가 거른다(`@expects_json`)
            if sc.path_inspected and _ROOT_RE.match(member).group(0) in sc.route_params:
                return False                             # 핸들러가 요청 경로 전체를 조건에 썼다(`if ".." in request.path`)
        for other, inside in sc.only_inside:
            if find(other) == find(key) and (at is None or id(at) not in inside):
                return False
    return True


# ── 매개변수 ─────────────────────────────────────────────────────────────────

def _params(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    a = fn.args
    return [p.arg for p in (*a.posonlyargs, *a.args)] + [p.arg for p in a.kwonlyargs]


def _route_info(fn: ast.FunctionDef | ast.AsyncFunctionDef, cx: _Context) -> tuple[bool, set[str] | None, set[str], bool]:
    """(라우트 핸들러인가, 경로에 적힌 매개변수(Flask 식일 때만), 변환기가 값을 좁힌 것, 무엇을 하는지 모르는 데코레이터가 있는가)."""
    is_route = False
    path_params: set[str] | None = None
    typed: set[str] = set()
    opaque = False
    params = set(_params(fn))
    for dec in fn.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        d = _dotted(target) or ""
        last = d.rsplit(".", 1)[-1]
        if _ROUTE_DECORATOR_RE.search(d) and isinstance(dec, ast.Call):
            head = cx.resolve(d).split(".")[0]
            if head in _TEST_TOOLS or ("." not in d and head not in _WEB_FRAMEWORKS):
                continue                               # `@patch("pkg.fn")`·`@mock.patch(…)` 는 라우트가 아니다
            route = dec.args[0] if dec.args else next((kw.value for kw in dec.keywords if kw.arg in {"path", "rule"}), None)
            if isinstance(route, ast.Constant):
                if not (isinstance(route.value, str) and (route.value == "" or route.value.startswith("/"))):
                    continue
                text = route.value
            elif isinstance(route, (ast.BinOp, ast.JoinedStr, ast.Name, ast.Attribute)):
                text = None                            # `@app.get(API_V1 + "/fetch")` — 경로를 읽을 수 없다
            else:
                continue
            is_route = True
            if any(kw.arg == "dependencies" for kw in dec.keywords):
                opaque = True                          # `dependencies=[Depends(…)]` — 무엇을 거르는지 모른다
            if text is not None and (last == "route" or "<" in text):
                # Flask 식 — 경로에 적힌 이름만 요청 값이다. 그 밖의 매개변수는 데코레이터가 넣어 준 객체다.
                found: set[str] = set()
                for first, args, second in _ANGLE_PARAM_RE.findall(text):
                    # Flask 는 <변환기:이름>, bottle·sanic 은 <이름:변환기> — 함수 매개변수에 있는 쪽이 이름이다
                    name, conv = (second, first) if second in params or first not in params else (first, second)
                    found.add(name)
                    if conv not in _OPEN_CONVERTERS or args:
                        typed.add(name)
                found |= set(_BRACE_PARAM_RE.findall(text)) & params
                path_params = (path_params or set()) | found
            if text is not None and re.search(r"\{\w+:[^}]+\}", text):
                typed |= {m for m in re.findall(r"\{(\w+):(?!path\})[^}]+\}", text)}     # `{item_id:int}`·`{id:\d+}`
        elif not _NEUTRAL_DECORATOR_RE.search(last):
            opaque = True                              # `@validate_query(Schema)`·`@only_known_reports` — 무엇을 거르는지 모른다
    return is_route, path_params, typed, opaque


def _expand_annotation(note: str, cx: _Context) -> str:
    for _ in range(3):
        alias = cx.type_aliases.get(note)
        if alias is None:
            break
        note = alias
    return note


def _annotation_kind(note: str, cx: _Context) -> str:
    """``string``(이름 그대로 요청 값) · ``upload`` · 모델 이름 · ``inert``(그 밖 — 숫자·열거형·제약이 있는 형·모르는 클래스)."""
    core = _expand_annotation(note.strip(), cx)
    if not core:
        return "string"
    for _ in range(4):
        # 바깥부터 벗긴다 — `Optional[Slug]` → `Slug` → (별칭) `Annotated[str, StringConstraints(…)]`
        if _CONSTRAINT_RE.search(core):
            return "inert"
        inner = _WRAPPER_RE.sub("", core)
        if inner == core:
            break
        core = _expand_annotation(inner.split(",")[0].split("|")[0].strip().rstrip("]").strip(), cx)
    core = core.split("|")[0].strip()
    head = core.split("[")[0].split(".")[-1].strip()
    if head in cx.models:
        return head
    if _UPLOAD_ANNOTATION_RE.search(core):
        return "upload"
    return "string" if _STRING_ANNOTATION_RE.match(core) else "inert"


def _initial_taint(sc: _Scope, fn: ast.FunctionDef | ast.AsyncFunctionDef, *, probe: bool) -> bool:
    """이 함수가 시작할 때 요청 값인 매개변수를 놓는다. 돌려주는 값: 이 함수의 요청 본문을 봐도 되는가.

    ``probe`` 면 모든 매개변수를 요청 값으로 놓고 본다(함수 요약용).
    """
    cx = sc.cx
    a = fn.args
    positional = [*a.posonlyargs, *a.args]
    if probe:
        for p in _params(fn):
            if p not in {"self", "cls"}:
                sc.taint[p] = True
                sc.ever.add(p)
        return True
    defaults: dict[str, ast.AST] = {}
    for p, d in zip(reversed(positional), reversed(a.defaults)):
        defaults[p.arg] = d
    for p, d in zip(a.kwonlyargs, a.kw_defaults):
        if d is not None:
            defaults[p.arg] = d
    is_route, path_params, typed, opaque = _route_info(fn, cx)
    propagated, propagated_lead = cx.param_sources.get(fn.name, (set(), set())) \
        if fn.name in cx.funcs or fn.name in cx.methods else (set(), set())
    # 의존성이 같은 이름의 매개변수를 받으면 그쪽에서 걸렀을 수 있다 — `_: None = Depends(verify_name)`
    inspected: set[str] = set()
    for node in (*defaults.values(), *(p.annotation for p in (*positional, *a.kwonlyargs) if p.annotation is not None)):
        for n in ast.walk(node):
            if isinstance(n, ast.Call) and _call_name(n) in {"Depends", "Security"} and n.args:
                dep = _dotted(n.args[0]) or ""
                last = dep.rsplit(".", 1)[-1]
                if dep in cx.funcs:
                    inspected |= set(cx.funcs[dep])
                elif isinstance(n.args[0], ast.Call) or (_INSPECTING_DEPENDENCY_RE.search(last)
                                                         and not _AUTH_DEPENDENCY_RE.search(last)):
                    inspected |= set(_params(fn))        # `Depends(NameGuard(…))`·`Depends(load_document)` — 무엇을 거르는지 모른다
    hooked = id(fn) in cx.hooked_classes
    for p in (*positional, *a.kwonlyargs):
        if p.arg in propagated:
            sc.taint[p.arg] = p.arg in propagated_lead
            sc.ever.add(p.arg)
            continue
        if not is_route or opaque or hooked or p.arg in typed or p.arg in inspected or p.arg in cx.hook_checked \
                or p.arg in {"self", "cls"}:
            continue
        if path_params is not None and (p.arg not in path_params or cx.path_hook):
            continue
        note = ast.unparse(p.annotation) if p.annotation is not None else ""
        default = ast.unparse(defaults[p.arg]) if p.arg in defaults else ""
        if _CONSTRAINT_RE.search(default):
            continue
        kind = _annotation_kind(note, cx)
        if kind == "inert":
            continue
        if p.arg in _INERT_PARAM_NAMES and kind not in cx.models and (not note or _REQUEST_ANNOTATION_RE.search(note)):
            continue                                   # `def view(request)` — 요청 객체는 속성으로 읽는다
        if kind in cx.models:
            if "*" in cx.models[kind]:
                continue                               # 모델 전체를 보는 코드가 있다
            sc.objects[p.arg] = kind
        elif kind == "upload":
            sc.objects[p.arg] = None
        sc.taint[p.arg] = True
        sc.ever.add(p.arg)
        sc.route_params.add(p.arg)
    return not (opaque and is_route) and not hooked


def _http_clients(tree: ast.AST, cx: _Context, *, shallow: bool = False) -> set[str]:
    """HTTP 클라이언트 객체를 담은 이름 — `async with httpx.AsyncClient() as client`·`s = requests.Session()`."""
    out: set[str] = set()
    for n in (getattr(tree, "body", []) if shallow else ast.walk(tree)):
        pairs: list[tuple[ast.AST, ast.AST | None]] = []
        if isinstance(n, ast.Assign) and len(n.targets) == 1:
            pairs.append((n.value, n.targets[0]))
        elif isinstance(n, (ast.With, ast.AsyncWith)):
            pairs.extend((item.context_expr, item.optional_vars) for item in n.items)
        for value, target in pairs:
            value = _unwrap(value)
            if isinstance(value, ast.Call) and isinstance(target, ast.Name) \
                    and _HTTP_CLIENT_CTOR_RE.match(cx.resolve(_dotted(value.func))):
                out.add(target.id)
    return out


def _analyse(fn: ast.AST, cx: _Context, *, probe: bool = False) -> None:
    """가장 바깥 함수 하나(또는 모듈)를 보고 발견·요약·'파일에서 쓰인 요청 필드'를 적는다."""
    sc = _Scope(cx)
    is_function = isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))
    body = fn.body if is_function else [s for s in fn.body if not isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
    sc.clients = set(cx.module_clients)
    sc.requests = set(cx.request_imports)
    report = True
    if is_function:
        sc.clients |= _http_clients(fn, cx)
        for inner in ast.walk(fn):
            if not isinstance(inner, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            a = inner.args
            for p in (*a.posonlyargs, *a.args, *a.kwonlyargs):
                if p.annotation is not None and _HTTP_CLIENT_ANNOTATION_RE.search(cx.resolve(_dotted(p.annotation))):
                    sc.clients.add(p.arg)
                note = ast.unparse(p.annotation) if p.annotation is not None else ""
                if p.arg == "request" and (not note or _REQUEST_ANNOTATION_RE.search(note)):
                    sc.requests.add("request")         # `def view(request)` — 핸들러가 받은 요청 객체
                if p.arg == "req" and (_REQUEST_ANNOTATION_RE.search(note) or "falcon" in cx.frameworks):
                    sc.requests.add("req")
        stored = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
        sc.requests -= stored | cx.module_shadowed     # `req = requests.get(…)` 는 웹 요청이 아니다
        report = _initial_taint(sc, fn, probe=probe)
        sc.reportable = report
        sc.path_inspected = any(
            isinstance(x, ast.Attribute) and x.attr in {"path", "full_path", "url", "base_url"} and _dotted(x.value) in sc.requests
            for n in ast.walk(fn) if isinstance(n, (ast.If, ast.Assert, ast.IfExp)) for x in ast.walk(n.test))
    _aliases(sc, fn, body)
    _walk(sc, body)
    used = _used_groups(sc, body)
    for key in sc.seen:                                  # 이 함수가 들여다본 요청 필드는 파일 전체에 알린다
        if key.startswith((REQ, UPLOAD)) and sc.groups.find(key) in used:
            cx.request_used_next.add(key)
    if probe:
        params = _params(fn)
        find = sc.groups.find
        cx.summaries[fn.name] = (
            {p for p in params if find(p) in used},
            {p for p in params for keys, _ in sc.returns if any(find(k) == find(p) for k in keys)},
            {p for p in params for keys, leads in sc.returns if leads and any(find(k) == find(p) for k in keys)},
        )
        return
    for rule_id, call, keys in sc.sinks:
        if not _is_unused(sc, keys, used, call):
            continue
        line = cx.source_lines[call.lineno - 1] if 1 <= call.lineno <= len(cx.source_lines) else ""
        if not _is_ignored(line, rule_id):
            cx.hits.append((rule_id, call.lineno, redact_evidence(line), CONFIDENCE))
    for callee, param, keys, leads in sc.calls:
        if _is_unused(sc, keys, used):
            found, leading = cx.collected.setdefault(callee, (set(), set()))
            found.add(param)
            if leads:
                leading.add(param)


# ── 파일 전체에서 미리 알아 두는 것 ──────────────────────────────────────────

def _is_web_module(aliases: dict[str, str]) -> bool:
    return any(full.split(".")[0] in _WEB_FRAMEWORKS for full in aliases.values())


def _model_fields(cls: ast.ClassDef, cx: _Context) -> dict[str, str]:
    """모델 클래스의 필드 → 종류(``string`` 만 요청 값으로 따라간다). 모델 안에 값을 보는 코드가 있으면 ``*``.

    검증기든 `model_post_init` 이든, 메서드가 무엇을 거르는지는 모른다.
    """
    out: dict[str, str] = {}
    for n in cls.body:
        if isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name):
            default = ast.unparse(n.value) if n.value is not None else ""
            out[n.target.id] = "inert" if _CONSTRAINT_RE.search(default) else _annotation_kind(ast.unparse(n.annotation), cx)
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out["*"] = "inert"
    return out


def _full_aliases(tree: ast.AST, aliases: dict[str, str]) -> dict[str, str]:
    """`import urllib.request as ur` 는 `ur` → `urllib.request` — 기본 별칭 표는 최상위 이름만 남긴다."""
    out = dict(aliases)
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for alias in n.names:
                if alias.asname:
                    out[alias.asname] = alias.name
    return out


def _prepare(tree: ast.AST, cx: _Context) -> list[ast.AST]:
    """파일 전체에서 미리 알아 둘 것을 채우고, 분석할 가장 바깥 함수들을 돌려준다."""
    body = getattr(tree, "body", [])
    cx.parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    cx.frameworks = {full.split(".")[0] for full in cx.aliases.values()} & _WEB_FRAMEWORKS
    cx.request_imports = {name for name, full in cx.aliases.items()
                          if name in {"request", "req"} and full.split(".")[0] in _WEB_FRAMEWORKS}
    for n in body:                                       # 형 별칭 — `Slug = Annotated[str, …]`·`Name = constr(pattern=…)`
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) \
                and isinstance(n.value, (ast.Subscript, ast.Call)):
            cx.type_aliases[n.targets[0].id] = ast.unparse(n.value)
    classes = [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
    cx.enums = {c.name for c in classes if any((_dotted(b) or "").rsplit(".", 1)[-1].endswith("Enum") for b in c.bases)}
    models = [c for c in classes if c.name not in cx.enums and any(isinstance(n, ast.AnnAssign) for n in c.body)]
    cx.models = {c.name: {} for c in models}             # 이름부터 — 중첩·상속이 서로를 가리킨다
    for c in models:
        cx.models[c.name] = _model_fields(c, cx)
    for _ in range(2):                                   # 상속 — 부모의 필드도 내 필드다
        for c in models:
            for b in c.bases:
                parent = (_dotted(b) or "").rsplit(".", 1)[-1]
                if parent in cx.models and parent != c.name:
                    cx.models[c.name] = {**cx.models[parent], **cx.models[c.name]}
    for c in classes:                                    # 클래스 수준 훅·데코레이터 — 메서드가 받는 값이 무엇을 거쳤는지 모른다
        def opaque(node: ast.AST) -> bool:
            names = [(_dotted(x.func if isinstance(x, ast.Call) else x) or "?").rsplit(".", 1)[-1]
                     for x in (node.elts if isinstance(node, (ast.List, ast.Tuple)) else [node])]
            return any(not _NEUTRAL_DECORATOR_RE.search(name) for name in names)

        hooks = any(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name in _CLASS_HOOKS for n in c.body) \
            or any(isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id in _CLASS_HOOK_ATTRS for t in n.targets)
                   and opaque(n.value) for n in c.body) \
            or any(opaque(d) for d in c.decorator_list)
        if hooks:
            cx.hooked_classes |= {id(n) for n in c.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                                  and n.name not in _CLASS_HOOKS}
    method_ids = {id(n) for c in classes for n in c.body}
    outer: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
    seen: dict[str, list[ast.FunctionDef | ast.AsyncFunctionDef]] = {}
    for n in ast.walk(tree):
        if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        seen.setdefault(n.name, []).append(n)
        up = cx.parents.get(n)
        while up is not None and not isinstance(up, (ast.FunctionDef, ast.AsyncFunctionDef)):
            up = cx.parents.get(up)
        if up is None:
            outer.append(n)                              # 다른 함수 안에 들어 있지 않다
    # 이름이 겹치거나 import 한 이름과 같은 것은 뺀다(`save(x)` 가 어느 쪽인지 모른다)
    unique = {name: defs[0] for name, defs in seen.items() if len(defs) == 1 and name not in cx.aliases}
    cx.funcs = {name: _params(fn) for name, fn in unique.items() if id(fn) not in method_ids}
    cx.methods = {name: [p for p in _params(fn) if p not in {"self", "cls"}]
                  for name, fn in unique.items() if id(fn) in method_ids}
    cx.decorated = {name for name, fn in unique.items()
                    if any(not _NEUTRAL_DECORATOR_RE.search((_dotted(d.func if isinstance(d, ast.Call) else d) or "").rsplit(".", 1)[-1])
                           for d in fn.decorator_list)}
    cx.module_clients = _http_clients(tree, cx, shallow=True)
    cx.module_shadowed = {t.id for n in body if isinstance(n, ast.Assign) for t in n.targets
                          if isinstance(t, ast.Name) and t.id in {"request", "req"}}
    called_hooks = {n.args[0].id for n in ast.walk(tree)
                    if isinstance(n, ast.Call) and re.search(r"before_(?:app_)?request|add_middleware|url_value_preprocessor", _call_name(n))
                    and n.args and isinstance(n.args[0], ast.Name)}
    for n in ast.walk(tree):
        # 라우터·앱 수준 의존성(`APIRouter(dependencies=[Depends(verify_name)])`)과 요청 전 훅 — 검사가 다른 자리에 있다
        if isinstance(n, ast.Call) and not isinstance(cx.parents.get(n), (ast.FunctionDef, ast.AsyncFunctionDef)):
            for kw in n.keywords:
                if kw.arg == "dependencies":
                    for dep in ast.walk(kw.value):
                        if isinstance(dep, ast.Call) and _call_name(dep) in {"Depends", "Security"} and dep.args:
                            cx.hook_checked |= set(cx.funcs.get(_dotted(dep.args[0]) or "", ()))
        if isinstance(n, ast.Call) and re.search(r"before_(?:app_)?request|add_middleware|url_value_preprocessor", _call_name(n)) \
                and n.args and isinstance(n.args[0], ast.Name):
            called_hooks.add(n.args[0].id)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and (n.name in called_hooks or any(
                re.search(r"before_(?:app_)?request|middleware|url_value_preprocessor", _dotted(d.func if isinstance(d, ast.Call) else d) or "")
                for d in n.decorator_list)):
            if any(isinstance(x, ast.Attribute) and x.attr in {"view_args", "path_params", "match_info", "path", "full_path", "url"}
                   for x in ast.walk(n)) \
                    or any(p not in {"request", "call_next", "endpoint", "values"} for p in _params(n)):
                cx.path_hook = True
    for _ in range(3):                                   # 함수가 함수를 부르는 두 겹까지
        before = {k: (set(a), set(b), set(c)) for k, (a, b, c) in cx.summaries.items()}
        for fn in unique.values():
            _analyse(fn, cx, probe=True)
        if cx.summaries == before:
            break
    return [tree, *outer]


def scan_web_flows(tree: ast.AST, source_lines: list[str], aliases: dict[str, str], *,
                   strict: bool = False) -> list[tuple[str, int, str, str]]:
    """``(rule_id, line_no, evidence, confidence)`` — 웹 프레임워크를 쓰는 파일에서만.

    이 분석이 실패하거나 일의 양 한도를 넘어도 같은 파일의 다른 분석(SQL 삽입 등)은 계속돼야 하므로 빈 결과를
    돌려준다(일부만 본 결과는 내지 않는다). ``strict`` 는 시험용 — 실패를 그대로 드러낸다.
    """
    if not _is_web_module(aliases):
        return []
    try:
        cx = _Context(source_lines, _full_aliases(tree, aliases))
        scopes = _prepare(tree, cx)
        for _ in range(4):                      # f → g → h 두 홉까지 + 파일 전체에서 쓰인 요청 필드가 자리 잡을 때까지
            cx.collected = {}
            cx.hits = []
            cx.request_used_next = set()
            for scope in scopes:
                _analyse(scope, cx)
            merged = {k: (set(a), set(b)) for k, (a, b) in cx.param_sources.items()}
            for name, (found, leading) in cx.collected.items():
                mine = merged.setdefault(name, (set(), set()))
                mine[0].update(found)
                mine[1].update(leading)
            stable = merged == cx.param_sources and cx.request_used_next <= cx.request_used
            cx.param_sources = merged
            cx.request_used |= cx.request_used_next
            if stable:
                break
    except (RecursionError, _OutOfBudget):
        if strict:
            raise
        return []
    except Exception:                           # noqa: BLE001 — 격리가 목적이다(위 설명)
        if strict:
            raise
        return []
    return sorted(set(cx.hits), key=lambda h: (h[1], h[0]))
