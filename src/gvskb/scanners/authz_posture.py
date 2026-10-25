"""인가 자세(authz-posture, 42차 · P0-03) — 관리자 경로에 **서버측 보호 근거가 없다**를 관찰한다.

실측(2026-10-15 챗봇 비교): 관리자 API 블루프린트의 조회·발급·삭제 라우트에 인증·역할 검사가 없었고,
화면은 공개 번들에 들어가는 PIN 과 sessionStorage 로만 관문을 세웠다. 체커도 비교 도구도 주요 항목으로
올리지 못했다 — 줄 단위 룰은 "있는 것"만 잡고, 이것은 "없는 것"이기 때문이다.

이 엔진은 프로젝트 단위로 두 가지를 본다.
1. 관리자·민감 경로(`/admin`·`/manage`·`/internal`·설정·사용자 삭제/역할 변경)의 라우트 핸들러에
   **거부 분기가 있는 검사**(데코레이터·미들웨어·본문의 401/403·전역 before_request/use/middleware)가 없음.
2. 공개 번들에 들어가는 환경변수(`NEXT_PUBLIC_*`·`VITE_*` 등)에 PIN·비밀·토큰 이름이 쓰이거나,
   관리자 화면이 sessionStorage/localStorage 값만으로 관문을 세움.

판정은 **경고**(likely 이하)다 — 외부 SSO·리버스 프록시·WAF 가 보호하는 배치는 제출물로 알 수 없으므로
"보호 근거 없음(미확인)"이라고 적지 "침해"라고 적지 않는다. 전역 보호(거부 분기가 있는 before_request·
`app.use(인증)`·Next.js middleware·FastAPI dependencies)가 프로젝트 어디든 있으면 라우트 발견을 내지 않는다.
"""
from __future__ import annotations

import re
from pathlib import Path

from ..schema import Finding
from .ecosystem_surface import _HARD_EXCLUDE, _JS, _PY, EcoEntry, EcoResult, PolicyFn, _read, _rel, _walk
from .regex_scanner import build_finding, lookup_rule, redact_evidence

ENGINE = "authz-posture"
CATEGORY = "access-control"
RULE_ADMIN = "GOV-AUTHZ-ADMIN-POSTURE-001"
RULE_CLIENT_GATE = "GOV-AUTHZ-CLIENT-GATE-001"
RULE_IDS = (RULE_ADMIN, RULE_CLIENT_GATE)

_MAX_PER_FILE = 6
#: 라우트 등록은 데이터 번들·압축 번들에 없다 — 큰 파일은 읽지 않는다(실측: 2.8MB catalog.js).
_MAX_SRC = 512_000

# 관리자·민감 경로. 사용자 자원의 삭제·역할·활성 토글도 포함한다.
_ADMIN_PATH = re.compile(
    r"/(?:admin|administrator|manage(?:ment|r)?|internal|backoffice|console|superuser|staff)(?:/|$|['\"`])"
    r"|/(?:users?|members?|accounts?)/[^'\"`\s]*(?:delete|remove|ban|role|toggle|activate|reset)",
    re.IGNORECASE,
)
# 설정·역할·권한 경로는 **쓰기 메서드일 때만** 민감 경로로 본다 — `GET /api/config` 는 공개 설정 응답이 흔하다(실측).
_SENSITIVE_WRITE_PATH = re.compile(r"/(?:settings?|config(?:uration)?|roles?|permissions?)(?:/|$|['\"`])", re.IGNORECASE)
_ADMIN_NAME = re.compile(r"(?:^|_)admin|Admin[A-Z_]|_staff|superuser", re.IGNORECASE)

# 거부 분기가 있는 검사의 흔적(핸들러 본문·전역 훅 본문). "검사"는 거부가 있어야 성립한다 — 토큰을 배정만
# 하는 before_request 는 보호가 아니다(실측).
_DENY = re.compile(
    r"abort\(\s*40[13]|status(?:_code)?\s*[=(]\s*40[13]|\b40[13]\b[^\n]{0,40}(?:Unauthorized|Forbidden|unauth|forbidden|denied)"
    r"|(?:Unauthorized|Forbidden|PermissionDenied|HTTPException|AuthenticationError)\s*\("
    r"|res\.(?:status|sendStatus)\(\s*40[13]|\.status\(40[13]\)|NextResponse\.(?:redirect|json\([^)]*40[13])"
    r"|redirect\([^)]*(?:login|signin|auth)|raise\s+\w*(?:Auth|Perm|Forbid)\w*"
    # 프로젝트 자체 보조 함수 `require(cond, msg, 'FORBIDDEN', 403)` 류(실측).
    r"|\brequire\w*\([^\n]*\b40[13]\b|['\"](?:FORBIDDEN|UNAUTHORIZED)['\"]",
    re.IGNORECASE,
)
_CHECK = re.compile(
    r"session(?:\[|\.get\()|current_user|request\.user|\bg\.user|is_admin|is_staff|is_superuser|\brole|permission"
    r"|verify_token|decode_token|get_jwt|jwt\.verify|req\.(?:user|session|auth)|getServerSession|currentUser\(\)|auth\(\)"
    r"|headers?\(\)\.get\(\s*['\"]authorization|Authorization",
    re.IGNORECASE,
)
# 데코레이터·미들웨어 이름 — 인증·인가를 뜻하는 것만. csrf_exempt 같은 '면제'는 보호가 아니다.
_GUARD_NAME = re.compile(
    r"login_required|permission_required|roles?_required|admin_required|staff_member_required|superuser_required"
    r"|user_passes_test|jwt_required|requires?_(?:auth|login|role|permission|admin)|auth_required|authenticated"
    r"|authorize|authenticate|protect(?:ed)?|ensure(?:Auth|Logged|Admin)|is_?admin|require(?:Auth|Admin|Login|User|Role)"
    r"|passport\.|verify(?:Token|Jwt|Session)|checkAuth|withAuth|guard|Depends\(",
    re.IGNORECASE,
)

# 파이썬 라우트 데코레이터 / 전역 훅
_PY_ROUTE = re.compile(
    r"^\s*@(?P<obj>[\w.]+)\.(?P<verb>route|get|post|put|patch|delete|api_route)\(\s*['\"](?P<path>[^'\"]+)['\"](?P<rest>[^\n]*)",
)
_PY_METHODS = re.compile(r"methods\s*=\s*[\[(]([^\])]*)[\])]")
# FastAPI 의존성 주입 — 시그니처의 Depends( 또는 Annotated 별칭 타입(AdminUser·CurrentUser 등, 실측 trusted-registry).
_PY_SIG_GUARD = re.compile(r"Depends\(|:\s*(?:Annotated\[[^\]]*Depends|\w*(?:Admin|Current|Auth|Principal|Staff)\w*)\b")
_PY_GLOBAL_HOOK = re.compile(r"^\s*@[\w.]+\.(?:before_request|before_app_request)\b|dependencies\s*=\s*\[\s*Depends\(|MIDDLEWARE\s*=", re.M)
_PY_MIDDLEWARE_AUTH = re.compile(r"MIDDLEWARE\s*=\s*\[[^\]]*(?:Authentication|LoginRequired|auth)", re.I | re.S)

# JS 라우트 등록 / 전역 미들웨어 / Next.js. 라우트 "등록"은 서버 프레임워크를 쓰는 파일에서만 — 프런트의
# `api.delete('/admin/…')` 는 HTTP 호출이지 라우트가 아니다(실측 trusted-registry frontend).
_JS_SERVER_MARK = re.compile(
    r"require\(\s*['\"](?:express|koa|@koa/router|koa-router|fastify|hono|@hapi/hapi|restify|polka)['\"]\s*\)"
    r"|from\s+['\"](?:express|koa|@koa/router|koa-router|fastify|hono|@hapi/hapi|restify|polka)['\"]"
    r"|\bexpress\(\)|\bRouter\(\)|new\s+(?:Koa|Hono|Router)\(|\bfastify\(",
)
_JS_ROUTE = re.compile(
    r"^\s*(?P<obj>\w+)\.(?P<verb>get|post|put|patch|delete|all)\(\s*['\"`](?P<path>[^'\"`]+)['\"`]\s*,(?P<rest>[^\n]*)", re.M,
)
_JS_GLOBAL_USE = re.compile(r"\b(?:app|router|server)\.use\(\s*(?:['\"`][^'\"`]*['\"`]\s*,\s*)?(?P<mw>[^\n;]{1,120})")
_NEXT_EXPORT = re.compile(r"^export\s+(?:async\s+)?function\s+(?P<verb>GET|POST|PUT|PATCH|DELETE)\b"
                          r"|^export\s+(?:const|let)\s+(?P<verb2>GET|POST|PUT|PATCH|DELETE)\s*=", re.M)
_NEXT_MIDDLEWARE = re.compile(r"middleware\.(?:ts|js|mjs)$")

# 공개 번들 비밀 · 클라이언트 전용 관문
_PUBLIC_ENV_SECRET = re.compile(
    r"(?:process\.env|import\.meta\.env)\.(?P<name>(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|PUBLIC|NUXT_PUBLIC|GATSBY)_\w*"
    r"(?:PIN|PASS(?:WORD|WD|CODE)?|SECRET|TOKEN|API_?KEY|ADMIN_?(?:KEY|CODE|PW))\w*)",
)
_STORAGE_GATE = re.compile(
    r"(?:sessionStorage|localStorage)\.getItem\(\s*(?P<key>[\w.]+|['\"][^'\"]*(?:admin|auth|login|role|token)[^'\"]*['\"])\s*\)"
    r"\s*(?:===?|!==?)\s*['\"](?:true|1|ok|yes)['\"]",
    re.IGNORECASE,
)


def _methods_py(verb: str, rest: str) -> set[str]:
    if verb != "route" and verb != "api_route":
        return {verb.upper()}
    m = _PY_METHODS.search(rest)
    if not m:
        return {"GET"}
    return {x.strip().strip("'\"").upper() for x in m.group(1).split(",") if x.strip()}


def _body_lines(lines: list[str], start: int, indent: int, limit: int = 60) -> str:
    """start 다음 줄부터 같은(또는 얕은) 들여쓰기의 새 정의가 나올 때까지."""
    out: list[str] = []
    for ln in lines[start + 1: start + 1 + limit]:
        stripped = ln.lstrip()
        if stripped and (len(ln) - len(stripped)) <= indent and re.match(r"(?:@|def |async def |class |\}|export |app\.|router\.)", stripped):
            break
        out.append(ln)
    return "\n".join(out)


def _has_global_guard_py(text: str) -> bool:
    if _PY_MIDDLEWARE_AUTH.search(text) or re.search(r"include_router\([^)]*dependencies\s*=\s*\[\s*Depends\(", text):
        return True
    lines = text.splitlines()
    for i, ln in enumerate(lines):
        if re.match(r"^\s*@[\w.]+\.(?:before_request|before_app_request)\b", ln):
            body = _body_lines(lines, i + 1, len(ln) - len(ln.lstrip()))
            if _DENY.search(body) and _CHECK.search(body):
                return True
        if re.search(r"(?:APIRouter|FastAPI)\([^)]*dependencies\s*=\s*\[\s*Depends\(", ln):
            return True
    return False


def _has_global_guard_js(text: str, rel: str) -> bool:
    if _NEXT_MIDDLEWARE.search(rel) and (_CHECK.search(text) or _GUARD_NAME.search(text)) and _DENY.search(text):
        return True
    for m in _JS_GLOBAL_USE.finditer(text):
        mw = m.group("mw")
        if _GUARD_NAME.search(mw) and not re.search(r"\bstatic\b|json\(|urlencoded\(|cors\(|helmet\(|morgan\(", mw):
            return True
    return False


def judge_py_routes(text: str, rel: str, *, global_guard: bool) -> list[Finding]:
    out: list[Finding] = []
    lines = text.splitlines()
    for i, ln in enumerate(lines):
        m = _PY_ROUTE.match(ln)
        if not m:
            continue
        path = m.group("path")
        methods = _methods_py(m.group("verb"), m.group("rest"))
        # def 줄과 데코레이터 묶음(위·아래) 찾기
        j = i + 1
        while j < len(lines) and lines[j].lstrip().startswith("@"):
            j += 1
        if j >= len(lines) or not re.match(r"\s*(?:async\s+)?def\s+\w+", lines[j]):
            continue
        name = re.match(r"\s*(?:async\s+)?def\s+(\w+)", lines[j]).group(1)
        k = i - 1
        while k >= 0 and lines[k].lstrip().startswith("@"):
            k -= 1
        decorators = "\n".join(lines[k + 1: j + 1])
        mutating = bool(methods & {"POST", "PUT", "PATCH", "DELETE"})
        if not (_ADMIN_PATH.search(path) or _ADMIN_NAME.search(name) or (mutating and _SENSITIVE_WRITE_PATH.search(path))):
            continue
        if global_guard or _GUARD_NAME.search(decorators):
            continue
        sig_end = j
        while sig_end < len(lines) - 1 and not re.search(r"\)\s*(?:->[^:]*)?:\s*(?:#.*)?$", lines[sig_end]) and sig_end - j < 12:
            sig_end += 1
        if _PY_SIG_GUARD.search(chr(10).join(lines[j: sig_end + 1])):
            continue
        body = _body_lines(lines, j, len(lines[j]) - len(lines[j].lstrip()))
        if _DENY.search(body) and _CHECK.search(body):
            continue
        conf = "likely" if mutating else "pattern-only"
        ev = (f"관리자·민감 경로 {'/'.join(sorted(methods))} {path} ({name}) — 핸들러 데코레이터·본문·전역 훅에 "
              f"거부 분기가 있는 인증·역할 검사 근거 없음(외부 SSO·프록시 보호는 제출물로 확인 불가)")
        f = _emit(RULE_ADMIN, rel=rel, line=i + 1, evidence=ev, confidence=conf)
        if f:
            out.append(f)
        if len(out) >= _MAX_PER_FILE:
            break
    return out


def judge_js_routes(text: str, rel: str, *, global_guard: bool) -> list[Finding]:
    out: list[Finding] = []
    lines = text.splitlines()
    for m in (_JS_ROUTE.finditer(text) if _JS_SERVER_MARK.search(text) else ()):
        path, rest = m.group("path"), m.group("rest")
        mutating = m.group("verb").upper() in ("POST", "PUT", "PATCH", "DELETE", "ALL")
        if not (_ADMIN_PATH.search(path) or (mutating and _SENSITIVE_WRITE_PATH.search(path))):
            continue
        if global_guard or _GUARD_NAME.search(rest):
            continue
        ln = text.count("\n", 0, m.start())
        body = "\n".join(lines[ln: ln + 30])
        if _DENY.search(body) and _CHECK.search(body):
            continue
        ev = (f"관리자·민감 경로 {m.group('verb').upper()} {path} — 미들웨어·본문·전역 use/middleware 에 "
              f"거부 분기가 있는 인증·역할 검사 근거 없음(외부 SSO·프록시 보호는 제출물로 확인 불가)")
        f = _emit(RULE_ADMIN, rel=rel, line=ln + 1, evidence=ev, confidence="likely" if mutating else "pattern-only")
        if f:
            out.append(f)
        if len(out) >= _MAX_PER_FILE:
            break
    # Next.js App Router: app/**/admin/**/route.ts 의 export GET/POST
    if re.search(r"(?:^|/)app/.*admin.*/route\.(?:ts|js|mjs)$", rel, re.I) and not global_guard:
        for m in _NEXT_EXPORT.finditer(text):
            verb = m.group("verb") or m.group("verb2")
            ln = text.count("\n", 0, m.start())
            body = "\n".join(lines[ln: ln + 40])
            if _GUARD_NAME.search(body) or (_DENY.search(body) and _CHECK.search(body)):
                continue
            f = _emit(RULE_ADMIN, rel=rel, line=ln + 1,
                      evidence=f"관리자 경로 라우트 핸들러 {verb} ({rel}) — 세션·토큰 검사와 거부 분기 없음, middleware 도 없음",
                      confidence="likely" if verb != "GET" else "pattern-only")
            if f:
                out.append(f)
    return out


def judge_client_gate(text: str, rel: str) -> list[Finding]:
    out: list[Finding] = []
    m = _PUBLIC_ENV_SECRET.search(text)
    if m:
        f = _emit(RULE_CLIENT_GATE, rel=rel, line=text.count("\n", 0, m.start()) + 1,
                  evidence=f"공개 번들에 포함되는 환경변수 `{m.group('name')}` 에 비밀·PIN 이름 — 브라우저에서 읽히므로 접근 통제가 아님",
                  confidence="likely")
        if f:
            out.append(f)
    g = _STORAGE_GATE.search(text)
    if g and ("admin" in rel.lower() or re.search(r"admin", g.group(0), re.I)):
        f = _emit(RULE_CLIENT_GATE, rel=rel, line=text.count("\n", 0, g.start()) + 1,
                  evidence="관리자 화면 관문이 sessionStorage/localStorage 값 비교뿐 — 서버 API 의 검사와 별개로 우회 가능",
                  confidence="pattern-only")
        if f:
            out.append(f)
    return out


def _emit(rule_id: str, *, rel: str, line: int, evidence: str, confidence: str) -> Finding | None:
    rule = lookup_rule(rule_id)
    if rule is None:
        return None
    return build_finding(rule, filename=rel, line_no=max(1, line), evidence=redact_evidence(evidence)[:240],
                         engine=ENGINE, confidence=confidence)


def collect_authz_posture(root: Path, *, policy: PolicyFn) -> EcoResult:
    res = EcoResult()
    root = Path(root)
    if not root.is_dir():
        return res
    files: list[tuple[Path, str, str]] = []
    for p in _walk(root):
        suf = p.suffix.lower()
        if suf not in _JS and suf not in _PY:
            continue
        rel = _rel(p, root)
        if any(seg in _HARD_EXCLUDE for seg in rel.split("/")):
            continue
        try:
            if p.stat().st_size > _MAX_SRC:
                continue
        except OSError:
            continue
        text = _read(p)
        if text is None:
            continue
        files.append((p, rel, text))

    # 1차: 전역 보호 근거(프로젝트 어디든)
    global_py = any(suf == ".py" and _has_global_guard_py(t) for _, rel, t in files for suf in [Path(rel).suffix.lower()])
    global_js = any(Path(rel).suffix.lower() in _JS and _has_global_guard_js(t, rel) for _, rel, t in files)

    # 2차: 라우트·클라이언트 관문
    for p, rel, text in files:
        suf = Path(rel).suffix.lower()
        findings: list[Finding] = []
        kind = None
        if suf in _PY and ("route(" in text or "api_route(" in text or re.search(r"@\w+\.(?:get|post|put|patch|delete)\(", text)):
            findings += judge_py_routes(text, rel, global_guard=global_py)
            kind = "authz-route"
        elif suf in _JS:
            if _JS_ROUTE.search(text) or re.search(r"/route\.(?:ts|js|mjs)$", rel):
                findings += judge_js_routes(text, rel, global_guard=global_js)
                kind = "authz-route"
            cg = judge_client_gate(text, rel)
            if cg:
                findings += cg
                kind = kind or "client-gate"
        if not findings and kind != "authz-route":
            continue
        if kind == "authz-route" and not findings and not (_ADMIN_PATH.search(text)):
            continue
        findings = policy(findings, rel)
        res.findings.extend(findings)
        res.entries.append(EcoEntry(path=rel, kind=kind or "client-gate", finding_count=len(findings),
                                    note="전역 보호 근거 있음" if (global_py if suf in _PY else global_js) else ""))
    return res
