"""보안 자세 관찰(정보) — "있어야 할 것이 없는" 부재형 항목.

룰은 코드에 **있는** 모양을 잡는다. CSP·X-Frame-Options·쿠키 보호 속성처럼 **없어서**
생기는 위험은 줄 단위 패턴으로는 보이지 않는다(개선요청 #34 D4·E — 포털 자체 점검에서
사람이 찾은 실제 결함). 이 모듈은 프로젝트 단위로 "웹 서버 진입점은 있는데 보안 헤더
설정 흔적이 없다"를 **정보 항목**으로 낸다.

판정(block/warn)에 넣지 않는다 — 리버스 프록시·WAF·플랫폼이 헤더를 붙이는 배치가
흔해 소스만으로 단정할 수 없다. 그래서 finding 이 아니라 ``ScanReport.posture_notes`` 다.

증거의 범위는 **같은 프로젝트 루트**(진입점에서 가장 가까운 매니페스트 디렉터리)다.
포털 실측(2026-08-30): 저장소가 동봉한 골든 템플릿(`shared/golden-templates/*`)이 헤더를
설정해 정작 앱 `src/server.js` 의 공백이 가려졌다. `nosniff`(X-Content-Type-Options)만으로는
CSP·프레임 보호가 아니므로 증거로 치지 않는다.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# 웹 서버 진입점 — 운영 코드 경로에서만 인정한다(픽스처·테스트의 서버는 진입점이 아니다).
_ENTRY_RE = re.compile(
    r"\bexpress\s*\(\s*\)|\bnew\s+Koa\s*\(|\bfastify\s*\(|\bhttp2?\.createServer\s*\(|\bcreateServer\s*\("
    r"|\bFlask\s*\(\s*__name__|\bFastAPI\s*\(|\bMIDDLEWARE\s*=\s*\[|\bapp\s*=\s*Sanic\s*\(",
)
# CSP·프레임 보호·보안 헤더 미들웨어의 흔적. HSTS·nosniff 는 여기 넣지 않는다 —
# 클릭재킹·인젝션 확대와 무관한 헤더가 "설정돼 있다"로 읽히면 안 된다.
_HEADER_RE = re.compile(
    r"helmet|Content-Security-Policy|contentSecurityPolicy|X-Frame-Options|X_FRAME_OPTIONS|frame-ancestors"
    r"|SecurityMiddleware|Talisman|secure_headers|SecureHeaders|CSP_DEFAULT_SRC|add_header\s+X-Frame",
    re.IGNORECASE,
)
_COOKIE_USE_RE = re.compile(
    r"res\.cookie\s*\(|set_cookie\s*\(|cookie-session|express-session|cookie-parser|SESSION_COOKIE|session\s*\(\s*\{",
)
_COOKIE_GUARD_RE = re.compile(
    r"httpOnly|HttpOnly|httponly\s*=\s*True|sameSite|samesite\s*=|SESSION_COOKIE_SECURE|SESSION_COOKIE_HTTPONLY"
    r"|SESSION_COOKIE_SAMESITE|secure\s*:\s*true|secure\s*=\s*True",
)
_PROXY_HINT_RE = re.compile(r"nginx|apache|httpd|caddy|traefik|cloudfront|X-Forwarded-For", re.IGNORECASE)
# 문서·산문·목록은 증거가 아니다 — 설계 문서가 "CSP 를 넣을 것"이라 적어 둔 것, 승인 패키지
# 목록(approved-packages.yaml)에 helmet 이 적힌 것은 설정이 아니다(포털 실측 2026-08-30).
# 증거는 코드·설정 파일에서만 본다. package.json 의 의존성도 "쓴다"는 뜻이 아니라 뺀다.
_DOC_SUFFIXES = (".md", ".txt", ".rst", ".adoc", ".yaml", ".yml", ".json", ".lock", ".csv")

MANIFEST_NAMES = {"package.json", "pyproject.toml", "requirements.txt", "manage.py", "setup.py", "setup.cfg", "go.mod"}


def _norm(p: str) -> str:
    return p.replace("\\", "/").strip("/")


def _dirname(p: str) -> str:
    n = _norm(p)
    return n.rsplit("/", 1)[0] if "/" in n else ""


@dataclass
class PostureCollector:
    entry_files: list[str] = field(default_factory=list)
    header_evidence: list[str] = field(default_factory=list)
    cookie_use_files: list[str] = field(default_factory=list)
    cookie_guard_evidence: list[str] = field(default_factory=list)
    proxy_hint: bool = False
    manifest_dirs: set[str] = field(default_factory=set)

    def observe(self, rel_path: str, text: str, *, runtime: bool) -> None:
        rel = _norm(rel_path)
        name = rel.rsplit("/", 1)[-1].lower()
        if name in MANIFEST_NAMES:
            self.manifest_dirs.add(_dirname(rel))
        if rel.lower().endswith(_DOC_SUFFIXES):
            return
        if runtime and _ENTRY_RE.search(text):
            self.entry_files.append(rel)
        if _HEADER_RE.search(text):
            self.header_evidence.append(rel)
        if runtime and _COOKIE_USE_RE.search(text):
            self.cookie_use_files.append(rel)
        if _COOKIE_GUARD_RE.search(text):
            self.cookie_guard_evidence.append(rel)
        if not self.proxy_hint and _PROXY_HINT_RE.search(text):
            self.proxy_hint = True

    def register_paths(self, paths: list[str]) -> None:
        """검사되지 않은 파일(requirements.txt 등)도 매니페스트 위치로는 쓴다."""
        for p in paths:
            rel = _norm(p)
            if rel.rsplit("/", 1)[-1].lower() in MANIFEST_NAMES:
                self.manifest_dirs.add(_dirname(rel))

    def _root_of(self, rel: str) -> str:
        """가장 가까운(가장 긴) 매니페스트 디렉터리. 없으면 저장소 루트("")."""
        d = _dirname(rel)
        best = ""
        for m in self.manifest_dirs:
            if (d == m or d.startswith(m + "/") or m == "") and len(m) >= len(best):
                best = m
        return best

    def notes(self) -> list[dict]:
        """관찰 목록. 진입점이 없으면 아무것도 말하지 않는다(웹 서버가 아니다)."""
        if not self.entry_files:
            return []
        caveat = (
            " 리버스 프록시·플랫폼이 헤더를 붙이는 배치라면 그 설정을 근거로 남기세요."
            + (" (프록시 설정 흔적이 보입니다 — 거기서 붙이는지 확인)" if self.proxy_hint else "")
        )
        header_roots = {self._root_of(p) for p in self.header_evidence}
        guard_roots = {self._root_of(p) for p in self.cookie_guard_evidence}
        by_root: dict[str, list[str]] = {}
        for e in self.entry_files:
            by_root.setdefault(self._root_of(e), []).append(e)
        cookie_by_root: dict[str, list[str]] = {}
        for c in self.cookie_use_files:
            cookie_by_root.setdefault(self._root_of(c), []).append(c)

        out: list[dict] = []
        for root, entries in sorted(by_root.items()):
            label = root or "(저장소 루트)"
            if root not in header_roots:
                out.append({
                    "id": "POSTURE-HEADERS-001",
                    "level": "info",
                    "project": label,
                    "title": "보안 응답 헤더 설정 흔적 없음 (CSP · X-Frame-Options)",
                    "detail": (
                        f"프로젝트 `{label}` 에 웹 서버 진입점은 있는데 Content-Security-Policy·"
                        "X-Frame-Options(frame-ancestors)·보안 헤더 미들웨어(helmet·Talisman·SecurityMiddleware)"
                        "를 설정하는 코드가 그 프로젝트 안에 보이지 않습니다. 클릭재킹·인젝션 피해 확대·"
                        "토큰 탈취를 넓히는 부재형 약점입니다." + caveat
                    ),
                    "files": entries[:10],
                    "safe_fix": (
                        "Node: `app.use(helmet())` (CSP 는 정책을 명시) · Django: SecurityMiddleware + "
                        "`X_FRAME_OPTIONS = 'DENY'` · Flask: flask-talisman · FastAPI: secure 미들웨어. "
                        "최소한 `X-Frame-Options: DENY` 와 `frame-ancestors 'none'`."
                    ),
                    "references": ["OWASP Secure Headers Project", "CWE-1021 Improper Restriction of Rendered UI Layers"],
                })
            cookies = cookie_by_root.get(root) or []
            if cookies and root not in guard_roots:
                out.append({
                    "id": "POSTURE-COOKIE-001",
                    "level": "info",
                    "project": label,
                    "title": "쿠키 보호 속성 흔적 없음 (HttpOnly · Secure · SameSite)",
                    "detail": (
                        f"프로젝트 `{label}` 에 세션·쿠키를 쓰는 코드는 있는데 HttpOnly·Secure·SameSite 를 "
                        "지정하는 곳이 보이지 않습니다. XSS 한 건이 세션 탈취로, 링크 한 번이 CSRF 로 "
                        "이어집니다." + caveat
                    ),
                    "files": cookies[:10],
                    "safe_fix": (
                        "Express: `res.cookie(name, v, { httpOnly: true, secure: true, sameSite: 'lax' })` · "
                        "Django: `SESSION_COOKIE_SECURE/HTTPONLY/SAMESITE` · Flask: `SESSION_COOKIE_*` 설정."
                    ),
                    "references": ["OWASP Session Management Cheat Sheet", "CWE-1004 · CWE-614"],
                })
        return out
