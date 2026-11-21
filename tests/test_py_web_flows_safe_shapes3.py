"""독립 적대적 검증 3차(2026-11-21)가 만든 안전한 코드 — 셋째 판은 이 가운데 16개를 '확인된 취약점'으로 냈다.

금지 토큰 루프, `BASE not in target.parents`, 기본값으로 떨어지는 도우미 같은 흔한 코드였다.
"""
from __future__ import annotations

import ast
import textwrap

import pytest

from gvskb.scanner import scan_code
from gvskb.scanners.ast_scanner import _collect_import_aliases
from gvskb.scanners.py_web_flows import scan_web_flows

SHORT = {"KISA-PY-INPUT-12": "SSRF", "KISA-PY-INPUT-04": "TPL", "KISA-PY-INPUT-03": "PATH", "KISA-PY-INPUT-07": "REDIR"}
N = chr(10)
FL = N.join(["from flask import Flask, request, redirect, send_file, render_template_string, abort, url_for, jsonify",
             "import os, re, requests", "app = Flask(__name__)", ""])
FA = N.join(["import os, re, httpx", "from fastapi import FastAPI, Depends, Query, HTTPException, UploadFile",
             "from fastapi.responses import FileResponse, RedirectResponse", "app = FastAPI()", ""])
DJ = N.join(["import os, requests", "from django.http import HttpResponse, HttpResponseRedirect, FileResponse, Http404",
             "from django.shortcuts import redirect, get_object_or_404", ""])
NONE = ""
AIO = 'import os, re, aiohttp\nfrom aiohttp import web\n'
BOTTLE = 'import os\nfrom bottle import route, request, redirect, post\n'
DJJ = 'import json\nimport os, requests\nfrom django.http import HttpResponse, HttpResponseRedirect, FileResponse, Http404\nfrom django.shortcuts import redirect, get_object_or_404\n'
DRF = 'import os, requests\nfrom rest_framework.views import APIView\nfrom rest_framework.response import Response\nfrom rest_framework.permissions import BasePermission\nfrom django.http import FileResponse\n'
FALCON = 'import os, falcon, requests\n'
QUART = 'import os, httpx\nfrom quart import Quart, request, redirect, send_file, render_template_string\napp = Quart(__name__)\n'
SANIC = "import os, httpx\nfrom sanic import Sanic\nfrom sanic.response import text, redirect\napp = Sanic('x')\n"
ST = 'import os, re, httpx\nfrom starlette.applications import Starlette\nfrom starlette.responses import FileResponse, PlainTextResponse, RedirectResponse\nfrom starlette.routing import Route\n'
TO = 'import json, os, re\nimport tornado.web\nimport requests\n'


def _flows(header: str, body: str) -> list[str]:
    """추적 분석이 낸 룰 약칭. 분석 결과를 직접 본다(내부 오류는 strict 로 드러난다) — 전체 검사도 예외 없이 끝나야 한다."""
    code = header + textwrap.dedent(body)
    tree = ast.parse(code)
    hits = scan_web_flows(tree, code.split(N), _collect_import_aliases(tree), strict=True)
    scan_code(code, filename="app.py")
    return sorted({SHORT[h[0]] for h in hits})


#: 안전한데도 보고하는 것(근거 '유력') — 줄여 가야 할 목록이다. 사라지면 시험이 알린다.
KNOWN_REPORTS: dict[str, list[str]] = {

}

SAFE3 = [
('T01', 'loop over forbidden tokens, abort on any', FL, """
    @app.route("/dl")
    def dl():
        name = request.args.get("name", "")
        for token in ("..", "/", "\\\\"):
            if token in name:
                abort(400)
        return send_file(os.path.join("/srv/files", name))
"""),
('T02', 'any(tok in name for tok in BAD)', FL, """
    BAD_TOKENS = ("..", "/", "\\\\", "\\x00")

    @app.route("/dl")
    def dl():
        name = request.args.get("name", "")
        if any(tok in name for tok in BAD_TOKENS):
            abort(400)
        return send_file(os.path.join("/srv/files", name))
"""),
('T03', 'helper returns None for an invalid name', FL, """
    NAME_RE = re.compile(r"[a-z0-9_-]{1,40}\\.pdf")

    def storage_path(name):
        if not NAME_RE.fullmatch(name):
            return None
        return os.path.join("/srv/reports", name)

    @app.route("/report")
    def report():
        path = storage_path(request.args.get("name", ""))
        if path is None:
            abort(404)
        return send_file(path)
"""),
('T04', 'helper falls back to a default', FL, """
    THEMES = {"light", "dark", "contrast"}

    def theme_css(theme):
        if theme not in THEMES:
            theme = "light"
        return f"/srv/static/css/{theme}.css"

    @app.route("/theme.css")
    def css():
        return send_file(theme_css(request.cookies.get("theme", "")))
"""),
('T05', 'imported validate_host(urlparse(url).hostname) [cross-file]', FL, """
    from urllib.parse import urlparse
    from netguard import validate_host   # raises Forbidden unless the host is allow-listed

    @app.route("/p")
    def p():
        url = request.args.get("url", "")
        validate_host(urlparse(url).hostname)
        return requests.get(url, timeout=5).text
"""),
('T06', 'imported validate_output_path(dest) [cross-file]', FL, """
    from fsguard import validate_output_path   # raises unless dest stays under the export root

    @app.route("/export", methods=["POST"])
    def export():
        dest = os.path.join("/srv/exports", request.form["name"])
        validate_output_path(dest)
        with open(dest, "w") as fh:
            fh.write(request.form["body"])
        return "ok"
"""),
('T07', 'strptime(...).date() in try/abort, raw string used', FL, """
    from datetime import datetime

    @app.route("/log")
    def log():
        day = request.args.get("day", "")
        try:
            when = datetime.strptime(day, "%Y-%m-%d").date()
        except ValueError:
            abort(400)
        return send_file(f"/var/log/app/{day}.log", download_name=when.isoformat() + ".log")
"""),
('T08', 'nested .get(...).get(...) checked, [..][..] used', FL, """
    LANGS = {"ko", "en", "ja"}

    @app.route("/i18n", methods=["POST"])
    def i18n():
        data = request.get_json()
        if data.get("meta", {}).get("lang") not in LANGS:
            abort(400)
        return send_file(f"/srv/i18n/{data['meta']['lang']}.json")
"""),
('T09', 'set(name) - ALLOWED_CHARS', FL, """
    import string
    ALLOWED_CHARS = set(string.ascii_lowercase + string.digits + "_-")

    @app.route("/note")
    def note():
        name = request.args.get("id", "")
        if set(name) - ALLOWED_CHARS:
            abort(400)
        return send_file(f"/srv/notes/{name}.md")
"""),
('T10', 'strip(allowed) leaves a remainder -> reject', FL, """
    import string
    ALLOWED = string.ascii_lowercase + string.digits + "_-"

    @app.route("/note")
    def note():
        name = request.args.get("id", "")
        if name.strip(ALLOWED):
            abort(400)
        return send_file(f"/srv/notes/{name}.md")
"""),
('T11', 'ALLOWED.index(name) in try/abort', FL, """
    ALLOWED = ["terms.pdf", "manual.pdf", "faq.pdf"]

    @app.route("/docs")
    def docs():
        name = request.args.get("name", "")
        try:
            position = ALLOWED.index(name)
        except ValueError:
            abort(404)
        return send_file(os.path.join("/srv/docs", name), download_name=f"{position + 1}-{name}")
"""),
('T12', 'bad-flag view, Django HttpResponseBadRequest return', DJ, """
    from django.http import HttpResponseBadRequest
    from django.conf import settings

    def download(request):
        name = request.GET.get("name", "")
        bad = ".." in name or "/" in name or "\\\\" in name
        if bad:
            return HttpResponseBadRequest("bad name")
        return FileResponse(open(os.path.join(settings.MEDIA_ROOT, name), "rb"))
"""),
('T13', 'not (ok and authenticated) -> redirect to login', FL, """
    from flask_login import current_user

    @app.route("/go")
    def go():
        target = request.args.get("next", "/")
        ok = target.startswith("/") and not target.startswith("//") and "\\\\" not in target
        if not (ok and current_user.is_authenticated):
            return redirect(url_for("login"))
        return redirect(target)
"""),
('T14', 'blocklist regex: serve only when nothing bad is found', FL, """
    BAD = re.compile(r"\\.\\.|[/\\\\]")

    @app.route("/dl")
    def dl():
        name = request.args.get("name", "")
        bad = BAD.search(name)
        if not bad:
            return send_file(os.path.join("/srv/files", name))
        abort(400)
"""),
('T15', 'router-level dependency validates the path param', FA, """
    from fastapi import APIRouter

    def verify_name(name: str):
        if not re.fullmatch(r"[a-z0-9_-]{1,40}", name):
            raise HTTPException(400)

    router = APIRouter(prefix="/files", dependencies=[Depends(verify_name)])

    @router.get("/{name}")
    def files(name: str):
        return FileResponse(f"/srv/files/{name}.pdf")
"""),
('T16', 'dict[str, Model] body, int field', FA, """
    from pydantic import BaseModel

    class Item(BaseModel):
        doc_id: int

    @app.post("/bundle")
    def bundle(items: dict[str, Item]):
        out = {}
        for label, it in items.items():
            with open(f"/srv/docs/{it.doc_id}.txt") as fh:
                out[label] = fh.read()
        return out
"""),
('T17', 'nested model aliased to a local, int fields', FA, """
    from pydantic import BaseModel

    class Period(BaseModel):
        year: int
        month: int

    class ReportReq(BaseModel):
        period: Period

    @app.post("/report")
    def report(body: ReportReq):
        period = body.period
        return FileResponse(f"/srv/reports/{period.year}/{period.month:02d}.pdf")
"""),
('T18', 'sink in the success branch, error tuple afterwards', FL, """
    from urllib.parse import urlparse
    ALLOWED = {"api.example.go.kr"}

    @app.route("/p")
    def p():
        url = request.args.get("url", "")
        host = urlparse(url).hostname
        if host in ALLOWED:
            return requests.get(url, timeout=5).text
        return jsonify(error="forbidden"), 403
"""),
('T19', 'loop with allowlist continue', FL, """
    from urllib.parse import urlparse
    ALLOWED = {"api.example.go.kr", "data.example.go.kr"}

    @app.route("/batch", methods=["POST"])
    def batch():
        out = {}
        for url in request.get_json()["urls"]:
            if urlparse(url).hostname not in ALLOWED:
                continue
            out[url] = requests.get(url, timeout=5).status_code
        return jsonify(out)
"""),
('T20', 'retry loop around a validated URL', FL, """
    import time
    PREFIX = "https://api.example.go.kr/"

    @app.route("/poll")
    def poll():
        url = request.args.get("url", "")
        if not url.startswith(PREFIX):
            abort(403)
        while True:
            resp = requests.get(url, timeout=5)
            if resp.status_code != 202:
                break
            time.sleep(1)
        return resp.text
"""),
('T21', 'try/except/else: sink in else after UUID parse', FA, """
    import uuid

    @app.get("/docs/{doc_id}")
    def doc(doc_id: str):
        try:
            uuid.UUID(doc_id)
        except ValueError:
            raise HTTPException(400)
        else:
            return FileResponse(f"/srv/docs/{doc_id}.pdf")
"""),
('T22', 'nested ifs, both levels validated', FL, """
    KINDS = {"daily", "weekly"}
    FORMATS = {"csv", "xlsx"}

    @app.route("/export")
    def export():
        kind = request.args.get("kind", "")
        fmt = request.args.get("fmt", "")
        if kind in KINDS:
            if fmt in FORMATS:
                return send_file(f"/srv/export/{kind}.{fmt}")
        abort(404)
"""),
('T23', 'validator method on the same class', TO, """
    BASE = os.path.realpath("/srv/files")

    class Download(tornado.web.RequestHandler):
        def _ensure_inside(self, path):
            if not path.startswith(BASE + os.sep):
                raise tornado.web.HTTPError(403)

        def get(self):
            path = os.path.realpath(os.path.join(BASE, self.get_argument("name")))
            self._ensure_inside(path)
            with open(path) as fh:
                self.write(fh.read())
"""),
('T24', 'ternary allowlist assignment then redirect', FL, """
    SAFE = {"/", "/home", "/settings"}

    @app.route("/go")
    def go():
        nxt = request.args.get("next", "/")
        target = nxt if nxt in SAFE else "/"
        app.logger.info("redirecting to %s", target)
        return redirect(target)
"""),
('T25', 'comprehension allowlist filter then loop', FL, """
    ALLOWED = {"a.csv", "b.csv", "c.csv"}

    @app.route("/merge")
    def merge():
        names = [n for n in request.args.getlist("f") if n in ALLOWED]
        out = ""
        for n in names:
            with open(os.path.join("/srv/data", n)) as fh:
                out += fh.read()
        return out
"""),
('T26', 'validated value stored in a dict then used', FL, """
    from urllib.parse import urlparse
    ALLOWED = {"api.example.go.kr"}

    @app.route("/p")
    def p():
        url = request.args.get("url", "")
        if urlparse(url).hostname not in ALLOWED:
            abort(403)
        job = {"timeout": 5}
        job["url"] = url
        return requests.get(job["url"], timeout=job["timeout"]).text
"""),
('T27', 'validated values appended to a list', FL, """
    NAME_RE = re.compile(r"[a-z0-9_-]{1,40}\\.txt")

    @app.route("/cat")
    def cat():
        paths = []
        for name in request.args.getlist("f"):
            if not NAME_RE.fullmatch(name):
                abort(400)
            paths.append(os.path.join("/srv/files", name))
        return "".join(open(p).read() for p in paths)
"""),
('T28', 'pathlib containment then read_text', FA, """
    from pathlib import Path
    BASE = Path("/srv/files").resolve()

    @app.get("/read")
    def read(name: str):
        target = (BASE / name).resolve()
        if BASE not in target.parents:
            raise HTTPException(404)
        return {"text": target.read_text()}
"""),
('T29', 'requests.Session().get on a fixed base', FL, """
    API = "https://api.example.go.kr/v1"

    @app.route("/users/<uid>")
    def user(uid):
        return requests.Session().get(f"{API}/users/{uid}", timeout=5).text
"""),
('T30', 'tornado allowlist with set_status + return', TO, """
    ALLOWED = {"https://a.example.go.kr/feed", "https://b.example.go.kr/feed"}

    class Proxy(tornado.web.RequestHandler):
        def get(self):
            url = self.get_argument("url")
            if url not in ALLOWED:
                self.set_status(403)
                return
            self.write(requests.get(url, timeout=5).text)
"""),
('T31', 'aiohttp query allowlist, raise HTTPForbidden', AIO, """
    from urllib.parse import urlparse
    ALLOWED = {"api.example.go.kr"}

    async def proxy(request):
        url = request.query.get("url", "")
        if urlparse(url).hostname not in ALLOWED:
            raise web.HTTPForbidden()
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as resp:
                return web.Response(text=await resp.text())
"""),
('T32', 'Django GET + HttpResponseBadRequest on a direct check', DJ, """
    from django.http import HttpResponseBadRequest
    FORMATS = ("csv", "xlsx")

    def export(request):
        fmt = request.GET.get("format", "csv")
        if fmt not in FORMATS:
            return HttpResponseBadRequest("unknown format")
        return FileResponse(open(f"/srv/export/latest.{fmt}", "rb"))
"""),
('T33', 'nested key validated and used in the same form', FL, """
    HOSTS = {"api.example.go.kr"}

    @app.route("/hook", methods=["POST"])
    def hook():
        data = request.get_json()
        if data["target"]["host"] not in HOSTS:
            abort(403)
        return requests.post(f"https://{data['target']['host']}/hook", json=data.get("payload"), timeout=5).text
"""),
('T34', ".get('k') checked, ['k'] used, value extracted later", FL, """
    KINDS = {"users", "orders"}

    @app.route("/export", methods=["POST"])
    def export():
        data = request.get_json()
        if data.get("kind") not in KINDS:
            return jsonify(error="unknown kind"), 400
        kind = data["kind"]
        return send_file(f"/srv/export/{kind}.csv")
"""),
('T35', 'match with literal cases, default aborts, value reused', FL, """
    @app.route("/asset")
    def asset():
        kind = request.args.get("kind", "")
        match kind:
            case "logo" | "banner" | "icon":
                pass
            case _:
                abort(404)
        return send_file(f"/srv/assets/{kind}.png")
"""),
('T36', 'regex match object: success branch only', FL, """
    NAME_RE = re.compile(r"[a-z0-9_-]{1,40}\\.pdf")

    @app.route("/report")
    def report():
        name = request.args.get("name", "")
        m = NAME_RE.fullmatch(name)
        if m:
            return send_file(os.path.join("/srv/reports", name))
        abort(404)
"""),
('T37', 'same-file passer that applies secure_filename', FL, """
    from werkzeug.utils import secure_filename

    def upload_path(name):
        return os.path.join("/srv/uploads", secure_filename(name))

    @app.route("/dl")
    def dl():
        return send_file(upload_path(request.args.get("name", "")))
"""),
('T38', 'scheme variable + fixed host', FL, """
    API_HOST = "api.example.go.kr"

    @app.route("/items/<path:rest>")
    def items(rest):
        scheme = "https" if app.config.get("TLS", True) else "http"
        return requests.get(f"{scheme}://{API_HOST}/v1/{rest}", timeout=5).text
"""),
('T39', "urljoin(API, quote(path, safe=''))", FL, """
    from urllib.parse import urljoin, quote
    API = "https://api.example.go.kr/v1/"

    @app.route("/proxy")
    def proxy():
        path = request.args.get("path", "")
        return requests.get(urljoin(API, quote(path, safe="")), timeout=5).text
"""),
('T40', 'redirect through url_for with the raw next as a parameter', FL, """
    @app.route("/logout")
    def logout():
        nxt = request.args.get("next", "")
        return redirect(url_for("login", next=nxt))
"""),
('T41', 'repair to a default when the host is not allow-listed', FL, """
    from urllib.parse import urlparse
    ALLOWED = {"api.example.go.kr"}
    DEFAULT_URL = "https://api.example.go.kr/status"

    @app.route("/p")
    def p():
        url = request.args.get("url", "")
        if urlparse(url).hostname not in ALLOWED:
            url = DEFAULT_URL
        return requests.get(url, timeout=5).text
"""),
('T42', "relpath(...).startswith('..')", FL, """
    BASE = os.path.realpath("/srv/files")

    @app.route("/dl")
    def dl():
        full = os.path.realpath(os.path.join(BASE, request.args.get("name", "")))
        if os.path.relpath(full, BASE).startswith(".."):
            abort(403)
        return send_file(full)
"""),
('T43', 'assert commonpath', FL, """
    BASE = os.path.realpath("/srv/files")

    @app.route("/dl")
    def dl():
        full = os.path.realpath(os.path.join(BASE, request.args.get("name", "")))
        assert os.path.commonpath([BASE, full]) == BASE, "outside base"
        return send_file(full)
"""),
('T44', 'stored bool, error tuple return', FL, """
    BASE = os.path.realpath("/srv/files")

    @app.route("/dl")
    def dl():
        full = os.path.realpath(os.path.join(BASE, request.args.get("name", "")))
        inside = full.startswith(BASE + os.sep)
        if not inside:
            return jsonify(error="forbidden"), 403
        return send_file(full)
"""),
('T45', 'strptime without try (exception -> 500), raw string used', FL, """
    from datetime import datetime

    @app.route("/log")
    def log():
        day = request.args.get("day", "")
        when = datetime.strptime(day, "%Y-%m-%d")
        app.logger.info("log for %s", when.date())
        return send_file(f"/var/log/app/{day}.log")
"""),
('T46', 'same-file validator that inspects a derived view', FL, """
    from urllib.parse import urlparse
    PUBLIC = {"api.example.go.kr", "data.example.go.kr"}

    def require_public_host(url):
        host = urlparse(url).hostname
        if host not in PUBLIC:
            abort(403)

    @app.route("/p")
    def p():
        url = request.args.get("url", "")
        require_public_host(url)
        return requests.get(url, timeout=5).text
"""),
('T47', 'validated before a streaming closure', FL, """
    from flask import Response
    BASE = os.path.realpath("/srv/media")

    @app.route("/stream")
    def stream():
        path = os.path.realpath(os.path.join(BASE, request.args.get("name", "")))
        if not path.startswith(BASE + os.sep):
            abort(403)

        def generate():
            with open(path, "rb") as fh:
                yield from fh

        return Response(generate(), mimetype="application/octet-stream")
"""),
('T48', 'membership in a set built from os.scandir', FL, """
    BASE = "/srv/files"

    @app.route("/dl")
    def dl():
        name = request.args.get("name", "")
        available = {entry.name for entry in os.scandir(BASE) if entry.is_file()}
        if name not in available:
            abort(404)
        return send_file(os.path.join(BASE, name))
"""),
]


@pytest.mark.parametrize("case", SAFE3, ids=[c[0] + " " + c[1] for c in SAFE3])
def test_safe_shape(case: tuple) -> None:
    cid, title, header, code = case[:4]
    assert _flows(header, code) == KNOWN_REPORTS.get(cid, []), (cid, title)
