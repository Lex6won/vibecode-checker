"""독립 적대적 검증 4차(2026-11-21)가 만든 안전한 코드 — '다른 쓰임이 없을 때만 보고'라는 원칙 자체를 겨냥했다.

검사가 훅·데코레이터·의존성에 있거나 같은 요청 필드를 다른 식으로 읽는 코드다. 넷째 판은 이 가운데 46개를 냈다.
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

SAFE4 = [
('A01', 'same-file decorator with a non-validator name', FL, """
    from functools import wraps
    REPORTS = {"daily.pdf", "weekly.pdf"}

    def only_known_reports(view):
        @wraps(view)
        def wrapper(name, *args, **kwargs):
            if name not in REPORTS:
                abort(404)
            return view(name, *args, **kwargs)
        return wrapper

    @app.route("/reports/<name>")
    @only_known_reports
    def report(name):
        return send_file(os.path.join("/srv/reports", name))
"""),
('A02', 'before_request checks request.args for every route', FL, """
    SAFE_TARGETS = {"/", "/home", "/settings"}

    @app.before_request
    def reject_foreign_next():
        nxt = request.args.get("next")
        if nxt is not None and nxt not in SAFE_TARGETS:
            abort(400)

    @app.route("/go")
    def go():
        return redirect(request.args.get("next", "/"))
"""),
('A03', 'FastAPI: validation dependency as a separate parameter', FA, """
    def verify_name(name: str):
        if not re.fullmatch(r"[a-z0-9_-]{1,40}", name):
            raise HTTPException(400)

    @app.get("/files/{name}")
    def files(name: str, _: None = Depends(verify_name)):
        return FileResponse(f"/srv/files/{name}.pdf")
"""),
('A04', 'tornado prepare() validates the argument', TO, """
    NAME_RE = re.compile(r"[a-z0-9_-]{1,40}\\.txt")

    class Download(tornado.web.RequestHandler):
        def prepare(self):
            if not NAME_RE.fullmatch(self.get_argument("name", "")):
                raise tornado.web.HTTPError(400)

        def get(self):
            with open(os.path.join("/srv/files", self.get_argument("name"))) as fh:
                self.write(fh.read())
"""),
('A05', 'helper reads and checks the request itself', FL, """
    NAME_RE = re.compile(r"[a-z0-9_-]{1,40}\\.pdf")

    def require_valid_name():
        if not NAME_RE.fullmatch(request.args.get("name", "")):
            abort(400)

    @app.route("/report")
    def report():
        require_valid_name()
        return send_file(os.path.join("/srv/reports", request.args["name"]))
"""),
('A06', 'Django class-based view: dispatch() rejects unknown formats', DJ, """
    from django.http import HttpResponseBadRequest
    from django.views import View
    FORMATS = ("csv", "xlsx")

    class Export(View):
        def dispatch(self, request, *args, **kwargs):
            if request.GET.get("fmt", "csv") not in FORMATS:
                return HttpResponseBadRequest("unknown format")
            return super().dispatch(request, *args, **kwargs)

        def get(self, request):
            fmt = request.GET.get("fmt", "csv")
            return FileResponse(open(f"/srv/export/latest.{fmt}", "rb"))
"""),
('A07', '@expects_json schema with an enum of URLs', FL, """
    from flask_expects_json import expects_json
    SCHEMA = {"type": "object", "required": ["feed"],
              "properties": {"feed": {"enum": ["https://a.example.go.kr/rss", "https://b.example.go.kr/rss"]}}}

    @app.route("/pull", methods=["POST"])
    @expects_json(SCHEMA)
    def pull():
        return requests.get(request.get_json()["feed"], timeout=5).text
"""),
('A08', 'FastAPI http middleware validates the query parameter', FA, """
    from fastapi import Request
    from fastapi.responses import JSONResponse
    ALLOWED = {"https://a.example.go.kr/feed", "https://b.example.go.kr/feed"}

    @app.middleware("http")
    async def only_known_feeds(request: Request, call_next):
        feed = request.query_params.get("feed")
        if feed is not None and feed not in ALLOWED:
            return JSONResponse({"error": "forbidden"}, status_code=403)
        return await call_next(request)

    @app.get("/pull")
    async def pull(feed: str):
        async with httpx.AsyncClient() as client:
            return (await client.get(feed)).text
"""),
('A09', 'MethodView.decorators with a checking decorator', FL, """
    from functools import wraps
    from flask.views import MethodView
    PAGES = {"about", "contact"}

    def known_page(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if kwargs.get("page") not in PAGES:
                abort(404)
            return view(*args, **kwargs)
        return wrapper

    class Page(MethodView):
        decorators = [known_page]

        def get(self, page):
            return send_file(f"/srv/pages/{request.view_args['page']}.html")

    app.add_url_rule("/pages/<page>", view_func=Page.as_view("page"))
"""),
('A10', 'imported dependency in the route decorator [cross-file]', FA, """
    from myapp.deps import verify_name   # raises 400 unless name matches [a-z0-9_-]+

    @app.get("/files/{name}", dependencies=[Depends(verify_name)])
    def files(name: str):
        return FileResponse(f"/srv/files/{name}.pdf")
"""),
('A11', 'DRF permission class checks the query parameter', DRF, """
    REPORTS = {"daily", "weekly"}

    class OnlyKnownReports(BasePermission):
        def has_permission(self, request, view):
            return request.query_params.get("name") in REPORTS

    class Report(APIView):
        permission_classes = [OnlyKnownReports]

        def get(self, request):
            name = request.query_params["name"]
            return FileResponse(open(f"/srv/reports/{name}.pdf", "rb"))
"""),
('A12', 'validator method that re-reads the request', TO, """
    ALLOWED = {"https://a.example.go.kr/feed", "https://b.example.go.kr/feed"}

    class Proxy(tornado.web.RequestHandler):
        def _reject_unknown_feed(self):
            if self.get_argument("feed") not in ALLOWED:
                raise tornado.web.HTTPError(403)

        def get(self):
            self._reject_unknown_feed()
            self.write(requests.get(self.get_argument("feed"), timeout=5).text)
"""),
('B01', 'checked through request.values, used through request.args', FL, """
    SAFE_TARGETS = {"/", "/home", "/settings"}

    @app.route("/go")
    def go():
        if request.values.get("next", "/") not in SAFE_TARGETS:
            abort(400)
        return redirect(request.args.get("next", "/"))
"""),
('B02', 'checked on data = request.get_json(), used via request.json', FL, """
    ALLOWED = {"https://a.example.go.kr/hook", "https://b.example.go.kr/hook"}

    @app.route("/notify", methods=["POST"])
    def notify():
        data = request.get_json()
        if data.get("url") not in ALLOWED:
            abort(403)
        return requests.post(request.json["url"], json={"ok": True}, timeout=5).text
"""),
('B03', 'args = request.args alias checked, request.args used', FL, """
    FORMATS = {"csv", "xlsx"}

    @app.route("/export")
    def export():
        args = request.args
        if args.get("fmt") not in FORMATS:
            abort(400)
        return send_file(f"/srv/export/latest.{request.args['fmt']}")
"""),
('B04', 'field validated, then read from a copy of the body', FL, """
    KINDS = {"users", "orders"}

    @app.route("/export", methods=["POST"])
    def export():
        body = request.get_json()
        if body.get("kind") not in KINDS:
            abort(400)
        params = body.copy()
        params.setdefault("compress", False)
        return send_file(f"/srv/export/{params['kind']}.csv")
"""),
('B05', 'nested dict aliased for the check, full path used later', FL, """
    HOSTS = {"api.example.go.kr", "data.example.go.kr"}

    @app.route("/hook", methods=["POST"])
    def hook():
        data = request.get_json()
        target = data["target"]
        if target["host"] not in HOSTS:
            abort(403)
        return requests.post(f"https://{data['target']['host']}/hook", json={"ok": True}, timeout=5).text
"""),
('B06', 'validate-all loop, then a second loop with another variable name', FL, """
    KINDS = {"users", "orders", "items"}

    @app.route("/bundle", methods=["POST"])
    def bundle():
        jobs = request.get_json()["jobs"]
        for job in jobs:
            if job["kind"] not in KINDS:
                abort(400)
        out = []
        for j in jobs:
            with open(f"/srv/export/{j['kind']}.csv") as fh:
                out.append(fh.read())
        return jsonify(out)
"""),
('B07', 'typed Flask converter, value read from request.view_args', FL, """
    @app.route("/pages/<int:page>")
    def pages(page):
        app.logger.info("page %s", page)
        return send_file(f"/srv/pages/{request.view_args['page']}.html")
"""),
('B08', 'whole body checked via a dict of fields, field used', FL, """
    ALLOWED_BODIES = [{"feed": "https://a.example.go.kr/rss"}, {"feed": "https://b.example.go.kr/rss"}]

    @app.route("/pull", methods=["POST"])
    def pull():
        data = request.get_json()
        if data not in ALLOWED_BODIES:
            abort(403)
        return requests.get(data["feed"], timeout=5).text
"""),
('C01', 'Starlette int path convertor', ST, """
    async def item(request):
        item_id = request.path_params["item_id"]
        return FileResponse(f"/srv/items/{item_id}.json")

    app = Starlette(routes=[Route("/items/{item_id:int}", item)])
"""),
('C02', 'aiohttp route regex {id:\\\\d+}', AIO, """
    async def invoice(request):
        invoice_id = request.match_info["id"]
        with open(f"/srv/invoices/{invoice_id}.pdf", "rb") as fh:
            return web.Response(body=fh.read(), content_type="application/pdf")

    app = web.Application()
    app.router.add_get(r"/invoices/{id:\\d+}", invoice)
"""),
('C03', "request.args.get('page', 1, int) — positional type", FL, """
    @app.route("/pages")
    def pages():
        page = request.args.get("page", 1, int)
        return send_file(f"/srv/pages/{page}.html")
"""),
('C04', 'JSON field accepted only when isinstance(..., int)', FL, """
    @app.route("/doc", methods=["POST"])
    def doc():
        doc_id = request.get_json().get("doc_id")
        if not isinstance(doc_id, int):
            abort(400)
        return send_file(f"/srv/docs/{doc_id}.pdf")
"""),
('C05', 'FileNameStr = constr(pattern=...) alias used as the parameter type', FA, """
    from pydantic import constr
    FileNameStr = constr(pattern=r"^[a-z0-9_-]{1,40}$")

    @app.get("/files/{name}")
    def files(name: FileNameStr):
        return FileResponse(f"/srv/files/{name}.pdf")
"""),
('C06', 'imported constrained type SlugStr [cross-file]', FA, """
    from myapp.types import SlugStr   # Annotated[str, StringConstraints(pattern=r"^[a-z0-9-]{1,40}$")]

    @app.get("/pages/{slug}")
    def page(slug: SlugStr):
        return FileResponse(f"/srv/pages/{slug}.html")
"""),
('C07', 'helper guarded by pydantic @validate_call', FA, """
    from typing import Annotated
    from pydantic import StringConstraints, validate_call
    Slug = Annotated[str, StringConstraints(pattern=r"^[a-z0-9-]{1,40}$")]

    @validate_call
    def page_path(slug: Slug) -> str:
        return f"/srv/pages/{slug}.html"

    @app.get("/pages")
    def page(slug: str):
        return FileResponse(page_path(slug))
"""),
('C08', 'Flask string converter limited to one character', FL, """
    @app.route("/glossary/<string(length=1):letter>")
    def glossary(letter):
        return send_file(f"/srv/glossary/{letter}/index.html")
"""),
('C09', 'type(x) is int', FL, """
    @app.route("/doc", methods=["POST"])
    def doc():
        doc_id = request.get_json().get("doc_id")
        if type(doc_id) is not int:
            abort(400)
        return send_file(f"/srv/docs/{doc_id}.pdf")
"""),
('C10', 'model with HttpUrl + host validator', FA, """
    from pydantic import BaseModel, HttpUrl, field_validator
    HOSTS = {"api.example.go.kr"}

    class Hook(BaseModel):
        url: HttpUrl

        @field_validator("url")
        @classmethod
        def known_host(cls, v):
            if v.host not in HOSTS:
                raise ValueError("unknown host")
            return v

    @app.post("/hook")
    def hook(body: Hook):
        return httpx.post(str(body.url), json={"ok": True}).status_code
"""),
('C11', 'DRF serializer.validated_data', DRF, """
    from .serializers import HookSerializer   # url = ChoiceField(choices=REGISTERED_HOOKS)

    class HookTest(APIView):
        def post(self, request):
            ser = HookSerializer(data=request.data)
            ser.is_valid(raise_exception=True)
            r = requests.post(ser.validated_data["url"], json={"ping": True}, timeout=5)
            return Response({"status": r.status_code})
"""),
('C12', 'WTForms field after validate_on_submit', FL, """
    from .forms import ExportForm   # kind = SelectField(choices=[("users", "Users"), ("orders", "Orders")])

    @app.route("/export", methods=["GET", "POST"])
    def export():
        form = ExportForm()
        if not form.validate_on_submit():
            abort(400)
        return send_file(f"/srv/export/{form.kind.data}.csv")
"""),
('C13', 'FastAPI path convertor int, value read from request.path_params', FA, """
    from fastapi import Request

    @app.get("/items/{item_id:int}")
    def item(request: Request):
        return FileResponse(f"/srv/items/{request.path_params['item_id']}.json")
"""),
('C14', 'request.args.get(..., type=uuid.UUID)', FL, """
    import uuid

    @app.route("/doc")
    def doc():
        doc_id = request.args.get("id", type=uuid.UUID)
        if doc_id is None:
            abort(400)
        return send_file(f"/srv/docs/{doc_id}.pdf")
"""),
('D01', 'send_file of the uploaded FileStorage object (echo)', FL, """
    @app.route("/preview", methods=["POST"])
    def preview():
        upload = request.files["image"]
        return send_file(upload, mimetype="image/png")
"""),
('D02', 'loop variable reuses the name of a request value', FL, """
    FEEDS = ("https://a.example.go.kr/rss", "https://b.example.go.kr/rss")

    @app.route("/refresh")
    def refresh():
        url = request.args.get("callback", "")
        app.logger.info("refresh requested, callback=%s", url)
        out = []
        for url in FEEDS:
            out.append(requests.get(url, timeout=5).status_code)
        return jsonify(out)
"""),
('D03', 'deprecated parameter logged, then overwritten in both branches', FL, """
    DEFAULT_DEST = "/dashboard"

    @app.route("/done")
    def done():
        dest = request.args.get("dest")
        if dest:
            app.logger.warning("ignoring deprecated dest=%s", dest)
            dest = DEFAULT_DEST
        else:
            dest = DEFAULT_DEST
        return redirect(dest)
"""),
('D04', 'nested function with its own local of the same name', FL, """
    DIR = "/srv/releases"

    @app.route("/latest")
    def latest():
        name = request.args.get("name", "")
        app.logger.info("client asked for %s, serving newest instead", name)

        def newest():
            name = max(os.listdir(DIR))
            return open(os.path.join(DIR, name), "rb").read()

        return newest()
"""),
('D05', 'internal job object happens to be called req', FL, """
    from dataclasses import dataclass

    @dataclass
    class ExportRequest:
        params: dict

    NIGHTLY = ExportRequest(params={"out": "/srv/exports/nightly.csv"})

    def run_export(req: ExportRequest = NIGHTLY):
        with open(req.params["out"], "w") as fh:
            fh.write("id,name\\n")
"""),
('D06', 'FileResponse(path=CONSTANT, filename=value)', FA, """
    @app.get("/terms")
    def terms(name: str = "terms.pdf"):
        return FileResponse(path="/srv/static/terms.pdf", filename=name)
"""),
('D07', 'redirect(url_for(..., next=value))', FL, """
    @app.route("/logout")
    def logout():
        nxt = request.args.get("next", "")
        return redirect(url_for("login", next=nxt, _external=True))
"""),
('D08', 'client with fixed base_url, relative path', FA, """
    api = httpx.Client(base_url="https://api.example.go.kr/v1/")

    @app.get("/users/{user_id}")
    def user(user_id: str):
        return api.get("users/" + user_id).json()
"""),
('D09', 'basename taken in another statement', FL, """
    @app.route("/dl")
    def dl():
        raw = request.args.get("name", "")
        app.logger.info("download %s", raw)
        safe = os.path.basename(raw)
        return send_file(os.path.join("/srv/files", safe))
"""),
('D10', 'comprehension variable reuses the name of a request value', FL, """
    DIR = "/srv/notices"

    @app.route("/notices")
    def notices():
        name = request.args.get("highlight", "")
        texts = [open(os.path.join(DIR, name)).read() for name in sorted(os.listdir(DIR))]
        return jsonify(texts=texts, highlight=request.args.get("highlight", ""))
"""),
('D11', 'send_file(BytesIO(...)) with the request body', FL, """
    import io

    @app.route("/echo", methods=["POST"])
    def echo():
        payload = request.get_data()
        return send_file(io.BytesIO(payload), mimetype="application/octet-stream")
"""),
('D12', 'value only chooses the download name', FL, """
    @app.route("/report")
    def report():
        title = request.args.get("title", "report")
        return send_file("/srv/reports/latest.pdf", download_name=title + ".pdf", as_attachment=True)
"""),
('E01', 'cursor.execute lookup + fetchone None check, name reused', FL, """
    import sqlite3

    @app.route("/doc")
    def doc():
        name = request.args.get("name", "")
        cur = sqlite3.connect("/srv/app.db").cursor()
        cur.execute("SELECT 1 FROM published_docs WHERE filename = ?", (name,))
        if cur.fetchone() is None:
            abort(404)
        return send_file(os.path.join("/srv/docs", name))
"""),
('E02', 'separators replaced before joining', FL, """
    @app.route("/note")
    def note():
        name = request.args.get("id", "").replace("/", "_").replace("\\\\", "_")
        return send_file(os.path.join("/srv/notes", name + ".md"))
"""),
('E03', 'len + isdigit', FL, """
    @app.route("/otp")
    def otp():
        code = request.args.get("code", "")
        if len(code) != 6 or not code.isdigit():
            abort(400)
        return send_file(f"/srv/otp/{code}.png")
"""),
('E04', 'name must be listed in the directory', FL, """
    BASE = "/srv/files"

    @app.route("/dl")
    def dl():
        name = request.args.get("name", "")
        if name not in os.listdir(BASE):
            abort(404)
        return send_file(os.path.join(BASE, name))
"""),
('E05', 'allowlist dict .get + None check', FL, """
    FILES = {"terms": "/srv/static/terms.pdf", "privacy": "/srv/static/privacy.pdf"}

    @app.route("/legal")
    def legal():
        path = FILES.get(request.args.get("doc", ""))
        if path is None:
            abort(404)
        return send_file(path)
"""),
('E06', 'SQLAlchemy text() lookup chained with .first()', FL, """
    from sqlalchemy import text
    from models import db

    @app.route("/doc")
    def doc():
        name = request.args.get("name", "")
        row = db.session.execute(text("SELECT 1 FROM published_docs WHERE filename = :n"), {"n": name}).first()
        if row is None:
            abort(404)
        return send_file(os.path.join("/srv/docs", name))
"""),
('E07', 'empty-string comparison is the protection (only the default is served)', FL, """
    @app.route("/readme")
    def readme():
        sub = request.args.get("dir", "")
        if sub != "":
            abort(400)
        return send_file(os.path.join("/srv/docs", sub, "README.md"))
"""),
('F01', 'helper validates and returns the value', FL, """
    NAME_RE = re.compile(r"[a-z0-9_-]{1,40}\\.pdf")

    def clean_name(raw):
        if not NAME_RE.fullmatch(raw):
            abort(400)
        return raw

    @app.route("/report")
    def report():
        return send_file(os.path.join("/srv/reports", clean_name(request.args.get("name", ""))))
"""),
('F02', 'check bound with functools.partial', FL, """
    from functools import partial

    def require_match(pattern, value):
        if not re.fullmatch(pattern, value):
            abort(400)

    require_slug = partial(require_match, r"[a-z0-9-]{1,40}")

    @app.route("/pages/<slug>")
    def page(slug):
        require_slug(slug)
        return send_file(f"/srv/pages/{slug}.html")
"""),
('F03', 'check through a lambda table', FL, """
    CHECKS = {"slug": lambda v: re.fullmatch(r"[a-z0-9-]{1,40}", v) is not None}

    @app.route("/pages/<slug>")
    def page(slug):
        if not CHECKS["slug"](slug):
            abort(400)
        return send_file(f"/srv/pages/{slug}.html")
"""),
('F04', 'async helper raising HTTPException', FA, """
    HOSTS = {"api.example.go.kr"}

    async def ensure_known_host(url: str) -> None:
        if httpx.URL(url).host not in HOSTS:
            raise HTTPException(403)

    @app.get("/fetch")
    async def fetch(url: str):
        await ensure_known_host(url)
        async with httpx.AsyncClient() as client:
            return (await client.get(url)).text
"""),
('F05', 'staticmethod guard on a helper class', FL, """
    class Names:
        ALLOWED = {"a.csv", "b.csv"}

        @staticmethod
        def require(name):
            if name not in Names.ALLOWED:
                abort(404)

    @app.route("/data")
    def data():
        name = request.args.get("name", "")
        Names.require(name)
        return send_file(os.path.join("/srv/data", name))
"""),
('F06', 'closure defined after the value, called before the sink', FL, """
    ALLOWED = {"a.csv", "b.csv"}

    @app.route("/data")
    def data():
        name = request.args.get("name", "")

        def reject_unknown():
            if name not in ALLOWED:
                abort(404)

        reject_unknown()
        return send_file(os.path.join("/srv/data", name))
"""),
('F07', 'generator helper that filters', FL, """
    ALLOWED = {"a.csv", "b.csv", "c.csv"}

    def only_allowed(names):
        for n in names:
            if n in ALLOWED:
                yield n

    @app.route("/merge")
    def merge():
        out = ""
        for name in only_allowed(request.args.getlist("f")):
            with open(os.path.join("/srv/data", name)) as fh:
                out += fh.read()
        return out
"""),
('F08', 'variadic guard', FL, """
    ALLOWED = {"a.csv", "b.csv"}

    def reject_unknown(*names):
        for n in names:
            if n not in ALLOWED:
                abort(404)

    @app.route("/diff")
    def diff():
        left, right = request.args.get("left", ""), request.args.get("right", "")
        reject_unknown(left, right)
        return open(os.path.join("/srv/data", left)).read() + open(os.path.join("/srv/data", right)).read()
"""),
('G01', 'walrus + regex', FL, """
    @app.route("/pages")
    def pages():
        if (m := re.fullmatch(r"[a-z0-9-]{1,40}", request.args.get("slug", ""))) is None:
            abort(400)
        return send_file(f"/srv/pages/{m.group(0)}.html")
"""),
('G02', 'match with literal alternatives', FL, """
    @app.route("/asset")
    def asset():
        kind = request.args.get("kind", "")
        match kind:
            case "logo" | "banner":
                return send_file(f"/srv/assets/{kind}.png")
        abort(404)
"""),
('G03', 'tuple unpacking, both validated', FL, """
    KINDS, FORMATS = {"daily", "weekly"}, {"csv", "xlsx"}

    @app.route("/export")
    def export():
        kind, fmt = request.args.get("kind", ""), request.args.get("fmt", "")
        if kind not in KINDS or fmt not in FORMATS:
            abort(400)
        return send_file(f"/srv/export/{kind}.{fmt}")
"""),
('G04', 'try/finally around a validated open', FL, """
    BASE = os.path.realpath("/srv/files")

    @app.route("/cat")
    def cat():
        full = os.path.realpath(os.path.join(BASE, request.args.get("name", "")))
        if not full.startswith(BASE + os.sep):
            abort(403)
        fh = open(full)
        try:
            return fh.read()
        finally:
            fh.close()
"""),
('G05', 'module-level allowlist mutated elsewhere (global)', FL, """
    ENABLED = set()

    def enable(name):
        global ENABLED
        ENABLED = ENABLED | {name}

    @app.route("/plugin")
    def plugin():
        name = request.args.get("name", "")
        if name not in ENABLED:
            abort(404)
        return send_file(os.path.join("/srv/plugins", name, "README.md"))
"""),
('G06', 'class attribute allowlist on a MethodView', FL, """
    from flask.views import MethodView

    class Theme(MethodView):
        themes = ("light", "dark")

        def get(self):
            theme = request.cookies.get("theme", "light")
            if theme not in self.themes:
                theme = "light"
            return send_file(f"/srv/static/css/{theme}.css")

    app.add_url_rule("/theme.css", view_func=Theme.as_view("theme"))
"""),
('G07', 'comprehension filter with allowlist, sink in the same expression', FL, """
    ALLOWED = {"a.csv", "b.csv", "c.csv"}

    @app.route("/merge")
    def merge():
        return "".join(open(os.path.join("/srv/data", n)).read() for n in request.args.getlist("f") if n in ALLOWED)
"""),
('H01', 'x and A or B: the request value only selects a constant', FL, """
    @app.route("/mail/preview")
    def preview():
        name = request.args.get("compact") and "compact.html" or "full.html"
        return send_file(os.path.join("/srv/templates", name))
"""),
('H02', 'dict literal mixing a constant URL with a request label', FL, """
    FEED_URL = "https://api.example.go.kr/feed"

    @app.route("/pull")
    def pull():
        job = {"url": FEED_URL, "label": request.args.get("label", "")}
        body = requests.get(job["url"], timeout=5).text
        return jsonify(label=job["label"], size=len(body))
"""),
('H03', 'request body field overwritten with a server constant before use', FL, """
    INTERNAL_CALLBACK = "https://hooks.example.go.kr/internal"

    @app.route("/relay", methods=["POST"])
    def relay():
        payload = request.get_json()
        payload["callback"] = INTERNAL_CALLBACK
        return requests.post(payload["callback"], json=payload, timeout=5).text
"""),
('H04', 'getlist(..., type=int)', FL, """
    @app.route("/docs")
    def docs():
        out = []
        for doc_id in request.args.getlist("id", type=int):
            with open(f"/srv/docs/{doc_id}.txt") as fh:
                out.append(fh.read())
        return jsonify(out)
"""),
('H05', 'manual basename: normalise separators, keep the last piece', FL, """
    @app.route("/dl")
    def dl():
        name = request.args.get("name", "").replace("\\\\", "/").split("/")[-1]
        return send_file(os.path.join("/srv/files", name))
"""),
('H06', 'model_post_init rejects unknown hosts', FA, """
    from pydantic import BaseModel
    HOSTS = {"api.example.go.kr"}

    class Hook(BaseModel):
        url: str

        def model_post_init(self, context):
            if httpx.URL(self.url).host not in HOSTS:
                raise ValueError("unknown host")

    @app.post("/hook")
    def hook(body: Hook):
        return httpx.post(body.url, json={"ok": True}).status_code
"""),
('H07', 'two-character language code slice', FL, """
    @app.route("/i18n")
    def i18n():
        lang = request.headers.get("Accept-Language", "ko")[:2]
        return send_file(f"/srv/i18n/{lang}.json")
"""),
]


@pytest.mark.parametrize("case", SAFE4, ids=[c[0] + " " + c[1] for c in SAFE4])
def test_safe_shape(case: tuple) -> None:
    cid, title, header, code = case[:4]
    assert _flows(header, code) == KNOWN_REPORTS.get(cid, []), (cid, title)
