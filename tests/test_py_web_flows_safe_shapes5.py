"""독립 적대적 검증 5차(2026-11-21)가 만든 안전한 코드 — 마지막 판의 장치(요청 필드 열쇠·별칭·형·무해 목록)를 겨냥한 40가지와
평범한 핸들러 10가지(O01~O10). 평범한 10가지에서는 보고가 없어야 한다.
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
    'K12': ['PATH'],
    'L03': ['SSRF'],
    'L04': ['SSRF'],
    'L05': ['SSRF'],
    'L06': ['PATH'],
    'L10': ['SSRF'],
    'M01': ['REDIR'],
}

SAFE5 = [
('K01', 'before_request checks the field; handler joins it into a local path', FL, """
    SAFE = re.compile(r"[a-z0-9_-]{1,40}\\.pdf")

    @app.before_request
    def reject_bad_names():
        name = request.args.get("name")
        if name is not None and not SAFE.fullmatch(name):
            abort(400)

    @app.route("/report")
    def report():
        path = os.path.join("/srv/reports", request.args.get("name", "index.pdf"))
        return send_file(path)
"""),
('K02', 'tornado prepare() checks the argument; get() strips it first', TO, """
    NAME_RE = re.compile(r"\\s*[a-z0-9_-]{1,40}\\.txt\\s*")

    class Download(tornado.web.RequestHandler):
        def prepare(self):
            if not NAME_RE.fullmatch(self.get_argument("name", "")):
                raise tornado.web.HTTPError(400)

        def get(self):
            name = self.get_argument("name").strip()
            with open(os.path.join("/srv/files", name)) as fh:
                self.write(fh.read())
"""),
('K03', 'FastAPI middleware checks the query parameter; handler strips it', FA, """
    from fastapi import Request
    from fastapi.responses import JSONResponse
    ALLOWED = {"https://a.example.go.kr/feed", "https://b.example.go.kr/feed"}

    @app.middleware("http")
    async def only_known_feeds(request: Request, call_next):
        feed = request.query_params.get("feed")
        if feed is not None and feed.strip() not in ALLOWED:
            return JSONResponse({"error": "forbidden"}, status_code=403)
        return await call_next(request)

    @app.get("/pull")
    async def pull(feed: str):
        url = feed.strip()
        async with httpx.AsyncClient() as client:
            return (await client.get(url)).text
"""),
('K04', '@expects_json enum schema; handler lower-cases the field', FL, """
    from flask_expects_json import expects_json
    SCHEMA = {"type": "object", "required": ["kind"], "properties": {"kind": {"enum": ["users", "orders", "USERS", "ORDERS"]}}}

    @app.route("/export", methods=["POST"])
    @expects_json(SCHEMA)
    def export():
        kind = request.get_json()["kind"].lower()
        return send_file(f"/srv/export/{kind}.csv")
"""),
('K05', 'Django: helper validates the JSON body, the view parses it again', DJJ, """
    from django.core.exceptions import PermissionDenied
    ALLOWED = {"https://a.example.go.kr/feed", "https://b.example.go.kr/feed"}

    def _require_known_feed(request):
        body = json.loads(request.body)
        if body.get("feed") not in ALLOWED:
            raise PermissionDenied("unknown feed")

    def pull(request):
        _require_known_feed(request)
        payload = json.loads(request.body)
        return HttpResponse(requests.get(payload["feed"], timeout=5).content)
"""),
('K06', 'tornado: prepare() validates the JSON body, post() parses it again', TO, """
    KINDS = {"users", "orders"}

    class Export(tornado.web.RequestHandler):
        def prepare(self):
            if json.loads(self.request.body).get("kind") not in KINDS:
                raise tornado.web.HTTPError(400)

        def post(self):
            body = json.loads(self.request.body)
            with open(f"/srv/export/{body['kind']}.csv") as fh:
                self.write(fh.read())
"""),
('K07', 'field checked on request.form, then read from request.form.to_dict()', FL, """
    KINDS = {"users", "orders"}

    @app.route("/export", methods=["POST"])
    def export():
        if request.form.get("kind") not in KINDS:
            abort(400)
        form = request.form.to_dict()
        form.setdefault("compress", "0")
        return send_file(f"/srv/export/{form['kind']}.csv")
"""),
('K09', 'handler validates a field, passes the dict to a helper that uses it', FL, """
    KINDS = {"users", "orders"}

    def export_file(options):
        return send_file(f"/srv/export/{options['kind']}.csv", as_attachment=bool(options.get("download")))

    @app.route("/export", methods=["POST"])
    def export():
        data = request.get_json()
        if data.get("kind") not in KINDS:
            abort(400)
        return export_file(data)
"""),
('K10', 'hook checks request.values; handler picks JSON or form by content type', FL, """
    KINDS = {"users", "orders"}

    @app.before_request
    def reject_unknown_kind():
        kind = request.values.get("kind") or (request.get_json(silent=True) or {}).get("kind")
        if kind is not None and kind not in KINDS:
            abort(400)

    @app.route("/export", methods=["POST"])
    def export():
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form
        return send_file(f"/srv/export/{data.get('kind', 'users')}.csv")
"""),
('K11', 'traversal rejected by looking at request.path', FL, """
    @app.route("/files/<path:name>")
    def files(name):
        if ".." in request.path:
            abort(400)
        return send_file("/srv/files/" + name)
"""),
('K12', 'global filter on request.full_path', FL, """
    @app.before_request
    def block_traversal():
        probe = request.full_path.lower()
        if ".." in probe or "%2e" in probe or "%5c" in probe or "\\\\" in probe:
            abort(400)

    @app.route("/read")
    def read():
        name = request.args.get("name", "index.txt")
        with open("/srv/files/" + name) as fh:
            return fh.read()
"""),
('K13', 'loop over field names with a variable key', FL, """
    ALLOWED = {"kind": {"users", "orders"}, "fmt": {"csv", "xlsx"}}

    @app.route("/export")
    def export():
        for key, values in ALLOWED.items():
            if request.args.get(key, "") not in values:
                abort(400)
        return send_file(f"/srv/export/{request.args['kind']}.{request.args['fmt']}")
"""),
('K15', 'hook registered with app.before_request(fn), checks view_args', FL, """
    PAGES = {"about", "contact", "terms"}

    def only_known_pages():
        page = (request.view_args or {}).get("page")
        if page is not None and page not in PAGES:
            abort(404)

    app.before_request(only_known_pages)

    @app.route("/pages/<page>")
    def pages(page):
        return send_file(f"/srv/pages/{page}.html")
"""),
('K16', 'decorator named authorized_report checks the path parameter', FL, """
    from functools import wraps
    from flask_login import current_user

    def authorized_report(view):
        @wraps(view)
        def wrapper(name):
            if name not in current_user.report_names:
                abort(403)
            return view(name)
        return wrapper

    @app.route("/reports/<name>")
    @authorized_report
    def report(name):
        return send_file(os.path.join("/srv/reports", name))
"""),
('K17', 'callable-class dependency validates the path parameter', FA, """
    class NameGuard:
        def __init__(self, pattern: str):
            self.pattern = re.compile(pattern)

        def __call__(self, name: str) -> None:
            if not self.pattern.fullmatch(name):
                raise HTTPException(400)

    @app.get("/files/{name}")
    def files(name: str, _: None = Depends(NameGuard(r"[a-z0-9_-]{1,40}"))):
        return FileResponse(f"/srv/files/{name}.pdf")
"""),
('L01', 'constant dict, request value added later, constant field used', FL, """
    FEED_URL = "https://api.example.go.kr/feed"

    @app.route("/pull")
    def pull():
        opts = {"url": FEED_URL, "timeout": 5}
        opts["label"] = request.args.get("label", "")
        body = requests.get(opts["url"], timeout=opts["timeout"]).text
        return jsonify(label=opts["label"], size=len(body))
"""),
('L02', 'empty dict filled field by field, constant first', FL, """
    @app.route("/mail/preview")
    def preview():
        job = {}
        job["template"] = "/srv/templates/welcome.html"
        job["recipient"] = request.args.get("to", "")
        with open(job["template"]) as fh:
            return jsonify(to=job["recipient"], html=fh.read())
"""),
('L03', 'request body field overwritten with update(callback=CONST)', FL, """
    INTERNAL_CALLBACK = "https://hooks.example.go.kr/internal"

    @app.route("/relay", methods=["POST"])
    def relay():
        payload = request.get_json()
        payload.update(callback=INTERNAL_CALLBACK)
        return requests.post(payload["callback"], json=payload, timeout=5).text
"""),
('L04', 'dict(body, target=CONST) overrides the field', FL, """
    INTERNAL_URL = "https://jobs.example.go.kr/submit"

    @app.route("/submit", methods=["POST"])
    def submit():
        job = dict(request.get_json(), target=INTERNAL_URL)
        return requests.post(job["target"], json=job, timeout=5).text
"""),
('L05', 'list with the constant URL first', FL, """
    API_URL = "https://api.example.go.kr/search"

    @app.route("/search")
    def search():
        call = [API_URL, request.args.get("q", "")]
        return requests.get(call[0], params={"q": call[1]}, timeout=5).text
"""),
('L06', 'model checked through model_dump(), used through the attribute', FA, """
    from pydantic import BaseModel
    KINDS = {"users", "orders"}

    class ExportReq(BaseModel):
        kind: str
        compress: bool = False

    @app.post("/export")
    def export(body: ExportReq):
        data = body.model_dump()
        if data["kind"] not in KINDS:
            raise HTTPException(400)
        return FileResponse(f"/srv/export/{body.kind}.csv")
"""),
('L07', 'args, form = request.args, request.form (tuple alias)', FL, """
    FORMATS = {"csv", "xlsx"}

    @app.route("/export", methods=["GET", "POST"])
    def export():
        args, form = request.args, request.form
        if request.args.get("fmt") not in FORMATS:
            abort(400)
        return send_file(f"/srv/export/latest.{args['fmt']}", download_name=form.get("title", "export"))
"""),
('L08', 'alias chain a = request.args; b = a', FL, """
    FORMATS = {"csv", "xlsx"}

    @app.route("/export")
    def export():
        a = request.args
        b = a
        if b.get("fmt") not in FORMATS:
            abort(400)
        return send_file(f"/srv/export/latest.{request.args['fmt']}")
"""),
('L10', 'client-supplied internal field rejected by a key test, then defaulted', FL, """
    INTERNAL_CALLBACK = "https://hooks.example.go.kr/internal"

    @app.route("/relay", methods=["POST"])
    def relay():
        payload = request.get_json()
        if "callback" in payload:
            abort(400, "callback is not accepted from clients")
        payload.setdefault("callback", INTERNAL_CALLBACK)
        return requests.post(payload["callback"], json=payload, timeout=5).text
"""),
('M01', 'nonlocal reset by a nested function that is always called', FL, """
    @app.route("/done")
    def done():
        target = request.args.get("next", "")
        app.logger.info("client suggested %s", target)

        def use_dashboard():
            nonlocal target
            target = url_for("dashboard")

        use_dashboard()
        return redirect(target)
"""),
('M02', 'rebinding in try, handler aborts, finally logs', FL, """
    from exports import build_export, ExportError

    @app.route("/export")
    def export():
        path = request.args.get("path", "")
        app.logger.info("legacy path parameter ignored: %s", path)
        try:
            path = build_export()
        except ExportError:
            abort(500)
        finally:
            app.logger.info("export attempted")
        return send_file(path)
"""),
('M03', 'while loop rebinding the logged name', FL, """
    SEEDS = ("https://a.example.go.kr/feed", "https://b.example.go.kr/feed")

    @app.route("/crawl")
    def crawl():
        url = request.args.get("start", "")
        app.logger.info("crawl requested, client start=%s ignored", url)
        queue, seen = list(SEEDS), 0
        while queue:
            url = queue.pop()
            seen += requests.get(url, timeout=5).status_code == 200
        return jsonify(ok=seen)
"""),
('N01', 'NewType parameter backed by a validating dependency elsewhere', FA, """
    from typing import NewType
    ReportName = NewType("ReportName", str)
    REPORTS = {"daily", "weekly"}

    def known_report(name: str) -> ReportName:
        if name not in REPORTS:
            raise HTTPException(404)
        return ReportName(name)

    @app.get("/reports/{name}")
    def report(report_name: ReportName = Depends(known_report)):
        return FileResponse(f"/srv/reports/{report_name}.pdf")
"""),
('N03', 'typing.cast after an Enum lookup', FL, """
    from enum import Enum
    from typing import cast

    class Kind(str, Enum):
        users = "users"
        orders = "orders"

    @app.route("/export")
    def export():
        kind = cast(Kind, Kind(request.args.get("kind", "users")))
        return send_file(f"/srv/export/{kind.value}.csv")
"""),
('N04', 'dataclass built from validated JSON', FL, """
    from dataclasses import dataclass
    KINDS = {"users", "orders"}

    @dataclass
    class Job:
        kind: str
        compress: bool = False

    @app.route("/export", methods=["POST"])
    def export():
        data = request.get_json()
        if data.get("kind") not in KINDS:
            abort(400)
        job = Job(kind=data["kind"], compress=bool(data.get("compress")))
        return send_file(f"/srv/export/{job.kind}.csv")
"""),
('U01', 'Django UploadedFile.name (already reduced to a base name by Django)', DJ, """
    from django.conf import settings

    def upload(request):
        doc = request.FILES["doc"]
        with open(os.path.join(settings.MEDIA_ROOT, "inbox", doc.name), "wb") as dest:
            dest.write(doc.read())
        return HttpResponse("ok")
"""),
('U02', 'FileStorage.name is the form field name, not the client file name', FL, """
    @app.route("/avatar", methods=["POST"])
    def avatar():
        f = request.files["avatar"]
        with open(os.path.join("/srv/uploads", f.name + ".bin"), "wb") as out:
            out.write(f.read())
        return "ok"
"""),
('U03', 'send_file of the uploaded object', FL, """
    @app.route("/preview", methods=["POST"])
    def preview():
        upload = request.files["image"]
        return send_file(upload, mimetype="image/png")
"""),
('W01', 'Redis membership via exists()', FL, """
    import redis
    r = redis.Redis()

    @app.route("/doc")
    def doc():
        name = request.args.get("name", "")
        if not r.exists(f"published:{name}"):
            abort(404)
        return send_file(os.path.join("/srv/docs", name))
"""),
('W02', 'Django default_storage.exists() (raises outside MEDIA_ROOT)', DJ, """
    from django.conf import settings
    from django.core.files.storage import default_storage

    def download(request):
        name = request.GET.get("name", "")
        if not default_storage.exists(name):
            raise Http404
        return FileResponse(open(os.path.join(settings.MEDIA_ROOT, name), "rb"))
"""),
('W03', 'length test: exactly one character', FL, """
    @app.route("/glossary")
    def glossary():
        letter = request.args.get("letter", "a")
        if len(letter) != 1:
            abort(400)
        return send_file("/srv/glossary/" + letter + "/index.html")
"""),
('W04', 'validator called inside the log statement', FL, """
    NAME_RE = re.compile(r"[a-z0-9_-]{1,40}\\.pdf")

    def checked(name):
        if not NAME_RE.fullmatch(name):
            abort(400)
        return name

    @app.route("/report")
    def report():
        name = request.args.get("name", "")
        app.logger.info("serving report %s", checked(name))
        return send_file(os.path.join("/srv/reports", name))
"""),
('W06', 'basename must equal the name', FL, """
    @app.route("/dl")
    def dl():
        name = request.args.get("name", "")
        if not name or os.path.basename(name) != name or name in (".", ".."):
            abort(400)
        return send_file(os.path.join("/srv/files", name))
"""),
('W08', 'parameter must be absent (presence test aborts)', FL, """
    DEFAULT_PATH = "/srv/reports/latest.pdf"

    @app.route("/report")
    def report():
        if request.args.get("path"):
            abort(400, "path is no longer supported")
        return send_file(request.args.get("path") or DEFAULT_PATH)
"""),
('W09', 'guessed MIME type must be allow-listed', FL, """
    import mimetypes
    ALLOWED = {"image/png", "image/jpeg"}
    NAMES = set(os.listdir("/srv/images"))

    @app.route("/image")
    def image():
        name = request.args.get("name", "")
        mime = mimetypes.guess_type(name)[0]
        if mime not in ALLOWED or name not in NAMES:
            abort(404)
        return send_file(os.path.join("/srv/images", name), mimetype=mime)
"""),
('O01', 'send_from_directory', 'from flask import Flask, request, send_from_directory, abort\napp = Flask(__name__)\n', """
    @app.route("/download/<path:filename>")
    def download(filename):
        return send_from_directory("/srv/files", filename, as_attachment=True)
"""),
('O02', 'secure_filename upload, then served back', FL, """
    from werkzeug.utils import secure_filename
    UPLOAD_FOLDER = "/srv/uploads"

    @app.route("/upload", methods=["POST"])
    def upload():
        f = request.files.get("file")
        if f is None or f.filename == "":
            return jsonify(error="no file"), 400
        filename = secure_filename(f.filename)
        path = os.path.join(UPLOAD_FOLDER, filename)
        f.save(path)
        return send_file(path)
"""),
('O03', 'proxy through an allowlist dict', FL, """
    SERVICES = {"weather": "https://weather.example.go.kr/api", "air": "https://air.example.go.kr/api"}

    @app.route("/api/<service>")
    def api(service):
        base = SERVICES.get(service)
        if base is None:
            return jsonify(error="unknown service"), 404
        resp = requests.get(base, params=request.args, timeout=5)
        return resp.content, resp.status_code
"""),
('O04', 'int converter + DB row', FL, """
    from models import Document

    @app.route("/documents/<int:doc_id>/download")
    def download(doc_id):
        doc = Document.query.get_or_404(doc_id)
        return send_file(doc.path, as_attachment=True, download_name=doc.title + ".pdf")
"""),
('O05', 'Django login redirect with url_has_allowed_host_and_scheme', DJ, """
    from django.utils.http import url_has_allowed_host_and_scheme

    def login_done(request):
        next_url = request.POST.get("next") or request.GET.get("next") or "/"
        if not url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()}, require_https=request.is_secure()):
            next_url = "/"
        return redirect(next_url)
"""),
('O06', 'FastAPI pathlib resolve + is_relative_to', FA, """
    from pathlib import Path
    BASE = Path("/srv/files").resolve()

    @app.get("/files/{file_path:path}")
    def files(file_path: str):
        target = (BASE / file_path).resolve()
        if not target.is_relative_to(BASE) or not target.is_file():
            raise HTTPException(status_code=404, detail="not found")
        return FileResponse(target)
"""),
('O07', 'render_template_string with a constant template', FL, """
    GREETING = "<h1>Hello {{ name }}</h1><p>{{ message }}</p>"

    @app.route("/hello")
    def hello():
        name = request.args.get("name", "guest")
        return render_template_string(GREETING, name=name, message=request.args.get("msg", ""))
"""),
('O08', 'fixed API base with user parameters', FL, """
    API = "https://api.example.go.kr/v1"

    @app.route("/users/<user_id>/orders")
    def orders(user_id):
        page = request.args.get("page", 1, type=int)
        resp = requests.get(f"{API}/users/{user_id}/orders", params={"page": page, "q": request.args.get("q", "")}, timeout=5)
        return jsonify(resp.json())
"""),
('O09', 'DRF serializer', DRF, """
    from .serializers import ExportSerializer   # kind = ChoiceField(["users", "orders"])

    class Export(APIView):
        def post(self, request):
            serializer = ExportSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            kind = serializer.validated_data["kind"]
            return FileResponse(open(f"/srv/export/{kind}.csv", "rb"))
"""),
('O10', 'uuid-named upload with an extension allowlist', FA, """
    import uuid
    ALLOWED = {".png", ".jpg", ".pdf"}

    @app.post("/upload")
    async def upload(file: UploadFile):
        ext = os.path.splitext(file.filename or "")[1].lower()
        if ext not in ALLOWED:
            raise HTTPException(status_code=400, detail="unsupported type")
        dest = os.path.join("/srv/uploads", uuid.uuid4().hex + ext)
        with open(dest, "wb") as out:
            out.write(await file.read())
        return {"stored": os.path.basename(dest)}
"""),
]


@pytest.mark.parametrize("case", SAFE5, ids=[c[0] + " " + c[1] for c in SAFE5])
def test_safe_shape(case: tuple) -> None:
    cid, title, header, code = case[:4]
    assert _flows(header, code) == KNOWN_REPORTS.get(cid, []), (cid, title)
