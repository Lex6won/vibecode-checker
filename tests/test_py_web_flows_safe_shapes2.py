"""독립 적대적 검증 2차(2026-11-21)가 만든 안전한 코드 — 1차와 다른 모양. 둘째 판은 이 가운데 20개를 냈다.
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

SAFE2 = [
('N01', "urljoin(BASE, '/v1/items/' + id) keeps the host", FL, """
    from urllib.parse import urljoin
    API_BASE = "https://api.example.go.kr/"

    @app.route("/items/<item_id>")
    def item(item_id):
        return requests.get(urljoin(API_BASE, f"/v1/items/{item_id}"), timeout=5).text
"""),
('N02', 'list[Model] body, int field in path', FA, """
    from pydantic import BaseModel

    class Item(BaseModel):
        doc_id: int
        note: str = ""

    @app.post("/bundle")
    def bundle(items: list[Item]):
        out = []
        for it in items:
            with open(f"/srv/docs/{it.doc_id}.txt") as fh:
                out.append(fh.read())
        return out
"""),
('N03', 'route-level dependency validates the path param', FA, """
    def verify_name(name: str):
        if not re.fullmatch(r"[a-z0-9_-]{1,40}", name):
            raise HTTPException(400)

    @app.get("/files/{name}", dependencies=[Depends(verify_name)])
    def files(name: str):
        return FileResponse(f"/srv/files/{name}.pdf")
"""),
('N04', 'imported guard with a non-validator name', FL, """
    from netguard import block_private_hosts   # raises Forbidden for non-public hosts

    @app.route("/preview")
    def preview():
        url = request.args.get("url", "")
        block_private_hosts(url)
        return requests.get(url, timeout=5).text
"""),
('N05', 'Enum(raw) in try, raw string used afterwards', FL, """
    from enum import Enum

    class Kind(Enum):
        USERS = "users"
        ORDERS = "orders"

    @app.route("/export")
    def export():
        raw = request.args.get("kind", "")
        try:
            kind = Kind(raw)
        except ValueError:
            abort(400)
        return send_file(f"/srv/export/{raw}.csv", download_name=kind.name.lower() + ".csv")
"""),
('N06', "checked with .get('url'), used with ['url']", FL, """
    ALLOWED_URLS = {"https://a.example.go.kr/feed", "https://b.example.go.kr/feed"}

    @app.route("/pull", methods=["POST"])
    def pull():
        data = request.get_json()
        if data.get("url") not in ALLOWED_URLS:
            abort(403)
        return requests.get(data["url"], timeout=5).text
"""),
('N07', 'checked request.args.get with default, used without', FL, """
    SAFE_TARGETS = {"/", "/home", "/settings"}

    @app.route("/go")
    def go():
        if request.args.get("next", "/") not in SAFE_TARGETS:
            abort(400)
        return redirect(request.args.get("next") or "/")
"""),
('N08', 'private guard method on the handler class', TO, """
    BASE = os.path.realpath("/srv/files")

    class Download(tornado.web.RequestHandler):
        def _abort_if_outside(self, path):
            if not path.startswith(BASE + os.sep):
                raise tornado.web.HTTPError(403)

        def post(self):
            name = json.loads(self.request.body)["name"]
            path = os.path.realpath(os.path.join(BASE, name))
            self._abort_if_outside(path)
            with open(path) as fh:
                self.write(fh.read())
"""),
('N09', 'custom URL converter with a strict regex', FL, """
    from werkzeug.routing import BaseConverter

    class SlugConverter(BaseConverter):
        regex = r"[a-z0-9-]{1,40}"

    app.url_map.converters["slug"] = SlugConverter

    @app.route("/pages/<slug:name>")
    def page(name):
        return send_file(f"/srv/pages/{name}.html")
"""),
('N10', 'p = Path(raw); p.name', FL, """
    from pathlib import Path
    BASE = Path("/srv/files")

    @app.route("/dl")
    def dl():
        p = Path(request.args.get("name", ""))
        return send_file(BASE / p.name)
"""),
('N11', 'bytes.fromhex() in try as validation', FL, """
    @app.route("/blob/<digest>")
    def blob(digest):
        try:
            bytes.fromhex(digest)
        except ValueError:
            abort(400)
        return send_file(f"/srv/blobs/{digest[:2]}/{digest}")
"""),
('N12', 'before_request validates view_args for the blueprint', FL, """
    from flask import Blueprint
    bp = Blueprint("docs", __name__)
    NAME_RE = re.compile(r"[a-z0-9_-]{1,40}")

    @bp.before_request
    def check_name():
        if not NAME_RE.fullmatch((request.view_args or {}).get("name", "")):
            abort(400)

    @bp.route("/docs/<name>")
    def doc(name):
        return send_file(f"/srv/docs/{name}.pdf")
"""),
('N13', 'nested model numeric field', FA, """
    from pydantic import BaseModel

    class Period(BaseModel):
        year: int
        month: int

    class ReportReq(BaseModel):
        period: Period
        title: str

    @app.post("/report")
    def report(body: ReportReq):
        return FileResponse(f"/srv/reports/{body.period.year}/{body.period.month}.pdf", filename=body.title)
"""),
('N14', 'inherited model numeric field', FA, """
    from pydantic import BaseModel

    class BaseReq(BaseModel):
        doc_id: int

    class DownloadReq(BaseReq):
        note: str = ""

    @app.post("/download")
    def download(body: DownloadReq):
        return FileResponse(f"/srv/docs/{body.doc_id}.pdf")
"""),
('N15', 'list[Enum] query parameter', FA, """
    from enum import Enum

    class Section(str, Enum):
        intro = "intro"
        usage = "usage"

    @app.get("/manual")
    def manual(sections: list[Section] = Query(...)):
        out = []
        for s in sections:
            with open(f"/srv/manual/{s.value}.md") as fh:
                out.append(fh.read())
        return out
"""),
('N16', 'yarl URL / segment (aiohttp)', AIO, """
    from yarl import URL
    API = URL("https://api.example.go.kr/v1")

    async def user(request):
        uid = (await request.json())["uid"]
        async with aiohttp.ClientSession() as session:
            async with session.get(API / "users" / uid) as resp:
                return web.Response(text=await resp.text())
"""),
('N17', '.format() keywords in a different order than the placeholders', FL, """
    API_BASE = "https://api.example.go.kr"

    @app.route("/items/<item_id>")
    def item(item_id):
        url = "{base}/v1/items/{item_id}".format(item_id=item_id, base=API_BASE)
        return requests.get(url, timeout=5).text
"""),
('N18', 'extracted field validated, original expression used', FL, """
    NAME_RE = re.compile(r"[a-z0-9_-]{1,40}")

    @app.route("/read", methods=["POST"])
    def read():
        data = request.get_json()
        name = data["name"]
        if not NAME_RE.fullmatch(name):
            abort(400)
        with open(os.path.join("/srv/notes", data["name"] + ".md")) as fh:
            return fh.read()
"""),
('N19', 'x = int(x) in try, except aborts', FL, """
    @app.route("/doc")
    def doc():
        doc_id = request.args.get("id")
        try:
            doc_id = int(doc_id)
        except (TypeError, ValueError):
            abort(400)
        return send_file(f"/srv/docs/{doc_id}.pdf")
"""),
('N20', 'name = secure_filename(name) in try, except aborts', FL, """
    from werkzeug.utils import secure_filename

    @app.route("/dl")
    def dl():
        name = request.args.get("name")
        try:
            name = secure_filename(name)
        except TypeError:
            abort(400)
        return send_file(os.path.join("/srv/files", name))
"""),
('N21', "'%(base)s/...' % mapping", FL, """
    API_BASE = "https://api.example.go.kr"

    @app.route("/items/<item_id>")
    def item(item_id):
        url = "%(base)s/v1/items/%(id)s" % {"id": item_id, "base": API_BASE}
        return requests.get(url, timeout=5).text
"""),
('N22', 'for/else prefix allowlist', FL, """
    PREFIXES = ("https://api.example.go.kr/", "https://data.example.go.kr/")

    @app.route("/proxy")
    def proxy():
        url = request.args.get("url", "")
        for prefix in PREFIXES:
            if url.startswith(prefix):
                break
        else:
            abort(403)
        return requests.get(url, timeout=5).text
"""),
('N23', 'name must be in os.listdir(BASE)', FL, """
    BASE = "/srv/files"

    @app.route("/dl")
    def dl():
        name = request.args.get("name", "")
        if name not in os.listdir(BASE):
            abort(404)
        return send_file(os.path.join(BASE, name))
"""),
('N24', 'candidates dict built from glob', FL, """
    from pathlib import Path
    BASE = Path("/srv/reports")

    @app.route("/report")
    def report():
        candidates = {p.name: p for p in BASE.glob("*.pdf")}
        path = candidates.get(request.args.get("name", ""))
        if path is None:
            abort(404)
        return send_file(path)
"""),
('N25', 'int() inside os.path.join', FL, """
    @app.route("/doc/<doc_id>")
    def doc(doc_id):
        return send_file(os.path.join("/srv/docs", str(int(doc_id)), "main.pdf"))
"""),
('N26', 'Enum[raw] lookup', FL, """
    from enum import Enum

    class Theme(Enum):
        light = "light.css"
        dark = "dark.css"

    @app.route("/css")
    def css():
        raw = request.args.get("theme", "light")
        try:
            theme = Theme[raw]
        except KeyError:
            abort(404)
        return send_file("/srv/static/" + theme.value)
"""),
('N27', 'all() over a list of names, then a second loop', FL, """
    NAME_RE = re.compile(r"[a-z0-9_-]{1,40}\\.csv")

    @app.route("/merge")
    def merge():
        names = request.args.getlist("f")
        if not all(NAME_RE.fullmatch(n) for n in names):
            abort(400)
        out = ""
        for n in names:
            out += open(os.path.join("/srv/data", n)).read()
        return out
"""),
('N28', 'bad = [..]; if bad: abort', FL, """
    ALLOWED = {"a.csv", "b.csv", "c.csv"}

    @app.route("/merge")
    def merge():
        names = request.args.getlist("f")
        bad = [n for n in names if n not in ALLOWED]
        if bad:
            abort(400)
        out = ""
        for n in names:
            out += open(os.path.join("/srv/data", n)).read()
        return out
"""),
('N29', 'segment-by-segment join with rejects', FL, """
    @app.route("/tree/<path:rel>")
    def tree(rel):
        path = "/srv/tree"
        for part in rel.split("/"):
            if part in ("", ".", "..") or "\\\\" in part:
                abort(400)
            path = os.path.join(path, part)
        return send_file(path)
"""),
('N30', 'realpath + stored startswith result', FL, """
    BASE = os.path.realpath("/srv/files")

    @app.route("/dl")
    def dl():
        full = os.path.join(BASE, request.args.get("name", ""))
        real = os.path.realpath(full)
        inside = real.startswith(BASE + os.sep)
        if not inside:
            abort(403)
        return send_file(real)
"""),
('N31', 'MethodView with resolving helper method', FL, """
    from flask.views import MethodView
    BASE = os.path.realpath("/srv/files")

    class Download(MethodView):
        def _resolve(self, name):
            full = os.path.realpath(os.path.join(BASE, name))
            if not full.startswith(BASE + os.sep):
                abort(403)
            return full

        def get(self):
            return send_file(self._resolve(request.args.get("name", "")))
"""),
('N32', 'strptime(...).strftime(...) rebuilt value', FL, """
    from datetime import datetime

    @app.route("/log")
    def log():
        day = datetime.strptime(request.args.get("day", ""), "%Y-%m-%d").strftime("%Y%m%d")
        return send_file(f"/var/log/app/{day}.log")
"""),
('N33', 'host picked from a table, path from the request', FL, """
    HOSTS = {"kr": "kr.api.example.go.kr", "us": "us.api.example.go.kr"}

    @app.route("/r/<region>/<path:rest>")
    def region(region, rest):
        if region not in HOSTS:
            abort(404)
        return requests.get(f"https://{HOSTS[region]}/v1/{rest}", timeout=5).text
"""),
('N34', 'urlsplit().netloc equality', FL, """
    from urllib.parse import urlsplit

    @app.route("/proxy")
    def proxy():
        url = request.args.get("url", "")
        parts = urlsplit(url)
        if parts.scheme != "https" or parts.netloc != "api.example.go.kr":
            abort(403)
        return requests.get(url, timeout=5).text
"""),
('N35', 'jsonschema.validate on the whole body', FL, """
    import jsonschema
    SCHEMA = {"type": "object", "properties": {"feed": {"enum": ["https://a.example.go.kr/rss"]}}, "required": ["feed"]}

    @app.route("/pull", methods=["POST"])
    def pull():
        data = request.get_json()
        jsonschema.validate(instance=data, schema=SCHEMA)
        return requests.get(data["feed"], timeout=5).text
"""),
('N36', 'upload saved under tempfile name', FA, """
    import shutil, tempfile
    from pathlib import Path

    @app.post("/convert")
    async def convert(file: UploadFile):
        with tempfile.NamedTemporaryFile(suffix=Path(file.filename).suffix, delete=False) as tmp:
            shutil.copyfileobj(file.file, tmp)
        with open(tmp.name, "rb") as fh:
            return {"size": len(fh.read())}
"""),
('N37', 'upload ext allowlist via rsplit', FL, """
    import uuid
    ALLOWED_EXT = {"png", "jpg", "gif"}

    @app.route("/upload", methods=["POST"])
    def upload():
        f = request.files["file"]
        ext = f.filename.rsplit(".", 1)[-1].lower()
        if ext not in ALLOWED_EXT:
            abort(400)
        dest = os.path.join("/srv/uploads", f"{uuid.uuid4().hex}.{ext}")
        with open(dest, "wb") as out:
            out.write(f.read())
        return "ok"
"""),
('N38', 'Django storage + get_valid_filename', DJ, """
    from django.conf import settings
    from django.utils.text import get_valid_filename

    def download(request):
        name = get_valid_filename(request.GET.get("name", ""))
        return FileResponse(open(os.path.join(settings.MEDIA_ROOT, "public", name), "rb"))
"""),
('N39', 'DRF query_params choice', 'import os\nfrom rest_framework.views import APIView\nfrom django.http import FileResponse\n', """
    FORMATS = ("csv", "xlsx")

    class Export(APIView):
        def get(self, request):
            fmt = request.query_params.get("format", "csv")
            if fmt not in FORMATS:
                fmt = "csv"
            return FileResponse(open(f"/srv/export/latest.{fmt}", "rb"))
"""),
('N40', 'aiohttp match_info + fixed upstream', AIO, """
    UPSTREAM = "http://inventory.internal:8080"

    async def stock(request):
        sku = request.match_info["sku"]
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{UPSTREAM}/stock/{sku}") as resp:
                return web.json_response(await resp.json())
"""),
('N41', 'template file read from disk, value as context', FL, """
    TPL_DIR = "/srv/templates"

    @app.route("/mail/preview")
    def preview():
        with open(os.path.join(TPL_DIR, "welcome.html")) as fh:
            source = fh.read()
        return render_template_string(source, name=request.args.get("name", ""))
"""),
('N42', 'redirect to same host with fixed prefix', FL, """
    @app.route("/lang/<code>")
    def lang(code):
        if code not in ("ko", "en"):
            code = "ko"
        back = request.args.get("back", "")
        return redirect(f"/{code}/home?from=" + back)
"""),
('N43', 'getattr on Enum then None check', FL, """
    from enum import Enum

    class Report(Enum):
        daily = "/srv/reports/daily.pdf"
        weekly = "/srv/reports/weekly.pdf"

    @app.route("/report")
    def report():
        member = getattr(Report, request.args.get("kind", ""), None)
        if member is None:
            abort(404)
        return send_file(member.value)
"""),
('N44', 'hex-only token check with all()', FL, """
    @app.route("/blob")
    def blob():
        token = request.args.get("t", "")
        if len(token) != 40 or not all(c in "0123456789abcdef" for c in token):
            abort(400)
        return send_file(os.path.join("/srv/blobs", token))
"""),
('N45', 'Field(pattern=...) on a model field', FA, """
    from pydantic import BaseModel, Field

    class PageReq(BaseModel):
        slug: str = Field(pattern=r"^[a-z0-9-]{1,40}$")
        note: str = ""

    @app.post("/page")
    def page(body: PageReq):
        return FileResponse(f"/srv/pages/{body.slug}.html")
"""),
('N46', 'Depends()-validated name returned by dependency', FA, """
    def valid_name(name: str) -> str:
        if not re.fullmatch(r"[a-z0-9_-]{1,40}", name):
            raise HTTPException(400)
        return name

    @app.get("/files/{name}")
    def files(safe_name: str = Depends(valid_name)):
        return FileResponse(f"/srv/files/{safe_name}.pdf")
"""),
('N47', 'set subset check', FL, """
    ALLOWED = {"a.csv", "b.csv"}

    @app.route("/merge")
    def merge():
        names = request.args.getlist("f")
        if not set(names) <= ALLOWED:
            abort(400)
        return "".join(open(os.path.join("/srv/data", n)).read() for n in names)
"""),
('N48', 'while loop that strips traversal then basename check', FL, """
    @app.route("/dl")
    def dl():
        name = request.args.get("name", "")
        name = name.replace("\\\\", "/")
        if name != os.path.basename(name) or name in ("", ".", ".."):
            abort(400)
        return send_file(os.path.join("/srv/files", name))
"""),
('N49', 'client from Depends with fixed base path', FA, """
    from myapp.deps import get_client

    @app.get("/orders/{order_id}")
    async def order(order_id: str, client: httpx.AsyncClient = Depends(get_client)):
        r = await client.get(f"/internal/orders/{order_id}")
        return r.json()
"""),
('N50', 'str field compared to a constant list via lower()', FA, """
    @app.get("/stats")
    def stats(period: str = "daily"):
        if period.lower() not in ("daily", "weekly", "monthly"):
            raise HTTPException(400)
        return FileResponse(f"/srv/stats/{period.lower()}.csv")
"""),
('N51', 'imported model, numeric-looking field (cross-file)', FA, """
    from myapp.schemas import ExportBody   # doc_id: int

    @app.post("/export")
    def export(body: ExportBody):
        return FileResponse(f"/srv/exports/{body.doc_id}.pdf")
"""),
('N52', 'sink inside validated branch only, default otherwise', FL, """
    from urllib.parse import urlparse

    @app.route("/avatar")
    def avatar():
        src = request.args.get("src", "")
        if urlparse(src).hostname == "cdn.example.go.kr":
            return requests.get(src, timeout=5).content
        return send_file("/srv/static/default.png")
"""),
]


@pytest.mark.parametrize("case", SAFE2, ids=[c[0] + " " + c[1] for c in SAFE2])
def test_safe_shape(case: tuple) -> None:
    cid, title, header, code = case[:4]
    assert _flows(header, code) == KNOWN_REPORTS.get(cid, []), (cid, title)
