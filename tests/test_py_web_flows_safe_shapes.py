"""독립 적대적 검증 1차(2026-11-21)가 만든 안전한 코드 100가지 — 웹 요청 값 추적(py_web_flows)이 **보고하면 안 되는** 모양.

첫 판 추적기는 이 가운데 42개를 '확인된 취약점'으로 냈다.
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

SAFE = [
('S01', 'allowlist set membership', FL, """
    ALLOWED = {"https://a.example.go.kr/feed", "https://b.example.go.kr/feed"}

    @app.route("/proxy")
    def proxy():
        url = request.args.get("url", "")
        if url not in ALLOWED:
            return jsonify(error="forbidden"), 403
        return requests.get(url, timeout=5).text
"""),
('S02', 'urlparse two-step (parsed -> host)', FL, """
    from urllib.parse import urlparse
    ALLOWED_HOSTS = {"api.example.go.kr"}

    @app.route("/proxy")
    def proxy():
        url = request.args.get("url", "")
        parsed = urlparse(url)
        host = parsed.hostname
        if host not in ALLOWED_HOSTS:
            abort(403)
        return requests.get(url, timeout=5).text
"""),
('S03', 'urlparse scheme+host in one if', FL, """
    from urllib.parse import urlparse
    ALLOWED_HOSTS = {"api.example.go.kr"}

    @app.route("/proxy")
    def proxy():
        url = request.args.get("url", "")
        parsed = urlparse(url)
        if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
            abort(403)
        return requests.get(url, timeout=5).text
"""),
('S04', 're.fullmatch result in variable, if not m', FL, """
    BASE = "/srv/reports"

    @app.route("/report")
    def report():
        name = request.args.get("name", "")
        m = re.fullmatch(r"[a-z0-9_]{1,40}\\.pdf", name)
        if not m:
            abort(400)
        return send_file(os.path.join(BASE, name))
"""),
('S05', 're.fullmatch inline', FL, """
    BASE = "/srv/reports"

    @app.route("/report")
    def report():
        name = request.args.get("name", "")
        if not re.fullmatch(r"[a-z0-9_]{1,40}\\.pdf", name):
            abort(400)
        return send_file(os.path.join(BASE, name))
"""),
('S06', 'pathlib resolve + is_relative_to', FA, """
    from pathlib import Path
    BASE = Path("/srv/files").resolve()

    @app.get("/files/{name:path}")
    def files(name: str):
        target = (BASE / name).resolve()
        if not target.is_relative_to(BASE):
            raise HTTPException(status_code=404)
        return FileResponse(target)
"""),
('S07', 'pathlib relative_to in try/except (assigned)', FA, """
    from pathlib import Path
    BASE = Path("/srv/files").resolve()

    @app.get("/files/{name:path}")
    def files(name: str):
        target = (BASE / name).resolve()
        try:
            rel = target.relative_to(BASE)
        except ValueError:
            raise HTTPException(status_code=404)
        return FileResponse(BASE / rel)
"""),
('S08', 'os.path.commonpath', FL, """
    BASE = os.path.realpath("/srv/files")

    @app.route("/dl")
    def dl():
        name = request.args["name"]
        full = os.path.realpath(os.path.join(BASE, name))
        if os.path.commonpath([BASE, full]) != BASE:
            abort(403)
        return send_file(full)
"""),
('S09', 'str(target).startswith(str(BASE))', FA, """
    from pathlib import Path
    BASE = Path("/srv/files").resolve()

    @app.get("/files/{name:path}")
    def files(name: str):
        target = (BASE / name).resolve()
        if not str(target).startswith(str(BASE) + os.sep):
            raise HTTPException(status_code=403)
        return FileResponse(target)
"""),
('S10', 'early return allowlist of file names', FL, """
    DOWNLOADABLE = ("manual.pdf", "terms.pdf")

    @app.route("/dl/<name>")
    def dl(name):
        if name not in DOWNLOADABLE:
            return jsonify(error="not found"), 404
        return send_file(os.path.join("/srv/static/docs", name))
"""),
('S11', 'helper validates and returns cleaned path', FL, """
    BASE = os.path.realpath("/srv/files")

    def resolve_report_path(name):
        full = os.path.realpath(os.path.join(BASE, name))
        if not full.startswith(BASE + os.sep):
            abort(403)
        return full

    @app.route("/dl")
    def dl():
        path = resolve_report_path(request.args.get("name", ""))
        return send_file(path)
"""),
('S12', 'same-file helper that aborts (name without validator word)', FL, """
    from urllib.parse import urlparse

    def _same_origin_or_404(target):
        host = urlparse(target).netloc
        if host and host != request.host:
            abort(404)
        if not target.startswith("/") or target.startswith("//"):
            abort(404)

    @app.route("/go")
    def go():
        target = request.args.get("next", "/")
        _same_origin_or_404(target)
        return redirect(target)
"""),
('S13', 'MethodView class with allowlist', FL, """
    from flask.views import MethodView
    FEEDS = {"notice": "https://www.example.go.kr/notice.xml"}

    class FeedView(MethodView):
        def get(self):
            key = request.args.get("feed", "notice")
            if key not in FEEDS:
                abort(404)
            return requests.get(FEEDS[key], timeout=5).text

    app.add_url_rule("/feed", view_func=FeedView.as_view("feed"))
"""),
('S14', 'pydantic model with host allowlist validator', FA, """
    from pydantic import BaseModel, HttpUrl, field_validator
    ALLOWED_HOSTS = {"api.example.go.kr"}

    class FetchBody(BaseModel):
        url: HttpUrl

        @field_validator("url")
        @classmethod
        def host_allowed(cls, v):
            if v.host not in ALLOWED_HOSTS:
                raise ValueError("host not allowed")
            return v

    @app.post("/fetch")
    async def fetch(payload: FetchBody):
        async with httpx.AsyncClient() as client:
            r = await client.get(str(payload.url))
        return r.json()
"""),
('S15', 'pydantic model int field in path', FA, """
    from pydantic import BaseModel

    class ExportBody(BaseModel):
        doc_id: int
        year: int

    @app.post("/export")
    def export(body: ExportBody):
        return FileResponse(f"/srv/exports/{body.year}/{body.doc_id}.pdf")
"""),
('S16', 'Enum param imported from another module', FA, """
    from app.schemas import ReportKind   # class ReportKind(str, Enum)

    @app.get("/reports/{kind}")
    def report(kind: ReportKind):
        return FileResponse(f"/srv/reports/{kind.value}.pdf")
"""),
('S17', 'Literal type alias param', FA, """
    from typing import Literal
    Mode = Literal["daily", "weekly", "monthly"]

    @app.get("/stats/{mode}")
    def stats(mode: Mode):
        return FileResponse(f"/srv/stats/{mode}.csv")
"""),
('S18', 'dict dispatch', FL, """
    BACKENDS = {"tax": "https://tax.example.go.kr/api", "civil": "https://civil.example.go.kr/api"}

    @app.route("/svc/<name>/status")
    def status(name):
        base = BACKENDS.get(name)
        if base is None:
            abort(404)
        return requests.get(f"{base}/status", timeout=3).text
"""),
('S19', 'SQLAlchemy lookup by id', FL, """
    from models import db, Document

    @app.route("/doc/<doc_id>")
    def doc(doc_id):
        row = db.session.query(Document).filter(Document.id == doc_id).first()
        if row is None:
            abort(404)
        return send_file(row.storage_path, download_name=row.title)
"""),
('S20', 'Django get_object_or_404', DJ, """
    from .models import Attachment

    def download(request, pk):
        att = get_object_or_404(Attachment, pk=request.GET.get("id", pk))
        return FileResponse(open(att.file.path, "rb"))
"""),
('S21', 'config base URL f-string', FL, """
    @app.route("/users/<uid>/orders")
    def orders(uid):
        base = app.config["ORDER_API"]
        page = request.args.get("page", "1")
        return requests.get(f"{base}/users/{uid}/orders?page={page}", timeout=5).json()
"""),
('S22', 'constant URL template .format()', FL, """
    DETAIL_URL = "https://api.example.go.kr/v1/items/{item_id}"

    @app.route("/items/<item_id>")
    def item(item_id):
        return requests.get(DETAIL_URL.format(item_id=item_id), timeout=5).json()
"""),
('S23', "'/'.join([API_BASE, ...])", FL, """
    API_BASE = "https://api.example.go.kr/v1"

    @app.route("/users/<uid>")
    def user(uid):
        url = "/".join([API_BASE, "users", uid])
        return requests.get(url, timeout=5).json()
"""),
('S24', 'constant URL template % value', FL, """
    DETAIL_URL = "https://api.example.go.kr/v1/items/%s"

    @app.route("/items/<item_id>")
    def item(item_id):
        return requests.get(DETAIL_URL % item_id, timeout=5).json()
"""),
('S25', 'walrus allowlist on host', FL, """
    from urllib.parse import urlparse
    ALLOWED_HOSTS = {"api.example.go.kr"}

    @app.route("/proxy")
    def proxy():
        url = request.args.get("url", "")
        if (host := urlparse(url).hostname) not in ALLOWED_HOSTS:
            abort(403, f"{host} not allowed")
        return requests.get(url, timeout=5).text
"""),
('S26', 'walrus regex', FL, """
    NAME_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")

    @app.route("/page")
    def page():
        name = request.args.get("name", "")
        if not (m := NAME_RE.fullmatch(name)):
            abort(400)
        return open(f"/srv/pages/{m.group(0)}.html").read()
"""),
('S27', 'match statement on hostname', FL, """
    from urllib.parse import urlparse

    @app.route("/proxy")
    def proxy():
        url = request.args.get("url", "")
        match urlparse(url).hostname:
            case "api.example.go.kr" | "data.example.go.kr":
                pass
            case _:
                abort(403)
        return requests.get(url, timeout=5).text
"""),
('S28', 'match statement maps kind to constant', FL, """
    @app.route("/export")
    def export():
        kind = request.args.get("kind")
        match kind:
            case "users":
                path = "/srv/export/users.csv"
            case "orders":
                path = "/srv/export/orders.csv"
            case _:
                abort(400)
        return send_file(path)
"""),
('S29', 'comprehension filter then loop', FL, """
    from urllib.parse import urlparse
    ALLOWED_HOSTS = {"api.example.go.kr"}

    @app.route("/batch", methods=["POST"])
    def batch():
        urls = [u for u in request.get_json()["urls"] if urlparse(u).hostname in ALLOWED_HOSTS]
        return jsonify([requests.get(u, timeout=5).status_code for u in urls])
"""),
('S30', 'nested function validator (closure)', FL, """
    @app.route("/go")
    def go():
        def local_only(t):
            return t.startswith("/") and not t.startswith("//") and "\\\\" not in t

        target = request.args.get("next", "/")
        if not local_only(target):
            target = "/"
        return redirect(target)
"""),
('S31', 'decorator-injected object param', FL, """
    from functools import wraps
    from models import Report

    def load_report(fn):
        @wraps(fn)
        def inner(rid):
            return fn(rid, Report.query.get_or_404(rid))
        return inner

    @app.route("/reports/<int:rid>/file")
    @load_report
    def report_file(rid, report):
        return send_file(report.path)
"""),
('S32', 'int() in try as validation, string used', FL, """
    @app.route("/page")
    def page():
        num = request.args.get("n", "1")
        try:
            int(num)
        except ValueError:
            abort(400)
        return send_file(f"/srv/pages/{num}.html")
"""),
('S33', 'strptime in try as validation, string used', FL, """
    from datetime import datetime

    @app.route("/log")
    def log():
        day = request.args.get("day", "")
        try:
            datetime.strptime(day, "%Y-%m-%d")
        except ValueError:
            abort(400)
        return open(f"/var/log/app/{day}.log").read()
"""),
('S34', 'ternary allowlist', FL, """
    LANGS = ("ko", "en", "ja")

    @app.route("/i18n")
    def i18n():
        lang = request.args.get("lang", "ko")
        lang = lang if lang in LANGS else "ko"
        return open(f"/srv/i18n/{lang}.json").read()
"""),
('S35', 'boolean stored then tested', FL, """
    @app.route("/go")
    def go():
        target = request.args.get("next", "/")
        ok = target.startswith("/") and not target.startswith("//") and "\\\\" not in target
        if not ok:
            abort(400)
        return redirect(target)
"""),
('S36', 'validator or abort() short-circuit', FL, """
    from security import is_internal_url

    @app.route("/proxy")
    def proxy():
        url = request.args.get("url", "")
        is_internal_url(url) or abort(403)
        return requests.get(url, timeout=5).text
"""),
('S37', 'and-guard inside if', FL, """
    from urllib.parse import urlparse

    @app.route("/go")
    def go():
        nxt = request.args.get("next")
        if nxt and nxt.startswith("/") and not nxt.startswith("//") and "\\\\" not in nxt:
            return redirect(nxt)
        return redirect(url_for("index"))
"""),
('S38', 'if/else both branches reassign clean', FL, """
    from werkzeug.utils import secure_filename

    @app.route("/dl")
    def dl():
        name = request.args.get("name")
        if name:
            name = secure_filename(name)
        else:
            name = "index.txt"
        return send_file(os.path.join("/srv/files", name))
"""),
('S39', 'try/except both reassign (Enum)', FL, """
    from enum import Enum

    class Fmt(Enum):
        JSON = "json"
        CSV = "csv"

    @app.route("/export")
    def export():
        fmt = request.args.get("format", "json")
        try:
            fmt = Fmt(fmt).value
        except ValueError:
            fmt = "json"
        return send_file(f"/srv/export/data.{fmt}")
"""),
('S40', 'dict.get lookup then None check, key reused', FL, """
    DOCS = {"manual": "User manual", "terms": "Terms of service"}

    @app.route("/docs/<name>")
    def docs(name):
        title = DOCS.get(name)
        if title is None:
            abort(404)
        return send_file(os.path.join("/srv/docs", name + ".pdf"), download_name=title + ".pdf")
"""),
('S41', 'try TABLE[name] except KeyError, key reused', FL, """
    DOCS = {"manual": "User manual", "terms": "Terms of service"}

    @app.route("/docs/<name>")
    def docs(name):
        try:
            title = DOCS[name]
        except KeyError:
            abort(404)
        return send_file(os.path.join("/srv/docs", name + ".pdf"), download_name=title + ".pdf")
"""),
('S42', 'uuid name + Path(upload).suffix', FA, """
    import uuid
    from pathlib import Path
    UPLOAD_DIR = Path("/srv/uploads")

    @app.post("/upload")
    async def upload(file: UploadFile):
        suffix = Path(file.filename).suffix
        dest = UPLOAD_DIR / f"{uuid.uuid4().hex}{suffix}"
        with open(dest, "wb") as out:
            out.write(await file.read())
        return {"stored": dest.name}
"""),
('S43', 'Path(name).name', FL, """
    from pathlib import Path

    @app.route("/dl")
    def dl():
        name = Path(request.args.get("name", "")).name
        return send_file(os.path.join("/srv/files", name))
"""),
('S44', 'resolve + ipaddress is_private', FL, """
    import ipaddress, socket
    from urllib.parse import urlparse

    @app.route("/preview")
    def preview():
        url = request.args.get("url", "")
        host = urlparse(url).hostname or ""
        ip = ipaddress.ip_address(socket.gethostbyname(host))
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            abort(403)
        return requests.get(url, timeout=5, allow_redirects=False).text
"""),
('S45', 'itsdangerous signed token', FL, """
    from itsdangerous import URLSafeTimedSerializer, BadSignature
    signer = URLSafeTimedSerializer(app.config["SECRET_KEY"])

    @app.route("/dl")
    def dl():
        try:
            path = signer.loads(request.args["token"], max_age=300)
        except BadSignature:
            abort(403)
        return send_file(path)
"""),
('S46', 'upstream response variable named req', FL, """
    @app.route("/stations")
    def stations():
        req = requests.get("https://api.example.go.kr/v1/stations", timeout=5)
        data = req.json()
        detail = requests.get(data["detail_url"], timeout=5)
        return detail.text
"""),
('S47', 'httpx client with base_url, relative path', FA, """
    client = httpx.Client(base_url="https://api.example.go.kr/v1/")

    @app.get("/users/{user_id}")
    def user(user_id: str):
        return client.get(f"users/{user_id}").json()
"""),
('S48', 'relative redirect with query only', FL, """
    @app.route("/list")
    def listing():
        page = request.args.get("page", "1")
        if request.args.get("legacy"):
            return redirect("?page=" + page)
        return "ok"
"""),
('S49', 'test module with @patch and tmp_path', NONE, """
    from unittest.mock import patch
    from fastapi.testclient import TestClient
    from myapp.main import app

    client = TestClient(app)

    @patch("myapp.main.send_mail")
    def test_export_writes_file(send_mail, tmp_path):
        out = tmp_path / "report.csv"
        client.post("/export", json={"path": "report.csv"})
        with open(out, "w") as f:
            f.write("a,b")
        assert send_mail.called
"""),
('S50', 'Annotated dependency alias', FA, """
    from typing import Annotated
    from myapp.config import Config, get_config
    ConfigDep = Annotated[Config, Depends(get_config)]

    @app.get("/health/upstream")
    def upstream(cfg: ConfigDep):
        return httpx.get(cfg.upstream_url + "/health").json()

    @app.get("/license")
    def license_file(cfg: ConfigDep):
        return FileResponse(cfg.license_path)
"""),
('S51', 'Annotated[str, AfterValidator(...)]', FA, """
    from typing import Annotated
    from pydantic import AfterValidator

    def only_slug(v: str) -> str:
        if not re.fullmatch(r"[a-z0-9-]{1,40}", v):
            raise ValueError("bad slug")
        return v

    @app.get("/pages/{slug}")
    def page(slug: Annotated[str, AfterValidator(only_slug)]):
        return FileResponse(f"/srv/pages/{slug}.html")
"""),
('S52', 'alias of Annotated[str, StringConstraints(pattern)]', FA, """
    from typing import Annotated
    from pydantic import StringConstraints
    Slug = Annotated[str, StringConstraints(pattern=r"^[a-z0-9-]{1,40}$")]

    @app.get("/pages/{slug}")
    def page(slug: Slug):
        return FileResponse(f"/srv/pages/{slug}.html")
"""),
('S53', 'pydantic UUID4 param', FA, """
    from pydantic import UUID4

    @app.get("/docs/{doc_id}")
    def doc(doc_id: UUID4):
        return FileResponse(f"/srv/docs/{doc_id}.pdf")
"""),
('S54', 'pydantic PositiveInt param', FA, """
    from pydantic import PositiveInt

    @app.get("/docs/{doc_id}")
    def doc(doc_id: PositiveInt):
        return FileResponse(f"/srv/docs/{doc_id}.pdf")
"""),
('S55', 'Flask any() converter', FL, """
    @app.route("/help/<any(guide, faq, terms):section>")
    def help_page(section):
        return send_file(f"/srv/help/{section}.html")
"""),
('S56', 'Flask int converter with args', FL, """
    @app.route("/pages/<int(min=1):page>")
    def pages(page):
        return send_file(f"/srv/pages/{page}.html")
"""),
('S57', 'Django url_has_allowed_host_and_scheme', DJ, """
    from django.utils.http import url_has_allowed_host_and_scheme

    def login_done(request):
        nxt = request.GET.get("next", "/")
        if not url_has_allowed_host_and_scheme(nxt, allowed_hosts={request.get_host()}):
            nxt = "/"
        return HttpResponseRedirect(nxt)
"""),
('S58', 'DRF serializer validated_data', 'import requests\nfrom rest_framework.views import APIView\nfrom rest_framework.response import Response\n', """
    from .serializers import WebhookSerializer   # validates url against registered hooks

    class WebhookTest(APIView):
        def post(self, request):
            ser = WebhookSerializer(data=request.data)
            ser.is_valid(raise_exception=True)
            r = requests.post(ser.validated_data["url"], json={"ping": True}, timeout=5)
            return Response({"status": r.status_code})
"""),
('S59', 'Django form cleaned_data', DJ, """
    from .forms import ExportForm   # ChoiceField(kind)

    def export(request):
        form = ExportForm(request.POST)
        if not form.is_valid():
            raise Http404
        kind = form.cleaned_data["kind"]
        return FileResponse(open(f"/srv/export/{kind}.csv", "rb"))
"""),
('S60', 'aiohttp handler allowlist', 'import aiohttp\nfrom aiohttp import web\n', """
    FEEDS = {"notice": "https://www.example.go.kr/notice.xml"}

    async def feed(request):
        key = request.match_info["key"]
        if key not in FEEDS:
            raise web.HTTPNotFound()
        async with aiohttp.ClientSession() as session:
            async with session.get(FEEDS[key]) as resp:
                return web.Response(text=await resp.text())
"""),
('S61', 'tornado handler allowlist', 'import tornado.web\nimport requests\n', """
    ALLOWED = {"https://a.example.go.kr/x"}

    class Proxy(tornado.web.RequestHandler):
        def get(self):
            url = self.get_argument("url")
            if url not in ALLOWED:
                raise tornado.web.HTTPError(403)
            self.write(requests.get(url, timeout=5).text)
"""),
('S62', 'hashed cache file name', FL, """
    import hashlib

    @app.route("/thumb")
    def thumb():
        src = request.args.get("src", "")
        key = hashlib.sha256(src.encode()).hexdigest()
        path = os.path.join("/var/cache/thumbs", key + ".png")
        if os.path.exists(path):
            return send_file(path)
        abort(404)
"""),
('S63', 'uuid upload name + splitext', FL, """
    import uuid

    @app.route("/upload", methods=["POST"])
    def upload():
        f = request.files["file"]
        ext = os.path.splitext(f.filename)[1].lower()
        if ext not in (".png", ".jpg"):
            abort(400)
        stored = os.path.join("/srv/uploads", uuid.uuid4().hex + ext)
        with open(stored, "wb") as out:
            out.write(f.read())
        return jsonify(ok=True)
"""),
('S64', 'secure_filename upload then read back', FL, """
    from werkzeug.utils import secure_filename

    @app.route("/upload", methods=["POST"])
    def upload():
        f = request.files["file"]
        filename = secure_filename(f.filename)
        path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        f.save(path)
        with open(path, "rb") as fh:
            return jsonify(size=len(fh.read()))
"""),
('S65', 'if not in -> default reassign', FL, """
    THEMES = {"light", "dark"}

    @app.route("/css")
    def css():
        theme = request.cookies.get("theme", "light")
        if theme not in THEMES:
            theme = "light"
        return send_file(f"/srv/static/css/{theme}.css")
"""),
('S66', 'join of alnum generator', FL, """
    @app.route("/note")
    def note():
        raw = request.args.get("id", "")
        note_id = "".join(c for c in raw if c.isalnum())
        return open(os.path.join("/srv/notes", note_id + ".md")).read()
"""),
('S67', 're.sub sanitisation', FL, """
    @app.route("/note")
    def note():
        raw = request.args.get("id", "")
        note_id = re.sub(r"[^A-Za-z0-9_]", "", raw)
        return open(os.path.join("/srv/notes", note_id + ".md")).read()
"""),
('S68', 'isdigit guard', FL, """
    @app.route("/invoice")
    def invoice():
        num = request.args.get("no", "")
        if not num.isdigit():
            abort(400)
        return send_file(f"/srv/invoices/{num}.pdf")
"""),
('S69', 'for loop with continue filter', FL, """
    ALLOWED = {"a.csv", "b.csv"}

    @app.route("/merge")
    def merge():
        out = []
        for name in request.args.getlist("f"):
            if name not in ALLOWED:
                continue
            with open(os.path.join("/srv/data", name)) as fh:
                out.append(fh.read())
        return "\\n".join(out)
"""),
('S70', 'while retry with constant URL', FL, """
    import time
    STATUS_URL = "https://api.example.go.kr/v1/jobs/"

    @app.route("/jobs/<int:job_id>/wait")
    def wait(job_id):
        tries = int(request.args.get("tries", 3))
        while tries > 0:
            r = requests.get(STATUS_URL + str(job_id), timeout=5)
            if r.json()["done"]:
                return r.text
            tries -= 1
            time.sleep(1)
        abort(504)
"""),
('S71', 'proxy to fixed upstream', FL, """
    UPSTREAM = "http://backend.internal:8080"

    @app.route("/api/<path:path>", methods=["GET", "POST"])
    def api_proxy(path):
        r = requests.request(request.method, f"{UPSTREAM}/{path}", params=request.args,
                             data=request.get_data(), headers={"X-Req": request.headers.get("X-Req", "")})
        return r.content, r.status_code
"""),
('S72', 'redirect to OAuth provider with urlencode', FL, """
    from urllib.parse import urlencode
    AUTH_URL = "https://auth.example.go.kr/authorize"

    @app.route("/login")
    def login():
        state = request.args.get("state", "")
        qs = urlencode({"client_id": app.config["CID"], "state": state, "redirect_uri": url_for("cb", _external=True)})
        return redirect(AUTH_URL + "?" + qs)
"""),
('S73', 'redirect to session value', FL, """
    from flask import session

    @app.route("/after-login")
    def after_login():
        if request.args.get("skip"):
            return redirect(url_for("index"))
        return redirect(session.pop("next_url", "/"))
"""),
('S74', 'send_file BytesIO with user download name', FL, """
    import io

    @app.route("/qr")
    def qr():
        text = request.args.get("text", "")
        buf = io.BytesIO(make_qr(text))
        return send_file(buf, mimetype="image/png", download_name=request.args.get("name", "qr.png"))
"""),
('S75', 'template from fixed dict, user value as context', FL, """
    TEMPLATES = {"hello": "<h1>Hello {{ name }}</h1>", "bye": "<h1>Bye {{ name }}</h1>"}

    @app.route("/greet")
    def greet():
        kind = request.args.get("kind", "hello")
        name = request.args.get("name", "")
        return render_template_string(TEMPLATES.get(kind, TEMPLATES["hello"]), name=name)
"""),
('S76', 'jinja env.from_string with stored template', FL, """
    from jinja2.sandbox import SandboxedEnvironment
    from models import MailTemplate
    jinja_env = SandboxedEnvironment(autoescape=True)

    @app.route("/mail/<int:tid>/preview")
    def preview(tid):
        tpl = MailTemplate.query.get_or_404(tid)
        return jinja_env.from_string(tpl.body).render(name=request.args.get("name", ""))
"""),
('S77', 'os.remove path from DB row', FL, """
    from models import db, Upload

    @app.route("/uploads/<upload_id>", methods=["DELETE"])
    def delete_upload(upload_id):
        row = Upload.query.filter_by(id=upload_id, owner_id=current_user.id).first_or_404()
        os.remove(row.path)
        db.session.delete(row)
        db.session.commit()
        return "", 204
"""),
('S78', 'webhook URL from DB row by id', FA, """
    from sqlalchemy.orm import Session
    from myapp.db import get_db
    from myapp.models import Hook

    @app.post("/hooks/{hook_id}/test")
    async def test_hook(hook_id: str, db: Session = Depends(get_db)):
        hook = db.get(Hook, hook_id)
        if hook is None:
            raise HTTPException(404)
        async with httpx.AsyncClient() as client:
            r = await client.post(hook.url, json={"ping": True})
        return {"status": r.status_code}
"""),
('S79', 'FastAPI Annotated Query(pattern=)', FA, """
    from typing import Annotated

    @app.get("/pages")
    def page(slug: Annotated[str, Query(pattern=r"^[a-z0-9-]{1,40}$")]):
        return FileResponse(f"/srv/pages/{slug}.html")
"""),
('S80', 'str(value) not in allowlist', FL, """
    PUBLIC_IDS = {"1", "2", "3"}

    @app.route("/public/<doc_id>")
    def public(doc_id):
        if str(doc_id) not in PUBLIC_IDS:
            abort(404)
        return send_file(f"/srv/public/{doc_id}.pdf")
"""),
('S81', 'with-block reassign via secure_filename, sink after', FL, """
    import threading
    from werkzeug.utils import secure_filename
    lock = threading.Lock()

    @app.route("/dl")
    def dl():
        name = request.args.get("name", "")
        with lock:
            name = secure_filename(name)
            COUNTS[name] = COUNTS.get(name, 0) + 1
        return send_file(os.path.join("/srv/files", name))
"""),
('S82', 'echo uploaded stream with send_file', FL, """
    @app.route("/echo", methods=["POST"])
    def echo():
        f = request.files["image"]
        return send_file(f.stream, mimetype="image/png")
"""),
('S83', 'imported function name equals a method name', FL, """
    from storage import save

    class LocalCache:
        def __init__(self, path):
            self.path = path

        def save(self, blob):
            with open(self.path, "wb") as fh:
                fh.write(blob)

    @app.route("/put", methods=["POST"])
    def put():
        save(request.get_data())
        return "ok"
"""),
('S84', 'elif tuple membership', FL, """
    @app.route("/asset")
    def asset():
        kind = request.args.get("kind")
        if kind is None:
            abort(400)
        elif kind not in ("logo", "banner"):
            abort(404)
        return send_file(f"/srv/assets/{kind}.png")
"""),
('S85', 'any(startswith) prefix allowlist', FL, """
    PREFIXES = ("https://api.example.go.kr/", "https://data.example.go.kr/")

    @app.route("/proxy")
    def proxy():
        url = request.args.get("url", "")
        if not any(url.startswith(p) for p in PREFIXES):
            abort(403)
        return requests.get(url, timeout=5).text
"""),
('S86', 'Django redirect by name / reverse + query', DJ, """
    from django.urls import reverse

    def search_done(request, pk):
        q = request.GET.get("q", "")
        if request.GET.get("detail"):
            return redirect("item-detail", pk=pk)
        return HttpResponseRedirect(reverse("search") + "?q=" + q)
"""),
('S87', 'marshmallow schema.load', FL, """
    from schemas import FetchSchema   # url = fields.Url(validate=OneOf(REGISTERED))

    @app.route("/fetch", methods=["POST"])
    def fetch():
        data = FetchSchema().load(request.get_json())
        return requests.get(data["url"], timeout=5).text
"""),
('S88', 'Starlette path_params allowlist', 'from starlette.applications import Starlette\nfrom starlette.responses import FileResponse\n', """
    PAGES = {"about", "contact"}

    async def page(request):
        name = request.path_params["name"]
        if name not in PAGES:
            return FileResponse("/srv/pages/404.html", status_code=404)
        return FileResponse(f"/srv/pages/{name}.html")
"""),
('S89', 'helper returning bool, non-validator name, in if', FL, """
    from urllib.parse import urlparse

    def same_origin(u):
        p = urlparse(u)
        return not p.netloc and u.startswith("/") and not u.startswith("//")

    @app.route("/go")
    def go():
        nxt = request.args.get("next", "/")
        if not same_origin(nxt):
            nxt = "/"
        return redirect(nxt)
"""),
('S90', 'separator characters rejected', FL, """
    @app.route("/dl")
    def dl():
        name = request.args.get("name", "")
        if "/" in name or "\\\\" in name or name in (".", "..") or name.startswith("."):
            abort(400)
        return send_file(os.path.join("/srv/files", name))
"""),
('S91', 'name != basename(name)', FL, """
    @app.route("/dl")
    def dl():
        name = request.args.get("name", "")
        if not name or name != os.path.basename(name):
            abort(400)
        return send_file(os.path.join("/srv/files", name))
"""),
('S92', 'Optional int params (PEP 604)', FA, """
    @app.get("/pages")
    def pages(page: int | None = None, size: int = 10):
        return FileResponse(f"/srv/pages/{page or 1}-{size}.html")
"""),
('S93', 'class-based FastAPI style with staticmethod validator', FA, """
    class Fetcher:
        ALLOWED = {"api.example.go.kr"}

        @staticmethod
        def host_ok(url: str) -> bool:
            return httpx.URL(url).host in Fetcher.ALLOWED

    @app.get("/fetch")
    async def fetch(url: str):
        if not Fetcher.host_ok(url):
            raise HTTPException(403)
        async with httpx.AsyncClient() as client:
            return (await client.get(url)).text
"""),
('S94', 'sanic handler with dict lookup', "from sanic import Sanic\nfrom sanic.response import redirect, text\napp = Sanic('x')\n", """
    TARGETS = {"docs": "https://docs.example.go.kr", "home": "/"}

    @app.get("/go")
    async def go(request):
        return redirect(TARGETS.get(request.args.get("to"), "/"))
"""),
('S95', 'branch constant vs validated', FL, """
    @app.route("/avatar")
    def avatar():
        uid = request.args.get("uid")
        if uid is None:
            path = "/srv/avatars/default.png"
        else:
            if not uid.isalnum():
                abort(400)
            path = f"/srv/avatars/{uid}.png"
        return send_file(path)
"""),
('S96', 'validation in nested try with early raise', FA, """
    import uuid

    @app.get("/docs/{doc_id}")
    def doc(doc_id: str):
        try:
            uuid.UUID(doc_id)
        except ValueError:
            raise HTTPException(400)
        return FileResponse(f"/srv/docs/{doc_id}.pdf")
"""),
('S97', 'value looked up via getattr on settings', FL, """
    import settings

    @app.route("/svc/<name>/ping")
    def ping(name):
        base = getattr(settings, name.upper() + "_URL", None)
        if not base:
            abort(404)
        return requests.get(base + "/ping", timeout=3).text
"""),
('S98', 'membership stored in variable', FL, """
    ALLOWED = {"a.csv", "b.csv"}

    @app.route("/data")
    def data():
        name = request.args.get("name", "")
        known = name in ALLOWED
        if not known:
            abort(404)
        return send_file(os.path.join("/srv/data", name))
"""),
('S99', 'Flask route with defaults and typed converter', FL, """
    @app.route("/gallery/", defaults={"page": 1})
    @app.route("/gallery/<int:page>")
    def gallery(page):
        return send_file(f"/srv/gallery/page-{page}.html")
"""),
('S100', 'pydantic model with Literal field', FA, """
    from typing import Literal
    from pydantic import BaseModel

    class Req(BaseModel):
        template: Literal["invoice", "receipt"]
        name: str

    @app.post("/render")
    def render(body: Req):
        with open(f"/srv/tpl/{body.template}.html") as fh:
            return {"html": fh.read().replace("{{name}}", body.name)}
"""),
]


@pytest.mark.parametrize("case", SAFE, ids=[c[0] + " " + c[1] for c in SAFE])
def test_safe_shape(case: tuple) -> None:
    cid, title, header, code = case[:4]
    assert _flows(header, code) == KNOWN_REPORTS.get(cid, []), (cid, title)
