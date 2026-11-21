"""독립 적대적 검증 3차(2026-11-21)가 만든 **실제로 뚫리는** 코드 — 직전 판(검사 모양을 인정해 가던 판)의 빈틈을 겨냥했다.

그 판은 이 가운데 4개만 잡았고, 같은 검증의 안전한 코드 48개 중 16개를 '확인된 취약점'으로 냈다. 그래서 원칙을 뒤집었다.
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


#: 지금 보고하지 않는 것. 대부분은 원칙대로다 — 값이 조건문·비교·조회·모르는 함수에 쓰였으면 그것이 검사인지 판단하지 않는다.
#: 나머지는 따라가지 않는 흐름(다른 자리의 라우트 선언·객체 속성·간접 호출·3홉)과 호스트 고정 규칙의 한계다.
#: 잡히기 시작하면 시험이 알린다(목록에서 지운다). 새로 놓치면 실패한다.
KNOWN_MISSES = {
    'W01': 'memoisation: sink inside `if url not in CACHE`',
    'W02': 'new variable bound in both branches of a non-blocking if',
    'W03': 'early continue on comment entries',
    'W04': 'equality special case with a plain (success) return',
    'W05': 'extension dispatch, both sinks',
    'W06': "'repair' through an unknown function, other path untouched",
    'W07': 'derived value repaired, raw value used later',
    'W08': "default 'repair' behind a suffix-only check",
    'W09': 'parsed URL: only scheme/netloc presence, abort otherwise',
    'W10': 'basename computed and tested for emptiness, raw name used',
    'W11': 'parse of a prefix in a blocking try',
    'W12': 'table lookup of the extension in a blocking try',
    'W13': 'same-file helper: branches on the value, raises for something else',
    'W14': 'validate_required(data, [...]) only checks presence',
    'W15': 'Flask-docs allowed_file() then raw filename',
    'W16': 'nested model kept in a variable, .name used',
    'W17': 'loop over body.files, pathlib read_text on .name',
    'W19': 'ternary on another argument of the same call',
    'W20': 'comprehension filter that only skips dotfiles',
    'W21': 'filtered list (comments dropped) then loop',
    'W23': 'items(): key inspected, value fetched',
    'W24': 'star-unpack: first validated, rest used',
    'W25': 'rsplit: extension allowlisted, whole name used',
    'W26': 'dict comprehension copy of request.args',
    'W27': 'closure defined before the tainted assignment',
    'W28': 'two handler classes share a helper method name',
    'W29': 'method returns the joined path',
    'W30': 'loop-carried reassignment to an unchecked mirror',
    'W31': 'assign + validate in try, exception swallowed',
    'W32': 'match with a mapping pattern capture',
    'W33': 'match with a capture-name default case',
    'W34': 'constant prefix variable, request value completes the host',
    'W35': 'FastAPI dependency function reads the query param',
    'W36': 'webargs @use_args only type-checks',
    'W37': 'field_validator that only rejects empty strings',
    'W38': 'aiohttp form data: await request.post()',
    'W42': 'flask_restful reqparse',
    'W43': 'nested dict store',
    'W46': 'same-file clean_markup() strips tags, result is the template',
    'W47': 'ensure_scheme() passer with a fuzzy name',
    'W48': 'check only on POST (nested if), GET path unchecked',
    'W50': 'validated in try, deleted in finally (runs on the failing path too)',
}

VULN3 = [
('W01', 'memoisation: sink inside `if url not in CACHE`', FL, """
    CACHE = {}

    @app.route("/p")
    def p():
        url = request.args.get("url", "")
        if url not in CACHE:
            CACHE[url] = requests.get(url, timeout=5).text
        return CACHE[url]
""", 'SSRF'),
('W02', 'new variable bound in both branches of a non-blocking if', FL, """
    @app.route("/p")
    def p():
        url = request.args.get("url", "")
        if url.startswith("http://"):
            target = "https://" + url[7:]
        else:
            target = url
        return requests.get(target, timeout=5).text
""", 'SSRF'),
('W03', 'early continue on comment entries', FL, """
    @app.route("/cat")
    def cat():
        out = []
        for name in request.args.getlist("f"):
            if name.startswith("#"):
                continue
            with open(os.path.join("/srv/files", name)) as fh:
                out.append(fh.read())
        return "\\n".join(out)
""", 'PATH'),
('W04', 'equality special case with a plain (success) return', FL, """
    @app.route("/release/<path:name>")
    def release(name):
        if name == "latest":
            return send_file("/srv/releases/latest.zip")
        return send_file(os.path.join("/srv/releases", name))
""", 'PATH'),
('W05', 'extension dispatch, both sinks', FL, """
    import json

    @app.route("/view")
    def view():
        path = os.path.join("/srv/data", request.args.get("name", ""))
        if path.endswith(".json"):
            return jsonify(json.load(open(path)))
        return send_file(path)
""", 'PATH'),
('W06', "'repair' through an unknown function, other path untouched", FL, """
    from werkzeug.urls import url_quote

    @app.route("/p")
    def p():
        url = request.args.get("url", "")
        if " " in url:
            url = url_quote(url)
        return requests.get(url, timeout=5).text
""", 'SSRF'),
('W07', 'derived value repaired, raw value used later', FL, """
    BASE = "/srv/notes"

    @app.route("/note")
    def note():
        name = request.args.get("name", "")
        path = os.path.join(BASE, name)
        if not path.endswith(".txt"):
            path = os.path.join(BASE, "readme.txt")
        app.logger.info("serving %s", path)
        return send_file(os.path.join(BASE, name))
""", 'PATH'),
('W08', "default 'repair' behind a suffix-only check", FL, """
    @app.route("/site")
    def site():
        name = request.args.get("page", "")
        if not name.endswith(".html"):
            name = "index.html"
        return send_file(os.path.join("/srv/site", name))
""", 'PATH'),
('W09', 'parsed URL: only scheme/netloc presence, abort otherwise', FL, """
    from urllib.parse import urlparse

    @app.route("/p")
    def p():
        url = request.args.get("url", "")
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            abort(400)
        return requests.get(url, timeout=5).text
""", 'SSRF'),
('W10', 'basename computed and tested for emptiness, raw name used', FL, """
    @app.route("/dl")
    def dl():
        name = request.args.get("name", "")
        base = os.path.basename(name)
        if not base:
            abort(400)
        return send_file(os.path.join("/srv/files", name))
""", 'PATH'),
('W11', 'parse of a prefix in a blocking try', FL, """
    from datetime import datetime

    @app.route("/log")
    def log():
        name = request.args.get("name", "")
        try:
            datetime.strptime(name[:10], "%Y-%m-%d")
        except ValueError:
            abort(400)
        return send_file(os.path.join("/var/log/app", name))
""", 'PATH'),
('W12', 'table lookup of the extension in a blocking try', FL, """
    MIME = {".png": "image/png", ".jpg": "image/jpeg", ".pdf": "application/pdf"}

    @app.route("/media")
    def media():
        name = request.args.get("name", "")
        try:
            mime = MIME[os.path.splitext(name)[1]]
        except KeyError:
            abort(415)
        return send_file(os.path.join("/srv/media", name), mimetype=mime)
""", 'PATH'),
('W13', 'same-file helper: branches on the value, raises for something else', FL, """
    from flask_login import current_user
    STATS = {"zip": 0}

    def record_download(name):
        if name.endswith(".zip"):
            STATS["zip"] += 1
        if not current_user.is_authenticated:
            abort(401)

    @app.route("/dl")
    def dl():
        name = request.args.get("name", "")
        record_download(name)
        return send_file(os.path.join("/srv/files", name))
""", 'PATH'),
('W14', 'validate_required(data, [...]) only checks presence', FL, """
    def validate_required(payload, fields):
        missing = [f for f in fields if f not in payload]
        return missing

    @app.route("/hook", methods=["POST"])
    def hook():
        data = request.get_json()
        validate_required(data, ["url", "event"])
        return requests.post(data["url"], json={"event": data["event"]}, timeout=5).text
""", 'SSRF'),
('W15', 'Flask-docs allowed_file() then raw filename', FL, """
    ALLOWED_EXTENSIONS = {"png", "jpg", "gif"}

    def allowed_file(filename):
        return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

    @app.route("/upload", methods=["POST"])
    def upload():
        f = request.files["file"]
        if not allowed_file(f.filename):
            abort(400)
        with open(os.path.join("/srv/uploads", f.filename), "wb") as out:
            out.write(f.read())
        return "ok"
""", 'PATH'),
('W16', 'nested model kept in a variable, .name used', FA, """
    from pydantic import BaseModel

    class Doc(BaseModel):
        name: str
        folder: str

    class Req(BaseModel):
        doc: Doc

    @app.post("/open")
    def open_doc(body: Req):
        doc = body.doc
        return FileResponse(os.path.join("/srv/docs", doc.folder, doc.name))
""", 'PATH'),
('W17', 'loop over body.files, pathlib read_text on .name', FA, """
    from pathlib import Path
    from pydantic import BaseModel

    class Entry(BaseModel):
        name: str

    class Bundle(BaseModel):
        files: list[Entry]

    @app.post("/bundle")
    def bundle(body: Bundle):
        return [(Path("/srv/files") / f.name).read_text() for f in body.files]
""", 'PATH'),
('W18', 'comprehension variable reuses the tainted name', FL, """
    BASE = "/srv/files"

    @app.route("/dl")
    def dl():
        name = request.args.get("name", "")
        known = [name.lower() for name in os.listdir(BASE)]
        app.logger.info("%d files known", len(known))
        return send_file(os.path.join(BASE, name))
""", 'PATH'),
('W19', 'ternary on another argument of the same call', FL, """
    @app.route("/dl")
    def dl():
        name = request.args.get("name", "")
        return send_file(os.path.join("/srv/files", name),
                         mimetype="application/pdf" if name.endswith(".pdf") else None)
""", 'PATH'),
('W20', 'comprehension filter that only skips dotfiles', FL, """
    @app.route("/cat")
    def cat():
        names = request.args.getlist("f")
        return "".join(open(os.path.join("/srv/files", n)).read() for n in names if not n.startswith("."))
""", 'PATH'),
('W21', 'filtered list (comments dropped) then loop', FL, """
    @app.route("/batch", methods=["POST"])
    def batch():
        urls = [u for u in request.get_json()["urls"] if not u.startswith("#")]
        return jsonify([requests.get(u, timeout=5).status_code for u in urls])
""", 'SSRF'),
('W22', "(data.get('action') or '').lower() validated, other field used", FL, """
    @app.route("/call", methods=["POST"])
    def call():
        data = request.get_json()
        action = (data.get("action") or "").lower()
        if action not in ("fetch", "head"):
            abort(400)
        return requests.request(action, data["url"], timeout=5).text
""", 'SSRF'),
('W23', 'items(): key inspected, value fetched', FL, """
    @app.route("/resolve", methods=["POST"])
    def resolve():
        data = request.get_json()
        out = {}
        for key, value in data.items():
            if key.endswith("_url"):
                out[key] = requests.get(value, timeout=5).status_code
        return jsonify(out)
""", 'SSRF'),
('W24', 'star-unpack: first validated, rest used', FL, """
    ALLOWED = {"https://a.example.go.kr/feed"}

    @app.route("/mirror", methods=["POST"])
    def mirror():
        urls = request.get_json()["urls"]
        primary, *rest = urls
        if primary not in ALLOWED:
            abort(403)
        return jsonify([requests.get(u, timeout=5).status_code for u in rest])
""", 'SSRF'),
('W25', 'rsplit: extension allowlisted, whole name used', FL, """
    @app.route("/img")
    def img():
        raw = request.args.get("name", "x.png")
        stem, ext = raw.rsplit(".", 1)
        if ext not in ("png", "jpg"):
            abort(400)
        return send_file(os.path.join("/srv/img", raw))
""", 'PATH'),
('W26', 'dict comprehension copy of request.args', FL, """
    @app.route("/p")
    def p():
        params = {k: v for k, v in request.args.items() if k != "token"}
        return requests.get(params["url"], timeout=5).text
""", 'SSRF'),
('W27', 'closure defined before the tainted assignment', FL, """
    from flask import Response

    @app.route("/stream")
    def stream():
        def generate():
            with open(path, "rb") as fh:
                yield from fh

        path = os.path.join("/srv/media", request.args.get("name", ""))
        return Response(generate(), mimetype="application/octet-stream")
""", 'PATH'),
('W28', 'two handler classes share a helper method name', TO, """
    class Text(tornado.web.RequestHandler):
        def _read(self, name):
            return open(os.path.join("/srv/text", name)).read()

        def get(self):
            self.write(self._read(self.get_argument("name")))

    class Raw(tornado.web.RequestHandler):
        def _read(self, name):
            return open(os.path.join("/srv/raw", name), "rb").read()

        def get(self):
            self.write(self._read(self.get_argument("name")))
""", 'PATH'),
('W29', 'method returns the joined path', FL, """
    from flask.views import MethodView

    class Files(MethodView):
        root = "/srv/files"

        def _path_for(self, name):
            return os.path.join(self.root, name)

        def get(self):
            return send_file(self._path_for(request.args.get("name", "")))
""", 'PATH'),
('W30', 'loop-carried reassignment to an unchecked mirror', FL, """
    from urllib.parse import urlparse
    ALLOWED = {"api.example.go.kr"}

    @app.route("/fetch")
    def fetch():
        target = request.args.get("primary", "")
        if urlparse(target).hostname not in ALLOWED:
            abort(403)
        for backup in request.args.getlist("backup"):
            resp = requests.get(target, timeout=3)
            if resp.ok:
                return resp.text
            target = backup
        abort(502)
""", 'SSRF'),
('W31', 'assign + validate in try, exception swallowed', FL, """
    NAME_RE = re.compile(r"[a-z0-9_]{1,40}\\.txt")

    def check_name(name):
        if not NAME_RE.fullmatch(name):
            raise ValueError(name)

    @app.route("/dl")
    def dl():
        name = "index.txt"
        try:
            name = request.args["name"]
            check_name(name)
        except (KeyError, ValueError):
            app.logger.warning("bad or missing name")
        return send_file(os.path.join("/srv/files", name))
""", 'PATH'),
('W32', 'match with a mapping pattern capture', FL, """
    @app.route("/rpc", methods=["POST"])
    def rpc():
        match request.get_json():
            case {"action": "fetch", "url": url}:
                return requests.get(url, timeout=5).text
            case _:
                abort(400)
""", 'SSRF'),
('W33', 'match with a capture-name default case', FL, """
    @app.route("/dl")
    def dl():
        match request.args.get("name", ""):
            case "latest":
                path = "/srv/releases/latest.zip"
            case other:
                path = os.path.join("/srv/releases", other)
        return send_file(path)
""", 'PATH'),
('W34', 'constant prefix variable, request value completes the host', FL, """
    ENV = "prod"

    @app.route("/health/<service>")
    def health(service):
        return requests.get(f"http://{ENV}-{service}.svc.cluster.local/healthz", timeout=2).text
""", 'SSRF'),
('W35', 'FastAPI dependency function reads the query param', FA, """
    def load_doc(name: str) -> str:
        with open(os.path.join("/srv/docs", name)) as fh:
            return fh.read()

    @app.get("/doc")
    def doc(text: str = Depends(load_doc)):
        return {"text": text}
""", 'PATH'),
('W36', 'webargs @use_args only type-checks', FL, """
    from webargs import fields
    from webargs.flaskparser import use_args

    @app.route("/fetch")
    @use_args({"url": fields.Str(required=True)}, location="query")
    def fetch(args):
        return requests.get(args["url"], timeout=5).text
""", 'SSRF'),
('W37', 'field_validator that only rejects empty strings', FA, """
    from pydantic import BaseModel, field_validator

    class ReadReq(BaseModel):
        path: str

        @field_validator("path")
        @classmethod
        def not_empty(cls, v):
            if not v.strip():
                raise ValueError("path is required")
            return v

    @app.post("/read")
    def read(body: ReadReq):
        with open(os.path.join("/srv/data", body.path)) as fh:
            return {"text": fh.read()}
""", 'PATH'),
('W38', 'aiohttp form data: await request.post()', AIO, """
    async def proxy(request):
        form = await request.post()
        url = form["url"]
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as resp:
                return web.Response(text=await resp.text())
""", 'SSRF'),
('W39', 'aiohttp redirect: raise web.HTTPFound(next)', AIO, """
    async def after_login(request):
        nxt = request.query.get("next", "/")
        raise web.HTTPFound(location=nxt)
""", 'REDIR'),
('W40', 'Django request.COOKIES', DJ, """
    THEME_DIR = "/srv/themes"

    def theme_css(request):
        theme = request.COOKIES.get("theme", "light.css")
        return FileResponse(open(os.path.join(THEME_DIR, theme), "rb"))
""", 'PATH'),
('W41', 'falcon req.get_param', 'import falcon, requests\n', """
    class Proxy:
        def on_get(self, req, resp):
            url = req.get_param("url", required=True)
            resp.text = requests.get(url, timeout=5).text
""", 'SSRF'),
('W42', 'flask_restful reqparse', 'import requests\nfrom flask_restful import Resource, reqparse\n', """
    parser = reqparse.RequestParser()
    parser.add_argument("url", type=str, required=True)

    class Fetch(Resource):
        def get(self):
            args = parser.parse_args()
            return {"body": requests.get(args["url"], timeout=5).text}
""", 'SSRF'),
('W43', 'nested dict store', FL, """
    @app.route("/p")
    def p():
        cfg = {"http": {"timeout": 5}}
        cfg["http"]["url"] = request.args.get("url", "")
        return requests.get(cfg["http"]["url"], timeout=cfg["http"]["timeout"]).text
""", 'SSRF'),
('W44', "requests.Session().request('GET', url)", FL, """
    @app.route("/p")
    def p():
        url = request.args.get("url", "")
        return requests.Session().request("GET", url, timeout=5).text
""", 'SSRF'),
('W45', 'pathlib Path(...).open()', FA, """
    from pathlib import Path

    @app.get("/read")
    def read(name: str):
        with Path("/srv/files", name).open() as fh:
            return {"text": fh.read()}
""", 'PATH'),
('W46', 'same-file clean_markup() strips tags, result is the template', FL, """
    def clean_markup(text):
        return re.sub(r"<[^>]+>", "", text)

    @app.route("/note", methods=["POST"])
    def note():
        body = clean_markup(request.form["body"])
        return render_template_string("<article>" + body + "</article>")
""", 'TPL'),
('W47', 'ensure_scheme() passer with a fuzzy name', FL, """
    def ensure_scheme(u):
        return u if "://" in u else "http://" + u

    @app.route("/p")
    def p():
        url = ensure_scheme(request.args.get("url", ""))
        return requests.get(url, timeout=5).text
""", 'SSRF'),
('W48', 'check only on POST (nested if), GET path unchecked', FL, """
    @app.route("/dl", methods=["GET", "POST"])
    def dl():
        name = request.values.get("name", "")
        if request.method == "POST":
            if not name.isidentifier():
                abort(400)
        return send_file(os.path.join("/srv/files", name))
""", 'PATH'),
('W49', 'nested field: sibling of a validated key', FL, """
    KINDS = {"ping", "status"}

    @app.route("/call", methods=["POST"])
    def call():
        data = request.get_json()
        if data["target"]["kind"] not in KINDS:
            abort(400)
        return requests.get(data["target"]["url"], timeout=5).text
""", 'SSRF'),
('W50', 'validated in try, deleted in finally (runs on the failing path too)', FL, """
    NAME_RE = re.compile(r"[a-z0-9_]{1,40}\\.tmp")

    def check_tmp_name(name):
        if not NAME_RE.fullmatch(name):
            raise ValueError(name)

    @app.route("/process", methods=["POST"])
    def process():
        name = request.form["name"]
        tmp = os.path.join("/tmp/uploads", name)
        try:
            check_tmp_name(name)
            result = run_job(tmp)
        finally:
            os.remove(tmp)
        return jsonify(result)
""", 'PATH'),
('W51', 'value stored under a dict key, then used as the URL', FL, """
    @app.route("/enqueue", methods=["POST"])
    def enqueue():
        job = {"retries": 3}
        job["callback"] = request.form.get("callback", "")
        return requests.post(job["callback"], json={"ok": True}, timeout=5).text
""", 'SSRF'),
('W52', 'secure_filename() result kept aside, raw filename used', FL, """
    from werkzeug.utils import secure_filename

    @app.route("/upload", methods=["POST"])
    def upload():
        f = request.files["file"]
        display = secure_filename(f.filename)
        with open(os.path.join("/srv/uploads", f.filename), "wb") as out:
            out.write(f.read())
        return jsonify(saved=display)
""", 'PATH'),
]


@pytest.mark.parametrize("case", VULN3, ids=[c[0] + " " + c[1] for c in VULN3])
def test_vulnerable_shape(case: tuple) -> None:
    cid, title, header, code, rule = case
    assert (rule in _flows(header, code)) == (cid not in KNOWN_MISSES), (cid, title)
