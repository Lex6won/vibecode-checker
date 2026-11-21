"""독립 적대적 검증 4차(2026-11-21)가 만든 **실제로 뚫리는** 코드 — 값이 다른 데 쓰이지 않는, 원칙상 잡아야 하는 모양이 대부분이다.
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
    'P40': 'aiohttp: match_info -> web.FileResponse',
    'P51': 'chalice: app.current_request',
    'Q05': 'cache.set(url, body) after the fetch',
    'Q06': 'audit row: db.session.add(FetchLog(url=url))',
}

VULN4 = [
('P01', 'Flask: variable, truthiness, logging -> requests.get', FL, """
    @app.route("/fetch")
    def fetch():
        url = request.args.get("url")
        if not url:
            abort(400)
        app.logger.info("fetching %s", url)
        return requests.get(url, timeout=5).text
""", 'SSRF'),
('P02', 'Flask: f-string host', FL, """
    @app.route("/node")
    def node():
        host = request.args.get("host", "")
        return requests.get(f"http://{host}:8080/status", timeout=3).text
""", 'SSRF'),
('P03', 'Flask: os.path.join + existence check -> open', FL, """
    @app.route("/cat")
    def cat():
        path = os.path.join("/srv/files", request.args.get("name", ""))
        if not os.path.exists(path):
            abort(404)
        with open(path) as fh:
            return fh.read()
""", 'PATH'),
('P04', 'Flask: pathlib read_text', FL, """
    from pathlib import Path

    @app.route("/read")
    def read():
        name = request.args.get("name", "")
        return (Path("/srv/files") / name).read_text()
""", 'PATH'),
('P05', 'Flask: JSON field -> redirect', FL, """
    @app.route("/done", methods=["POST"])
    def done():
        data = request.get_json()
        if "return_to" not in data:
            abort(400)
        return redirect(data["return_to"])
""", 'REDIR'),
('P06', 'Flask: loop over getlist -> os.remove', FL, """
    @app.route("/purge", methods=["POST"])
    def purge():
        removed = 0
        for name in request.form.getlist("name"):
            os.remove(os.path.join("/srv/uploads", name))
            removed += 1
        return jsonify(removed=removed)
""", 'PATH'),
('P07', 'Flask: enumerate loop', FL, """
    @app.route("/batch", methods=["POST"])
    def batch():
        out = {}
        for i, u in enumerate(request.get_json()["urls"]):
            out[i] = requests.get(u, timeout=5).status_code
        return jsonify(out)
""", 'SSRF'),
('P08', 'Flask: zip loop', FL, """
    @app.route("/mirror", methods=["POST"])
    def mirror():
        data = request.get_json()
        out = {}
        for label, u in zip(data["labels"], data["urls"]):
            out[label] = requests.get(u, timeout=5).status_code
        return jsonify(out)
""", 'SSRF'),
('P09', 'Flask: tuple unpacking -> open', FL, """
    @app.route("/diff")
    def diff():
        left, right = request.args.get("left", ""), request.args.get("right", "")
        a = open(os.path.join("/srv/data", left)).read()
        b = open(os.path.join("/srv/data", right)).read()
        return jsonify(same=a == b)
""", 'PATH'),
('P10', 'Flask: walrus -> redirect', FL, """
    @app.route("/go")
    def go():
        if (nxt := request.args.get("next")):
            return redirect(nxt)
        return redirect(url_for("index"))
""", 'REDIR'),
('P11', 'Flask: comprehension with the sink inside', FL, """
    @app.route("/status", methods=["POST"])
    def status():
        codes = [requests.get(u, timeout=5).status_code for u in request.get_json()["urls"]]
        return jsonify(codes)
""", 'SSRF'),
('P12', 'Flask: helper one hop -> open', FL, """
    def read_doc(name):
        with open(os.path.join("/srv/docs", name)) as fh:
            return fh.read()

    @app.route("/doc")
    def doc():
        return read_doc(request.args.get("name", ""))
""", 'PATH'),
('P13', 'Flask: helper two hops -> requests.post', FL, """
    def _send(url, payload):
        return requests.post(url, json=payload, timeout=5).status_code

    def notify(callback, event):
        return _send(callback, {"event": event})

    @app.route("/notify", methods=["POST"])
    def do_notify():
        return str(notify(request.form["callback"], "done"))
""", 'SSRF'),
('P14', 'Flask MethodView: method helper', FL, """
    from flask.views import MethodView

    class Notes(MethodView):
        def _load(self, name):
            return open(os.path.join("/srv/notes", name)).read()

        def get(self):
            return self._load(request.args.get("name", ""))
""", 'PATH'),
('P15', 'Flask: template source built by concatenation', FL, """
    @app.route("/hello")
    def hello():
        title = request.args.get("title", "")
        return render_template_string("<h1>" + title + "</h1>")
""", 'TPL'),
('P16', 'Flask: jinja2.Template(source)', FL, """
    from jinja2 import Template

    @app.route("/card", methods=["POST"])
    def card():
        source = request.form.get("template", "")
        return Template(source).render(user="guest")
""", 'TPL'),
('P17', "Flask: uploaded file's filename -> send_file", FL, """
    @app.route("/upload", methods=["POST"])
    def upload():
        name = request.files["file"].filename
        return send_file(os.path.join("/srv/thumbs", name + ".png"))
""", 'PATH'),
('P18', 'Flask: makedirs(dirname(path)) then write', FL, """
    @app.route("/save", methods=["POST"])
    def save():
        path = os.path.join("/srv/data", request.form["name"])
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write("saved")
        return "ok"
""", 'PATH'),
('P19', 'Flask: dict store then use', FL, """
    @app.route("/enqueue", methods=["POST"])
    def enqueue():
        job = {"retries": 3}
        job["callback"] = request.form.get("callback", "")
        return requests.post(job["callback"], json={"ok": True}, timeout=5).text
""", 'SSRF'),
('P20', 'Flask: list append then loop', FL, """
    @app.route("/cat2")
    def cat2():
        names = []
        names.append(request.args.get("a", ""))
        names.append(request.args.get("b", ""))
        out = ""
        for n in names:
            out += open(os.path.join("/srv/files", n)).read()
        return out
""", 'PATH'),
('P21', 'Flask: streaming generator closure', FL, """
    from flask import Response

    @app.route("/stream")
    def stream():
        path = os.path.join("/srv/media", request.args.get("name", ""))

        def generate():
            with open(path, "rb") as fh:
                yield from fh

        return Response(generate(), mimetype="application/octet-stream")
""", 'PATH'),
('P22', 'Flask: str() + .format() -> send_file', FL, """
    @app.route("/dl")
    def dl():
        name = str(request.args.get("name", ""))
        return send_file("/srv/files/{}".format(name), as_attachment=True)
""", 'PATH'),
('P23', 'Flask: .strip() -> urllib urlopen', 'from flask import Flask, request\nimport urllib.request\napp = Flask(__name__)\n', """
    @app.route("/head")
    def head():
        url = request.args.get("url", "").strip()
        with urllib.request.urlopen(url, timeout=5) as resp:
            return str(resp.status)
""", 'SSRF'),
('P24', 'Flask: requests.Session client', FL, """
    @app.route("/proxy")
    def proxy():
        target = request.args.get("target", "")
        with requests.Session() as s:
            return s.get(target, timeout=5).text
""", 'SSRF'),
('P25', 'Flask: flash + redirect to form value', FL, """
    from flask import flash

    @app.route("/saved", methods=["POST"])
    def saved():
        nxt = request.form.get("next", "")
        flash("saved")
        return redirect(nxt)
""", 'REDIR'),
('P26', 'FastAPI: query param -> AsyncClient', FA, """
    @app.get("/fetch")
    async def fetch(url: str):
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.get(url)
        return {"status": r.status_code}
""", 'SSRF'),
('P27', 'FastAPI: {name:path} -> FileResponse', FA, """
    @app.get("/files/{name:path}")
    def files(name: str):
        return FileResponse(os.path.join("/srv/files", name))
""", 'PATH'),
('P28', 'FastAPI: model str field -> RedirectResponse', FA, """
    from pydantic import BaseModel

    class Done(BaseModel):
        return_to: str
        order_id: int

    @app.post("/done")
    def done(body: Done):
        return RedirectResponse(body.return_to, status_code=303)
""", 'REDIR'),
('P29', 'FastAPI: UploadFile.filename -> open', FA, """
    @app.post("/upload")
    async def upload(file: UploadFile):
        with open(os.path.join("/srv/uploads", file.filename), "wb") as out:
            out.write(await file.read())
        return {"ok": True}
""", 'PATH'),
('P30', 'FastAPI: async helper', FA, """
    async def pull(src: str) -> str:
        async with httpx.AsyncClient() as client:
            return (await client.get(src)).text

    @app.get("/pull")
    async def do_pull(src: str):
        return {"body": await pull(src)}
""", 'SSRF'),
('P31', 'FastAPI: Request.query_params -> RedirectResponse', FA, """
    from fastapi import Request

    @app.get("/out")
    def out(request: Request):
        target = request.query_params.get("to", "/")
        return RedirectResponse(target)
""", 'REDIR'),
('P32', 'Django: request.GET -> HttpResponseRedirect', DJ, """
    def after_login(request):
        nxt = request.GET.get("next", "/")
        return HttpResponseRedirect(nxt)
""", 'REDIR'),
('P33', 'Django: request.POST -> open', DJ, """
    def read_note(request):
        name = request.POST.get("name", "")
        with open(os.path.join("/srv/notes", name)) as fh:
            return HttpResponse(fh.read())
""", 'PATH'),
('P34', 'Django: json.loads(request.body) field -> requests.get', DJJ, """
    def preview(request):
        body = json.loads(request.body)
        resp = requests.get(body["url"], timeout=5)
        return HttpResponse(resp.content)
""", 'SSRF'),
('P35', 'DRF: request.data -> requests.post', DRF, """
    class Hook(APIView):
        def post(self, request):
            target = request.data.get("target")
            r = requests.post(target, json={"ping": True}, timeout=5)
            return Response({"status": r.status_code})
""", 'SSRF'),
('P36', 'DRF: self.request.query_params -> open', DRF, """
    class Report(APIView):
        def get(self, request):
            name = self.request.query_params.get("name", "")
            return FileResponse(open(os.path.join("/srv/reports", name), "rb"))
""", 'PATH'),
('P37', 'tornado: get_argument -> self.redirect', TO, """
    class Go(tornado.web.RequestHandler):
        def get(self):
            target = self.get_argument("next", "/")
            self.redirect(target)
""", 'REDIR'),
('P38', 'tornado: JSON body -> open', TO, """
    class Read(tornado.web.RequestHandler):
        def post(self):
            body = json.loads(self.request.body)
            with open(os.path.join("/srv/files", body["name"])) as fh:
                self.write(fh.read())
""", 'PATH'),
('P39', 'aiohttp: request.query -> ClientSession', AIO, """
    async def proxy(request):
        url = request.query.get("url", "")
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as resp:
                return web.Response(text=await resp.text())
""", 'SSRF'),
('P40', 'aiohttp: match_info -> web.FileResponse', AIO, """
    async def download(request):
        name = request.match_info["name"]
        return web.FileResponse(os.path.join("/srv/files", name))
""", 'PATH'),
('P41', 'aiohttp: request.rel_url.query -> HTTPFound', AIO, """
    async def after_login(request):
        nxt = request.rel_url.query.get("next", "/")
        raise web.HTTPFound(location=nxt)
""", 'REDIR'),
('P42', 'falcon: req.get_param -> requests.get', FALCON, """
    class Proxy:
        def on_get(self, req, resp):
            url = req.get_param("url", required=True)
            resp.text = requests.get(url, timeout=5).text
""", 'SSRF'),
('P43', 'falcon: req.media field -> open', FALCON, """
    class Reader:
        def on_post(self, req, resp):
            name = req.media["name"]
            with open(os.path.join("/srv/files", name)) as fh:
                resp.text = fh.read()
""", 'PATH'),
('P44', 'bottle: request.query -> open', BOTTLE, """
    @route("/cat")
    def cat():
        name = request.query.get("name", "")
        return open(os.path.join("/srv/files", name)).read()
""", 'PATH'),
('P45', 'bottle: request.forms -> redirect', BOTTLE, """
    @post("/saved")
    def saved():
        nxt = request.forms.get("next", "/")
        return redirect(nxt)
""", 'REDIR'),
('P46', 'bottle: <filepath:path> -> open', BOTTLE, """
    @route("/static/<filepath:path>")
    def static(filepath):
        return open(os.path.join("/srv/static", filepath), "rb").read()
""", 'PATH'),
('P47', 'sanic: request.args -> httpx', SANIC, """
    @app.get("/fetch")
    async def fetch(request):
        url = request.args.get("url", "")
        async with httpx.AsyncClient() as client:
            return text((await client.get(url)).text)
""", 'SSRF'),
('P48', 'sanic: <name:path> -> open', SANIC, """
    @app.get("/files/<name:path>")
    async def files(request, name):
        return text(open(os.path.join("/srv/files", name)).read())
""", 'PATH'),
('P49', 'quart: await request.get_json() -> AsyncClient', QUART, """
    @app.route("/hook", methods=["POST"])
    async def hook():
        data = await request.get_json()
        async with httpx.AsyncClient() as client:
            r = await client.post(data["callback"], json={"ok": True})
        return {"status": r.status_code}
""", 'SSRF'),
('P50', "quart: (await request.form)['title'] -> template", QUART, """
    @app.route("/hello", methods=["POST"])
    async def hello():
        form = await request.form
        return await render_template_string("<h1>%s</h1>" % form["title"])
""", 'TPL'),
('P51', 'chalice: app.current_request', "import requests\nfrom chalice import Chalice\napp = Chalice(app_name='x')\n", """
    @app.route("/fetch")
    def fetch():
        request = app.current_request
        url = request.query_params.get("url", "")
        return {"body": requests.get(url, timeout=5).text}
""", 'SSRF'),
('P52', 'Flask: AugAssign path building', FL, """
    @app.route("/page")
    def page():
        path = "/srv/pages/"
        path += request.args.get("name", "index")
        path += ".html"
        return send_file(path)
""", 'PATH'),
('Q01', 'download_name=os.path.basename(path)', FL, """
    @app.route("/dl")
    def dl():
        path = os.path.join("/srv/files", request.args.get("name", ""))
        return send_file(path, as_attachment=True, download_name=os.path.basename(path))
""", 'PATH'),
('Q02', 'mimetypes.guess_type(path)', FL, """
    import mimetypes

    @app.route("/view")
    def view():
        path = os.path.join("/srv/files", request.args.get("name", ""))
        mime = mimetypes.guess_type(path)[0] or "application/octet-stream"
        return send_file(path, mimetype=mime)
""", 'PATH'),
('Q03', "abort(404, f'{name} not found')", FL, """
    @app.route("/dl")
    def dl():
        name = request.args.get("name", "")
        path = os.path.join("/srv/files", name)
        if not os.path.isfile(path):
            abort(404, f"{name} not found")
        return send_file(path)
""", 'PATH'),
('Q04', "HTTPException(detail=f'{name} not found')", FA, """
    @app.get("/files/{name:path}")
    def files(name: str):
        path = os.path.join("/srv/files", name)
        if not os.path.isfile(path):
            raise HTTPException(status_code=404, detail=f"{name} not found")
        return FileResponse(path)
""", 'PATH'),
('Q05', 'cache.set(url, body) after the fetch', FL, """
    from extensions import cache

    @app.route("/fetch")
    def fetch():
        url = request.args.get("url", "")
        body = requests.get(url, timeout=5).text
        cache.set(url, body, timeout=60)
        return body
""", 'SSRF'),
('Q06', 'audit row: db.session.add(FetchLog(url=url))', FL, """
    from models import db, FetchLog

    @app.route("/fetch")
    def fetch():
        url = request.args.get("url", "")
        db.session.add(FetchLog(url=url))
        db.session.commit()
        return requests.get(url, timeout=5).text
""", 'SSRF'),
('Q07', 'host extracted only for the log line', FL, """
    from urllib.parse import urlparse

    @app.route("/fetch")
    def fetch():
        url = request.args.get("url", "")
        app.logger.info("fetching from %s", urlparse(url).hostname)
        return requests.get(url, timeout=5).text
""", 'SSRF'),
('Q08', 'upload saved with f.save(path), then path reused', FL, """
    @app.route("/upload", methods=["POST"])
    def upload():
        f = request.files["file"]
        path = os.path.join("/srv/uploads", request.form.get("name", ""))
        f.save(path)
        return send_file(path)
""", 'PATH'),
]


@pytest.mark.parametrize("case", VULN4, ids=[c[0] + " " + c[1] for c in VULN4])
def test_vulnerable_shape(case: tuple) -> None:
    cid, title, header, code, rule = case
    assert (rule in _flows(header, code)) == (cid not in KNOWN_MISSES), (cid, title)
