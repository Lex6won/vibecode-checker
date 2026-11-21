"""독립 적대적 검증 5차(2026-11-21)가 만든 **실제로 뚫리는** 코드 — 개발자가 평소 쓰는 모양의 내려받기·대리 요청·리다이렉트·템플릿 핸들러.
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
    'R11': 'Flask upload saved under the client file name (f.save)',
    'R14': 'FastAPI download with HTTPException message',
    'R32': 'Flask download choosing mimetype by extension',
}

VULN5 = [
('R01', 'Flask download: 400 json, isfile, 404 message, basename download name', FL, """
    DOWNLOAD_DIR = "/srv/downloads"

    @app.route("/download")
    def download():
        filename = request.args.get("file")
        if not filename:
            return jsonify({"error": "file parameter is required"}), 400
        path = os.path.join(DOWNLOAD_DIR, filename)
        if not os.path.isfile(path):
            abort(404, description=f"{filename} not found")
        app.logger.info("download %s", path)
        return send_file(path, as_attachment=True, download_name=os.path.basename(path))
""", 'PATH'),
('R02', 'Flask proxy: fetch and relay the response', FL, """
    from flask import Response

    @app.route("/proxy")
    def proxy():
        url = request.args.get("url")
        if url is None:
            return jsonify(error="url is required"), 400
        try:
            upstream = requests.get(url, timeout=10)
        except requests.RequestException as exc:
            app.logger.warning("proxy failed for %s: %s", url, exc)
            return jsonify(error="upstream error"), 502
        return Response(upstream.content, status=upstream.status_code, content_type=upstream.headers.get("Content-Type"))
""", 'SSRF'),
('R03', 'Flask login redirect', FL, """
    from flask import flash

    @app.route("/login", methods=["POST"])
    def login():
        next_url = request.args.get("next") or url_for("index")
        flash("Welcome back")
        return redirect(next_url)
""", 'REDIR'),
('R04', 'Flask template preview from the form', FL, """
    @app.route("/preview", methods=["POST"])
    def preview():
        template = request.form.get("template", "")
        if not template:
            return jsonify(error="empty template"), 400
        return render_template_string(template, user="guest")
""", 'TPL'),
('R05', 'Flask read with try/except FileNotFoundError', FL, """
    @app.route("/logs")
    def logs():
        name = request.args.get("name", "app.log")
        try:
            with open(os.path.join("/var/log/myapp", name)) as fh:
                return fh.read(), 200, {"Content-Type": "text/plain"}
        except FileNotFoundError:
            return jsonify(error=f"{name} does not exist"), 404
""", 'PATH'),
('R06', 'Flask JSON webhook test with dict of params', FL, """
    @app.route("/webhooks/test", methods=["POST"])
    def test_webhook():
        data = request.get_json(force=True)
        if "url" not in data:
            return jsonify(error="url missing"), 400
        params = {"url": data["url"], "timeout": 5}
        resp = requests.post(params["url"], json={"event": "ping"}, timeout=params["timeout"])
        return jsonify(status=resp.status_code)
""", 'SSRF'),
('R07', 'Flask delete uploaded file', FL, """
    from flask import flash
    UPLOAD_FOLDER = "/srv/uploads"

    @app.route("/files/delete", methods=["POST"])
    def delete_file():
        filename = request.form["filename"]
        target = os.path.join(UPLOAD_FOLDER, filename)
        if os.path.exists(target):
            os.remove(target)
            flash(f"{filename} deleted")
        return redirect(url_for("files"))
""", 'PATH'),
('R08', 'Flask send_file with guessed mimetype and header', FL, """
    import mimetypes

    @app.route("/media/<path:name>")
    def media(name):
        path = os.path.join("/srv/media", name)
        mime = mimetypes.guess_type(path)[0] or "application/octet-stream"
        resp = send_file(path, mimetype=mime)
        resp.headers["Content-Disposition"] = f"inline; filename={os.path.basename(path)}"
        return resp
""", 'PATH'),
('R09', 'Flask login_required download', FL, """
    from flask_login import login_required

    @app.route("/reports/<path:name>")
    @login_required
    def report(name):
        return send_file(os.path.join("/srv/reports", name))
""", 'PATH'),
('R10', 'Flask handler with @cross_origin()', FL, """
    from flask_cors import cross_origin

    @app.route("/fetch")
    @cross_origin()
    def fetch():
        url = request.args.get("url", "")
        return requests.get(url, timeout=5).text
""", 'SSRF'),
('R11', 'Flask upload saved under the client file name (f.save)', FL, """
    UPLOAD_FOLDER = "/srv/uploads"

    @app.route("/upload", methods=["POST"])
    def upload():
        f = request.files["file"]
        if f.filename == "":
            return jsonify(error="no file selected"), 400
        f.save(os.path.join(UPLOAD_FOLDER, f.filename))
        return jsonify(saved=f.filename)
""", 'PATH'),
('R12', 'Flask upload written with open() under the client file name', FL, """
    UPLOAD_FOLDER = "/srv/uploads"

    @app.route("/upload2", methods=["POST"])
    def upload2():
        f = request.files["file"]
        dest = os.path.join(UPLOAD_FOLDER, f.filename)
        with open(dest, "wb") as out:
            out.write(f.read())
        return jsonify(saved=True)
""", 'PATH'),
('R13', 'Flask image fetch by URL then save', FL, """
    @app.route("/import", methods=["POST"])
    def import_image():
        image_url = request.json.get("image_url")
        if not image_url:
            return jsonify(error="image_url required"), 400
        resp = requests.get(image_url, stream=True, timeout=10)
        resp.raise_for_status()
        return jsonify(size=len(resp.content))
""", 'SSRF'),
('R14', 'FastAPI download with HTTPException message', FA, """
    from pathlib import Path
    FILES = Path("/srv/files")

    @app.get("/download")
    def download(name: str):
        file = FILES / name
        if not file.exists():
            raise HTTPException(status_code=404, detail=f"{name} not found")
        return FileResponse(file, filename=file.name)
""", 'PATH'),
('R15', 'FastAPI proxy with Query(...) declaration', FA, """
    @app.get("/proxy")
    async def proxy(url: str = Query(..., description="address to fetch")):
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(url)
        return {"status": resp.status_code, "body": resp.text}
""", 'SSRF'),
('R16', 'FastAPI form field with Form(...)', FA, """
    from fastapi import Form

    @app.post("/render")
    def render(template: str = Form(...)):
        from jinja2 import Template
        return {"html": Template(template).render()}
""", 'TPL'),
('R17', 'FastAPI redirect with a default', FA, """
    @app.get("/logout")
    def logout(next: str = "/"):
        return RedirectResponse(url=next, status_code=302)
""", 'REDIR'),
('R18', 'FastAPI proxy behind an auth dependency named verify_token', FA, """
    from myapp.security import verify_token

    @app.get("/fetch")
    async def fetch(url: str, user=Depends(verify_token)):
        async with httpx.AsyncClient() as client:
            return (await client.get(url)).text
""", 'SSRF'),
('R19', 'FastAPI JSON body model -> webhook call', FA, """
    from pydantic import BaseModel

    class WebhookTest(BaseModel):
        url: str
        secret: str = ""

    @app.post("/webhooks/test")
    async def test_webhook(body: WebhookTest):
        async with httpx.AsyncClient() as client:
            resp = await client.post(body.url, json={"event": "ping"}, headers={"X-Secret": body.secret})
        return {"status": resp.status_code}
""", 'SSRF'),
('R20', 'FastAPI upload saved under the client file name', FA, """
    import shutil

    @app.post("/upload")
    def upload(file: UploadFile):
        dest = os.path.join("/srv/uploads", file.filename)
        with open(dest, "wb") as out:
            shutil.copyfileobj(file.file, out)
        return {"filename": file.filename}
""", 'PATH'),
('R21', 'Django download view (the usual snippet)', DJ, """
    from django.conf import settings

    def download(request):
        file_name = request.GET.get("file")
        file_path = os.path.join(settings.MEDIA_ROOT, file_name)
        if os.path.exists(file_path):
            with open(file_path, "rb") as fh:
                response = HttpResponse(fh.read(), content_type="application/octet-stream")
                response["Content-Disposition"] = "attachment; filename=" + os.path.basename(file_path)
                return response
        raise Http404
""", 'PATH'),
('R22', 'Django redirect after POST', DJ, """
    def set_language(request):
        next_url = request.POST.get("next", request.GET.get("next", "/"))
        response = HttpResponseRedirect(next_url)
        response.set_cookie("lang", "ko")
        return response
""", 'REDIR'),
('R23', 'Django staff-only fetch', DJ, """
    from django.contrib.admin.views.decorators import staff_member_required

    @staff_member_required
    def fetch_feed(request):
        url = request.GET.get("url", "")
        return HttpResponse(requests.get(url, timeout=5).content)
""", 'SSRF'),
('R24', 'DRF APIView export by name', DRF, """
    class Export(APIView):
        def get(self, request):
            name = request.query_params.get("name")
            if name is None:
                return Response({"detail": "name is required"}, status=400)
            return FileResponse(open(os.path.join("/srv/exports", name), "rb"), as_attachment=True)
""", 'PATH'),
('R25', 'tornado download with initialize()', TO, """
    class Download(tornado.web.RequestHandler):
        def initialize(self, storage_dir):
            self.storage_dir = storage_dir

        def get(self):
            name = self.get_argument("name")
            with open(os.path.join(self.storage_dir, name), "rb") as fh:
                self.write(fh.read())
""", 'PATH'),
('R26', 'tornado download setting Content-Disposition', TO, """
    class Attachment(tornado.web.RequestHandler):
        def get(self):
            name = self.get_argument("name")
            self.set_header("Content-Disposition", "attachment; filename=" + name)
            with open(os.path.join("/srv/files", name), "rb") as fh:
                self.write(fh.read())
""", 'PATH'),
('R27', 'tornado redirect', TO, """
    class AfterLogin(tornado.web.RequestHandler):
        def post(self):
            self.set_secure_cookie("user", "1")
            self.redirect(self.get_argument("next", "/"))
""", 'REDIR'),
('R28', 'aiohttp proxy', AIO, """
    async def proxy(request):
        url = request.query.get("url")
        if not url:
            raise web.HTTPBadRequest(text="url is required")
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as resp:
                body = await resp.read()
        return web.Response(body=body, status=resp.status)
""", 'SSRF'),
('R29', 'aiohttp static download', AIO, """
    async def download(request):
        name = request.match_info.get("name") or request.query.get("name", "")
        path = os.path.join("/srv/files", name)
        if not os.path.isfile(path):
            raise web.HTTPNotFound(text=f"{name} not found")
        return web.FileResponse(path)
""", 'PATH'),
('R30', 'aiohttp redirect', AIO, """
    async def logout(request):
        raise web.HTTPFound(location=request.query.get("next", "/"))
""", 'REDIR'),
('R31', 'Flask MethodView with decorators = [login_required]', FL, """
    from flask.views import MethodView
    from flask_login import login_required

    class Logs(MethodView):
        decorators = [login_required]

        def get(self):
            name = request.args.get("name", "app.log")
            return send_file(os.path.join("/var/log/myapp", name))
""", 'PATH'),
('R32', 'Flask download choosing mimetype by extension', FL, """
    MIME = {".pdf": "application/pdf", ".csv": "text/csv"}

    @app.route("/export")
    def export():
        name = request.args.get("name", "")
        ext = os.path.splitext(name)[1].lower()
        return send_file(os.path.join("/srv/export", name), mimetype=MIME.get(ext, "application/octet-stream"))
""", 'PATH'),
('R33', 'Flask blueprint handler with @csrf.exempt', FL, """
    from extensions import csrf

    @app.route("/hooks/relay", methods=["POST"])
    @csrf.exempt
    def relay():
        target = request.form.get("target", "")
        return requests.post(target, data=request.get_data(), timeout=5).text
""", 'SSRF'),
('R34', 'Flask f-string template', FL, """
    @app.route("/greet")
    def greet():
        name = request.args.get("name", "guest")
        app.logger.info("greeting %s", name)
        return render_template_string(f"<h1>Hello {name}!</h1>")
""", 'TPL'),
]


@pytest.mark.parametrize("case", VULN5, ids=[c[0] + " " + c[1] for c in VULN5])
def test_vulnerable_shape(case: tuple) -> None:
    cid, title, header, code, rule = case
    assert (rule in _flows(header, code)) == (cid not in KNOWN_MISSES), (cid, title)
