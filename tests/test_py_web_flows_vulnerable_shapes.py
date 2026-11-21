"""독립 적대적 검증 1·2차(2026-11-21)가 만든 **실제로 뚫리는** 코드 — 웹 요청 값 추적(py_web_flows)의 정탐 기준선.

검사처럼 보이지만 검사가 아닌 코드를 일부러 많이 넣은 모음이다. 추적기는 '값이 다른 데 쓰인 적이 없을 때만 보고한다'는
원칙이라 그런 코드는 판단하지 않는다 — 놓치는 것을 이유와 함께 그대로 적어 둔다.
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
    'V17': 'validation after the sink',
    'V20': 'a different variable is validated',
    'L03': 'mimetypes.guess_type result used in a condition',
    'L04': 'cache lookup keyed by the url, then fetch',
    'L08': 'required-keys loop',
    'L09': ".endswith('.pdf') only before a path join",
    'L10': 'scheme normalisation, nothing blocked',
    'L11': 'special-case comparison only',
    'L12': 'index.html append (static server)',
    'L13': 'validated branch returns, fallback uses raw value',
    'L14': 'checked, then re-read from the request inside a branch',
    'L15': 'validation only when a flag is set',
    'L16': 'ensure_dir(dirname(path)) then write',
    'L17': 'invalidate_cache(name) then open',
    'L18': 'bleach.clean() result as template source',
    'L19': 'field_validator that only strips',
    'L20': 'model_validator about other fields',
    'L22': 'StringConstraints without a pattern',
    'L26': 'URL template with the value in the host',
    'L27': "f'https://{DOMAIN}{path}'",
    'L28': 'match with fallthrough default',
    'L35': 'background_tasks.add_task(fetch, url)',
    'L38': 'Django URL kwarg',
    'L47': 'Model.model_validate(json) then str field',
    'L48': 'os.path.splitext(name)[0] keeps the directory part',
    'L49': 're.sub that only replaces whitespace',
    'L50': 'query-parameter class via Depends()',
    'L52': 'same-file bookkeeping helper that returns bool',
    'L53': 'defaultdict counter lookup TABLE[name]',
    'L55': 'unknown lookup result used in an unrelated condition',
    'L56': 'imported model, field called value',
    'L57': 'whole model object passed to a helper',
    'L62': 'MethodView path parameter',
    'L67': 'port in the authority (userinfo trick)',
    'L68': 'only a slash-count check',
    'L69': 'checked in the helper by scheme only',
    'L70': 'pandas boolean-index lookup then open',
    'X01': 'int() in try, except passes (raw string survives)',
    'X03': 'Expr int(x) in try, except passes',
    'X04': 'TABLE[name] in try, except passes',
    'X05': 'view var only in a ternary for something else',
    'X06': 'is_valid-style name on an unrelated object method',
    'X07': 'check_password(user, pw) names the user, url untouched',
    'X08': 'FastAPI constr() without pattern',
    'X09': 'print(name in SEEN) style predicate arg to unknown call',
    'X10': 'validated decorator on unrelated thing',
    'X14': 'Flask route param not in <...> but read from view_args',
    'X15': 'object param stringified',
    'X16': 'pattern that only fixes the suffix',
    'X17': 'Django class-based view self.kwargs',
    'X18': 'isinstance + strip only',
}

VULN = [
('V01', 'FastAPI query param -> httpx client', FA, """
    @app.get("/fetch")
    async def fetch(url: str, timeout: int = 5):
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.get(url)
        return {"body": r.text}
""", 'SSRF'),
('V02', 'Django request.GET -> requests.get', DJ, """
    def preview(request):
        target = request.GET.get("target", "")
        resp = requests.get(target, timeout=5)
        return HttpResponse(resp.content)
""", 'SSRF'),
('V03', 'tornado self.request.body JSON -> open', TO, """
    class Read(tornado.web.RequestHandler):
        def post(self):
            body = json.loads(self.request.body)
            path = body["path"]
            with open(path) as fh:
                self.write(fh.read())
""", 'PATH'),
('V04', 'dict field then os.remove', FL, """
    @app.route("/rm", methods=["POST"])
    def rm():
        data = request.get_json()
        target = data["file"]
        os.remove(os.path.join("/srv/uploads", target))
        return "ok"
""", 'PATH'),
('V05', 'tuple unpacking host/port', FL, """
    @app.route("/probe")
    def probe():
        host, port = request.args["host"], request.args.get("port", "80")
        return requests.get(f"http://{host}:{port}/health", timeout=2).text
""", 'SSRF'),
('V06', 'loop over JSON list', FL, """
    @app.route("/batch", methods=["POST"])
    def batch():
        out = []
        for u in request.get_json()["urls"]:
            out.append(requests.get(u, timeout=5).status_code)
        return jsonify(out)
""", 'SSRF'),
('V07', 'helper one hop (keyword arg)', FL, """
    def read_file(base, name):
        with open(os.path.join(base, name)) as fh:
            return fh.read()

    @app.route("/doc")
    def doc():
        return read_file("/srv/docs", name=request.args.get("name", ""))
""", 'PATH'),
('V08', 'helper two hops', FL, """
    def _download(u):
        return requests.get(u, timeout=10).content

    def mirror(src):
        blob = _download(src)
        return len(blob)

    @app.route("/mirror", methods=["POST"])
    def do_mirror():
        return str(mirror(request.form["src"]))
""", 'SSRF'),
('V09', 'str()/.format() into template source', FL, """
    @app.route("/hello")
    def hello():
        name = str(request.args.get("name", "guest"))
        html = "<h1>Hello {}</h1>".format(name)
        return render_template_string(html)
""", 'TPL'),
('V10', 'os.path.join then send_file', FL, """
    @app.route("/dl")
    def dl():
        fname = request.args.get("file", "")
        full = os.path.join(app.root_path, "exports", fname)
        return send_file(full, as_attachment=True)
""", 'PATH'),
('V11', 'Path(BASE)/name -> FileResponse', FA, """
    from pathlib import Path
    STORE = Path("/srv/store")

    @app.get("/raw")
    def raw(name: str):
        return FileResponse(STORE / "raw" / name)
""", 'PATH'),
('V12', 'pydantic model str field -> httpx.get', FA, """
    from pydantic import BaseModel

    class Hook(BaseModel):
        callback: str
        retries: int = 0

    @app.post("/hook/test")
    def hook_test(hook: Hook):
        return {"status": httpx.get(hook.callback).status_code}
""", 'SSRF'),
('V13', 'UploadFile.filename -> open', FA, """
    @app.post("/upload")
    async def upload(file: UploadFile):
        dest = os.path.join("/srv/uploads", file.filename)
        with open(dest, "wb") as out:
            out.write(await file.read())
        return {"ok": True}
""", 'PATH'),
('V14', 'f-string host', FL, """
    @app.route("/node")
    def node():
        host = request.args.get("node", "")
        return requests.get(f"http://{host}/metrics", timeout=3).text
""", 'SSRF'),
('V15', "'https://' + host + path", FL, """
    @app.route("/site")
    def site():
        domain = request.args.get("domain", "")
        url = "https://" + domain + "/robots.txt"
        return requests.get(url, timeout=3).text
""", 'SSRF'),
('V16', 'urljoin(BASE, user value)', FL, """
    from urllib.parse import urljoin
    BASE = "https://api.example.go.kr/v1/"

    @app.route("/api")
    def api():
        path = request.args.get("path", "")
        return requests.get(urljoin(BASE, path), timeout=5).text
""", 'SSRF'),
('V17', 'validation after the sink', FL, """
    ALLOWED = {"https://a.example.go.kr/"}

    @app.route("/p")
    def p():
        url = request.args.get("url", "")
        body = requests.get(url, timeout=5).text
        if url not in ALLOWED:
            abort(403)
        return body
""", 'SSRF'),
('V18', 'only emptiness and length checks', FL, """
    @app.route("/dl")
    def dl():
        name = request.args.get("name")
        if not name or len(name) > 100:
            abort(400)
        return send_file(os.path.join("/srv/files", name))
""", 'PATH'),
('V19', 'value only logged', FL, """
    import logging
    log = logging.getLogger(__name__)

    @app.route("/dl")
    def dl():
        name = request.args.get("name", "")
        log.info("download requested: %s", name)
        return send_file("/srv/files/" + name)
""", 'PATH'),
('V20', 'a different variable is validated', FL, """
    ALLOWED = {"a.csv"}

    @app.route("/dl")
    def dl():
        name = request.args.get("name", "")
        fallback = request.args.get("fallback", "")
        if name not in ALLOWED:
            name = fallback
        return send_file(os.path.join("/srv/files", fallback))
""", 'PATH'),
('V21', 'a different field of the same JSON body is validated', FL, """
    @app.route("/call", methods=["POST"])
    def call():
        data = request.get_json()
        if data["method"] not in ("GET", "POST"):
            abort(400)
        return requests.request(data["method"], data["url"], timeout=5).text
""", 'SSRF'),
('V22', 'existence check then send', FL, """
    @app.route("/dl")
    def dl():
        path = os.path.join("/srv/files", request.args.get("name", ""))
        if not os.path.exists(path):
            abort(404)
        return send_file(path)
""", 'PATH'),
('V23', 'unrelated check_rate_limit(ip), url untouched', FL, """
    from limits import check_rate_limit

    @app.route("/p")
    def p():
        url = request.args.get("url", "")
        check_rate_limit(request.remote_addr)
        return requests.get(url, timeout=5).text
""", 'SSRF'),
('V24', 'RedirectResponse(url=param)', FA, """
    @app.get("/out")
    def out(to: str):
        return RedirectResponse(url=to, status_code=302)
""", 'REDIR'),
('V25', 'jinja2.Template(source)', FL, """
    from jinja2 import Template

    @app.route("/card", methods=["POST"])
    def card():
        src = request.form["template"]
        return Template(src).render(user="x")
""", 'TPL'),
('V26', 'env.from_string(source)', FL, """
    from jinja2 import Environment
    jinja_env = Environment()

    @app.route("/card", methods=["POST"])
    def card():
        body = request.get_json()
        tpl = jinja_env.from_string("<div>" + body["html"] + "</div>")
        return tpl.render()
""", 'TPL'),
('V27', 'Django redirect(next)', DJ, """
    def logout_done(request):
        nxt = request.GET.get("next") or "/"
        return redirect(nxt)
""", 'REDIR'),
('L01', 'existence check on a joined path, inline', FL, """
    @app.route("/dl")
    def dl():
        name = request.args.get("name", "")
        if not os.path.exists(os.path.join("/srv/files", name)):
            abort(404)
        return send_file(os.path.join("/srv/files", name))
""", 'PATH'),
('L02', '(BASE / name).exists() inline', FA, """
    from pathlib import Path
    BASE = Path("/srv/files")

    @app.get("/dl")
    def dl(name: str):
        if not (BASE / name).is_file():
            raise HTTPException(404)
        return FileResponse(BASE / name)
""", 'PATH'),
('L03', 'mimetypes.guess_type result used in a condition', FL, """
    import mimetypes

    @app.route("/view")
    def view():
        path = os.path.join("/srv/files", request.args.get("name", ""))
        mime, _ = mimetypes.guess_type(path)
        if mime is None:
            mime = "application/octet-stream"
        return send_file(path, mimetype=mime)
""", 'PATH'),
('L04', 'cache lookup keyed by the url, then fetch', FL, """
    from extensions import cache

    @app.route("/p")
    def p():
        url = request.args.get("url", "")
        cached = cache.get(url)
        if cached is not None:
            return cached
        body = requests.get(url, timeout=5).text
        cache.set(url, body)
        return body
""", 'SSRF'),
('L05', 'length stored in a variable then tested', FL, """
    @app.route("/dl")
    def dl():
        name = request.args.get("name", "")
        size = len(name)
        if size == 0 or size > 100:
            abort(400)
        return send_file(os.path.join("/srv/files", name))
""", 'PATH'),
('L06', 'two fields unpacked, only one validated', FL, """
    @app.route("/call", methods=["POST"])
    def call():
        data = request.get_json()
        url, kind = data["url"], data["kind"]
        if kind not in ("ping", "status"):
            abort(400)
        return requests.get(url, timeout=5).text
""", 'SSRF'),
('L07', 'one field normalised and validated, another used', FL, """
    @app.route("/call", methods=["POST"])
    def call():
        data = request.get_json()
        action = data.get("action", "").lower()
        if action not in ("fetch", "head"):
            abort(400)
        return requests.get(data["url"], timeout=5).text
""", 'SSRF'),
('L08', 'required-keys loop', FL, """
    @app.route("/call", methods=["POST"])
    def call():
        data = request.get_json()
        for field in ("url", "token"):
            if field not in data:
                abort(400)
        return requests.get(data["url"], timeout=5).text
""", 'SSRF'),
('L09', ".endswith('.pdf') only before a path join", FL, """
    @app.route("/dl")
    def dl():
        name = request.args.get("name", "")
        if not name.endswith(".pdf"):
            abort(400)
        return send_file(os.path.join("/srv/reports", name))
""", 'PATH'),
('L10', 'scheme normalisation, nothing blocked', FL, """
    @app.route("/p")
    def p():
        url = request.args.get("url", "")
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        return requests.get(url, timeout=5).text
""", 'SSRF'),
('L11', 'special-case comparison only', FL, """
    @app.route("/dl/<path:name>")
    def dl(name):
        if name == "latest":
            name = current_release_name()
        return send_file(os.path.join("/srv/releases", name))
""", 'PATH'),
('L12', 'index.html append (static server)', FL, """
    @app.route("/site/<path:name>")
    def site(name):
        if name.endswith("/"):
            name += "index.html"
        return send_file(os.path.join("/srv/site", name))
""", 'PATH'),
('L13', 'validated branch returns, fallback uses raw value', FL, """
    PUBLIC = {"terms.pdf", "manual.pdf"}

    @app.route("/dl")
    def dl():
        name = request.args.get("name", "")
        if name in PUBLIC:
            return send_file(os.path.join("/srv/public", name))
        return send_file(os.path.join("/srv/private", name))
""", 'PATH'),
('L14', 'checked, then re-read from the request inside a branch', FL, """
    @app.route("/p")
    def p():
        url = request.args["a"]
        if not is_allowed_host(url):
            abort(400)
        if request.args.get("override"):
            url = request.args["override"]
        return requests.get(url).text
""", 'SSRF'),
('L15', 'validation only when a flag is set', FL, """
    ALLOWED = {"a.csv"}

    @app.route("/dl")
    def dl():
        name = request.args.get("name", "")
        if app.config.get("STRICT"):
            if name not in ALLOWED:
                abort(403)
        return send_file(os.path.join("/srv/files", name))
""", 'PATH'),
('L16', 'ensure_dir(dirname(path)) then write', FL, """
    from fsutil import ensure_dir

    @app.route("/save", methods=["POST"])
    def save():
        path = os.path.join("/srv/data", request.form["name"])
        ensure_dir(os.path.dirname(path))
        with open(path, "w") as fh:
            fh.write(request.form["body"])
        return "ok"
""", 'PATH'),
('L17', 'invalidate_cache(name) then open', FL, """
    from extensions import invalidate_cache

    @app.route("/reload")
    def reload_doc():
        name = request.args.get("name", "")
        invalidate_cache(name)
        return open(os.path.join("/srv/docs", name)).read()
""", 'PATH'),
('L18', 'bleach.clean() result as template source', FL, """
    import bleach

    @app.route("/note", methods=["POST"])
    def note():
        html = bleach.clean(request.form["body"])
        return render_template_string("<article>" + html + "</article>")
""", 'TPL'),
('L19', 'field_validator that only strips', FA, """
    from pydantic import BaseModel, field_validator

    class Fetch(BaseModel):
        url: str

        @field_validator("url")
        @classmethod
        def strip(cls, v):
            return v.strip()

    @app.post("/fetch")
    def fetch(body: Fetch):
        return httpx.get(body.url).text
""", 'SSRF'),
('L20', 'model_validator about other fields', FA, """
    from pydantic import BaseModel, model_validator

    class Export(BaseModel):
        start: int
        end: int
        filename: str

        @model_validator(mode="after")
        def order(self):
            if self.start > self.end:
                raise ValueError("start > end")
            return self

    @app.post("/export")
    def export(body: Export):
        return FileResponse(os.path.join("/srv/exports", body.filename))
""", 'PATH'),
('L21', 'model field named file', FA, """
    from pydantic import BaseModel

    class ReadReq(BaseModel):
        file: str

    @app.post("/read")
    def read(body: ReadReq):
        with open(os.path.join("/srv/data", body.file)) as fh:
            return {"text": fh.read()}
""", 'PATH'),
('L22', 'StringConstraints without a pattern', FA, """
    from typing import Annotated
    from pydantic import StringConstraints

    @app.get("/dl")
    def dl(name: Annotated[str, StringConstraints(min_length=1, max_length=200)]):
        return FileResponse(os.path.join("/srv/files", name))
""", 'PATH'),
('L23', 'body model parameter named req', FA, """
    from pydantic import BaseModel

    class ProxyRequest(BaseModel):
        url: str

    @app.post("/proxy")
    def proxy(req: ProxyRequest):
        return httpx.get(req.url).text
""", 'SSRF'),
('L24', "redirect('/' + next)", FL, """
    @app.route("/go")
    def go():
        nxt = request.args.get("next", "")
        return redirect("/" + nxt)
""", 'REDIR'),
('L25', "f'{scheme}://{host}/...'", FL, """
    @app.route("/node")
    def node():
        scheme = "https" if app.config.get("TLS") else "http"
        host = request.args.get("node", "")
        return requests.get(f"{scheme}://{host}/metrics", timeout=3).text
""", 'SSRF'),
('L26', 'URL template with the value in the host', FL, """
    TENANT_URL = "https://{tenant}.example.go.kr/api/status"

    @app.route("/tenant/<tenant>/status")
    def status(tenant):
        return requests.get(TENANT_URL.format(tenant=tenant), timeout=3).text
""", 'SSRF'),
('L27', "f'https://{DOMAIN}{path}'", FL, """
    DOMAIN = "portal.example.go.kr"

    @app.route("/go")
    def go():
        path = request.args.get("path", "")
        return redirect(f"https://{DOMAIN}{path}")
""", 'REDIR'),
('L28', 'match with fallthrough default', FL, """
    @app.route("/dl")
    def dl():
        name = request.args.get("name", "")
        match name:
            case "latest":
                path = "/srv/releases/latest.zip"
            case _:
                path = os.path.join("/srv/releases", name)
        return send_file(path)
""", 'PATH'),
('L29', 'walrus binding', FL, """
    @app.route("/p")
    def p():
        if (url := request.args.get("url")):
            return requests.get(url, timeout=5).text
        return "", 204
""", 'SSRF'),
('L30', 'comprehension over request values', FL, """
    @app.route("/batch", methods=["POST"])
    def batch():
        urls = [u.strip() for u in request.get_json()["urls"]]
        out = []
        for u in urls:
            out.append(requests.get(u, timeout=5).status_code)
        return jsonify(out)
""", 'SSRF'),
('L31', 'enumerate() loop', FL, """
    @app.route("/batch", methods=["POST"])
    def batch():
        urls = request.get_json()["urls"]
        out = {}
        for i, u in enumerate(urls):
            out[i] = requests.get(u, timeout=5).status_code
        return jsonify(out)
""", 'SSRF'),
('L32', 'value stored into a dict key', FL, """
    @app.route("/p")
    def p():
        opts = {"timeout": 5}
        opts["url"] = request.args.get("url", "")
        return requests.get(opts["url"], timeout=opts["timeout"]).text
""", 'SSRF'),
('L33', 'list.append then loop', FL, """
    @app.route("/cat")
    def cat():
        names = []
        names.append(request.args.get("a", ""))
        names.append(request.args.get("b", ""))
        out = ""
        for n in names:
            out += open(os.path.join("/srv/files", n)).read()
        return out
""", 'PATH'),
('L34', 'streaming generator closure', FL, """
    from flask import Response

    @app.route("/stream")
    def stream():
        path = os.path.join("/srv/media", request.args.get("name", ""))

        def generate():
            with open(path, "rb") as fh:
                yield from fh

        return Response(generate(), mimetype="application/octet-stream")
""", 'PATH'),
('L35', 'background_tasks.add_task(fetch, url)', FA, """
    from fastapi import BackgroundTasks

    def crawl(url: str):
        httpx.get(url)

    @app.post("/crawl")
    def start(url: str, background_tasks: BackgroundTasks):
        background_tasks.add_task(crawl, url)
        return {"queued": True}
""", 'SSRF'),
('L36', 'same-file helper returns the joined path', FL, """
    def upload_path(name):
        return os.path.join("/srv/uploads", name)

    @app.route("/dl")
    def dl():
        return send_file(upload_path(request.args.get("name", "")))
""", 'PATH'),
('L37', 'helper method on the view class', FL, """
    from flask.views import MethodView

    class Proxy(MethodView):
        def _fetch(self, url):
            return requests.get(url, timeout=5).text

        def get(self):
            return self._fetch(request.args.get("url", ""))
""", 'SSRF'),
('L38', 'Django URL kwarg', DJ, """
    from django.conf import settings

    def download(request, name):
        return FileResponse(open(os.path.join(settings.MEDIA_ROOT, name), "rb"))
""", 'PATH'),
('L39', 'tornado get_argument', TO, """
    class Proxy(tornado.web.RequestHandler):
        def get(self):
            url = self.get_argument("url")
            self.write(requests.get(url, timeout=5).text)
""", 'SSRF'),
('L40', 'aiohttp request.query', AIO, """
    async def proxy(request):
        url = request.query.get("url", "")
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as resp:
                return web.Response(text=await resp.text())
""", 'SSRF'),
('L41', 'bottle <name:path> route', 'import os\nfrom bottle import route, request, static_file\n', """
    @route("/files/<filepath:path>")
    def files(filepath):
        return open(os.path.join("/srv/files", filepath)).read()
""", 'PATH'),
('L42', 'sanic <name:str> route', "import os\nfrom sanic import Sanic\nfrom sanic.response import text\napp = Sanic('x')\n", """
    @app.get("/files/<name:str>")
    async def files(request, name):
        return text(open(os.path.join("/srv/files", name)).read())
""", 'PATH'),
('L43', 'route path built from a constant prefix', FA, """
    API_V1 = "/api/v1"

    @app.get(API_V1 + "/fetch")
    async def fetch(url: str):
        async with httpx.AsyncClient() as client:
            return (await client.get(url)).text
""", 'SSRF'),
('L44', 'chalice {name} path parameter', "import os\nfrom chalice import Chalice\napp = Chalice(app_name='x')\n", """
    @app.route("/files/{name}")
    def files(name):
        return open(os.path.join("/srv/files", name)).read()
""", 'PATH'),
('L45', 'tornado.escape.json_decode(body)', TO, """
    class Fetch(tornado.web.RequestHandler):
        def post(self):
            data = tornado.escape.json_decode(self.request.body)
            self.write(requests.get(data["url"], timeout=5).text)
""", 'SSRF'),
('L46', 'yaml.safe_load(request.data)', FL, """
    import yaml

    @app.route("/job", methods=["POST"])
    def job():
        spec = yaml.safe_load(request.data)
        return requests.get(spec["source"], timeout=5).text
""", 'SSRF'),
('L47', 'Model.model_validate(json) then str field', 'import httpx\nfrom starlette.responses import PlainTextResponse\nfrom pydantic import BaseModel\n', """
    class Body(BaseModel):
        url: str

    async def fetch(request):
        body = Body.model_validate(await request.json())
        return PlainTextResponse(httpx.get(body.url).text)
""", 'SSRF'),
('L48', 'os.path.splitext(name)[0] keeps the directory part', FL, """
    @app.route("/thumb")
    def thumb():
        name = request.args.get("name", "")
        stem = os.path.splitext(name)[0]
        return send_file(os.path.join("/srv/thumbs", stem + ".png"))
""", 'PATH'),
('L49', 're.sub that only replaces whitespace', FL, """
    @app.route("/dl")
    def dl():
        name = re.sub(r"\\s+", "_", request.args.get("name", ""))
        return send_file(os.path.join("/srv/files", name))
""", 'PATH'),
('L50', 'query-parameter class via Depends()', FA, """
    class DlParams:
        def __init__(self, name: str, inline: bool = False):
            self.name = name
            self.inline = inline

    @app.get("/dl")
    def dl(params: DlParams = Depends()):
        return FileResponse(os.path.join("/srv/files", params.name))
""", 'PATH'),
('L51', 'IPvAnyAddress parameter (any IP, incl. internal)', FA, """
    from pydantic import IPvAnyAddress

    @app.get("/probe")
    def probe(host: IPvAnyAddress):
        return httpx.get(f"http://{host}/status").text
""", 'SSRF'),
('L52', 'same-file bookkeeping helper that returns bool', FL, """
    _recent = set()

    def first_time(name):
        if name in _recent:
            return False
        _recent.add(name)
        return True

    @app.route("/dl")
    def dl():
        name = request.args.get("name", "")
        first_time(name)
        return send_file(os.path.join("/srv/files", name))
""", 'PATH'),
('L53', 'defaultdict counter lookup TABLE[name]', FL, """
    from collections import defaultdict
    HITS = defaultdict(int)

    @app.route("/dl")
    def dl():
        name = request.args.get("name", "")
        seen = HITS[name]
        HITS[name] = seen + 1
        return send_file(os.path.join("/srv/files", name))
""", 'PATH'),
('L54', 'getmtime stored then compared', FL, """
    import time

    @app.route("/dl")
    def dl():
        path = os.path.join("/srv/files", request.args.get("name", ""))
        mtime = os.path.getmtime(path)
        if time.time() - mtime > 86400 * 30:
            abort(410)
        return send_file(path)
""", 'PATH'),
('L55', 'unknown lookup result used in an unrelated condition', FL, """
    from catalog import lookup_title

    @app.route("/dl")
    def dl():
        name = request.args.get("name", "")
        title = lookup_title(name)
        if title:
            app.logger.info("serving %s", title)
        return send_file(os.path.join("/srv/files", name))
""", 'PATH'),
('L56', 'imported model, field called value', FA, """
    from myapp.schemas import Setting   # class Setting(BaseModel): key: str; value: str

    @app.post("/go")
    def go(item: Setting):
        return RedirectResponse(item.value)
""", 'REDIR'),
('L57', 'whole model object passed to a helper', FA, """
    from myapp.schemas import FetchBody   # url: str

    def do_fetch(body):
        return httpx.get(body.url).text

    @app.post("/fetch")
    def fetch(payload: FetchBody):
        return do_fetch(payload)
""", 'SSRF'),
('L58', 'Environment(...).from_string(source)', FL, """
    from jinja2 import Environment, BaseLoader

    @app.route("/render", methods=["POST"])
    def render():
        src = request.form["tpl"]
        return Environment(loader=BaseLoader()).from_string(src).render()
""", 'TPL'),
('L59', 'pathlib read_text (sink list)', FA, """
    from pathlib import Path

    @app.get("/read")
    def read(name: str):
        return {"text": (Path("/srv/files") / name).read_text()}
""", 'PATH'),
('L60', 'found = not os.path.exists(path) stored then tested', FL, """
    @app.route("/dl")
    def dl():
        path = os.path.join("/srv/files", request.args.get("name", ""))
        missing = not os.path.exists(path)
        if missing:
            abort(404)
        return send_file(path)
""", 'PATH'),
('L61', 'escape() inside template source', FL, """
    from markupsafe import escape

    @app.route("/hello")
    def hello():
        name = request.args.get("name", "")
        return render_template_string("<h1>Hello " + escape(name) + "</h1>")
""", 'TPL'),
('L62', 'MethodView path parameter', FL, """
    from flask.views import MethodView

    class Files(MethodView):
        def get(self, name):
            return send_file(os.path.join("/srv/files", name))

    app.add_url_rule("/files/<path:name>", view_func=Files.as_view("files"))
""", 'PATH'),
('L63', 'Django request.META referer redirect', DJ, """
    def back(request):
        return HttpResponseRedirect(request.META.get("HTTP_REFERER", "/"))
""", 'REDIR'),
('L64', 'three helper hops', FL, """
    def a(u):
        return requests.get(u).text

    def b(v):
        return a(v)

    def c(w):
        return b(w)

    @app.route("/p")
    def p():
        return c(request.args["u"])
""", 'SSRF'),
('L65', 'import urllib.request as ur', 'from flask import Flask, request\nimport urllib.request as ur\napp = Flask(__name__)\n', """
    @app.route("/p")
    def p():
        url = request.args.get("url", "")
        return ur.urlopen(url).read()
""", 'SSRF'),
('L66', 'requests.Session().get(url) chained', FL, """
    @app.route("/p")
    def p():
        url = request.args.get("url", "")
        return requests.Session().get(url, timeout=5).text
""", 'SSRF'),
('L67', 'port in the authority (userinfo trick)', FL, """
    INTERNAL = "metrics.internal"

    @app.route("/m")
    def m():
        port = request.args.get("port", "9100")
        return requests.get(f"http://{INTERNAL}:{port}/metrics", timeout=3).text
""", 'SSRF'),
('L68', 'only a slash-count check', FL, """
    @app.route("/dl")
    def dl():
        name = request.args.get("name", "")
        if name.count("/") > 5:
            abort(400)
        return send_file(os.path.join("/srv/files", name))
""", 'PATH'),
('L69', 'checked in the helper by scheme only', FL, """
    def fetch(url):
        if not url.startswith("http"):
            raise ValueError("scheme")
        return requests.get(url, timeout=5).text

    @app.route("/p")
    def p():
        return fetch(request.args.get("url", ""))
""", 'SSRF'),
('L70', 'pandas boolean-index lookup then open', FL, """
    import pandas as pd
    INDEX = pd.read_csv("/srv/index.csv")

    @app.route("/dl")
    def dl():
        name = request.args.get("name", "")
        rows = INDEX[INDEX["title"].str.contains(name)]
        return send_file(os.path.join("/srv/files", name), download_name=str(len(rows)))
""", 'PATH'),
('X01', 'int() in try, except passes (raw string survives)', FL, """
    @app.route("/doc")
    def doc():
        doc_id = request.args.get("id")
        try:
            doc_id = int(doc_id)
        except (TypeError, ValueError):
            pass
        return send_file(f"/srv/docs/{doc_id}.pdf")
""", 'PATH'),
('X02', 'secure_filename in try, except logs only', FL, """
    from werkzeug.utils import secure_filename

    @app.route("/dl")
    def dl():
        name = request.args.get("name", "")
        try:
            name = secure_filename(name.decode("utf-8"))
        except AttributeError:
            app.logger.warning("already text")
        return send_file(os.path.join("/srv/files", name))
""", 'PATH'),
('X03', 'Expr int(x) in try, except passes', FL, """
    @app.route("/page")
    def page():
        num = request.args.get("n", "1")
        try:
            int(num)
        except ValueError:
            app.logger.info("non-numeric page %s", num)
        return send_file(f"/srv/pages/{num}.html")
""", 'PATH'),
('X04', 'TABLE[name] in try, except passes', FL, """
    TITLES = {"manual": "User manual"}

    @app.route("/docs/<path:name>")
    def docs(name):
        try:
            title = TITLES[name]
        except KeyError:
            title = name
        return send_file(os.path.join("/srv/docs", name), download_name=title)
""", 'PATH'),
('X05', 'view var only in a ternary for something else', FL, """
    @app.route("/dl")
    def dl():
        name = request.args.get("name", "")
        m = re.match(r"(.*)\\.(\\w+)$", name)
        ext = m.group(2) if m else "bin"
        return send_file(os.path.join("/srv/files", name), mimetype="application/" + ext)
""", 'PATH'),
('X06', 'is_valid-style name on an unrelated object method', FL, """
    @app.route("/p", methods=["POST"])
    def p():
        url = request.form.get("url", "")
        form = CsrfForm(request.form)
        if not form.validate():
            abort(400)
        return requests.get(url, timeout=5).text
""", 'SSRF'),
('X07', 'check_password(user, pw) names the user, url untouched', FL, """
    @app.route("/p", methods=["POST"])
    def p():
        data = request.get_json()
        verify_signature(data)
        return requests.get(data["callback"], timeout=5).text
""", 'SSRF'),
('X08', 'FastAPI constr() without pattern', FA, """
    from pydantic import constr

    @app.get("/dl")
    def dl(name: constr(min_length=1)):
        return FileResponse(os.path.join("/srv/files", name))
""", 'PATH'),
('X09', 'print(name in SEEN) style predicate arg to unknown call', FL, """
    @app.route("/dl")
    def dl():
        name = request.args.get("name", "")
        app.logger.debug("pdf=%s", name.endswith(".pdf"))
        return send_file(os.path.join("/srv/files", name))
""", 'PATH'),
('X10', 'validated decorator on unrelated thing', FL, """
    @app.route("/dl/<path:name>")
    @validate_api_key
    def dl(name):
        return send_file(os.path.join("/srv/files", name))
""", 'PATH'),
('X11', 'template text via % with dict', FL, """
    @app.route("/hello")
    def hello():
        return render_template_string("<h1>%(n)s</h1>" % {"n": request.args.get("n", "")})
""", 'TPL'),
('X12', 'sink in comprehension element', FL, """
    @app.route("/cat")
    def cat():
        names = request.args.getlist("f")
        return "".join([open(os.path.join("/srv/files", n)).read() for n in names])
""", 'PATH'),
('X13', 'validated in for-loop body only for one element', FL, """
    @app.route("/p")
    def p():
        urls = request.args.getlist("u")
        for u in urls:
            if u.startswith("https://api.example.go.kr/"):
                break
        return requests.get(urls[0], timeout=5).text
""", 'SSRF'),
('X14', 'Flask route param not in <...> but read from view_args', FL, """
    @app.route("/dl/<path:name>")
    def dl(**kwargs):
        return send_file(os.path.join("/srv/files", kwargs["name"]))
""", 'PATH'),
('X15', 'object param stringified', FA, """
    from myapp.types import FileName   # NewType('FileName', str)

    @app.get("/dl")
    def dl(name: FileName):
        return FileResponse(os.path.join("/srv/files", name))
""", 'PATH'),
('X16', 'pattern that only fixes the suffix', FA, """
    @app.get("/dl")
    def dl(name: str = Query(..., pattern=r".+\\.pdf$")):
        return FileResponse(os.path.join("/srv/reports", name))
""", 'PATH'),
('X17', 'Django class-based view self.kwargs', DJ, """
    from django.views import View

    class Download(View):
        def get(self, request, *args, **kwargs):
            return FileResponse(open(os.path.join("/srv/media", self.kwargs["name"]), "rb"))
""", 'PATH'),
('X18', 'isinstance + strip only', FL, """
    @app.route("/p", methods=["POST"])
    def p():
        url = request.get_json().get("url")
        if not isinstance(url, str) or not url.strip():
            abort(400)
        return requests.get(url.strip(), timeout=5).text
""", 'SSRF'),
('X19', 'blocklist of one host', FL, """
    @app.route("/p")
    def p():
        url = request.args.get("url", "")
        if "localhost" in url:
            abort(403)
        return requests.get(url, timeout=5).text
""", 'SSRF'),
('X20', "'http' key-like containment", FL, """
    @app.route("/p")
    def p():
        url = request.args.get("url", "")
        if "http" not in url:
            abort(400)
        return requests.get(url, timeout=5).text
""", 'SSRF'),
]


@pytest.mark.parametrize("case", VULN, ids=[c[0] + " " + c[1] for c in VULN])
def test_vulnerable_shape(case: tuple) -> None:
    cid, title, header, code, rule = case
    assert (rule in _flows(header, code)) == (cid not in KNOWN_MISSES), (cid, title)
