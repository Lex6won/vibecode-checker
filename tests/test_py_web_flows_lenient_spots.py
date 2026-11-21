"""검사처럼 보이지만 검사가 아닌 코드 — 웹 요청 값 추적(py_web_flows)이 **놓치면 안 되는** 모양.

오탐을 줄이려고 '검사한 흔적'을 넓게 인정하다 보면 진짜 취약점까지 가려진다. 있는지만 확인한 경로,
다른 필드를 검사한 본문, 상관없는 확인 함수, 길이만 본 값, 끝나는 분기 안에서만 한 검사가 그 예다.
"""
from __future__ import annotations

import ast
import textwrap

import pytest

from gvskb.scanners.ast_scanner import _collect_import_aliases
from gvskb.scanners.py_web_flows import scan_web_flows

N = chr(10)
FL = N.join(["from flask import Flask, request, redirect, send_file, render_template_string, abort, url_for",
             "import os, requests", "app = Flask(__name__)", ""])
FA = N.join(["import os, httpx", "from fastapi import FastAPI, Depends, Query, UploadFile",
             "from fastapi.responses import FileResponse, RedirectResponse", "from pydantic import BaseModel", "app = FastAPI()", ""])
S, T, P, R = "KISA-PY-INPUT-12", "KISA-PY-INPUT-04", "KISA-PY-INPUT-03", "KISA-PY-INPUT-07"
CASES = [
    ("있는지만 확인하고 연다", P, FL, """
        @app.route("/d")
        def d():
            name = request.args.get("name", "")
            full = os.path.join("/srv/files", name)
            if not os.path.exists(full):
                abort(404)
            return send_file(full)
    """),
    ("있는지 본 결과를 변수에 담음", P, FL, """
        @app.route("/d")
        def d():
            name = request.args.get("name", "")
            full = os.path.join("/srv/files", name)
            found = os.path.isfile(full)
            if not found:
                abort(404)
            return open(full).read()
    """),
    ("pathlib 로 있는지만 확인", P, FA, """
        from pathlib import Path

        @app.get("/f/{name:path}")
        def f(name: str):
            target = Path("/srv/files") / name
            if not target.is_file():
                return {"error": "none"}
            return FileResponse(target)
    """),
    ("다른 필드를 검사", S, FL, """
        @app.route("/p", methods=["POST"])
        def p():
            data = request.get_json()
            url = data["url"]
            name = data["name"]
            if not is_valid_name(name):
                abort(400)
            return requests.get(url).text
    """),
    ("다른 필드를 조건에서 검사", S, FL, """
        @app.route("/p", methods=["POST"])
        def p():
            data = request.get_json()
            if data["kind"] not in ("a", "b"):
                abort(400)
            return requests.get(data["url"]).text
    """),
    ("상관없는 확인 함수", S, FL, """
        @app.route("/p")
        def p():
            url = request.args.get("url")
            check_rate_limit(request.remote_addr)
            return requests.get(url).text
    """),
    ("길이만 확인", S, FL, """
        @app.route("/p")
        def p():
            url = request.args.get("url", "")
            if len(url) > 2000:
                abort(414)
            return requests.get(url).text
    """),
    ("모델의 문자열 필드", S, FA, """
        class Body(BaseModel):
            url: str
            count: int

        @app.post("/fetch")
        def fetch(body: Body):
            return httpx.get(body.url).text
    """),
    ("올린 파일 이름으로 저장", P, FA, """
        @app.post("/up")
        async def up(file: UploadFile):
            with open(os.path.join("/srv/uploads", file.filename), "wb") as out:
                out.write(await file.read())
            return {"ok": True}
    """),
    ("호출 뒤에 검사", S, FL, """
        @app.route("/p")
        def p():
            url = request.args.get("url", "")
            body = requests.get(url).text
            if not url.startswith("https://api.example.go.kr/"):
                abort(400)
            return body
    """),
    ("한꺼번에 풀어 담기", S, FL, """
        @app.route("/p")
        def p():
            a, b = request.args["a"], request.args["b"]
            return requests.get(a).text + b
    """),
    ("목록을 돌며 요청", S, FL, """
        @app.route("/p", methods=["POST"])
        def p():
            out = []
            for u in request.json["urls"]:
                out.append(requests.get(u).text)
            return str(out)
    """),
    ("스킴 뒤에 요청 값", S, FL, """
        @app.route("/p")
        def p():
            host = request.args["host"]
            return requests.get("https://" + host + "/status").text
    """),
    ("urljoin 은 절대 주소가 오면 기준을 버린다", S, FL, """
        from urllib.parse import urljoin
        BASE = "https://api.example.go.kr/"

        @app.route("/p")
        def p():
            path = request.args.get("path", "")
            return requests.get(urljoin(BASE, path)).text
    """),
    ("FastAPI 질의 매개변수 리다이렉트", R, FA, """
        @app.get("/go")
        def go(next: str = "/"):
            return RedirectResponse(next)
    """),
    ("검사는 한쪽 분기에서만", P, FL, """
        @app.route("/d")
        def d():
            name = request.args.get("name", "")
            if request.args.get("strict"):
                if not is_safe_name(name):
                    abort(400)
                return "checked"
            return open("/srv/files/" + name).read()
    """),
    ("값을 들여다본 결과를 상관없는 데 씀", P, FL, """
        @app.route("/d")
        def d():
            name = request.args.get("name", "")
            size = len(name)
            log_size(size)
            return open("/srv/files/" + name).read()
    """),
    ("템플릿 원문을 함수로 넘김", T, FL, """
        def render(page):
            return render_template_string(page)

        @app.route("/h")
        def h():
            return render("<p>" + request.args.get("msg", "") + "</p>")
    """),
]


#: 값이 조건에 한 번이라도 쓰여서 **판단하지 않는** 것. 검사가 호출보다 뒤에 있는지, 끝나는 분기 안에만 있는지까지는 보지 않는다.
SILENT_BY_DESIGN = {"호출 뒤에 검사", "검사는 한쪽 분기에서만"}


@pytest.mark.parametrize("label,rule,header,code", CASES, ids=[c[0] for c in CASES])
def test_unchecked_value_is_still_reported(label: str, rule: str, header: str, code: str) -> None:
    source = header + textwrap.dedent(code)
    tree = ast.parse(source)
    got = {hit[0] for hit in scan_web_flows(tree, source.split(N), _collect_import_aliases(tree), strict=True)}
    assert (rule in got) == (label not in SILENT_BY_DESIGN), label
