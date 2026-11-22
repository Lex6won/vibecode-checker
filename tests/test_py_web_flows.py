"""웹 요청 값이 변수·함수를 거쳐 닿는 흐름(py_web_flows) — 정탐과, 같은 모양의 안전한 코드.

실측(2026-11-21): 한 줄에 출처와 호출이 함께 있을 때만 잡았고 변수 하나만 거치면 전부 놓쳤다.
추적을 넓히되, 검사 흔적·조회·고정 호스트·숫자 변환이 있으면 보고하지 않는다.
"""
from __future__ import annotations

import textwrap

import pytest

from gvskb.scanner import scan_code

SSRF, TEMPLATE, PATH, REDIRECT = "KISA-PY-INPUT-12", "KISA-PY-INPUT-04", "KISA-PY-INPUT-03", "KISA-PY-INPUT-07"
FLASK = "from flask import Flask, request, redirect, send_file, render_template_string, abort, url_for\nimport os, requests\napp = Flask(__name__)\n"
FASTAPI = "import os, httpx\nfrom fastapi import FastAPI, Depends, Query\nfrom fastapi.responses import FileResponse, RedirectResponse\napp = FastAPI()\n"
TORNADO = "import json\nimport tornado.web\n"


def _flows(code: str, header: str = FLASK) -> set[str]:
    """추적 분석이 낸 룰들. 분석 결과를 직접 본다 — 보고서에서는 같은 줄을 다른 엔진이 먼저 보고했으면 그쪽이 남는다."""
    import ast

    from gvskb.scanners.ast_scanner import _collect_import_aliases
    from gvskb.scanners.py_web_flows import scan_web_flows

    source = header + textwrap.dedent(code)
    tree = ast.parse(source)
    hits = scan_web_flows(tree, source.split("\n"), _collect_import_aliases(tree), strict=True)
    assert all(confidence == "likely" for _, _, _, confidence in hits)
    return {rule_id for rule_id, _, _, _ in hits}


VULNERABLE = [
    ("변수 경유 SSRF", SSRF, FLASK, """
        @app.route("/p")
        def p():
            url = request.args.get("url")
            return requests.get(url, timeout=5).text
    """),
    ("빈 값 확인은 검사가 아니다", SSRF, FLASK, """
        @app.route("/p")
        def p():
            url = request.args.get("url")
            if not url:
                abort(400)
            return requests.get(url, timeout=5).text
    """),
    ("열쇠가 있는지만 본 것도 검사가 아니다", SSRF, FLASK, """
        @app.route("/p", methods=["POST"])
        def p():
            data = request.get_json()
            if "url" in data:
                return requests.post(data["url"], json={}).text
            return ""
    """),
    ("호스트 자리에 요청 값", SSRF, FLASK, """
        @app.route("/p")
        def p():
            host = request.args["host"]
            return requests.get(f"http://{host}:8080/status").text
    """),
    ("세션 객체로 보내는 요청", SSRF, FLASK, """
        @app.route("/p")
        def p():
            s = requests.Session()
            target = request.form["target"]
            return s.get(target).text
    """),
    ("분기 한쪽만 요청 값", SSRF, FLASK, """
        @app.route("/p")
        def p():
            if request.args.get("custom"):
                url = request.args["custom"]
            else:
                url = "https://api.example.go.kr/status"
            return requests.get(url).text
    """),
    ("함수 두 번 경유", SSRF, FLASK, """
        def fetch(u):
            return requests.get(u).text

        def relay(v):
            return fetch(v)

        @app.route("/p")
        def p():
            return relay(request.args["u"])
    """),
    ("FastAPI 라우트 매개변수", SSRF, FASTAPI, """
        @app.get("/fetch")
        async def fetch(target: str):
            async with httpx.AsyncClient() as client:
                r = await client.get(target)
            return r.text
    """),
    ("경로 조립 뒤 열기", PATH, FLASK, """
        @app.route("/d")
        def d():
            name = request.args.get("name", "")
            full = os.path.join("/srv/files", name)
            return open(full).read()
    """),
    ("이어 붙인 경로", PATH, FLASK, """
        @app.route("/d")
        def d():
            path = "/srv/files/"
            path += request.args["name"]
            return send_file(path)
    """),
    ("FastAPI 파일 응답", PATH, FASTAPI, """
        @app.get("/files/{name}")
        def files(name: str):
            return FileResponse(os.path.join("/srv/files", name))
    """),
    ("요청 본문에서 꺼낸 경로", PATH, TORNADO, """
        class Summaries(tornado.web.RequestHandler):
            def post(self):
                body = json.loads(self.request.body)
                file_path = body.get("file_path")
                with open(file_path) as f:
                    self.write(f.read(1000))
    """),
    ("확인 함수에 넘겼지만 값 검사가 아니다", PATH, FLASK, """
        @app.route("/d")
        def d():
            name = request.args.get("name", "")
            log_event("download", name)
            return open("/srv/files/" + name).read()
    """),
    ("템플릿 원문에 요청 값", TEMPLATE, FLASK, """
        @app.route("/h")
        def h():
            name = request.args.get("name", "")
            page = "<h1>" + name + "</h1>"
            return render_template_string(page)
    """),
    ("변수 경유 리다이렉트", REDIRECT, FLASK, """
        @app.route("/go")
        def go():
            nxt = request.args.get("next")
            return redirect(nxt)
    """),
    ("Django 리다이렉트", REDIRECT, "from django.http import HttpResponseRedirect\n", """
        def done(request):
            nxt = request.GET.get("next")
            return HttpResponseRedirect(nxt)
    """),
    ("검사한 뒤 다른 요청 값으로 덮어씀", SSRF, FLASK, """
        @app.route("/p")
        def p():
            url = request.args["a"]
            if not is_allowed_host(url):
                abort(400)
            url = request.args["b"]
            return requests.get(url).text
    """),
]

SAFE = [
    ("허용 목록으로 호스트 검사", FLASK, """
        from urllib.parse import urlparse
        ALLOWED = {"api.example.go.kr"}

        @app.route("/p")
        def p():
            url = request.args.get("url", "")
            if urlparse(url).hostname not in ALLOWED:
                abort(403)
            return requests.get(url).text
    """),
    ("유래한 값을 검사", FLASK, """
        from urllib.parse import urlparse
        ALLOWED = {"api.example.go.kr"}

        @app.route("/p")
        def p():
            url = request.args.get("url", "")
            host = urlparse(url).hostname
            if host not in ALLOWED:
                abort(403)
            return requests.get(url).text
    """),
    ("검사 함수 호출", FLASK, """
        @app.route("/p")
        def p():
            url = request.args["url"]
            validate_outbound_url(url)
            return requests.get(url).text
    """),
    ("검사 함수 결과를 조건에", FLASK, """
        @app.route("/p")
        def p():
            url = request.args["url"]
            ok = is_allowed(url)
            if not ok:
                abort(400)
            return requests.get(url).text
    """),
    ("호스트가 고정된 주소", FLASK, """
        @app.route("/p/<item>")
        def p(item):
            return requests.get("https://api.example.go.kr/items/" + item).text
    """),
    ("상수 접두", FLASK, """
        BASE_URL = os.environ["BACKEND_URL"]

        @app.route("/p/<item>")
        def p(item):
            a = requests.get(BASE_URL + "/items/" + item).text
            b = requests.get(f"{BASE_URL}/items/{item}").text
            return a + b
    """),
    ("호스트가 고정된 주소를 변수에 담음", FLASK, """
        @app.route("/p/<item>")
        def p(item):
            url = f"https://api.example.go.kr/items/{item}"
            return requests.get(url).text
    """),
    ("호스트가 고정된 주소를 함수에 넘김", FLASK, """
        def fetch(u):
            return requests.get(u).text

        @app.route("/p/<item>")
        def p(item):
            return fetch("https://api.example.go.kr/items/" + item)
    """),
    ("조회 열쇠", FLASK, """
        SERVICES = {"a": "https://a.example.go.kr", "b": "https://b.example.go.kr"}

        @app.route("/p")
        def p():
            one = SERVICES[request.args["svc"]]
            two = SERVICES.get(request.args.get("svc"), SERVICES["a"])
            return requests.get(one).text + requests.get(two).text
    """),
    ("요청 값으로 찾은 레코드의 경로", FLASK, """
        @app.route("/d/<doc_id>")
        def d(doc_id):
            doc = find_document(doc_id)
            return send_file(doc.path)
    """),
    ("파일 이름 정리", FLASK, """
        from werkzeug.utils import secure_filename

        @app.route("/d")
        def d():
            name = secure_filename(request.args.get("name", ""))
            a = open(os.path.join("/srv/files", name)).read()
            b = open("/srv/files/" + os.path.basename(request.args["other"])).read()
            return a + b
    """),
    ("기준 폴더 안인지 확인", FLASK, """
        BASE = "/srv/files"

        @app.route("/d")
        def d():
            name = request.args.get("name", "")
            full = os.path.realpath(os.path.join(BASE, name))
            if not full.startswith(BASE + os.sep):
                abort(403)
            return send_file(full)
    """),
    ("자체 확인 함수에 조건식을 넘김", FASTAPI, """
        from pathlib import Path
        WEB = Path("/srv/web")

        @app.get("/app/{relative:path}")
        async def screen(relative: str):
            target = (WEB / "runtime" / relative).resolve()
            require(target.is_relative_to((WEB / "runtime").resolve()) and target.is_file(), "없음", 404)
            return FileResponse(target)

        @app.get("/raw/{relative:path}")
        async def raw(relative: str):
            target = os.path.realpath(os.path.join("/srv/raw", relative))
            fail_unless(target.startswith("/srv/raw/"), 404)
            return FileResponse(target)
    """),
    ("기준 폴더 밖이면 예외", FASTAPI, """
        from pathlib import Path
        BASE = Path("/srv/files").resolve()

        @app.get("/f/{name:path}")
        def f(name: str):
            target = (BASE / name).resolve()
            try:
                target.relative_to(BASE)
            except ValueError:
                raise HTTPException(404)
            return FileResponse(target)
    """),
    ("숫자로 변환", FLASK, """
        @app.route("/d")
        def d():
            page = int(request.args["page"])
            n = request.args.get("n", 1, type=int)
            return open(f"/srv/pages/{page}-{n}.html").read()
    """),
    ("숫자 경로 변환기", FLASK, """
        @app.route("/d/<int:item_id>")
        def d(item_id):
            return open(f"/srv/items/{item_id}.json").read()
    """),
    ("숫자·열거형·제약이 있는 FastAPI 매개변수", FASTAPI, """
        from enum import Enum
        from typing import Literal

        class Kind(str, Enum):
            a = "a"

        @app.get("/d/{item_id}")
        def d(item_id: int, kind: Kind, mode: Literal["x", "y"], name: str = Query(..., pattern="^[a-z]+$"), db=Depends(get_db)):
            return FileResponse(f"/srv/{kind}/{mode}/{item_id}/{name}.json")
    """),
    ("내려받을 이름은 경로가 아니다", FASTAPI, """
        @app.get("/d")
        def d(name: str):
            return FileResponse("/srv/files/report.pdf", filename=name)
    """),
    ("시작이 슬래시인지 확인한 리다이렉트", FLASK, """
        @app.route("/go")
        def go():
            target = request.args.get("next", "/")
            if not target.startswith("/") or target.startswith("//"):
                target = "/"
            return redirect(target)
    """),
    ("한 줄 조건식 안에서 검사", FLASK, """
        @app.route("/go")
        def go():
            nxt = request.args.get("next", "/")
            return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else "/")
    """),
    ("사이트 안 주소로만", FLASK, """
        @app.route("/go")
        def go():
            item = request.args.get("item", "")
            a = redirect(url_for("detail", item=item))
            b = redirect("/detail?item=" + item)
            return a or b
    """),
    ("조회한 값으로 리다이렉트", FLASK, """
        ROUTES = {"home": "/", "help": "/help"}

        @app.route("/go")
        def go():
            return redirect(ROUTES.get(request.args.get("k"), "/"))
    """),
    ("템플릿은 고정, 값은 변수로", FLASK, """
        @app.route("/h")
        def h():
            name = request.args.get("name", "")
            return render_template_string("<h1>{{ name }}</h1>", name=name)
    """),
    ("다른 값으로 덮어씀", FLASK, """
        @app.route("/p")
        def p():
            url = request.args.get("url")
            url = "https://api.example.go.kr/status"
            return requests.get(url).text
    """),
    ("검사한 뒤 다듬기", FLASK, """
        @app.route("/d")
        def d():
            name = request.args.get("name", "")
            if not is_valid_name(name):
                abort(400)
            name = name.strip()
            return open("/srv/files/" + name).read()
    """),
    ("본문만 요청 값", FLASK, """
        WEBHOOK = "https://hooks.example.go.kr/notify"

        @app.route("/n", methods=["POST"])
        def n():
            link = request.json["link"]
            return requests.post(WEBHOOK, json={"link": link}).text
    """),
    ("다른 함수의 같은 이름은 HTTP 클라이언트가 아니다", FASTAPI, """
        async def ping():
            async with httpx.AsyncClient() as client:
                return await client.get("https://api.example.go.kr/ping")

        @app.get("/u/{user_id}")
        def u(user_id: str):
            client = make_cache()
            return client.get(f"user:{user_id}")
    """),
    ("입력 검사 데코레이터", FLASK, """
        @app.route("/p")
        @validate_query(UrlSchema)
        def p(url):
            return requests.get(url).text
    """),
    ("줄 단위 예외 표시", FLASK, """
        @app.route("/p")
        def p():
            url = request.args.get("url")
            return requests.get(url).text  # gvskb: ignore KISA-PY-INPUT-12
    """),
    ("웹 프레임워크를 쓰지 않는 명령줄 도구", "import sys, requests\n", """
        def main():
            url = sys.argv[1]
            path = sys.argv[2]
            body = requests.get(url).text
            open(path, "w").write(body)

        def handle(request):
            target = request.params["url"]
            return requests.get(target)
    """),
]


#: 값이 다른 데 쓰여서 **판단하지 않는** 것 — 검사인지 아닌지 모르는 쓰임이 있으면 보고하지 않는다(모듈 설명 참고).
SILENT_BY_DESIGN = {
    "확인 함수에 넘겼지만 값 검사가 아니다": "모르는 함수에 값을 넘겼다",
    "검사한 뒤 다른 요청 값으로 덮어씀": "같은 이름이 조건에 쓰였다",
}


@pytest.mark.parametrize("label,rule,header,code", VULNERABLE, ids=[c[0] for c in VULNERABLE])
def test_flow_is_reported(label: str, rule: str, header: str, code: str) -> None:
    assert (rule in _flows(code, header)) == (label not in SILENT_BY_DESIGN), label


@pytest.mark.parametrize("label,header,code", SAFE, ids=[c[0] for c in SAFE])
def test_safe_shape_is_not_reported(label: str, header: str, code: str) -> None:
    assert _flows(code, header) == set(), label


def test_findings_are_review_level() -> None:
    """이 분석이 말할 수 있는 것은 '검사를 못 봤다'까지다 — 근거는 '유력', 결정은 검토(차단이 아니다)."""
    report = scan_code(FLASK + textwrap.dedent("""
        @app.route("/p")
        def p():
            url = request.args.get("url")
            nxt = request.args.get("next")
            requests.get(url)
            return redirect(nxt)
    """), filename="app.py")
    by_rule = {f.rule_id: f for f in report.findings if f.engine == "python-flow"}
    assert by_rule[SSRF].decision.value == "warn" and by_rule[SSRF].confidence == "likely"
    assert by_rule[REDIRECT].decision.value == "warn" and by_rule[REDIRECT].confidence == "likely"
    assert "검사한 흔적을 찾지 못했습니다" in (by_rule[SSRF].severity_adjusted or "")


def test_template_flow_is_review_level_too() -> None:
    """템플릿 룰은 '구문 자체가 약점'이라 근거와 무관하게 차단으로 남는 룰이다 — 추적으로 찾은 것은 그래도 검토다."""
    report = scan_code(FLASK + textwrap.dedent("""
        @app.route("/h")
        def h():
            page = "<h1>" + request.args.get("name", "") + "</h1>"
            return render_template_string(page)
    """), filename="app.py")
    found = [f for f in report.findings if f.rule_id == TEMPLATE]
    assert [(f.engine, f.decision.value, f.confidence) for f in found] == [("python-flow", "warn", "likely")]


def test_existing_finding_on_the_same_line_is_kept() -> None:
    """한 줄에 출처와 호출이 함께 있으면 정규식 룰이 이미 보고한다 — 추적 분석이 그 발견을 대체하지 않는다."""
    report = scan_code(FLASK + textwrap.dedent("""
        @app.route("/h")
        def h():
            return render_template_string(request.args["tpl"])
    """), filename="app.py")
    found = [f for f in report.findings if f.rule_id == TEMPLATE]
    assert [(f.engine, f.decision.value) for f in found] == [("regex", "block")]


def test_pattern_only_finding_on_the_same_line_gives_way_to_the_flow() -> None:
    """차단으로 남지 않는 룰에서 같은 줄의 정규식 발견이 패턴 일치뿐이면 흐름을 본 발견(유력)이 남는다 — 결정은 같다."""
    report = scan_code(FLASK + textwrap.dedent("""
        @app.route("/go")
        def go():
            return redirect(request.args["next"])
    """), filename="app.py")
    found = [f for f in report.findings if f.rule_id == REDIRECT]
    assert [(f.engine, f.confidence, f.decision.value) for f in found] == [("python-flow", "likely", "warn")]


# ── 견고함 — 이 분석이 실패해도 같은 파일의 다른 분석은 살아야 한다 ──────────────────────────────

def test_long_derivation_chain_does_not_break_other_findings() -> None:
    """독립 검증(2026-11-21): 유래가 331단 넘게 이어지면 재귀 한도로 Python 분석 전체가 죽어 SQL 삽입 발견까지 사라졌다."""
    lines = ["@app.route('/c')", "def c():", "    v0 = request.args.get('name', '')"]
    lines += [f"    v{i} = v{i - 1} + '/'" for i in range(1, 600)]
    lines += ["    cur.execute('SELECT * FROM t WHERE n = ' + request.args['n'])", "    return send_file(v599)"]
    report = scan_code(FLASK + "\n".join(lines) + "\n", filename="app.py")
    by_engine = {(f.engine, f.rule_id) for f in report.findings}
    assert ("python-ast", "GOV-SQL-INJECTION-001") in by_engine and ("python-flow", PATH) in by_engine


def test_deep_expression_never_raises() -> None:
    """`+` 가 수천 번 이어진 식은 구문 트리를 만들다 재귀 한도에 걸린다 — 예외를 밖으로 내지 않는다."""
    code = FLASK + "@app.route('/c')\ndef c():\n    return send_file(" + " + ".join(["request.args['a']"] * 3000) + ")\n"
    scan_code(code, filename="app.py")


def test_generated_code_stays_fast() -> None:
    """라우트 300개짜리 파일(약 3,000줄)도 1초 안팎이어야 한다."""
    import time

    handler = textwrap.dedent('''
        @app.route("/r{i}")
        def r{i}():
            name = request.args.get("name", "")
            if not is_valid_name(name):
                abort(400)
            data = request.get_json() or {{}}
            url = data.get("url", "")
            if urlparse(url).hostname not in ALLOWED:
                abort(403)
            return send_file(os.path.join("/srv", name)) if name else requests.get(url).text
    ''')
    code = FLASK + "from urllib.parse import urlparse\nALLOWED = set()\n" + "".join(handler.format(i=i) for i in range(300))
    started = time.perf_counter()
    report = scan_code(code, filename="app.py")
    assert time.perf_counter() - started < 15
    assert not [f for f in report.findings if f.engine == "python-flow" and f.rule_id in {SSRF, PATH}]


def test_custom_assertion_helper_with_condition_is_a_blocking_check() -> None:
    """실측(사용자 프로젝트): 자체 확인 함수에 조건식을 넘긴 코드. 구조를 바꾸다 한 번 되살아난 오탐이라 따로 둔다."""
    code = FASTAPI + textwrap.dedent('''
        from pathlib import Path
        WEB = Path("/srv/web")

        @app.get("/app/{relative:path}")
        async def runtime_screen(relative: str):
            target = (WEB / "src/runtime" / relative).resolve()
            require(
                target.is_relative_to((WEB / "src/runtime").resolve()) and target.is_file(),
                "없음", "NOT_FOUND", 404,
            )
            connected = connected_html(relative)
            return connected if connected is not None else FileResponse(target)
    ''')
    report = scan_code(code, filename="web_api.py")
    assert not [f for f in report.findings if f.engine == "python-flow" and f.rule_id == PATH]


def test_real_library_shapes_are_not_reported() -> None:
    """실측(아나콘다 라이브러리 3만여 파일 대조에서 나온 오탐 두 모양).

    하나는 바깥 조건문 안에서 통과하지 못한 값을 기본값으로 바꿔 놓는 '고쳐 쓰는' 검사,
    다른 하나는 구분자가 변수인 `sep.join([설정값, 요청 값])` — 맨 앞은 설정값이다.
    """
    code = "import re\nfrom urllib.parse import urlparse\nimport tornado.web\n" + textwrap.dedent('''
        class Login(tornado.web.RequestHandler):
            def _redirect_safe(self, url, default=None):
                if default is None:
                    default = self.base_url
                parsed = urlparse(url)
                if (parsed.scheme or parsed.netloc) or not (parsed.path + "/").startswith(self.base_url):
                    allow = False
                    if parsed.scheme or parsed.netloc:
                        origin = f"{parsed.scheme}://{parsed.netloc}".lower()
                        if self.allow_origin:
                            allow = self.allow_origin == origin
                    if not allow:
                        url = default
                self.redirect(url)

            def get(self):
                self._redirect_safe(self.get_argument("next", default=self.base_url))


        class RedirectWithParams(tornado.web.RequestHandler):
            def get(self):
                sep = "&" if "?" in self._url else "?"
                url = sep.join([self._url, self.request.query])
                self.redirect(url, permanent=True)
    ''')
    report = scan_code(code, filename="handlers.py")
    assert not [f for f in report.findings if f.engine == "python-flow" and f.rule_id == REDIRECT]


def test_tornado_argument_reaches_redirect() -> None:
    code = TORNADO + textwrap.dedent('''
        class Go(tornado.web.RequestHandler):
            def prepare(self):
                self.redirect(self.get_argument("url"), status=302)
    ''')
    report = scan_code(code, filename="handlers.py")
    assert [f for f in report.findings if f.engine == "python-flow" and f.rule_id == REDIRECT and f.confidence == "likely"]
