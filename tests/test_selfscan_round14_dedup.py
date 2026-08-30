"""14차 — 같은 줄·같은 취약 유형의 룰 2개는 '1개 문제, 근거 룰 2개'다 (S-8, 개선요청 #34 C).

실측(자기검사 2026-08-29): 같은 줄 중복 133곳, dedup_group 선언 룰은 2개뿐(죽은 장치).
예전 순위 (심각도, 결정, rule_id) 는 동점이면 문자열 비교로 "KISA-" > "GOV-" 라
**regex KISA 가 AST-confirmed GOV 를 밀어내고** 패자의 근거는 버려졌다.
"""
from __future__ import annotations

import json

from gvskb.report import render_html, render_markdown
from gvskb.scanner import scan_code
from gvskb.schema import ScanReport


def _find(code: str, filename: str, **kw):
    return scan_code(code, filename=filename, **kw).findings


def test_exec_line_is_one_finding_with_both_rules():
    fs = _find("exec(user_input)\n", "app.py")
    exec_like = [f for f in fs if f.rule_id in {"GOV-CODE-EXEC-001", "KISA-PY-INPUT-02"}]
    assert len(exec_like) == 1
    f = exec_like[0]
    assert {f.rule_id, *f.also_matched} == {"GOV-CODE-EXEC-001", "KISA-PY-INPUT-02"}
    assert f.engine == "python-ast", "데이터 흐름을 본 엔진이 대표가 된다"


def test_ast_confirmed_wins_over_regex_regardless_of_order():
    code = "q = f\"SELECT * FROM t WHERE id={request.args['id']}\"\ncursor.execute(q)\n"
    fs = [f for f in _find(code, "app.py") if f.rule_id in {"GOV-SQL-INJECTION-001", "KISA-PY-INPUT-01"}]
    assert len(fs) == 1 and fs[0].engine == "python-ast"


def test_rule_metrics_unaffected_by_merge():
    fs = _find("exec(user_input)\n", "app.py", collapse_duplicates=False)
    ids = {f.rule_id for f in fs}
    assert {"GOV-CODE-EXEC-001", "KISA-PY-INPUT-02"} <= ids


def test_unrelated_rules_on_same_line_are_not_merged():
    # 코드 실행 + 하드코딩 자격증명 — 주제가 다르면 두 건이 맞다.
    code = 'exec(x); password = "hunter2plus9"\n'
    fs = _find(code, "app.py")
    assert any(f.rule_id in {"GOV-CODE-EXEC-001", "KISA-PY-INPUT-02"} for f in fs)
    assert any(f.rule_id in {"GOV-SECRET-APIKEY-001", "KISA-PY-SEC-06"} for f in fs)


def test_references_are_unioned_and_also_matched_survives_json():
    fs = [f for f in _find("os.system('rm -rf ' + path)\n", "app.py")
          if f.rule_id in {"GOV-CMD-INJECTION-001", "KISA-PY-INPUT-05"}]
    assert len(fs) == 1 and fs[0].also_matched
    rep = scan_code("os.system('rm -rf ' + path)\n", filename="app.py")
    back = ScanReport.model_validate(json.loads(rep.model_dump_json()))
    merged = [f for f in back.findings if f.also_matched]
    assert merged and set(merged[0].references) >= set(fs[0].references)


def test_legacy_json_without_also_matched_still_loads():
    rep = scan_code("x = 1\n", filename="app.py")
    data = json.loads(rep.model_dump_json())
    for f in data["findings"]:
        f.pop("also_matched", None)
    assert ScanReport.model_validate(data)


def test_js_eval_pair_and_html_dom_pair_merge():
    js = [f for f in _find("const r = eval(userInput);\n", "a.js") if f.rule_id in {"KISA-JS-API-02", "KISA-JS-INPUT-02"}]
    assert len(js) == 1 and js[0].also_matched
    html = [f for f in _find('<div></div><script>document.write(location.hash)</script>\n', "p.html")
            if f.rule_id in {"GOV-HTML-DOM-XSS-001", "KISA-JS-INPUT-04"}]
    assert len(html) == 1 and html[0].also_matched


def test_report_shows_secondary_rules():
    rep = scan_code("exec(user_input)\n", filename="app.py")
    md, html = render_markdown(rep), render_html(rep)
    assert "(+" in md and "(+" in html
