"""43차(C-19) — Finding.cwe + 행정안전부 49개 항목 결과표."""
from __future__ import annotations

from pathlib import Path

from gvskb.mois_table import MOIS_PREFIX, _catalog, mois_result_table, rule_to_items
from gvskb.report import render_html, render_markdown
from gvskb.scanner import scan_code, scan_path


def _w(root: Path, rel: str, text: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def test_catalog_has_every_mois_item_once_and_in_guide_order() -> None:
    items, mapping, detection = _catalog()
    ids = [it.id for it in items]
    assert len(ids) == len(set(ids)) >= 49
    assert ids[0] == "MOIS-49-INPUT-01" and ids.index("MOIS-49-SEC-01") > ids.index("MOIS-49-INPUT-17")
    # 핵심 항목에는 자동 탐지 룰이 잇닿아 있어야 한다.
    assert "GOV-SQL-INJECTION-001" in mapping["MOIS-49-INPUT-01"] or "KISA-PY-INPUT-01" in mapping["MOIS-49-INPUT-01"]
    assert "GOV-AUTHZ-ADMIN-POSTURE-001" in mapping["MOIS-49-SEC-01"]
    assert "GOV-SECRET-APIKEY-001" in mapping["MOIS-49-SEC-06"] or any("SECRET" in r for r in mapping["MOIS-49-SEC-06"])


def test_finding_carries_cwe_from_rule() -> None:
    r = scan_code("API_KEY = 'sk-proj-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE1234'\n", filename="a.py")
    secret = [f for f in r.findings if f.rule_id == "GOV-SECRET-APIKEY-001"]
    assert secret and "CWE-798" in secret[0].cwe
    r2 = scan_code("import sqlite3\nfrom flask import request\ndef q(c):\n    c.execute('SELECT * FROM t WHERE id = ' + request.args['id'])\n",
                   filename="b.py")
    assert any("CWE-89" in f.cwe for f in r2.findings)


def test_table_counts_findings_under_items_and_outside(tmp_path: Path) -> None:
    _w(tmp_path, "admin_api.py",
       "from flask import Blueprint\nbp = Blueprint('admin', __name__)\n\n@bp.route('/api/admin/users', methods=['POST'])\n"
       "def create_user():\n    return ''\n")
    _w(tmp_path, "vendor_hook.pth", "import vendor_hook\n")   # 49개 항목 밖(개발환경 자동 실행)
    report = scan_path(tmp_path)
    t = mois_result_table(report)
    rows = {r["id"]: r for r in t["items"]}
    assert rows["MOIS-49-SEC-01"]["findings"] >= 1 and rows["MOIS-49-SEC-01"]["status"] == "발견"
    assert t["summary"]["outside_findings"] >= 1
    assert any("GOV-AUTOEXEC-PYTHON-STARTUP-001" in o["rules"] for o in t["outside"])
    assert all(r["status"] in ("발견", "해당 발견 없음(안전 아님)", "자동 탐지 없음 — 사람 점검") for r in t["items"])


def test_suppressed_findings_are_not_counted() -> None:
    r = scan_code("API_KEY = 'sk-proj-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE1234'\n", filename="a.py")
    before = mois_result_table(r)["items"]
    for f in r.findings:
        f.suppressed = True
    after = mois_result_table(r)["items"]
    assert sum(x["findings"] for x in before) >= 1 and sum(x["findings"] for x in after) == 0


def test_rendered_reports_include_the_table() -> None:
    r = scan_code("x = 1\n", filename="a.py")
    md = render_markdown(r)
    assert "49개 항목 결과표" in md and "자동 탐지 없음" in md
    html = render_html(r)
    assert "49개 항목 결과표" in html and "MOIS-49-" not in html.split("49개 항목 결과표", 1)[1][:200]


def test_rule_to_items_is_inverse_of_mapping() -> None:
    _, mapping, _ = _catalog()
    r2i = rule_to_items()
    for item, rids in mapping.items():
        for rid in rids:
            assert item in r2i[rid] and item.startswith(MOIS_PREFIX)
