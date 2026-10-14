"""28차 — 읽기 전용 내장 함수는 상수를 실격시키지 않는다 · 라이선스 검토가 게이트에 들어간다 ·
권고 버전 미확정 문구 · SPDX 복합식 (코덱스 STARS 분석 2026-10-13 반영).

실측: STARS `stars_db.py` 는 모듈 상수 `ALL_COLUMNS` 를 `dict(zip(ALL_COLUMNS, row))` 로 읽는데
그 한 줄 때문에 상수 자격을 잃어, 바인딩만 쓰는 SQL 2건이 '치명·유력'으로 남았다. ultralytics
AGPL 은 표에만 ⚠ 가 찍히고 종합 판정에는 없었다. 아래는 같은 모양의 합성 코드다.
"""
from __future__ import annotations

from gvskb.gate import gate_status
from gvskb.report import render_markdown
from gvskb.scanner import scan_code
from gvskb.schema import ScanReport
from gvskb.vcps import license_verdict

_STARS_LIKE = '''
import json
import sqlite3

ALL_COLUMNS = [
    "id", "created_at", "filename", "total_score", "scores_json",
]


def _row_to_dict(row):
    d = dict(zip(ALL_COLUMNS, row))
    d["scores"] = json.loads(d.get("scores_json") or "[]")
    return d


def list_records(db_path, score_min=None, search=None):
    where = []
    params = []
    if score_min is not None:
        where.append("total_score >= ?")
        params.append(int(score_min))
    if search:
        where.append("(filename LIKE ?)")
        params.append(f"%{search}%")
    sql = f"SELECT {', '.join(ALL_COLUMNS)} FROM scoring_history"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY created_at DESC;"
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(sql, params).fetchall()
    return [_row_to_dict(r) for r in rows]


def get_record(db_path, record_id):
    sql = f"SELECT {', '.join(ALL_COLUMNS)} FROM scoring_history WHERE id = ?;"
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(sql, (record_id,)).fetchone()
    return _row_to_dict(row) if row else None
'''


def _sql_findings(code: str) -> list:
    r = scan_code(code, filename="stars_db.py")
    return [f for f in r.findings if "SQL" in f.rule_id]


def test_readonly_builtin_call_keeps_module_list_constant() -> None:
    assert _sql_findings(_STARS_LIKE) == []


def test_other_readonly_builtins_keep_constant() -> None:
    for call in ("len(COLS)", "sorted(COLS)", "tuple(COLS)", "list(COLS)", "enumerate(COLS)",
                 "print(COLS)", "set(COLS)", "max(COLS)"):
        code = f'''
COLS = ["id", "name"]

def peek():
    return {call}

def q(conn, rid):
    return conn.execute(f"SELECT {{', '.join(COLS)}} FROM t WHERE id = ?", (rid,))
'''
        assert _sql_findings(code) == [], call


def test_user_function_receiving_list_still_disqualifies() -> None:
    """적대: 같은 모양이지만 리스트를 받는 함수가 요청값을 넣는다 — 계속 잡혀야 한다."""
    code = '''
from flask import request
COLS = ["id", "name"]

def add_column(cols):
    cols.append(request.args["col"])

def q(conn, rid):
    add_column(COLS)
    return conn.execute(f"SELECT {', '.join(COLS)} FROM t WHERE id = ?", (rid,))
'''
    assert _sql_findings(code), "사용자 함수에 넘긴 리스트는 변형될 수 있다"


def test_shadowed_builtin_is_not_readonly() -> None:
    """적대: `zip` 을 다시 정의해 리스트를 바꾸는 코드 — 내장 함수 예외가 적용되면 안 된다."""
    code = '''
from flask import request
COLS = ["id", "name"]

def zip(a, b):
    a.append(request.args["col"])
    return []

def q(conn, rid):
    dict(zip(COLS, (1, 2)))
    return conn.execute(f"SELECT {', '.join(COLS)} FROM t WHERE id = ?", (rid,))
'''
    assert _sql_findings(code), "가려진 zip 은 읽기 전용이 아니다"


def test_direct_append_of_request_still_disqualifies() -> None:
    code = '''
from flask import request
COLS = ["id"]

def q(conn, rid):
    COLS.append(request.args["col"])
    return conn.execute(f"SELECT {', '.join(COLS)} FROM t WHERE id = ?", (rid,))
'''
    assert _sql_findings(code)


# ---------------------------------------------------------------------------
# 라이선스 검토 → 게이트 조건부 사유 · 조치 문장
# ---------------------------------------------------------------------------

def _report_with_checks(checks: list[dict]) -> ScanReport:
    r = scan_code("total = 1\n", filename="a.py")
    r.dependency_audit = {"audits": [{
        "ecosystem": "pypi", "manifest": "requirements.txt", "blocked": False,
        "parsed_count": len(checks), "checked_count": len(checks), "unchecked_count": 0,
        "truncated_count": 0, "checks": checks,
    }]}
    return r


def _pkg(name: str, **kw) -> dict:
    base = {"name": name, "version": "1.0.0", "ecosystem": "pypi", "checked": True,
            "verdict": "checked_clean"}
    base.update(kw)
    return base


def test_license_review_alone_makes_verdict_conditional() -> None:
    r = _report_with_checks([_pkg("ultralytics", version="8.3.145", license_verdict="review_required",
                                  registry_metadata={"license": "AGPL-3.0"})])
    g = gate_status(r)
    assert g["verdict"] == "conditional"
    assert "license" in g["conditional_criteria"]
    assert g["license_review"] == [{"name": "ultralytics", "version": "8.3.145", "license": "AGPL-3.0"}]
    assert "라이선스 검토 1종" in g["reason"]
    md = render_markdown(r)
    assert "ultralytics 8.3.145" in md and "AGPL-3.0" in md and "계약·법무" in md


def test_allowed_license_does_not_change_verdict() -> None:
    r = _report_with_checks([_pkg("httpx", license_verdict="allowed",
                                  registry_metadata={"license": "BSD-3-Clause"})])
    g = gate_status(r)
    assert g["verdict"] == "approved" and g["license_review"] == []


def test_license_review_does_not_block() -> None:
    r = _report_with_checks([_pkg("x", license_verdict="review_required",
                                  registry_metadata={"license": "GPL-3.0"})])
    assert gate_status(r)["blocked"] is False


# ---------------------------------------------------------------------------
# 권고 버전 미확정 ≠ 안전한 상위 버전 없음
# ---------------------------------------------------------------------------

def test_unresolved_fix_version_points_to_latest_not_no_safe_version() -> None:
    r = _report_with_checks([_pkg(
        "torch", version="2.7.0", verdict="vulnerable", vulnerability_count=15, max_cve="HIGH",
        advisories=[{"id": "GHSA-a", "severity": "HIGH"}], recommended_version=None,
        registry_metadata={"license": "BSD-3-Clause", "latest_version": "2.14.1"},
    )])
    md = render_markdown(r)
    assert "수정 버전을 확정하지 못했습니다" in md and "2.14.1" in md
    assert "안전한 상위 버전이 없습니다" not in md


def test_truly_no_newer_version_keeps_alternative_wording() -> None:
    r = _report_with_checks([_pkg(
        "dead", version="1.0.0", verdict="vulnerable", vulnerability_count=1, max_cve="HIGH",
        advisories=[{"id": "GHSA-b", "severity": "HIGH"}], recommended_version=None,
        registry_metadata={"latest_version": "1.0.0"},
    )])
    assert "대체 패키지를 검토하세요" in render_markdown(r)


# ---------------------------------------------------------------------------
# SPDX 복합식
# ---------------------------------------------------------------------------

def test_spdx_and_is_order_independent_and_strict() -> None:
    assert license_verdict("MIT AND AGPL-3.0-only") == "review_required"
    assert license_verdict("AGPL-3.0-only AND MIT") == "review_required"
    assert license_verdict("Apache-2.0 AND Apache-2.0 WITH LLVM-exception AND BSD-3-Clause") == "allowed"


def test_spdx_or_takes_most_permissive() -> None:
    assert license_verdict("GPL-2.0-only OR MIT") == "allowed"
    assert license_verdict("(GPL-2.0-only OR GPL-3.0-only)") == "review_required"
    # LGPL 도 검토 목록(34차) — GPL 과의 선택식은 가장 관대한 LGPL 로 판정해도 검토다
    assert license_verdict("LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only") == "review_required"
    assert license_verdict("MIT OR LGPL-3.0-only") == "allowed"


def test_spdx_with_exception_uses_base_license() -> None:
    assert license_verdict("GPL-3.0-only WITH GCC-exception-3.1") == "review_required"
    assert license_verdict("Apache-2.0 WITH LLVM-exception") == "allowed"


def test_prose_lowercase_and_is_not_an_spdx_operator() -> None:
    assert license_verdict("MIT and BSD style") == "allowed"   # 서술형은 접두 판정 그대로
