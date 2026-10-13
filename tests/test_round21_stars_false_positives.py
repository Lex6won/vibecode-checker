"""STARS 점검(2026-10-13) — 검토자가 "15건 전부 오탐"으로 판정한 보고서의 재발 방지.

소스는 받지 못했고(다른 기관 PC), 보고서의 증거 줄과 검토의견만으로 원인을 짚었다:
  · SQL '유력' 2건: 바인딩만 쓰는 쿼리에서 모듈 상수(`ALL_COLUMNS`)로 만든 지역 변수·화이트리스트
    조회·내포식이 동적으로 취급됐다 — 함수 범위 환경이 모듈 상수를 **고정점 전에** 받지 못해서.
  · 정수 오버플로 '패턴 일치만' 13건: `astype(np.uint8)` 만 보고 울렸다 — 이미지 처리 코드의
    bool 마스크·clip 뒤 변환은 오버플로가 아니다. 외부 입력이 닿는 변환만 출처 추적으로 올린다.
① 내려가야 하는 것(없어져야) / ② 같은 모양의 진짜 위험은 그대로.
"""

from __future__ import annotations

import pytest

from gvskb.scanner import scan_code
from gvskb.schema import Decision


def _rule(code: str, rule: str, filename: str = "app.py"):
    return [f for f in scan_code(code, filename=filename).findings if rule in (f.rule_id, *f.also_matched)]


# ---------------------------------------------------------------------------
# ② 그대로 — 같은 모양의 진짜 위험
# ---------------------------------------------------------------------------


def test_dict_whose_values_are_not_literal_is_still_dynamic() -> None:
    code = (
        'ORDER = {"name": build_order()}\n'
        "@app.get('/s')\n"
        "def search(conn, key):\n"
        "    conn.execute(f\"SELECT * FROM t ORDER BY {ORDER[key]}\")\n"
    )
    f = _rule(code, "GOV-SQL-INJECTION-001")
    assert f and f[0].decision == Decision.block and f[0].confidence == "confirmed"


def test_module_constant_shadowed_by_parameter_is_not_trusted() -> None:
    code = (
        'ALL_COLUMNS = ("id",)\n'
        "@app.get('/s')\n"
        "def load(conn, cols):\n"
        "    ALL_COLUMNS = cols\n"
        "    conn.execute(f\"SELECT {', '.join(ALL_COLUMNS)} FROM t\")\n"
    )
    f = _rule(code, "GOV-SQL-INJECTION-001")
    assert f and f[0].decision == Decision.block


@pytest.mark.parametrize("code", [
    'import numpy as np\nn = int(request.args["n"])\narr2 = (arr * n).astype(np.int32)\n',
    'import struct, sys\ncount = int(sys.argv[1])\nbuf = struct.pack("<i", count)\n',
    'import numpy as np\nvalue = np.int32(int(request.GET["n"]))\n',
    'import numpy as np\n@app.get("/n")\ndef f(n):\n    return np.int16(n) * 2\n',
    'import numpy as np\nk = int(request.form["k"])\nres = np.power(base, k, dtype=np.int64)\n',
], ids=["request-astype", "argv-struct-pack", "np-int32-request", "route-param-np-int16", "request-np-power-dtype"])
def test_fixed_width_cast_fed_by_external_input_is_confirmed(code: str) -> None:
    f = _rule(code, "KISA-PY-INPUT-14")
    assert f and f[0].confidence == "confirmed", [(x.engine, x.confidence) for x in f]


# ---------------------------------------------------------------------------
# ① 없어져야 하는 것 — STARS 보고서의 15건과 같은 모양
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("code", [
    # 모듈 상수에서 파생한 지역 변수 (stars_db.py ALL_COLUMNS 형태)
    'ALL_COLUMNS = ("id", "name", "score")\n'
    "def search(conn, q, lo):\n"
    "    cols = ', '.join(ALL_COLUMNS)\n"
    "    conds, params = [], []\n"
    "    if q: conds.append('name LIKE ?'); params.append(f'%{q}%')\n"
    "    if lo is not None: conds.append('score >= ?'); params.append(lo)\n"
    "    where = ('WHERE ' + ' AND '.join(conds)) if conds else ''\n"
    "    sql = f'SELECT {cols} FROM stars {where} ORDER BY id'\n"
    "    return conn.execute(sql, params).fetchall()\n",
    # 화이트리스트 조회
    'ORDER = {"name": "name ASC", "score": "score DESC"}\n'
    "def search(conn, key):\n"
    "    sql = f\"SELECT * FROM t ORDER BY {ORDER.get(key, 'id')}\"\n"
    "    return conn.execute(sql).fetchall()\n",
    # 내포식으로 고른 상수 조건
    'FILTERS = {"a": "a = ?", "b": "b = ?"}\n'
    "def search(conn, chosen):\n"
    "    conds = [FILTERS[k] for k in chosen if k in FILTERS]\n"
    "    sql = 'SELECT * FROM t WHERE ' + ' AND '.join(conds)\n"
    "    return conn.execute(sql, [1] * len(conds)).fetchall()\n",
], ids=["module-const-derived-local", "whitelist-get", "comprehension-of-consts"])
def test_parameterised_sql_built_from_module_constants_is_not_flagged(code: str) -> None:
    assert not _rule(code, "GOV-SQL-INJECTION-001")


@pytest.mark.parametrize("code", [
    "import numpy as np\nring_mask = np.logical_and(~yellow_bg, L_dark.astype(bool)).astype(np.uint8) * 255\n",
    "import numpy as np\nout = np.clip(img * 1.2, 0, 255).astype(np.uint8)\n",
    "import numpy as np\npts = np.round(coords).astype(np.int32)\n",
    "import struct\nhdr = struct.pack('<I', len(payload))\n",
], ids=["bool-mask", "clip", "coords", "struct-len"])
def test_fixed_width_cast_without_external_input_is_not_flagged(code: str) -> None:
    assert not _rule(code, "KISA-PY-INPUT-14")
