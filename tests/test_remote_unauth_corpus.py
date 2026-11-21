"""로그인 없이 원격에서 닿는 취약점 — 실측(2026-11-21)에서 나온 오탐·등급 오류 수정과 말뭉치(l_remote_unauth_2026).

- 문자열 인자가 패턴의 일부인 설정형 룰(`string_arguments`)은 Python 문자열 감쇄로 '낮음'이 되지 않는다.
  매치 전체가 문자열 안이면(테스트 입력·메시지) 지금처럼 감쇄한다. 표시하지 않은 룰은 동작이 그대로다.
- JWT 서명 검증 끄기·none 허용은 전용 룰이 차단·확정으로 낸다.
- 인증 미들웨어가 붙은 삭제 경로, 이스케이프한 응답은 발견이 아니다.
- SQL 문자열 안의 따옴표, 고정 접두 경로 결합을 놓치지 않는다.
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

from gvskb.scanner import scan_code

REPO = Path(__file__).resolve().parent.parent
CORPUS = REPO / "eval_corpus" / "projects" / "l_remote_unauth_2026"
JWT = "GOV-AUTH-JWT-VERIFY-001"


def _hits(code: str, filename: str, rule: str):
    return [f for f in scan_code(code, filename=filename).findings if f.rule_id == rule]


# ---------------------------------------------------------------- 설정형 룰과 문자열 감쇄

def test_jwt_verify_off_is_block_confirmed_in_python() -> None:
    for line in ('claims = jwt.decode(token, options={"verify_signature": False})',
                 "claims = jwt.decode(token, verify=False)",
                 'claims = jwt.decode(token, KEY, algorithms=["none", "HS256"])'):
        hits = _hits(f"import jwt\n{line}\n", "auth.py", JWT)
        assert hits, line
        assert (hits[0].severity.value, hits[0].decision.value, hits[0].confidence) == ("high", "block", "confirmed"), line


def test_jwt_shape_inside_a_string_is_still_attenuated() -> None:
    code = 'def test_scanner():\n    scan_code("claims = jwt.decode(token, options={\'verify_signature\': False})")\n'
    hits = _hits(code, "test_x.py", JWT)
    assert hits and hits[0].severity.value == "low" and hits[0].decision.value == "warn"


def test_rules_without_the_flag_keep_string_attenuation() -> None:
    """표시하지 않은 룰은 그대로 — 문자열 내용이 패턴의 일부여도 감쇄된다(기존 오탐 방어를 건드리지 않는다)."""
    hits = _hits('data = open("../config/settings.json").read()\n', "load.py", "KISA-PY-INPUT-03")
    assert hits and hits[0].severity.value == "low"


def test_jwt_rule_covers_javascript_and_leaves_safe_calls() -> None:
    assert _hits("const c = jwt.verify(token, key, { algorithms: ['none', 'HS256'] });\n", "auth.js", JWT)
    assert not _hits("const c = jwt.verify(token, process.env.JWT_KEY, { algorithms: ['HS256'] });\n", "auth.js", JWT)
    assert not _hits('kid = jwt.get_unverified_header(token)["kid"]\nclaims = jwt.decode(token, KEY, algorithms=["RS256"])\n', "auth.py", JWT)
    # 옮겨 온 패턴이 옛 룰에서 한 번 더 나오지 않는다
    assert not _hits('claims = jwt.decode(token, options={"verify_signature": False})\n', "auth.py", "KISA-PY-SEC-10")


# ---------------------------------------------------------------- 오탐 2건

def test_guarded_delete_route_is_not_missing_authorization() -> None:
    guarded = "app.delete('/admin/users/:id', requireAdmin, async (req, res) => {\n  await db.users.destroy({ where: { id: req.params.id } });\n  res.status(204).end();\n});\n"
    assert not _hits(guarded, "routes.js", "KISA-JS-SEC-02")
    open_route = "app.delete('/users/:id', async (req, res) => {\n  await User.destroy({ where: { id: req.params.id } });\n  res.send('ok');\n});\n"
    assert _hits(open_route, "routes.js", "KISA-JS-SEC-02")


def test_escaped_response_is_not_reflected_xss() -> None:
    assert not _hits("res.send(`<h1>Hello ${escapeHtml(String(req.query.name))}</h1>`);\n", "a.js", "KISA-JS-INPUT-13")
    assert not _hits("res.send('<p>' + _.escape(req.body.comment) + '</p>');\n", "a.js", "KISA-JS-INPUT-13")
    # 하나라도 맨 값이면 그대로 잡는다 · 이름만 비슷한 함수는 인정하지 않는다
    assert _hits("res.send('<p>' + escapeHtml(req.query.a) + req.query.b + '</p>');\n", "a.js", "KISA-JS-INPUT-13")
    assert _hits("res.send('<p>' + cleanup(req.query.a) + '</p>');\n", "a.js", "KISA-JS-INPUT-13")
    assert _hits("res.send(`<h1>${req.query.name}</h1>`);\n", "a.js", "KISA-JS-INPUT-13")


# ---------------------------------------------------------------- 직접 형태 미탐

def test_sql_concat_with_quotes_inside_the_string() -> None:
    assert _hits('db.query("SELECT * FROM t WHERE n=\'" + req.query.n + "\'");\n', "q.js", "KISA-JS-INPUT-01")
    assert not _hits("pool.query('SET time_zone = \"+09:00\"');\n", "q.js", "KISA-JS-INPUT-01")
    assert not _hits('db.query("SELECT * FROM t WHERE n = ?", [name]);\n', "q.js", "KISA-JS-INPUT-01")


def test_path_built_from_fixed_prefix_and_request_value() -> None:
    assert _hits("fs.readFile('/srv/app/files/' + req.query.p, 'utf8', cb);\n", "f.js", "KISA-JS-INPUT-03")
    assert _hits("res.sendFile(`/srv/files/${req.params.name}`);\n", "f.js", "KISA-JS-INPUT-03")
    assert not _hits("fs.readFile('/srv/app/files/' + SAFE_NAME, 'utf8', cb);\n", "f.js", "KISA-JS-INPUT-03")
    assert _hits("data = open('/srv/files/' + request.args.get('name')).read()\n", "f.py", "KISA-PY-INPUT-03")
    assert _hits("data = open(f'/srv/files/{request.args[\"name\"]}').read()\n", "f.py", "KISA-PY-INPUT-03")
    assert not _hits("data = open('/srv/files/' + FIXED_NAME).read()\n", "f.py", "KISA-PY-INPUT-03")


# ---------------------------------------------------------------- 말뭉치

def test_manifest_points_at_existing_files() -> None:
    m = yaml.safe_load((CORPUS / "manifest.yaml").read_text(encoding="utf-8"))
    ids = [c["id"] for c in m["cases"]]
    assert len(ids) == len(set(ids)) >= 137
    for c in m["cases"]:
        assert (CORPUS / c["root"] / c["file"]).is_file(), c["id"]
    for root in m["negative_roots"]:
        assert (CORPUS / root).is_dir() and any((CORPUS / root).iterdir())


def test_corpus_scores_clean_and_twins_stay_quiet() -> None:
    """기대한 탐지는 전부 나오고, 안전한 쌍둥이에서는 발견이 없다. 공백이 잡히기 시작하면 정답표를 고치라는 신호다."""
    sys.path.insert(0, str(REPO / "scripts"))
    import run_holdout

    out = run_holdout.run("l_remote_unauth_2026")
    c = out["counts"]
    assert c["miss"] == 0 and c["news"] == 0, [r["id"] for r in out["cases"] if r["status"] in ("miss", "news")]
    assert out["false_positives"] == [], out["false_positives"]
    # 폴더 단위 엔진(인가 구조·공개 번들 비밀)이 내는 발견은 말뭉치로만 고정된다
    by_id = {r["id"]: r for r in out["cases"]}
    assert by_id["L-T05"]["status"] == "ok" and by_id["L-T05"]["rule"] == "GOV-AUTHZ-CLIENT-GATE-001"   # service_role 브라우저 노출
