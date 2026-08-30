"""15차 — 개선요청 #34 D1·D2: 사람이 찾았고 체커가 놓친 실제 취약점 2종을 좁은 룰로.

D2 `resolved.startsWith(root)` 구분자 없는 경계 검사 · D1 응답 본문의 비밀·로그인 링크.
둘 다 정규식 한 줄 범위이므로 `warn`·`pattern-only` 로 두고, 정상 설계(로그인 응답의
access token · 구분자 붙인 비교 · 검증 문구)는 잡지 않는 것을 적대적으로 고정한다.
"""
from __future__ import annotations

import pytest

from gvskb.scanner import scan_code


def _ids(code: str, filename: str) -> set[str]:
    return {rid for f in scan_code(code, filename=filename).findings for rid in (f.rule_id, *f.also_matched)}


# ── D2 경로 경계 ──
@pytest.mark.parametrize("code, fn", [
    ("if (!resolved.startsWith(path.resolve(root))) throw new Error('bad');", "server.js"),
    ("if (!resolved.startsWith(root)) return res.status(400).end();", "server.js"),
    ("const ok = target.startsWith(UPLOAD_DIR);", "files.ts"),
    ("if not abs_path.startswith(os.path.abspath(base_dir)): abort(400)", "app.py"),
    ("if not abs_path.startswith(base_dir): abort(400)", "app.py"),
])
def test_prefix_only_boundary_check_is_flagged(code, fn):
    assert "GOV-PATH-BOUNDARY-001" in _ids(code + "\n", fn)


@pytest.mark.parametrize("code, fn", [
    ("if (!resolved.startsWith(path.resolve(root) + path.sep)) throw new Error('bad');", "server.js"),
    ("if (!resolved.startsWith(root + '/')) throw new Error('bad');", "server.js"),
    ("const rel = path.relative(root, resolved); if (rel.startsWith('..')) throw e;", "server.js"),
    ("if not Path(p).resolve().is_relative_to(base): abort(400)", "app.py"),
    ("if not p.startswith(os.path.join(base_dir, '')): abort(400)", "app.py"),
    ("if (url.startsWith('https://')) return;", "server.js"),
    ("if (name.startsWith('tmp')) continue;", "server.js"),
    ("if (href.startsWith(baseUrl)) open(href);", "app.js"),
])
def test_correct_or_unrelated_startswith_is_not_flagged(code, fn):
    assert "GOV-PATH-BOUNDARY-001" not in _ids(code + "\n", fn), code


def test_boundary_rule_is_warn_not_block():
    fs = [f for f in scan_code("if (!resolved.startsWith(root)) throw e;\n", filename="server.js").findings
          if f.rule_id == "GOV-PATH-BOUNDARY-001"]
    assert fs and fs[0].decision.value == "warn" and fs[0].confidence == "pattern-only"


# ── D1 응답 본문의 비밀 ──
@pytest.mark.parametrize("code, fn", [
    ("res.json({ ok: true, dev_login_url: `/login?token=${token}` });", "server.js"),
    ("res.send({ user: u.name, password: u.password });", "server.js"),
    ("reply.send({ api_key: key });", "routes.ts"),
    ("return jsonify({'ok': True, 'password': temp_pw})", "app.py"),
    ('return JSONResponse({"reset_token": tok})', "api.py"),
    ("ctx.body = { private_key: pem };", "server.js"),
    ('json(response, 200, { status: "sent", mode: "dev", dev_login_url: loginPath, expires_in_minutes });', "server.js"),  # 포털 실제
])
def test_secret_in_response_body_is_flagged(code, fn):
    assert "GOV-RESPONSE-SECRET-001" in _ids(code + "\n", fn)


@pytest.mark.parametrize("code, fn", [
    ("res.json({ token: accessToken, expires_in: 3600 });", "server.js"),        # 로그인 응답의 토큰은 정상
    ("res.json({ ok: true, user: { id: u.id, name: u.name } });", "server.js"),
    ("res.status(400).json({ error: 'password required', password: null });", "server.js"),
    ("res.json({ password_changed: true });", "server.js"),
    ("return jsonify({'has_password': bool(user.pw_hash)})", "app.py"),
    ("const cfg = { password: process.env.DB_PASS };", "config.js"),              # 응답이 아니다
    ("res.json({ password: '***' });", "server.js"),
    ("json(response, 200, { status: 'ok', token: accessToken });", "server.js"),
    ("const payload = JSON.stringify({ password: pw });", "client.js"),
])
def test_normal_responses_are_not_flagged(code, fn):
    assert "GOV-RESPONSE-SECRET-001" not in _ids(code + "\n", fn), code
