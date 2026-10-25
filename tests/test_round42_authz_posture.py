"""42차 — 인가 자세(authz-posture, P0-03): 관리자 경로의 서버측 보호 근거 부재 · 공개 번들 비밀/클라이언트 관문.

fixture 는 설정·구조 모양만. 모든 판정은 경고(likely 이하)이고 전역 보호 근거가 있으면 내지 않는다.
"""
from __future__ import annotations

import json
from pathlib import Path

from gvskb.scanner import path_level_rule_ids, scan_path
from gvskb.scanners.authz_posture import RULE_ADMIN, RULE_CLIENT_GATE

REPO = Path(__file__).resolve().parent.parent


def _w(root: Path, rel: str, text: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def _by(report, rule_id):
    return [f for f in report.findings if f.rule_id == rule_id]


_FLASK_ADMIN = (
    "from flask import Blueprint, jsonify, request\n"
    "bp = Blueprint('admin', __name__)\n\n"
    "@bp.route('/api/admin/users', methods=['GET'])\n"
    "def get_users():\n    return jsonify([])\n\n"
    "@bp.route('/api/admin/users', methods=['POST'])\n"
    "def create_user():\n    return jsonify({'ok': True})\n\n"
    "@bp.route('/api/public/health')\n"
    "def health():\n    return 'ok'\n"
)


def test_registered_as_path_level_rules() -> None:
    assert RULE_ADMIN in path_level_rule_ids() and RULE_CLIENT_GATE in path_level_rule_ids()


def test_flask_admin_routes_without_guard_are_flagged(tmp_path: Path) -> None:
    _w(tmp_path, "backend/admin_api.py", _FLASK_ADMIN)
    r = scan_path(tmp_path)
    hits = _by(r, RULE_ADMIN)
    assert sorted(h.location.line for h in hits) == [4, 8]
    by_line = {h.location.line: h for h in hits}
    assert by_line[8].confidence == "likely" and "POST" in by_line[8].evidence
    assert by_line[4].confidence == "pattern-only"
    assert all(h.decision.value == "warn" for h in hits)
    assert any(e["kind"] == "authz-route" for e in r.autoexec_surface)


def test_flask_decorator_guard_is_recognized(tmp_path: Path) -> None:
    _w(tmp_path, "backend/admin_api.py", _FLASK_ADMIN.replace(
        "@bp.route('/api/admin/users', methods=['POST'])\n", "@bp.route('/api/admin/users', methods=['POST'])\n@admin_required\n"))
    hits = _by(scan_path(tmp_path), RULE_ADMIN)
    assert [h.location.line for h in hits] == [4]


def test_flask_body_check_with_deny_is_recognized(tmp_path: Path) -> None:
    code = _FLASK_ADMIN.replace(
        "def create_user():\n    return jsonify({'ok': True})",
        "def create_user():\n    if not session.get('is_admin'):\n        abort(403)\n    return jsonify({'ok': True})")
    _w(tmp_path, "backend/admin_api.py", code)
    assert [h.location.line for h in _by(scan_path(tmp_path), RULE_ADMIN)] == [4]


def test_flask_global_before_request_with_deny_suppresses(tmp_path: Path) -> None:
    _w(tmp_path, "backend/admin_api.py", _FLASK_ADMIN)
    _w(tmp_path, "backend/app.py",
       "from flask import Flask, request, session, abort\napp = Flask(__name__)\n\n@app.before_request\n"
       "def guard():\n    if request.path.startswith('/api/admin') and not session.get('is_admin'):\n        abort(403)\n")
    assert _by(scan_path(tmp_path), RULE_ADMIN) == []


def test_before_request_that_only_assigns_is_not_a_guard(tmp_path: Path) -> None:
    _w(tmp_path, "backend/admin_api.py", _FLASK_ADMIN)
    _w(tmp_path, "backend/app.py",
       "from flask import Flask, request, g\napp = Flask(__name__)\n\n@app.before_request\n"
       "def assign():\n    g.token = request.headers.get('X-Token')\n")
    assert len(_by(scan_path(tmp_path), RULE_ADMIN)) == 2


def test_fastapi_depends_is_a_guard(tmp_path: Path) -> None:
    _w(tmp_path, "api.py",
       "from fastapi import APIRouter, Depends\nrouter = APIRouter()\n\n"
       "@router.delete('/admin/users/{uid}')\ndef remove(uid: int, user=Depends(require_admin)):\n    return {}\n\n"
       "@router.delete('/admin/users/{uid}/ban')\ndef ban(uid: int):\n    return {}\n")
    hits = _by(scan_path(tmp_path), RULE_ADMIN)
    assert [h.location.line for h in hits] == [8]


def test_express_admin_route_without_middleware(tmp_path: Path) -> None:
    _w(tmp_path, "server.js",
       "const express = require('express');\nconst app = express();\n"
       "app.get('/admin/users', (req, res) => res.json([]));\n"
       "app.delete('/admin/users/:id', (req, res) => res.sendStatus(204));\n"
       "app.get('/health', (req, res) => res.send('ok'));\n")
    hits = _by(scan_path(tmp_path), RULE_ADMIN)
    assert sorted((h.location.line, h.confidence) for h in hits) == [(3, "pattern-only"), (4, "likely")]


def test_express_route_middleware_and_global_use_are_guards(tmp_path: Path) -> None:
    _w(tmp_path, "server.js",
       "const express = require('express');\nconst app = express();\n"
       "app.delete('/admin/users/:id', requireAdmin, (req, res) => res.sendStatus(204));\n")
    assert _by(scan_path(tmp_path), RULE_ADMIN) == []
    _w(tmp_path, "server.js",
       "const express = require('express');\nconst app = express();\napp.use('/admin', authenticate);\n"
       "app.delete('/admin/users/:id', (req, res) => res.sendStatus(204));\n")
    assert _by(scan_path(tmp_path), RULE_ADMIN) == []


def test_express_generic_use_is_not_a_guard(tmp_path: Path) -> None:
    _w(tmp_path, "server.js",
       "const express = require('express');\nconst app = express();\napp.use(express.json());\napp.use(cors());\n"
       "app.post('/admin/settings', (req, res) => res.json({}));\n")
    assert len(_by(scan_path(tmp_path), RULE_ADMIN)) == 1


def test_nextjs_admin_route_handler_and_middleware(tmp_path: Path) -> None:
    _w(tmp_path, "app/api/admin/users/route.ts",
       "export async function POST(req: Request) {\n  const body = await req.json();\n  return Response.json({ ok: true });\n}\n")
    assert [h.confidence for h in _by(scan_path(tmp_path), RULE_ADMIN)] == ["likely"]
    _w(tmp_path, "middleware.ts",
       "import { NextResponse } from 'next/server';\nimport { getToken } from 'next-auth/jwt';\n"
       "export async function middleware(req) {\n  const token = await getToken({ req });\n"
       "  if (!token || token.role !== 'admin') return NextResponse.redirect(new URL('/login', req.url));\n}\n"
       "export const config = { matcher: ['/admin/:path*', '/api/admin/:path*'] };\n")
    assert _by(scan_path(tmp_path), RULE_ADMIN) == []


def test_public_env_secret_and_storage_gate(tmp_path: Path) -> None:
    _w(tmp_path, "app/admin/layout.tsx",
       "\"use client\";\nconst ADMIN_PIN = process.env.NEXT_PUBLIC_ADMIN_PIN || '';\nconst KEY = 'admin_authenticated';\n"
       "export default function Layout() {\n  const ok = sessionStorage.getItem(KEY) === 'true';\n  return ok ? null : null;\n}\n")
    hits = _by(scan_path(tmp_path), RULE_CLIENT_GATE)
    assert sorted((h.location.line, h.confidence) for h in hits) == [(2, "likely"), (5, "pattern-only")]
    assert "NEXT_PUBLIC_ADMIN_PIN" in hits[0].evidence or "NEXT_PUBLIC_ADMIN_PIN" in hits[1].evidence


def test_public_env_non_secret_is_clean(tmp_path: Path) -> None:
    _w(tmp_path, "src/api.ts",
       "const BASE = process.env.NEXT_PUBLIC_API_BASE_URL;\nconst FLAG = import.meta.env.VITE_FEATURE_BETA;\n"
       "export const url = (p: string) => `${BASE}${p}`;\n")
    assert _by(scan_path(tmp_path), RULE_CLIENT_GATE) == []


def test_non_admin_routes_are_quiet(tmp_path: Path) -> None:
    _w(tmp_path, "app.py",
       "from flask import Flask\napp = Flask(__name__)\n\n@app.route('/api/items', methods=['POST'])\ndef add():\n    return ''\n\n"
       "@app.route('/api/items/<int:i>', methods=['DELETE'])\ndef rm(i):\n    return ''\n")
    r = scan_path(tmp_path)
    assert _by(r, RULE_ADMIN) == [] and not any(e["kind"] == "authz-route" for e in r.autoexec_surface)


def test_checker_repo_itself_is_quiet() -> None:
    r = scan_path(REPO / "src")
    assert [f.rule_id for f in r.findings if f.rule_id in (RULE_ADMIN, RULE_CLIENT_GATE)] == []


def test_mcp_json_shape_does_not_trigger(tmp_path: Path) -> None:
    _w(tmp_path, ".mcp.json", json.dumps({"mcpServers": {"x": {"command": "gvskb-server"}}}))
    _w(tmp_path, "a.py", "x = 1\n")
    assert _by(scan_path(tmp_path), RULE_ADMIN) == []


def test_fastapi_annotated_alias_and_include_router_dependencies(tmp_path: Path) -> None:
    _w(tmp_path, "routes/admin.py",
       "from fastapi import APIRouter\nfrom app.dependencies import AdminUser, DbSession\nrouter = APIRouter(prefix='/admin')\n\n"
       "@router.put('/settings')\nasync def update_settings(\n    payload: dict, user: AdminUser, db: DbSession\n) -> dict:\n    return {}\n")
    assert _by(scan_path(tmp_path), RULE_ADMIN) == []
    _w(tmp_path, "routes/admin.py",
       "from fastapi import APIRouter\nrouter = APIRouter(prefix='/admin')\n\n@router.put('/settings')\nasync def update_settings(payload: dict) -> dict:\n    return {}\n")
    assert len(_by(scan_path(tmp_path), RULE_ADMIN)) == 1
    _w(tmp_path, "main.py",
       "from fastapi import FastAPI, Depends\nfrom routes import admin\napp = FastAPI()\n"
       "app.include_router(admin.router, dependencies=[Depends(require_admin)])\n")
    assert _by(scan_path(tmp_path), RULE_ADMIN) == []


def test_frontend_http_client_calls_are_not_routes(tmp_path: Path) -> None:
    _w(tmp_path, "src/services/registry.ts",
       "import axios from 'axios';\nconst api = axios.create({ baseURL: '/api' });\n"
       "export const adminApi = {\n  deleteApiKey: (id: string) => api.delete(`/admin/api-keys/${id}`).then((r) => r.data),\n"
       "  settings: () => api.get('/admin/settings'),\n};\n")
    assert _by(scan_path(tmp_path), RULE_ADMIN) == []


def test_project_helper_require_with_403_is_a_guard(tmp_path: Path) -> None:
    _w(tmp_path, "api.py",
       "def install(app, actor, store):\n    @app.get('/api/v2/admin/summary')\n    async def admin_summary(request):\n"
       "        person = await actor(request)\n        require(person.role == 'SUPER_ADMIN', '권한 필요', 'FORBIDDEN', 403)\n        return {}\n")
    assert _by(scan_path(tmp_path), RULE_ADMIN) == []


def test_config_path_is_sensitive_only_when_written(tmp_path: Path) -> None:
    _w(tmp_path, "api.py",
       "from flask import Flask\napp = Flask(__name__)\n\n@app.route('/api/v2/config')\ndef config():\n    return {}\n\n"
       "@app.route('/api/v2/config', methods=['PUT'])\ndef set_config():\n    return {}\n")
    hits = _by(scan_path(tmp_path), RULE_ADMIN)
    assert [(h.location.line, h.confidence) for h in hits] == [(8, "likely")]
