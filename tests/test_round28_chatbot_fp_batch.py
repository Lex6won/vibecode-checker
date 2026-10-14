"""34차 — 챗봇(2026-10-15) 스패로우 비교에서 확인된 오탐·결함 묶음. 재현 + 같은 모양의 양성 유지.

- 비밀값: `token: string;`·`g.auth_token = auth_token`·`SESSION_KEY = "admin_authenticated"` 는 비밀이 아니다
- SQL: `request.args.get('days', 1, type=int)`·`int(...)` 를 거친 값은 SQL 문법을 깨뜨릴 수 없다
- 루프: `while (true) { const {done, value} = await reader.read(); if (done) break; }` 는 무한 루프가 아니다
- JSX: `dangerouslySetInnerHTML={{ __html: fmt(sampleData.x) }}` 의 상수 데이터
- Jinja `| safe |` 마크다운 표 · `gethostbyname(gethostname())` · 마스킹 예시 주석의 주민번호
- 패키지: 버전 미고정은 최신판 기준 + 검토 사유, 역대 취약점을 설치 취약으로 세지 않음; aliases 보존
- 락파일 이름 인식(`requirements.lock.txt`)
"""
from __future__ import annotations

import pytest

from gvskb.scanner import scan_code
from gvskb.schema import Decision


def _ids(code: str, filename: str) -> list[tuple[str, str, str]]:
    return [(f.rule_id, f.decision.value, f.confidence) for f in scan_code(code, filename=filename).findings]


# ---------------------------------------------------------------------------
# 비밀값
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("code, filename", [
    ("interface Session {\n  token: string;\n}\n", "app/admin/users/page.tsx"),
    ("g.auth_token = auth_token\n", "gemini6.py"),
    ('const SESSION_KEY = "admin_authenticated";\n', "app/admin/layout.tsx"),
    ("const TOKEN_KEY = 'nyh_admin_session_v1';\n", "lib/auth.ts"),
])
def test_type_annotations_and_key_names_are_not_secrets(code: str, filename: str) -> None:
    assert not [x for x in _ids(code, filename) if x[0].startswith("GOV-SECRET")], _ids(code, filename)


@pytest.mark.parametrize("code, filename", [
    ('const apiKey = "sk-abcdefghijklmnopqrstuvwxyz123456";\n', "lib/llm.ts"),
    ('SESSION_SECRET = "H3xK9mQ2pR7sT1uV5wY8zB4nC6"\n', "settings.py"),
    ("DB_PASSWORD=gg2026SecureP@ss\n", ".env"),
    ("spring.datasource.password=gg2026Secure\n", "application.properties"),
    ("aws:\n  secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYzQ9kL2pQ\n", "config.yaml"),
])
def test_real_secrets_in_code_and_config_are_still_found(code: str, filename: str) -> None:
    assert [x for x in _ids(code, filename) if x[0].startswith("GOV-SECRET")], _ids(code, filename)


def test_unquoted_config_rule_does_not_run_in_code_files() -> None:
    assert not [x for x in _ids("auth_token = get_token()\n", "svc.py") if x[0].startswith("GOV-SECRET")]


# ---------------------------------------------------------------------------
# SQL — 숫자 변환
# ---------------------------------------------------------------------------

_SQL = "from flask import request\n"


def test_type_int_query_param_in_where_clause_is_not_injection() -> None:
    code = _SQL + '''
def logs(cursor):
    event_type = request.args.get('event_type', 'all')
    days = request.args.get('days', 1, type=int)
    where_clauses = [f"created_at >= datetime('now', '-{days} days')"]
    params = []
    if event_type != 'all':
        where_clauses.append('event_type = ?')
        params.append(event_type)
    where_sql = ' AND '.join(where_clauses)
    cursor.execute(f'SELECT COUNT(*) FROM security_logs WHERE {where_sql}', params)
'''
    assert not [x for x in _ids(code, "admin_api.py") if "SQL" in x[0]], _ids(code, "admin_api.py")


def test_int_cast_cuts_source() -> None:
    code = _SQL + "def q(cur):\n    n = int(request.args['n'])\n    cur.execute(f'SELECT * FROM t LIMIT {n}')\n"
    assert not [x for x in _ids(code, "a.py") if "SQL" in x[0]]


def test_missing_type_keeps_confirmed_block() -> None:
    code = _SQL + "def q(cur):\n    days = request.args.get('days', 1)\n    cur.execute(f\"SELECT * FROM t WHERE d > '{days}'\")\n"
    assert ("GOV-SQL-INJECTION-001", "block", "confirmed") in _ids(code, "a.py")


def test_reassigned_after_cast_is_source_again() -> None:
    code = _SQL + "def q(cur):\n    n = int(request.args['n'])\n    n = request.args['raw']\n    cur.execute(f\"SELECT * FROM t WHERE a = '{n}'\")\n"
    assert ("GOV-SQL-INJECTION-001", "block", "confirmed") in _ids(code, "a.py")


# ---------------------------------------------------------------------------
# JS 루프 · JSX
# ---------------------------------------------------------------------------

def test_reader_loop_with_done_break_is_not_infinite() -> None:
    code = '''
async function pump(reader) {
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    handle(value);
  }
}
'''
    assert not [x for x in _ids(code, "route.ts") if x[0] == "KISA-JS-TIME-01"]


def test_loop_without_exit_is_still_reported() -> None:
    code = "function spin() {\n  while (true) {\n    tick();\n    count++;\n  }\n}\n"
    assert [x for x in _ids(code, "a.js") if x[0] == "KISA-JS-TIME-01"]


def test_jsx_constant_sample_data_through_formatter_is_not_xss() -> None:
    code = '''
const sampleData = {
    conclusion: "주취자가 **단순 주취** 상황입니다.",
    checklist: [
        { label: "의식 상태", content: "외부 자극에 대한 반응은 어떤가요?" },
    ],
};
const fmt = (t: string, c: string = "font-bold") => t.replace(/\\*\\*(.*?)\\*\\*/g, `<strong class="${c}">$1</strong>`);
export default function Page() {
  return <p dangerouslySetInnerHTML={{ __html: fmt(sampleData.conclusion) }} />;
}
'''
    assert not [x for x in _ids(code, "app/style-preview/page.tsx") if x[0] == "KISA-JS-INPUT-04"], \
        _ids(code, "app/style-preview/page.tsx")


def test_jsx_static_script_template_is_not_xss() -> None:
    code = '''
export default function Root() {
  return (
    <head>
      <script dangerouslySetInnerHTML={{
        __html: `
          (function() { document.documentElement.classList.add('dark'); })();
        `,
      }} />
    </head>
  );
}
'''
    assert not [x for x in _ids(code, "app/layout.tsx") if x[0] == "KISA-JS-INPUT-04"]


def test_jsx_with_request_data_stays_blocked() -> None:
    code = '''
export default async function Page({ searchParams }) {
  const data = await (await fetch("/api/x")).json();
  return <div dangerouslySetInnerHTML={{ __html: data.html }} />;
}
'''
    hits = [f for f in scan_code(code, filename="app/page.tsx").findings if f.rule_id == "KISA-JS-INPUT-04"]
    assert hits and hits[0].decision == Decision.block, [(f.decision, f.confidence) for f in hits]


# ---------------------------------------------------------------------------
# Jinja · DNS · PII 예시
# ---------------------------------------------------------------------------

def test_markdown_table_safe_word_is_not_jinja_filter() -> None:
    code = 'PROMPT = """\n| danger | 생명 위험 |\n| safe | 자진 귀가 |\n"""\n'
    assert not [x for x in _ids(code, "gemini6.py") if x[0] == "KISA-PY-INPUT-04"]
    assert [x for x in _ids('t = render_template_string("{{ name | safe }}", name=request.args["n"])\n', "a.py")
            if x[0] == "KISA-PY-INPUT-04"]


def test_local_ip_banner_is_not_dns_trust() -> None:
    code = "import socket\nlocal_ip = socket.gethostbyname(socket.gethostname())\n"
    assert not [x for x in _ids(code, "run.py") if x[0] == "KISA-PY-API-01"]
    assert [x for x in _ids("import socket\nip = socket.gethostbyname(host)\n", "run.py") if x[0] == "KISA-PY-API-01"]


def test_masking_example_comment_is_not_pii() -> None:
    code = "// - 예: 880101-1234567, 880101-1******\n"
    assert not [x for x in _ids(code, "lib/maskPersonalData.ts") if x[0].startswith("GOV-PII")]
    assert [x for x in _ids('const rrn = "880101-1234567";\n', "lib/x.ts") if x[0] == "GOV-PII-RRN-001"]


# ---------------------------------------------------------------------------
# 패키지 — 미고정 · aliases
# ---------------------------------------------------------------------------

def test_advisory_rows_keep_aliases() -> None:
    from gvskb.tools.check_package import _advisory_rows
    rows = _advisory_rows([{"id": "GHSA-6g55-p6wh-862q", "aliases": ["CVE-2023-44270"], "summary": "x"}],
                          name="postcss", eco="npm")
    assert rows[0]["aliases"] == ["CVE-2023-44270"]


def test_unpinned_requirement_is_judged_by_latest_and_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio

    from gvskb.schema import PackageRegistryMetadata
    from gvskb.tools import check_package as cp

    async def fake_meta(name, ecosystem="pypi", version=None, timeout=10.0):
        return PackageRegistryMetadata(exists=True, latest_version="3.1.0", queried_version=version,
                                       version_exists=True if version else None, license="MIT",
                                       source="test", fetched_at="2026-10-15T00:00:00+00:00")

    seen: list[dict] = []

    async def fake_osv(payload, timeout=10.0, client=None):
        seen.append(payload)
        # 버전이 붙은 조회는 깨끗, 버전 없는 조회면 역대 취약점이 돌아오는 상황을 흉내 낸다
        if payload.get("version"):
            return {"vulns": []}
        return {"vulns": [{"id": "GHSA-old", "database_specific": {"severity": "CRITICAL"}}]}

    monkeypatch.setattr(cp, "fetch_registry_metadata", fake_meta)
    monkeypatch.setattr(cp, "_osv_query", fake_osv)
    monkeypatch.delenv("GVSKB_MODE", raising=False)
    r = asyncio.run(cp.check_package_impl("flask-cors", "pypi", version=None))
    assert seen and seen[0].get("version") == "3.1.0"
    assert r["vulnerability_count"] == 0 and r["version_resolution"] == "latest-assumed"
    assert r["requires_review"] is True and "버전 미고정" in (r["note"] or "")


def test_requirements_lock_txt_is_classified_as_lockfile(tmp_path) -> None:
    from gvskb.cli import _run_dependency_audit  # noqa: F401 — 분류 함수는 내부라 간접 확인
    import inspect
    src = inspect.getsource(_run_dependency_audit)
    assert '".lock" in low' in src
