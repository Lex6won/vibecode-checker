"""40차 — 생태계별 설정 판정(ecosystem-surface): Electron · VS Code 확장 · Chrome 확장 · MCP 서버.

의존성이 있을 때만 켜진다(없으면 발견 0·비용 0). fixture 는 설정 파일 모양만 쓴다.
"""
from __future__ import annotations

import json
from pathlib import Path

from gvskb.scanner import scan_path
from gvskb.scanners.ecosystem_surface import (
    RULE_CHROME_HEADER,
    RULE_CHROME_MESSAGE,
    RULE_CHROME_PERMISSION,
    RULE_ELECTRON_HARDENING,
    RULE_ELECTRON_IPC,
    RULE_ELECTRON_WEBPREFS,
    RULE_MCP_SERVER,
    RULE_VSCODE_TRUST,
    detect_ecosystems,
)

REPO = Path(__file__).resolve().parent.parent


def _w(root: Path, rel: str, text: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def _by(report, rule_id):
    return [f for f in report.findings if f.rule_id == rule_id]


def _eco(report):
    return [f for f in report.findings if f.engine == "ecosystem-surface"]


# ── 활성 조건 ────────────────────────────────────────────────────────────────

def test_inactive_without_dependencies(tmp_path: Path) -> None:
    _w(tmp_path, "package.json", json.dumps({"name": "web", "dependencies": {"express": "^4.19.2"}}))
    _w(tmp_path, "main.js", "const win = new BrowserWindow({ webPreferences: { nodeIntegration: true } });\n")
    active, _ = detect_ecosystems(tmp_path)
    assert active == set()
    assert _eco(scan_path(tmp_path)) == [], "electron 의존성이 없으면 Electron 판정을 하지 않는다"


# ── Electron ─────────────────────────────────────────────────────────────────

def _electron(tmp_path: Path, main_js: str, extra: dict | None = None) -> None:
    _w(tmp_path, "package.json", json.dumps({"name": "app", "main": "main.js", "devDependencies": {"electron": "^41.0.0"}}))
    _w(tmp_path, "main.js", main_js)
    for rel, txt in (extra or {}).items():
        _w(tmp_path, rel, txt)


def test_electron_insecure_webprefs_with_remote_load_is_confirmed(tmp_path: Path) -> None:
    _electron(tmp_path,
              "const { BrowserWindow } = require('electron');\n"
              "const win = new BrowserWindow({ webPreferences: { nodeIntegration: true, contextIsolation: false } });\n"
              "win.loadURL('https://portal.example/app');\n")
    hits = _by(scan_path(tmp_path), RULE_ELECTRON_WEBPREFS)
    assert len(hits) == 1 and hits[0].confidence == "confirmed" and hits[0].decision.value == "block"
    assert "nodeIntegration: true" in hits[0].evidence and "원격" in hits[0].evidence


def test_electron_insecure_webprefs_local_only_is_warn(tmp_path: Path) -> None:
    _electron(tmp_path, "const win = new BrowserWindow({ webPreferences: { nodeIntegration: true } });\nwin.loadFile('index.html');\n")
    hits = _by(scan_path(tmp_path), RULE_ELECTRON_WEBPREFS)
    assert len(hits) == 1 and hits[0].confidence == "likely" and hits[0].decision.value == "warn"


def test_electron_secure_defaults_are_clean(tmp_path: Path) -> None:
    _electron(tmp_path,
              "const win = new BrowserWindow({ webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, sandbox: true } });\n"
              "win.loadFile('index.html');\n",
              {"preload.js": "contextBridge.exposeInMainWorld('api', { getVersion: () => ipcRenderer.invoke('app:version') });\n"})
    assert _eco(scan_path(tmp_path)) == []


def test_electron_wholesale_bridge_is_confirmed(tmp_path: Path) -> None:
    _electron(tmp_path, "const win = new BrowserWindow({});\n",
              {"preload.js": "const { contextBridge, ipcRenderer } = require('electron');\ncontextBridge.exposeInMainWorld('electron', { ipcRenderer });\n"})
    hits = _by(scan_path(tmp_path), RULE_ELECTRON_IPC)
    assert any(h.confidence == "confirmed" and "통째로" in h.evidence for h in hits)


def test_electron_generic_channel_bridge_is_confirmed(tmp_path: Path) -> None:
    _electron(tmp_path, "const win = new BrowserWindow({});\n",
              {"preload.js": "contextBridge.exposeInMainWorld('api', { send: (channel, data) => ipcRenderer.send(channel, data) });\n"})
    hits = _by(scan_path(tmp_path), RULE_ELECTRON_IPC)
    assert any("범용" in h.evidence for h in hits)


def test_electron_ipc_handler_without_sender_check_is_likely(tmp_path: Path) -> None:
    _electron(tmp_path,
              "const { ipcMain } = require('electron');\nconst fs = require('fs');\n"
              "ipcMain.handle('read-file', async (event, p) => {\n  return fs.readFileSync(p, 'utf8');\n});\n")
    hits = _by(scan_path(tmp_path), RULE_ELECTRON_IPC)
    assert any("발신자" in h.evidence and h.confidence == "likely" for h in hits)


def test_electron_ipc_handler_with_sender_check_is_clean(tmp_path: Path) -> None:
    _electron(tmp_path,
              "const { ipcMain } = require('electron');\nconst fs = require('fs');\n"
              "ipcMain.handle('read-file', async (event, p) => {\n"
              "  if (new URL(event.senderFrame.url).origin !== APP_ORIGIN) throw new Error('denied');\n"
              "  return fs.readFileSync(p, 'utf8');\n});\n")
    assert not _by(scan_path(tmp_path), RULE_ELECTRON_IPC)


def test_electron_builder_without_fuses_is_warn(tmp_path: Path) -> None:
    _electron(tmp_path, "const win = new BrowserWindow({});\n",
              {"forge.config.js": "module.exports = { packagerConfig: { asar: true }, makers: [] };\n"})
    hits = _by(scan_path(tmp_path), RULE_ELECTRON_HARDENING)
    assert any("fuses" in h.evidence.lower() for h in hits) and all(h.decision.value == "warn" for h in hits)


# ── VS Code 확장 ─────────────────────────────────────────────────────────────

def _vscode(tmp_path: Path, manifest_extra: dict, src: str) -> None:
    m = {"name": "ext", "publisher": "org", "engines": {"vscode": "^1.90.0"}, "main": "./out/extension.js", "activationEvents": ["onCommand:ext.run"]}
    m.update(manifest_extra)
    _w(tmp_path, "package.json", json.dumps(m))
    _w(tmp_path, "src/extension.ts", src)


def test_vscode_setting_to_exec_with_untrusted_supported_is_confirmed(tmp_path: Path) -> None:
    _vscode(tmp_path, {"capabilities": {"untrustedWorkspaces": {"supported": True}}},
            "import * as vscode from 'vscode';\nimport { execFile } from 'child_process';\n"
            "const bin = vscode.workspace.getConfiguration('ext').get<string>('toolPath');\nexecFile(bin!, ['--version']);\n")
    hits = _by(scan_path(tmp_path), RULE_VSCODE_TRUST)
    assert any(h.confidence == "confirmed" and "toolPath" in h.evidence for h in hits)


def test_vscode_star_activation_is_warn_and_clean_extension_passes(tmp_path: Path) -> None:
    _vscode(tmp_path, {"activationEvents": ["*"], "capabilities": {"untrustedWorkspaces": {"supported": False}}},
            "import * as vscode from 'vscode';\nexport function activate() { vscode.window.showInformationMessage('hi'); }\n")
    hits = _by(scan_path(tmp_path), RULE_VSCODE_TRUST)
    assert any("activationEvents" in h.evidence for h in hits) and all(h.decision.value == "warn" for h in hits)
    _vscode(tmp_path, {"capabilities": {"untrustedWorkspaces": {"supported": False}}},
            "import * as vscode from 'vscode';\nexport function activate() { vscode.window.showInformationMessage('hi'); }\n")
    assert not _by(scan_path(tmp_path), RULE_VSCODE_TRUST)


# ── Chrome 확장 ──────────────────────────────────────────────────────────────

def _chrome(tmp_path: Path, manifest: dict, files: dict | None = None) -> None:
    base = {"manifest_version": 3, "name": "ext", "version": "1.0", "action": {}}
    base.update(manifest)
    _w(tmp_path, "manifest.json", json.dumps(base))
    for rel, txt in (files or {}).items():
        _w(tmp_path, rel, txt)


def test_chrome_broad_permissions_and_open_connectable(tmp_path: Path) -> None:
    _chrome(tmp_path, {"host_permissions": ["<all_urls>"], "permissions": ["cookies", "scripting", "tabs"],
                       "externally_connectable": {"matches": ["https://*/*"]}})
    hits = _by(scan_path(tmp_path), RULE_CHROME_PERMISSION)
    assert any("광역 호스트" in h.evidence for h in hits)
    assert any("externally_connectable" in h.evidence and h.confidence == "confirmed" for h in hits)


def test_chrome_minimal_manifest_is_clean(tmp_path: Path) -> None:
    _chrome(tmp_path, {"host_permissions": ["https://intranet.example/*"], "permissions": ["storage"]},
            {"background.js": "chrome.runtime.onInstalled.addListener(() => chrome.storage.local.set({ ok: true }));\n"})
    assert _eco(scan_path(tmp_path)) == []


def test_chrome_dnr_rules_removing_csp_is_confirmed(tmp_path: Path) -> None:
    _chrome(tmp_path, {"permissions": ["declarativeNetRequest"], "declarative_net_request": {"rule_resources": [{"id": "r", "enabled": True, "path": "rules.json"}]}},
            {"rules.json": json.dumps([{"id": 1, "priority": 1, "action": {"type": "modifyHeaders", "responseHeaders": [
                {"header": "content-security-policy", "operation": "remove"}]}, "condition": {"urlFilter": "*", "resourceTypes": ["main_frame"]}}])})
    hits = _by(scan_path(tmp_path), RULE_CHROME_HEADER)
    assert any(h.confidence == "confirmed" and "content-security-policy" in h.evidence for h in hits)


def test_chrome_external_message_without_sender_check_is_confirmed(tmp_path: Path) -> None:
    _chrome(tmp_path, {"permissions": ["cookies"], "externally_connectable": {"matches": ["https://partner.example/*"]}},
            {"background.js": "chrome.runtime.onMessageExternal.addListener((msg, sender, reply) => {\n  chrome.cookies.getAll({}, reply);\n});\n"})
    hits = _by(scan_path(tmp_path), RULE_CHROME_MESSAGE)
    assert len(hits) == 1 and hits[0].confidence == "confirmed"


def test_chrome_message_with_sender_check_is_clean(tmp_path: Path) -> None:
    _chrome(tmp_path, {"permissions": ["cookies"]},
            {"background.js": "chrome.runtime.onMessage.addListener((msg, sender, reply) => {\n  if (sender.id !== chrome.runtime.id) return;\n  if (msg.type === 'count') chrome.cookies.getAll({}, c => reply(c.length));\n});\n"})
    assert not _by(scan_path(tmp_path), RULE_CHROME_MESSAGE)


# ── MCP 서버 ─────────────────────────────────────────────────────────────────

def test_mcp_dynamic_shell_in_tool_module_is_confirmed(tmp_path: Path) -> None:
    _w(tmp_path, "requirements.txt", "fastmcp>=3.2\n")
    _w(tmp_path, "server.py",
       "from fastmcp import FastMCP\nimport subprocess\nmcp = FastMCP('x')\n\n@mcp.tool()\ndef run(cmd: str) -> str:\n"
       "    return subprocess.run(f'tool {cmd}', shell=True, capture_output=True, text=True).stdout\n")
    hits = _by(scan_path(tmp_path), RULE_MCP_SERVER)
    assert any(h.confidence == "confirmed" and "프로세스" in h.evidence for h in hits)


def test_mcp_http_transport_without_origin_check_is_likely(tmp_path: Path) -> None:
    _w(tmp_path, "package.json", json.dumps({"name": "s", "dependencies": {"@modelcontextprotocol/sdk": "^1.0.0"}}))
    _w(tmp_path, "server.js",
       "import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';\n"
       "const t = new StreamableHTTPServerTransport({});\napp.listen(3000, '0.0.0.0');\n")
    hits = _by(scan_path(tmp_path), RULE_MCP_SERVER)
    assert any("Origin" in h.evidence for h in hits)


def test_mcp_safe_server_is_clean(tmp_path: Path) -> None:
    _w(tmp_path, "requirements.txt", "fastmcp>=3.2\n")
    _w(tmp_path, "server.py",
       "from fastmcp import FastMCP\nimport subprocess\nmcp = FastMCP('x')\n\n@mcp.tool()\ndef version() -> str:\n"
       "    return subprocess.run(['tool', '--version'], capture_output=True, text=True).stdout\n\nif __name__ == '__main__':\n    mcp.run()\n")
    assert not _by(scan_path(tmp_path), RULE_MCP_SERVER)


def test_report_lists_ecosystem_entries(tmp_path: Path) -> None:
    _electron(tmp_path, "const win = new BrowserWindow({ webPreferences: { nodeIntegration: true } });\n")
    r = scan_path(tmp_path)
    kinds = {e["kind"] for e in r.autoexec_surface}
    assert "electron-manifest" in kinds and "electron-src" in kinds
