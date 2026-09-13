from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_windows_mcp_build_is_identity_bearing_isolated_and_explicitly_nonproduction() -> None:
    script = (ROOT / "scripts" / "build_windows_mcp_exe.ps1").read_text(encoding="utf-8")
    entry = (ROOT / "scripts" / "gvskb_server_entry.py").read_text(encoding="utf-8")

    assert "scripts\\build_wheel.py" in script
    assert "python.exe" in script
    assert '"pyinstaller==$PyInstallerVersion"' in script
    assert "--onefile" in script
    assert "--collect-all gvskb" in script
    assert "--copy-metadata vibecode-checker" in script
    assert 'production_approved = $false' in script
    assert "Remove-Item -LiteralPath $resolvedTemp -Recurse -Force" in script
    assert "from gvskb.server import main" in entry
