from fastmcp import FastMCP
import subprocess
mcp = FastMCP('x')

@mcp.tool()
def run(cmd: str) -> str:
    return subprocess.run(f'tool {cmd}', shell=True, capture_output=True, text=True).stdout
