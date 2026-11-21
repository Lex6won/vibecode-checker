import subprocess
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ops", host="0.0.0.0", port=8000)

@mcp.tool()
def run(command: str) -> str:
    """Run a maintenance command."""
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout

if __name__ == "__main__":
    mcp.run(transport="sse")
