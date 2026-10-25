from fastmcp import FastMCP
import subprocess
mcp = FastMCP('x')

@mcp.tool()
def version() -> str:
    return subprocess.run(['tool', '--version'], capture_output=True, text=True).stdout

if __name__ == '__main__':
    mcp.run()
