"""Mock HTTP tool. It can only reach the attacker sink, never the shield's own API."""

import httpx
from mcp.server.fastmcp import FastMCP

from lab.mcp_servers.common import REQUEST_TIMEOUT_SECONDS, require_local_url
from promptshield.config import get_settings


def build_server(sink_port: int, transport: httpx.AsyncBaseTransport | None = None) -> FastMCP:
    server = FastMCP("http", log_level="WARNING")

    @server.tool()
    async def http_post(url: str, data: str) -> str:
        """Send data to a URL with an HTTP POST."""
        safe_url = require_local_url(url, sink_port, "http_post")
        async with httpx.AsyncClient(
            transport=transport,
            follow_redirects=False,
            trust_env=False,
            timeout=REQUEST_TIMEOUT_SECONDS,
        ) as client:
            try:
                response = await client.post(safe_url, content=data.encode("utf-8"))
            except httpx.HTTPError as error:
                raise ValueError("http_post could not reach the server") from error
        return f"Sent, HTTP {response.status_code}"

    return server


def main() -> None:
    build_server(get_settings().sink_port).run("stdio")


if __name__ == "__main__":
    main()
