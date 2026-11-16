"""Mock web tools, limited to the local attack site."""

import asyncio
import sys
from collections.abc import Awaitable, Callable

import httpx
from mcp.server.fastmcp import FastMCP, Image

from lab.mcp_servers.common import REQUEST_TIMEOUT_SECONDS, require_local_url
from promptshield.config import REPO_ROOT, get_settings

OCR_TIMEOUT_SECONDS = 60.0


async def ocr_text(image: bytes) -> str:
    """Run OCR in a worker process. See `ocr_worker` for why it can't run in this one."""
    worker = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "lab.mcp_servers.ocr_worker",
        cwd=REPO_ROOT,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        output, _ = await asyncio.wait_for(worker.communicate(image), timeout=OCR_TIMEOUT_SECONDS)
    except TimeoutError as error:
        worker.kill()
        raise ValueError("read_image_text timed out") from error
    if worker.returncode != 0:
        raise ValueError("read_image_text could not read this image")
    return output.decode("utf-8", errors="replace")


def build_server(
    site_port: int,
    transport: httpx.AsyncBaseTransport | None = None,
    read_text: Callable[[bytes], Awaitable[str]] = ocr_text,
) -> FastMCP:
    server = FastMCP("web", log_level="WARNING")

    async def download(url: str, tool: str) -> httpx.Response:
        safe_url = require_local_url(url, site_port, tool)
        # No redirects and no proxies: either could carry a request out of the lab.
        async with httpx.AsyncClient(
            transport=transport,
            follow_redirects=False,
            trust_env=False,
            timeout=REQUEST_TIMEOUT_SECONDS,
        ) as client:
            response = await client.get(safe_url)
        if response.status_code != 200:
            raise ValueError(f"{tool} got HTTP {response.status_code}")
        return response

    @server.tool()
    async def web_fetch(url: str) -> str:
        """Fetch a web page and return its HTML."""
        return (await download(url, "web_fetch")).text

    @server.tool()
    async def fetch_image(url: str) -> Image:
        """Download an image from a web page."""
        return Image(data=(await download(url, "fetch_image")).content, format="png")

    @server.tool()
    async def read_image_text(url: str) -> str:
        """Read the text shown in an image. Give the full image URL."""
        response = await download(url, "read_image_text")
        return await read_text(response.content)

    return server


def main() -> None:
    build_server(get_settings().attack_site_port).run("stdio")


if __name__ == "__main__":
    main()
