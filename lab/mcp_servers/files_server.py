"""Mock file tools, confined to the run's sandbox."""

from pathlib import Path

from mcp.server.fastmcp import FastMCP

from lab.fixtures.runs import RunPaths
from lab.mcp_servers.common import paths_from_env


def resolve_in_sandbox(sandbox: Path, name: str) -> Path:
    """Return a path inside the sandbox, or refuse.

    Resolving first means `..` and symlinks can't escape. A colon is refused because on Windows it
    selects a drive or a hidden alternate data stream.
    """
    root = sandbox.resolve()
    target = (root / name).resolve()
    if not name.strip() or ":" in name or target == root or not target.is_relative_to(root):
        raise ValueError(f"path is outside the sandbox: {name}")
    return target


def build_server(paths: RunPaths) -> FastMCP:
    server = FastMCP("files", log_level="WARNING")
    sandbox = paths.sandbox

    @server.tool()
    def list_files() -> str:
        """List the files in the workspace."""
        root = sandbox.resolve()
        names = [path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()]
        return "\n".join(sorted(names))

    @server.tool()
    def read_file(path: str) -> str:
        """Read a file from the workspace."""
        target = resolve_in_sandbox(sandbox, path)
        if not target.is_file():
            raise ValueError(f"no file named {path}")
        return target.read_text(encoding="utf-8")

    @server.tool()
    def write_file(path: str, content: str) -> str:
        """Write a file in the workspace."""
        target = resolve_in_sandbox(sandbox, path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return f"Wrote {path}"

    @server.tool()
    def delete_file(path: str) -> str:
        """Delete a file from the workspace."""
        target = resolve_in_sandbox(sandbox, path)
        if not target.is_file():
            raise ValueError(f"no file named {path}")
        target.unlink()
        return f"Deleted {path}"

    return server


def main() -> None:
    build_server(paths_from_env()).run("stdio")


if __name__ == "__main__":
    main()
