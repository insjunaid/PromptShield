"""The `promptshield` command: set up, run, and connect AI apps to the shield.

    promptshield setup                 # classifier (no token needed), config files, checks
    promptshield start                 # the shield + dashboard on http://127.0.0.1:8000
    promptshield bridge                # what an AI app runs (stdio); starts the shield if needed
    promptshield servers add files -- npx -y @modelcontextprotocol/server-filesystem ~/Documents
    promptshield config cursor         # prints the snippet to paste into an app's MCP settings
    promptshield doctor                # what's installed and running

Everything binds to 127.0.0.1. This command never edits an AI app's own configuration: `config`
prints the entry, and you paste it.
"""

import argparse
import json
import os
import subprocess
import sys
import time
from collections.abc import Sequence

import httpx

from promptshield.config import (
    HOME,
    HOME_ENV,
    Settings,
    UpstreamServer,
    get_settings,
    is_source_checkout,
)

PACKAGE = "promptshield-mcp"
START_TIMEOUT_SECONDS = 120.0
ENV_TEMPLATE = """\
# PromptShield settings. Every name is optional; defaults are in promptshield/config.py.
# A free Hugging Face token lets `promptshield setup --prompt-guard` use Prompt Guard 2.
HF_TOKEN=
OLLAMA_URL=http://localhost:11434
PROMPTSHIELD_JUDGE_MODEL=qwen3:4b-instruct
"""


def err(text: str) -> None:
    """Messages go to stderr: in `bridge`, stdout carries the MCP protocol itself."""
    print(text, file=sys.stderr, flush=True)


# Apps


def stdio_entry() -> dict[str, object]:
    return {"command": "uvx", "args": [PACKAGE, "bridge"]}


def client_snippet(client: str) -> str:
    """The exact text to add to each app's MCP configuration."""
    entry = stdio_entry()
    servers = json.dumps({"mcpServers": {"promptshield": entry}}, indent=2)
    match client:
        case "claude-code":
            return f"claude mcp add promptshield -- uvx {PACKAGE} bridge"
        case "claude-desktop":
            return f"# claude_desktop_config.json (Settings > Developer > Edit Config)\n{servers}"
        case "cursor":
            return f"# ~/.cursor/mcp.json (or .cursor/mcp.json in a project)\n{servers}"
        case "windsurf":
            return f"# ~/.codeium/windsurf/mcp_config.json\n{servers}"
        case "gemini":
            return f"# ~/.gemini/settings.json\n{servers}"
        case "antigravity":
            return f"# Antigravity: MCP Servers > Manage MCP Servers > View raw config\n{servers}"
        case "vscode":
            vscode = {"servers": {"promptshield": {"type": "stdio", **entry}}}
            return (
                f"# .vscode/mcp.json (or the user-level mcp.json)\n{json.dumps(vscode, indent=2)}"
            )
        case "codex":
            return (
                "# ~/.codex/config.toml\n"
                "[mcp_servers.promptshield]\n"
                'command = "uvx"\n'
                f'args = ["{PACKAGE}", "bridge"]'
            )
        case "http":
            return (
                "# Apps that connect by URL. Start the shield first: promptshield start\n"
                "http://127.0.0.1:8000/mcp/"
            )
    raise SystemExit(f"unknown app: {client}")


CLIENTS = (
    "claude-code",
    "claude-desktop",
    "cursor",
    "vscode",
    "windsurf",
    "codex",
    "antigravity",
    "gemini",
    "http",
)


# Servers behind the shield


def read_servers(settings: Settings) -> list[UpstreamServer]:
    path = settings.servers_file
    if not path.is_file():
        return []
    return [UpstreamServer.model_validate(item) for item in json.loads(path.read_text("utf-8"))]


def write_servers(settings: Settings, servers: Sequence[UpstreamServer]) -> None:
    path = settings.servers_file
    path.parent.mkdir(parents=True, exist_ok=True)
    data = [server.model_dump() for server in servers]
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def add_server(settings: Settings, name: str, command: Sequence[str]) -> UpstreamServer:
    if not command:
        raise SystemExit("give the server's command after --, e.g. -- npx -y <package>")
    server = UpstreamServer(name=name, command=command[0], args=list(command[1:]))
    servers = [item for item in read_servers(settings) if item.name != name]
    write_servers(settings, [*servers, server])
    return server


def remove_server(settings: Settings, name: str) -> bool:
    servers = read_servers(settings)
    kept = [item for item in servers if item.name != name]
    write_servers(settings, kept)
    return len(kept) != len(servers)


# Running


def api_url(settings: Settings) -> str:
    return f"http://{settings.host}:{settings.api_port}"


def is_running(settings: Settings) -> bool:
    try:
        response = httpx.get(f"{api_url(settings)}/health", timeout=2, trust_env=False)
        return response.status_code == 200
    except httpx.HTTPError:
        return False


def start_in_background(settings: Settings) -> None:
    """For `bridge`: the app starts the bridge, so the shield must come up on its own. Apps stop
    the whole process tree when they close (on Windows the MCP client puts it in a job that can't
    be left), so an auto-started shield lives as long as the app that started it. For several apps
    at once, run `promptshield start` yourself: every bridge then shares that one."""
    logs = settings.db_path.parent / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    log = (logs / "server.log").open("ab")
    # -I: isolated, so a `promptshield` folder in the current directory can't shadow the installed
    # package. HOME is passed on explicitly, since -I also ignores the PYTHON* variables.
    command = [sys.executable, "-I", "-m", "promptshield.cli", "start"]
    env = {**os.environ, HOME_ENV: str(HOME)}
    home = HOME if HOME.is_dir() else None
    if sys.platform == "win32":
        flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
        subprocess.Popen(  # noqa: S603
            command,
            cwd=home,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=log,
            creationflags=flags | subprocess.CREATE_NO_WINDOW,
        )
    else:
        subprocess.Popen(  # noqa: S603
            command,
            cwd=home,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=log,
            start_new_session=True,
        )


def wait_until_running(settings: Settings, timeout: float = START_TIMEOUT_SECONDS) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if is_running(settings):
            return True
        time.sleep(0.5)
    return False


def cmd_start(args: argparse.Namespace) -> None:
    import uvicorn

    from promptshield.api.server import create_app
    from promptshield.api.web import dashboard_built
    from promptshield.classifiers import installed

    settings = get_settings()
    if is_running(settings):
        err(f"PromptShield is already running at {api_url(settings)}")
        return
    if not installed(settings):
        err("No classifier installed yet, so every scan will be blocked. Run: promptshield setup")
    where = (
        f"{api_url(settings)}/"
        if dashboard_built()
        else f"http://127.0.0.1:{settings.dashboard_port}/"
    )
    err(f"PromptShield on {api_url(settings)} (MCP gateway at /mcp/). Dashboard: {where}")
    if args.open:
        import webbrowser

        webbrowser.open(where)
    uvicorn.run(
        create_app(settings), host=settings.host, port=settings.api_port, log_level="warning"
    )


def cmd_bridge(args: argparse.Namespace) -> None:
    import asyncio

    from promptshield.gateway import stdio_bridge

    settings = get_settings()
    if not is_running(settings):
        if args.no_autostart:
            raise SystemExit("PromptShield isn't running. Start it with: promptshield start")
        err(
            "Starting PromptShield for this app (it stops when the app closes; "
            "run `promptshield start` to share one with several apps)..."
        )
        start_in_background(settings)
        if not wait_until_running(settings):
            raise SystemExit(f"PromptShield didn't start. See {settings.db_path.parent / 'logs'}")
    asyncio.run(stdio_bridge.run(f"{api_url(settings)}/mcp/", args.task))


def cmd_setup(args: argparse.Namespace) -> None:
    from promptshield import classifiers

    HOME.mkdir(parents=True, exist_ok=True)
    env_file = HOME / ".env"
    if not env_file.exists() and not is_source_checkout():
        env_file.write_text(ENV_TEMPLATE, encoding="utf-8")
        err(f"wrote {env_file}")
    settings = get_settings()
    if args.prompt_guard:
        if settings.hf_token is None:
            raise SystemExit(
                "Prompt Guard 2 is gated: accept the Llama license on its Hugging Face page, "
                f"then put HF_TOKEN=... in {env_file}"
            )
        try:
            classifiers.export(settings.classifier_model, settings, err)
        except ImportError as error:
            raise SystemExit(
                f'The export needs extra packages: uvx --from "{PACKAGE}[prompt-guard]" '
                "promptshield setup --prompt-guard"
            ) from error
    elif not classifiers.installed(settings):
        classifiers.install_fallback(settings, err)
    else:
        err(f"classifier ready: {classifiers.installed(settings)[0]}")
    check_ollama(settings, pull=args.pull_model)
    err("Setup done. Next: promptshield start, then promptshield config <your app>")


def check_ollama(settings: Settings, pull: bool) -> bool:
    """The judge is optional: without Ollama the fast layers still run."""
    try:
        tags = httpx.get(f"{settings.ollama_url}/api/tags", timeout=3, trust_env=False).json()
    except httpx.HTTPError:
        err(
            "Ollama isn't running: the LLM judge (L3) will be skipped. Get it at https://ollama.com"
        )
        return False
    names = {model["name"] for model in tags.get("models", [])}
    if settings.judge_model in names:
        err(f"Ollama ready with {settings.judge_model}")
        return True
    if not pull:
        err(
            f"Ollama is up, but {settings.judge_model} isn't pulled. "
            "Run: promptshield setup --pull-model"
        )
        return False
    err(f"pulling {settings.judge_model} (about 2.5 GB)...")
    with httpx.stream(
        "POST",
        f"{settings.ollama_url}/api/pull",
        json={"model": settings.judge_model},
        timeout=None,
        trust_env=False,
    ) as response:
        for line in response.iter_lines():
            status = json.loads(line).get("status", "") if line else ""
            if status and "pulling" not in status:
                err(status)
    return True


def cmd_doctor(_: argparse.Namespace) -> None:
    from promptshield.api.web import dashboard_built
    from promptshield.classifiers import installed

    settings = get_settings()
    found = installed(settings)
    rows = [
        ("home", str(HOME)),
        ("classifier", found[0] if found else "missing: run promptshield setup"),
        ("dashboard", "built in" if dashboard_built() else "dev server (cd dashboard && pnpm dev)"),
        (
            "servers behind the shield",
            ", ".join(s.name for s in settings.gateway_upstreams) or "none",
        ),
        ("running", f"yes, {api_url(settings)}" if is_running(settings) else "no"),
    ]
    for name, value in rows:
        print(f"{name:26} {value}")
    check_ollama(settings, pull=False)


def cmd_servers(args: argparse.Namespace) -> None:
    settings = get_settings()
    if args.action == "add":
        server = add_server(settings, args.name, args.server_command)
        print(f"added {server.name}: {server.command} {' '.join(server.args)}")
        print("Remove it from your AI app's own MCP config, so the app can't go around the shield.")
    elif args.action == "remove":
        print("removed" if remove_server(settings, args.name) else f"no server named {args.name}")
    else:
        servers = read_servers(settings)
        for server in servers:
            print(f"{server.name:16} {server.command} {' '.join(server.args)}")
        if not servers:
            print("No servers yet. Add one: promptshield servers add NAME -- COMMAND ARGS...")
    if args.action != "list":
        print("Restart the shield to apply: stop it, then promptshield start (or reopen your app).")


def cmd_config(args: argparse.Namespace) -> None:
    print(client_snippet(args.client))


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="promptshield", description=__doc__.splitlines()[0])
    sub = root.add_subparsers(dest="command", required=True)

    start = sub.add_parser("start", help="run the shield and its dashboard")
    start.add_argument("--open", action="store_true", help="open the dashboard in a browser")
    start.set_defaults(run=cmd_start)

    bridge = sub.add_parser("bridge", help="stdio MCP server for AI apps (starts the shield)")
    bridge.add_argument("--task", help="the user's task, so the judge can check for deviation")
    bridge.add_argument("--no-autostart", action="store_true")
    bridge.set_defaults(run=cmd_bridge)

    setup = sub.add_parser("setup", help="install a classifier and check Ollama")
    setup.add_argument("--prompt-guard", action="store_true", help="export Prompt Guard 2 (token)")
    setup.add_argument("--pull-model", action="store_true", help="pull the judge model in Ollama")
    setup.set_defaults(run=cmd_setup)

    doctor = sub.add_parser("doctor", help="show what's installed and running")
    doctor.set_defaults(run=cmd_doctor)

    servers = sub.add_parser("servers", help="the MCP servers the shield stands in front of")
    actions = servers.add_subparsers(dest="action", required=True)
    actions.add_parser("list")
    add = actions.add_parser("add")
    add.add_argument("name", help="lowercase, used in policy keys: <name>.<tool>")
    add.add_argument(
        "server_command", nargs=argparse.REMAINDER, help="-- then the server's command"
    )
    remove = actions.add_parser("remove")
    remove.add_argument("name")
    servers.set_defaults(run=cmd_servers)

    config = sub.add_parser("config", help="print the MCP config entry for an app")
    config.add_argument("client", choices=CLIENTS)
    config.set_defaults(run=cmd_config)
    return root


def main(argv: Sequence[str] | None = None) -> None:
    args = parser().parse_args(argv)
    if args.command == "servers" and args.action == "add" and args.server_command[:1] == ["--"]:
        args.server_command = args.server_command[1:]
    args.run(args)


if __name__ == "__main__":
    main()
