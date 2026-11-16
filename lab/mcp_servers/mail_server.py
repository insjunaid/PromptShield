"""Mock mailbox. `send_email` only appends to the run's outbox: nothing is ever really sent."""

import json

from mcp.server.fastmcp import FastMCP

from lab.fixtures.content import Email
from lab.fixtures.runs import RunPaths
from lab.mcp_servers.common import paths_from_env


def _load_inbox(paths: RunPaths) -> list[Email]:
    raw = json.loads(paths.inbox.read_text(encoding="utf-8"))
    return [Email.model_validate(item) for item in raw]


def build_server(paths: RunPaths) -> FastMCP:
    server = FastMCP("mail", log_level="WARNING")

    @server.tool()
    def list_emails() -> str:
        """List the emails in the inbox, without their bodies."""
        fields = {"id", "sender", "subject", "date"}
        summaries = [email.model_dump(include=fields) for email in _load_inbox(paths)]
        return json.dumps(summaries, ensure_ascii=False)

    @server.tool()
    def read_email(id: str) -> str:
        """Read one email by its id."""
        for email in _load_inbox(paths):
            if email.id == id:
                return email.model_dump_json()
        raise ValueError(f"no email with id {id}")

    @server.tool()
    def send_email(to: str, subject: str, body: str) -> str:
        """Send an email."""
        outbox = json.loads(paths.outbox.read_text(encoding="utf-8"))
        outbox.append({"to": to, "subject": subject, "body": body})
        paths.outbox.write_text(json.dumps(outbox, ensure_ascii=False, indent=2), encoding="utf-8")
        return f"Email sent to {to}"

    return server


def main() -> None:
    build_server(paths_from_env()).run("stdio")


if __name__ == "__main__":
    main()
