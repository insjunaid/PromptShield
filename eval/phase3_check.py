"""Phase 3 acceptance through the real API: every attack input, every benign page, real models.

    uv run python -m eval.phase3_check

Pages are sent as `web_fetch` returns them, as text. A07's attack is in its image, so the image is
scanned too. A08's email and A13's file are tool output, so they are scanned as text.
"""

import base64
import json
import statistics
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter

from fastapi.testclient import TestClient

from lab.attack_site.build import PAGES, build_site, render_attack_image
from lab.fixtures.content import ATTACK_FILE_TEXT, _attack_email
from promptshield.api.server import create_app
from promptshield.config import Settings, get_settings
from promptshield.provenance import git_description, machine_description

BASE_URL = "http://127.0.0.1"


def inputs(site: Path, sink_port: int) -> list[tuple[str, dict[str, object]]]:
    cases: list[tuple[str, dict[str, object]]] = []
    for page in PAGES:
        html = (site / page.filename).read_text(encoding="utf-8")
        cases.append(
            (page.id, {"kind": "text", "data": html, "source": f"web_fetch:{page.filename}"})
        )
    image = base64.b64encode(render_attack_image(sink_port)).decode()
    cases.append(
        (
            "A07-image",
            {"kind": "image", "data": image, "data_is_base64": True, "source": "fetch_image"},
        )
    )
    email = _attack_email()
    cases.append(
        (
            "A08-email",
            {"kind": "text", "data": f"{email.subject}\n{email.body}", "source": "read_email"},
        )
    )
    cases.append(("A13-file", {"kind": "text", "data": ATTACK_FILE_TEXT, "source": "read_file"}))
    return sorted(cases)


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    base = get_settings()
    rows: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        build_site(root / "site", base.sink_port)
        settings = Settings(_env_file=None, db_path=root / "check.db")  # type: ignore[call-arg]
        with TestClient(create_app(settings), base_url=BASE_URL) as client:
            for name, item in inputs(root / "site", base.sink_port):
                started = perf_counter()
                body = client.post(
                    "/v1/scan", json={"items": [item], "user_task": "Summarize this for me."}
                ).json()
                seconds = perf_counter() - started
                rules = sorted({finding["rule_id"] for finding in body["findings"]})
                rows.append(
                    {
                        "input": name,
                        "decision": body["decision"],
                        "risk": body["risk_score"],
                        "seconds": round(seconds, 2),
                        "rules": rules,
                        "judge": body["layers_run"].get("L3"),
                    }
                )
                print(
                    f"{name:10} {body['decision']:8} risk {body['risk_score']:.2f} "
                    f"{seconds:5.1f} s  L3 {body['layers_run'].get('L3'):7} {', '.join(rules)}",
                    flush=True,
                )
    times = [float(row["seconds"]) for row in rows]  # type: ignore[arg-type]
    summary = f"per input: p50 {statistics.median(times):.2f} s, max {max(times):.2f} s"
    print(summary)
    stamp = datetime.now(UTC).strftime("%Y%m%d_%H%M")
    path = base.reports_dir / f"phase3_check_{stamp}.json"
    record = {
        "date": stamp,
        "git": git_description(),
        "machine": machine_description(),
        "summary": summary,
        "rows": rows,
    }
    path.write_text(json.dumps(record, indent=2), encoding="utf-8")
    print(path)


if __name__ == "__main__":
    main()
