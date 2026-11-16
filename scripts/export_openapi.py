"""Write the API's OpenAPI schema, for generating the dashboard's types. No server needed.

uv run python scripts/export_openapi.py dashboard/openapi.json
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from promptshield.api.server import create_app  # noqa: E402
from promptshield.config import Settings  # noqa: E402


def main() -> None:
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("dashboard/openapi.json")
    schema = create_app(Settings(_env_file=None)).openapi()  # type: ignore[call-arg]
    target.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(target)


if __name__ == "__main__":
    main()
