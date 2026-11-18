"""Exports the L1 classifiers to ONNX, once. The shield itself runs them without torch.

    uv sync --group export
    uv run python scripts/export_classifiers.py --model primary

Each model is exported in its own run, so only one is in memory. Prompt Guard 2 is gated: accept
the Llama license on Hugging Face and put HF_TOKEN in .env. The token is never printed. The logic
lives in `promptshield.classifiers`, which `promptshield setup` uses too.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from promptshield.classifiers import export, install_fallback, model_ids  # noqa: E402
from promptshield.config import get_settings  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Export L1 classifiers to ONNX.")
    parser.add_argument("--model", choices=["primary", "fast", "fallback"], required=True)
    parser.add_argument(
        "--download",
        action="store_true",
        help="fallback only: download the published ONNX build instead of exporting",
    )
    args = parser.parse_args()
    settings = get_settings()
    if args.model == "fallback" and args.download:
        install_fallback(settings)
        return
    export(model_ids(settings)[args.model], settings)


if __name__ == "__main__":
    main()
