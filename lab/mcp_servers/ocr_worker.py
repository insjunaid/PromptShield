"""Reads image bytes from stdin and writes the text it finds to stdout.

OCR runs in its own short-lived process for two reasons. Loading the OCR libraries inside a stdio
MCP server hung every time on Windows, and a separate process gives the memory back on exit.
"""

import sys

from rapidocr_onnxruntime import RapidOCR  # type: ignore[import-untyped]


def main() -> None:
    lines, _ = RapidOCR()(sys.stdin.buffer.read())
    text = " ".join(line[1] for line in lines or [])
    sys.stdout.buffer.write(text.encode("utf-8"))


if __name__ == "__main__":
    main()
