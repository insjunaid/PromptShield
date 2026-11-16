"""OCR worker: loads RapidOCR once, then reads images from stdin until stdin closes.

Protocol, one request at a time: 4-byte big-endian length, then the image bytes. Each reply is one
line of JSON, `{"text": ...}` or `{"error": "<exception type>"}`. When the parent exits, stdin
closes and this process ends with it.
"""

import json
import sys
from typing import Any

HEADER_BYTES = 4


def _read_exactly(stream: Any, size: int) -> bytes:
    chunks: list[bytes] = []
    while size:
        chunk = stream.read(size)
        if not chunk:
            break
        chunks.append(chunk)
        size -= len(chunk)
    return b"".join(chunks)


def main() -> None:
    stdin, stdout = sys.stdin.buffer, sys.stdout.buffer
    engine: Any = None
    while len(header := _read_exactly(stdin, HEADER_BYTES)) == HEADER_BYTES:
        image = _read_exactly(stdin, int.from_bytes(header, "big"))
        try:
            if engine is None:
                # Loaded only after the first request has been read in full (see D040).
                from rapidocr_onnxruntime import RapidOCR  # type: ignore[import-untyped]

                engine = RapidOCR()
            lines, _ = engine(image)
            reply: dict[str, str] = {"text": " ".join(line[1] for line in lines or [])}
        except Exception as error:
            reply = {"error": type(error).__name__}
        stdout.write(json.dumps(reply, ensure_ascii=False).encode("utf-8") + b"\n")
        stdout.flush()


if __name__ == "__main__":
    main()
