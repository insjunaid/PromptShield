"""Reads text from images through one long-lived worker process.

Why a separate process: loading the OCR libraries inside a stdio server hung on Windows (D040), and
the gateway will be one. Why long-lived: loading the model per image costs seconds and breaks the
"load once" rule. The worker stops after a quiet spell, so its memory comes back when idle.
"""

import asyncio
import io
import json
import subprocess
import sys
from collections.abc import Sequence
from importlib.util import find_spec

import psutil
import structlog
from PIL import Image

from promptshield.config import REPO_ROOT, Settings

logger = structlog.get_logger(__name__)

WORKER_COMMAND = (sys.executable, "-m", "promptshield.ocr_worker")
OCR_PACKAGE = "rapidocr_onnxruntime"
HEADER_BYTES = 4


class UnreadableImage(Exception):
    """The image was refused before OCR, for a reason safe to show."""


class OcrFailed(Exception):
    """OCR itself failed. The caller must treat the image as unscanned."""


def ocr_installed() -> bool:
    return find_spec(OCR_PACKAGE) is not None


def _kill_tree(pid: int) -> None:
    try:
        children = psutil.Process(pid).children(recursive=True)
    except psutil.NoSuchProcess:
        return
    for child in children:
        try:
            child.kill()
        except psutil.NoSuchProcess:
            pass
    psutil.wait_procs(children, timeout=5)


class OcrEngine:
    def __init__(self, settings: Settings, command: Sequence[str] = WORKER_COMMAND) -> None:
        self._command = list(command)
        self._timeout = settings.ocr_timeout_seconds
        self._idle_seconds = settings.ocr_idle_seconds
        self._max_bytes = settings.ocr_max_image_bytes
        self._max_pixels = settings.ocr_max_pixels
        self._process: subprocess.Popen[bytes] | None = None
        self._lock: asyncio.Lock | None = None
        self._idle_timer: asyncio.TimerHandle | None = None

    @property
    def running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    async def read(self, image: bytes) -> str:
        """The text in the image. One image at a time, since the worker handles one."""
        self._check(image)
        if self._lock is None:
            self._lock = asyncio.Lock()
        async with self._lock:
            self._cancel_idle_timer()
            try:
                return await asyncio.wait_for(
                    asyncio.to_thread(self._exchange, image), timeout=self._timeout
                )
            except TimeoutError as error:
                self.stop()  # Unblocks the thread, which is still waiting on the pipe.
                raise OcrFailed("timeout") from error
            except OcrFailed:
                self.stop()
                raise
            finally:
                self._start_idle_timer()

    def stop(self) -> None:
        """Kills the whole tree. On Windows a venv's python.exe is a launcher that runs the real
        interpreter as a child, so killing only the launcher would leave the model loaded."""
        process, self._process = self._process, None
        if process is None:
            return
        _kill_tree(process.pid)
        process.kill()
        process.wait()
        for pipe in (process.stdin, process.stdout):
            if pipe is not None:
                pipe.close()

    def _check(self, image: bytes) -> None:
        """Header-only checks, so a decompression bomb is refused before anything decodes it."""
        if len(image) > self._max_bytes:
            raise UnreadableImage("image is too large to read")
        try:
            with Image.open(io.BytesIO(image)) as opened:
                width, height = opened.size
        except Exception as error:
            raise UnreadableImage("not a readable image") from error
        if width * height > self._max_pixels:
            raise UnreadableImage("image has too many pixels to read")

    def _exchange(self, image: bytes) -> str:
        process = self._ensure_process()
        if process.stdin is None or process.stdout is None:
            raise OcrFailed("no pipes")
        try:
            process.stdin.write(len(image).to_bytes(HEADER_BYTES, "big") + image)
            process.stdin.flush()
            line = process.stdout.readline()
        except (OSError, ValueError) as error:
            raise OcrFailed("worker pipe closed") from error
        if not line:
            raise OcrFailed("worker exited")
        reply = json.loads(line)
        if "error" in reply:
            raise OcrFailed(str(reply["error"]))
        return str(reply["text"])

    def _ensure_process(self) -> subprocess.Popen[bytes]:
        if self._process is None or self._process.poll() is not None:
            logger.info("ocr_worker_starting")
            self._process = subprocess.Popen(
                self._command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                cwd=REPO_ROOT,
            )
        return self._process

    def _start_idle_timer(self) -> None:
        loop = asyncio.get_running_loop()
        self._idle_timer = loop.call_later(self._idle_seconds, self._stop_if_idle)

    def _cancel_idle_timer(self) -> None:
        if self._idle_timer is not None:
            self._idle_timer.cancel()
            self._idle_timer = None

    def _stop_if_idle(self) -> None:
        if self._lock is None or not self._lock.locked():
            logger.info("ocr_worker_idle_stop")
            self.stop()
