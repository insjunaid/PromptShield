"""Logging setup.

Logs go to stderr because a stdio MCP gateway uses stdout for the protocol itself.
"""

import logging
import sys
from typing import Literal

import structlog


def configure_logging(log_format: Literal["dev", "json"]) -> None:
    """Use pretty logs in development and JSON lines in production."""
    renderer: structlog.typing.Processor = (
        structlog.processors.JSONRenderer()
        if log_format == "json"
        else structlog.dev.ConsoleRenderer()
    )
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=False,
    )
