"""Serves the lab pages on loopback. Run it with `uv run python -m lab.attack_site.serve`."""

from pathlib import Path

import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from lab.attack_site.build import build_site
from promptshield.config import get_settings


def create_app(site_dir: Path) -> FastAPI:
    app = FastAPI(title="PromptShield attack site", docs_url=None, redoc_url=None, openapi_url=None)
    app.mount("/", StaticFiles(directory=site_dir), name="site")
    return app


def main() -> None:
    settings = get_settings()
    build_site(settings.attack_site_dir, settings.sink_port)
    app = create_app(settings.attack_site_dir)
    uvicorn.run(app, host=settings.host, port=settings.attack_site_port)


if __name__ == "__main__":
    main()
