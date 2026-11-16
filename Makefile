# One-command tasks. Windows uses the .ps1 scripts; everything else uses the .sh scripts.

ifeq ($(OS),Windows_NT)
  RUN_SCRIPT := powershell -NoProfile -ExecutionPolicy Bypass -File
  EXT := ps1
else
  RUN_SCRIPT := bash
  EXT := sh
endif

ifeq ($(OS),Windows_NT)
  CHECK_FLAG := -Check
else
  CHECK_FLAG := --check
endif

.PHONY: help check setup demo demo-check test test-all lint dashboard dashboard-test api-types

help:
	@echo make check     - read-only prerequisite check
	@echo make setup     - install project dependencies
	@echo make demo      - start attack site, sink, API + gateway and dashboard; Ctrl+C stops
	@echo make demo-check - start everything, check every URL answers, stop
	@echo make test      - fast tests, no model downloads
	@echo make test-all  - every test, including slow and e2e
	@echo make lint      - ruff lint and format
	@echo make dashboard - dashboard dev server on 127.0.0.1:5173
	@echo make dashboard-test - dashboard tests, type check and build
	@echo make api-types - regenerate the dashboard's API types

check:
	$(RUN_SCRIPT) scripts/check.$(EXT)

setup:
	$(RUN_SCRIPT) scripts/setup.$(EXT)

demo:
	$(RUN_SCRIPT) scripts/demo.$(EXT)

demo-check:
	$(RUN_SCRIPT) scripts/demo.$(EXT) $(CHECK_FLAG)

test:
	uv run pytest -q -m "not slow and not e2e"

test-all:
	uv run pytest -q

lint:
	uv run ruff check . --fix
	uv run ruff format .

dashboard:
	cd dashboard && pnpm dev

dashboard-test:
	cd dashboard && pnpm test && pnpm build

api-types:
	cd dashboard && pnpm gen:api
