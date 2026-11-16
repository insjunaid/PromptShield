#!/usr/bin/env bash
# Project-level setup only: installs Python and dashboard dependencies.
# Never installs system software and never pulls models.

set -eu

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! bash "$root/scripts/check.sh"; then
  echo 'Setup stopped: fix the missing items above first.'
  exit 1
fi

if [ -f "$root/pyproject.toml" ]; then
  echo 'Installing Python dependencies...'
  (cd "$root" && uv sync)
else
  echo 'Skipping uv sync: no pyproject.toml yet.'
fi

if [ -f "$root/dashboard/package.json" ]; then
  echo 'Installing dashboard dependencies...'
  (cd "$root/dashboard" && pnpm install)
else
  echo 'Skipping pnpm install: no dashboard yet.'
fi

echo 'Setup complete.'
