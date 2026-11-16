#!/usr/bin/env bash
# Starts the whole demo with one command: attack site, attacker sink, API + MCP gateway, dashboard.
#
#   bash scripts/demo.sh           # start, print URLs, Ctrl+C stops everything
#   bash scripts/demo.sh --check   # start, check every URL answers, stop (exit 0/1)
#
# The mock MCP servers (files, mail, http, web) aren't long-running: every lab run starts its own.
# Everything binds to 127.0.0.1. Services already running on their port are reused and left alone.
# Logs: data/logs/demo_<stamp>/ (git-ignored).
set -euo pipefail

check=0
[ "${1:-}" = "--check" ] && check=1
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
logs="$root/data/logs/demo_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$logs"

names=("Attack site" "Attacker sink" "API + MCP gateway" "Dashboard")
ports=(8081 9999 8000 5173)
urls=(
  "http://127.0.0.1:8081/b01_article.html"
  "http://127.0.0.1:9999/captured"
  "http://127.0.0.1:8000/health"
  "http://127.0.0.1:5173/"
)
commands=(
  "uv run python -m lab.attack_site.serve"
  "uv run python -m lab.attacker_sink.server"
  "uv run python -m promptshield.api.server"
  "pnpm --dir dashboard dev"
)

is_up() { curl -fsS --max-time 3 -o /dev/null "$1" 2>/dev/null; }
port_busy() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }

pids=()
stop_started() {
  for pid in "${pids[@]:-}"; do
    [ -n "$pid" ] || continue
    # The whole process group: uv starts python, pnpm starts node.
    kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
  done
}
trap 'echo "Stopping the services this script started..."; stop_started' EXIT
trap 'exit 130' INT TERM

for tool in uv pnpm curl; do
  command -v "$tool" >/dev/null || { echo "Missing $tool. Run: bash scripts/check.sh" >&2; exit 1; }
done
if [ ! -d .venv ] || [ ! -d dashboard/node_modules ]; then
  echo "Dependencies are not installed. Run: make setup (or bash scripts/setup.sh)" >&2
  exit 1
fi
ollama="${OLLAMA_URL:-http://localhost:11434}"
ollama_up=1
is_up "$ollama/api/version" || {
  ollama_up=0
  echo "Ollama isn't reachable at $ollama. The dashboard works, but lab runs need it."
}

set -m  # each background job gets its own process group, so stopping it takes its children
for i in "${!names[@]}"; do
  if is_up "${urls[$i]}"; then
    printf '%-18s already running, reusing it\n' "${names[$i]}"
    continue
  fi
  if port_busy "${ports[$i]}"; then
    echo "Port ${ports[$i]} is taken by something that isn't the ${names[$i]}. Stop it, then try again." >&2
    exit 1
  fi
  slug="$(echo "${names[$i]}" | tr -cs 'A-Za-z' '_' | tr 'A-Z' 'a-z')"
  ${commands[$i]} >"$logs/$slug.log" 2>&1 &
  pids+=("$!")
  printf '%-18s starting (pid %s)\n' "${names[$i]}" "$!"
done
set +m

# The API loads the classifier at startup, so it gets the longest wait.
deadline=$(( $(date +%s) + 180 ))
for i in "${!names[@]}"; do
  until is_up "${urls[$i]}"; do
    if [ "$(date +%s)" -gt "$deadline" ]; then
      echo "${names[$i]} didn't answer at ${urls[$i]}. Logs: $logs" >&2
      exit 1
    fi
    sleep 0.5
  done
  printf '%-18s ready   %s\n' "${names[$i]}" "${urls[$i]}"
done

cat <<EOF

PromptShield demo is running (localhost only):
  Dashboard        http://127.0.0.1:5173/
  Red-Team Lab     http://127.0.0.1:5173/lab   (pick A02, then "Run comparison")
  API docs         http://127.0.0.1:8000/docs
  MCP gateway      http://127.0.0.1:8000/mcp/
  Attack page A02  http://127.0.0.1:8081/a02_article.html   (white-on-white instruction)
  Attacker sink    http://127.0.0.1:9999/captured
  Logs             $logs
EOF
[ "$ollama_up" = 1 ] || echo "  Note: start Ollama before running lab scenarios."

if [ "$check" = 1 ]; then
  # The browser reaches the API through the dashboard's proxy, so check that link too.
  for url in "http://127.0.0.1:5173/v1/stats?window=1h" "http://127.0.0.1:8000/docs" "http://127.0.0.1:8081/a02_article.html"; do
    is_up "$url" || { echo "No answer from $url. Logs: $logs" >&2; exit 1; }
  done
  echo "Check passed: every service answered, and the dashboard reaches the API."
  exit 0
fi
echo "Press Ctrl+C to stop everything this script started."
while true; do
  for pid in "${pids[@]:-}"; do
    [ -n "$pid" ] || continue
    kill -0 "$pid" 2>/dev/null || { echo "A service stopped (pid $pid). Logs: $logs" >&2; exit 1; }
  done
  sleep 2
done
