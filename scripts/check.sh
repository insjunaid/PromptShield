#!/usr/bin/env bash
# Read-only prerequisite check. Installs nothing and never prints secrets.
# Exit code: 0 when every required item passes, 1 otherwise.
# Overrides: PROMPTSHIELD_ENV_FILE, OLLAMA_URL, PROMPTSHIELD_AGENT_MODEL, PROMPTSHIELD_JUDGE_MODEL.

set -u

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
env_file="${PROMPTSHIELD_ENV_FILE:-$root/.env}"
failed=0

result() { printf '[%-7s] %-20s %s\n' "$1" "$2" "$3"; }
fail() { failed=$((failed + 1)); result MISSING "$1" "$2"; }

env_value() {
  local key="$1" default="$2" value=""
  value="$(printenv "$key" 2>/dev/null || true)"
  if [ -z "$value" ] && [ -f "$env_file" ]; then
    value="$(sed -n "s/^$key=//p" "$env_file" | head -1 | tr -d "\r\"' ")"
  fi
  printf '%s' "${value:-$default}"
}

check_tool() {
  local name="$1" hint="$2"
  if command -v "$name" >/dev/null 2>&1; then
    result OK "$name" "$("$name" --version 2>/dev/null | head -1)"
  else
    fail "$name" "install with: $hint"
  fi
}

# The token goes in over stdin so it never appears in process arguments. Redirects are not
# followed, so it only goes to huggingface.co.
hf_status() {
  printf 'Authorization: Bearer %s\n' "$2" | curl -s -I -m 15 -o /dev/null -w '%{http_code}' -H @- \
    "https://huggingface.co/$1/resolve/main/config.json"
}

echo 'PromptShield prerequisite check (read-only)'
echo
echo 'Tools'
check_tool git 'https://git-scm.com/downloads'
check_tool uv 'https://docs.astral.sh/uv/getting-started/installation/'
check_tool node 'https://nodejs.org (LTS)'
check_tool pnpm 'npm install -g pnpm'
check_tool make 'your package manager (Windows: winget install --id ezwinports.make -e)'

if command -v uv >/dev/null 2>&1; then
  python_path="$(uv python find 3.12 2>/dev/null | head -1)"
  if [ -n "$python_path" ]; then result OK 'python 3.12' "$python_path"
  else fail 'python 3.12' 'install with: uv python install 3.12'; fi
fi

if command -v docker >/dev/null 2>&1; then result OK 'docker (optional)' 'found'
else result INFO 'docker (optional)' 'not found; only needed for the stretch compose file'; fi

echo
echo 'Ollama (HTTP API)'
ollama_url="$(env_value OLLAMA_URL http://localhost:11434)"
agent_model="$(env_value PROMPTSHIELD_AGENT_MODEL qwen3:4b-instruct)"
judge_model="$(env_value PROMPTSHIELD_JUDGE_MODEL qwen3:4b-instruct)"
if version_json="$(curl -s -m 5 "$ollama_url/api/version")" && [ -n "$version_json" ]; then
  result OK 'ollama server' "$ollama_url, $version_json"
  tags="$(curl -s -m 5 "$ollama_url/api/tags")"
  models="$agent_model"
  [ "$judge_model" = "$agent_model" ] || models="$models $judge_model"
  for model in $models; do
    if printf '%s' "$tags" | grep -q "\"name\":\"$model\""; then result OK model "$model"
    else fail model "$model not pulled; POST $ollama_url/api/pull or 'ollama pull $model'"; fi
  done
else
  fail 'ollama server' "not reachable at $ollama_url; start the Ollama app"
fi

echo
echo 'Hugging Face'
token="$(env_value HF_TOKEN '')"
if [ -z "$token" ]; then
  result WARN HF_TOKEN 'not set; export the ungated fallback instead: export_classifiers.py --model fallback'
else
  result OK HF_TOKEN 'set (value not shown)'
  for repo in meta-llama/Llama-Prompt-Guard-2-22M meta-llama/Llama-Prompt-Guard-2-86M; do
    code="$(hf_status "$repo" "$token")"
    if [ "$code" -ge 200 ] 2>/dev/null && [ "$code" -lt 400 ]; then result OK 'gated access' "$repo (HTTP $code)"
    elif [ "$code" = 000 ]; then result WARN 'gated access' "$repo could not be checked (network)"
    else result WARN 'gated access' "$repo denied (HTTP $code); accept the license or check the token"; fi
  done
fi

echo
if [ "$failed" -eq 0 ]; then
  echo 'All required checks passed.'
  exit 0
fi
echo "$failed required item(s) missing. Install them, open a new terminal, and run this again."
exit 1
