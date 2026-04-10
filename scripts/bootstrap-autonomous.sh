#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${REPO_ROOT}"

if ! command -v python3 >/dev/null 2>&1; then
  echo "error: python3 is not installed" >&2
  exit 1
fi

python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/pip install -e .
.venv/bin/pip install pyright

if [[ ! -f .env ]]; then
  cp .env.example .env
fi

echo "[betta-morpho] autonomous environment bootstrapped"
echo "[betta-morpho] edit .env if you want different default targets or modes"
