#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${REPO_ROOT}"

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

PYTHON_BIN="${BETTA_PYTHON:-.venv/bin/python}"

if [[ ! -x "${PYTHON_BIN}" ]]; then
  echo "error: python executable not found: ${PYTHON_BIN}" >&2
  exit 1
fi

ARGS=(
  launcher.py scan
  --target "${BETTA_TARGET:-127.0.0.1}"
  --ports "${BETTA_PORTS:-top20}"
  --profile "${BETTA_PROFILE:-x10}"
  --transport "${BETTA_TRANSPORT:-connect}"
  --artifact "${BETTA_ARTIFACT:-artifacts/scanner_model.json}"
  --report "${BETTA_REPORT:-artifacts/snn_model.json}"
  --checkpoint-every "${BETTA_CHECKPOINT_EVERY:-1000}"
)

if [[ "${BETTA_VERIFY_WITH_NMAP:-0}" == "1" ]]; then
  ARGS+=(--verify-with-nmap)
fi

if [[ -n "${BETTA_SPEED_LEVEL:-}" ]]; then
  ARGS+=(--speed-level "${BETTA_SPEED_LEVEL}")
fi

exec "${PYTHON_BIN}" "${ARGS[@]}"
