#!/usr/bin/env bash
# AESOP installer — sets up the `aesop` command in an isolated environment.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

echo "  /\\_/\\     Installing AESOP"
echo " ( o.o )    the cryptanalyst's book of fables"
echo "  > ^ <"
echo

PY="${PYTHON:-python3}"
if ! command -v "$PY" >/dev/null 2>&1; then
  echo "error: python3 not found. Install Python 3.9+ first." >&2
  exit 1
fi

MODE="${1:-full}"   # full | core
EXTRA=""
[ "$MODE" = "full" ] && EXTRA="[full]"

echo "Creating virtual environment in .venv ..."
"$PY" -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate

echo "Installing AESOP${EXTRA} ..."
pip install --upgrade pip >/dev/null
pip install -e ".${EXTRA}"

echo
echo "Done. Activate with:  source \"$HERE/.venv/bin/activate\""
echo "Then try:             aesop version   |   aesop list   |   aesop manual"
