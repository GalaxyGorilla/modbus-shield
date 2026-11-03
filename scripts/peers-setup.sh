#!/bin/sh
# scripts/peers-setup.sh — provision the independent Python Modbus stack.
#
# Creates .venv and installs pymodbus. Idempotent. Exit 77 when Python or pip
# is unavailable (the optional interop target skips); `make acceptance` runs
# the interop with INTEROP_REQUIRED=1, where a missing peer is a failure.
set -e
cd "$(dirname "$0")/.."

PY="${PYTHON:-python3}"
command -v "$PY" >/dev/null 2>&1 || {
  echo "python3 not found; cannot provision the pymodbus peer (exit 77)"
  exit 77
}

if [ ! -x .venv/bin/python ]; then
  "$PY" -m venv .venv || exit 77
fi

.venv/bin/pip install --quiet --upgrade pip || exit 77
.venv/bin/pip install --quiet "pymodbus==3.16.2" || {
  echo "pip install pymodbus==3.16.2 failed (exit 77)"
  exit 77
}
.venv/bin/python -c 'import pymodbus; print("pymodbus", pymodbus.__version__)'
