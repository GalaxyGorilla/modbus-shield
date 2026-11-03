#!/bin/sh
# scripts/interop-pymodbus.sh — drive the gateway with an independent Python
# Modbus stack on BOTH legs:
#
#   pymodbus client --> modbus-shield gateway --> pymodbus device
#
# This complements interop-modbus.sh (mbpoll as the client against our fake
# device): here neither end is this project's code. It covers FC3/FC4 reads,
# FC6 write/read-back, unit-ID addressing, exception pass-through and
# concurrent client fan-in.
#
# Requires `make peers` (creates .venv with pymodbus). Exit 77 when the venv
# is missing, unless INTEROP_REQUIRED=1, where it is a failure.
set -e
cd "$(dirname "$0")/.."

PATH="$PATH:/usr/local/go/bin"

PY=./.venv/bin/python
if [ ! -x "$PY" ]; then
  echo "pymodbus venv missing; run 'make peers'"
  [ "${INTEROP_REQUIRED:-0}" = "1" ] && exit 1
  exit 77
fi

BIN=./bin/modbus-shield
go build -o "$BIN" ./cmd/modbus-shield

free_port() {
  python3 - <<EOF
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
EOF
}

wait_port() {
  python3 - "$1" <<'EOF'
import socket, sys, time
port = int(sys.argv[1])
for _ in range(100):
    try:
        s = socket.create_connection(("127.0.0.1", port), 0.1)
        s.close()
        sys.exit(0)
    except OSError:
        time.sleep(0.05)
sys.exit(1)
EOF
}

DEV_PORT=$(free_port)
GW_PORT=$(free_port)
while [ "$GW_PORT" = "$DEV_PORT" ]; do GW_PORT=$(free_port); done

"$PY" scripts/pymodbus_device.py --port "$DEV_PORT" &
DEV_PID=$!
GW_PID=""
cleanup() {
  [ -n "$GW_PID" ] && kill "$GW_PID" 2>/dev/null || true
  kill "$DEV_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

wait_port "$DEV_PORT" || { echo "FAIL: pymodbus device did not start"; exit 1; }

"$BIN" gateway --listen "127.0.0.1:$GW_PORT" --device "127.0.0.1:$DEV_PORT" \
  --log-level error &
GW_PID=$!
wait_port "$GW_PORT" || { echo "FAIL: gateway did not start"; exit 1; }

"$PY" scripts/interop_pymodbus.py --port "$GW_PORT"
