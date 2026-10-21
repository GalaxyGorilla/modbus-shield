#!/bin/sh
# scripts/interop-modbus.sh — real-client interop test: drive the gateway
# with mbpoll (epsilonrt/mbpoll, libmodbus-based Modbus master) instead of
# in-Go test clients. Requires mbpoll on PATH (or MBPOLL_BIN set) and a
# libmodbus it can load.
#
# Chain: mbpoll --> modbus-shield gateway --> python3 fake device
#
# Covers: FC3 read, FC4 read, FC6 write, unit-ID addressing, exception
# pass-through, multi-client multiplexing (concurrent mbpolls), and a
# chain-alive check after the burst.
#
# Exit 0 = all green. Skips (rc 77) when mbpoll is missing.
set -e
cd "$(dirname "$0")/.."

PATH="$PATH:/usr/local/go/bin"

MBPOLL_BIN="${MBPOLL_BIN:-mbpoll}"
command -v "$MBPOLL_BIN" >/dev/null 2>&1 || { echo "== mbpoll not found (apt: epsilonrt/mbpoll releases); SKIP"; exit 77; }

BIN=./bin/modbus-shield
go build -o "$BIN" ./cmd/modbus-shield

free_port() {
  python3 - <<EOF
import socket
s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("127.0.0.1",0))
print(s.getsockname()[1])
s.close()
EOF
}

DEV_PORT=$(free_port)
GW_PORT=$(free_port)

python3 scripts/fakedevice.py "$DEV_PORT" &
FAKE_PID=$!
trap 'kill $FAKE_PID $GW_PID 2>/dev/null || true' EXIT INT TERM

"$BIN" gateway --listen "127.0.0.1:$GW_PORT" --device "127.0.0.1:$DEV_PORT" \
  --log-level error &
GW_PID=$!
sleep 0.5

fail=0
D="127.0.0.1"
P="$GW_PORT"
OPTS="-1 -m tcp -a 1 -o 2"

echo "== mbpoll FC3 read holding register (ref 257 == 0x0100)"
out=$($MBPOLL_BIN $OPTS -r 257 -c 1 -t 4:hex -p "$P" "$D" 2>&1) || { echo "FAIL: $out"; fail=1; }
echo "$out" | grep -q "0xCAFE" || { echo "FAIL: unexpected value: $out"; fail=1; }

echo "== mbpoll FC4 read input register (same register on fake device)"
out=$($MBPOLL_BIN $OPTS -r 257 -c 1 -t 3:hex -p "$P" "$D" 2>&1) || { echo "FAIL: $out"; fail=1; }
echo "$out" | grep -q "0xCAFE" || { echo "FAIL: unexpected value: $out"; fail=1; }

echo "== mbpoll FC6 write single register"
out=$($MBPOLL_BIN $OPTS -r 257 -t 4 -p "$P" "$D" 42 2>&1) || { echo "FAIL: $out"; fail=1; }
echo "$out" | grep -q "Written 1 references" || { echo "FAIL: write failed: $out"; fail=1; }

echo "== mbpoll exception pass-through (missing register -> Illegal data address)"
out=$($MBPOLL_BIN $OPTS -r 1 -c 1 -t 4:hex -p "$P" "$D" 2>&1) && { echo "FAIL: expected failure: $out"; fail=1; } || true
echo "$out" | grep -q "Illegal data address" || { echo "FAIL: expected exception: $out"; fail=1; }

echo "== mbpoll unit-ID addressing (unit 17, fake device answers any unit)"
out=$($MBPOLL_BIN $OPTS -a 17 -r 257 -c 1 -t 4:hex -p "$P" "$D" 2>&1) || { echo "FAIL: $out"; fail=1; }
echo "$out" | grep -q "0xCAFE" || { echo "FAIL: unexpected value: $out"; fail=1; }

echo "== multi-client multiplexing: 8 concurrent mbpolls"
pids=""
i=0
while [ $i -lt 8 ]; do
  $MBPOLL_BIN $OPTS -r 257 -c 1 -t 4:hex -p "$P" "$D" >/dev/null 2>&1 &
  pids="$pids $!"
  i=$((i+1))
done
rc=0
for pid in $pids; do wait "$pid" || rc=1; done
[ "$rc" = 0 ] || { echo "FAIL: a concurrent mbpoll failed"; fail=1; }

echo "== chain alive after burst"
out=$($MBPOLL_BIN $OPTS -r 257 -c 1 -t 4:hex -p "$P" "$D" 2>&1) || { echo "FAIL: chain dead: $out"; fail=1; }
echo "$out" | grep -q "0xCAFE" || { echo "FAIL: chain broken: $out"; fail=1; }

if [ "$fail" = 0 ]; then
  echo "== interop: PASS"
  exit 0
else
  echo "== interop: FAIL" >&2
  exit 1
fi
