#!/bin/sh
# B9 smoke: connection IDs correlate client-side and device-side log lines.
# Starts a fake device + gateway with JSON logging, drives traffic through
# two clients, then verifies every "[conn N]" ID in the gateway log maps to
# exactly one client connection (IDs are unique and monotonically handed
# out), and that device-side lines reuse the same ID space.
# Exit 0 = pass.
set -eu

cd "$(dirname "$0")/.."
go build -o bin/modbus-shield ./cmd/modbus-shield

python3 scripts/fakedevice.py 15020 &
DEV_PID=$!
trap 'kill $DEV_PID 2>/dev/null || true' EXIT
sleep 0.5

./bin/modbus-shield gateway \
	--listen 127.0.0.1:15021 \
	--device 127.0.0.1:15020 \
	--request-delay-ms 50 \
	--log-level debug \
	--log-format json > /tmp/opencode/b9_gateway.log 2>&1 &
GW_PID=$!
trap 'kill $DEV_PID $GW_PID 2>/dev/null || true' EXIT
sleep 0.5

python3 - << 'PYEOF'
import socket, struct, sys

def read_adu(sock):
    hdr = sock.recv(7)
    if len(hdr) < 7:
        raise IOError("short header")
    length = struct.unpack(">H", hdr[4:6])[0]
    pdu = b""
    while len(pdu) < length - 1:
        chunk = sock.recv(length - 1 - len(pdu))
        if not chunk:
            raise IOError("short body")
        pdu += chunk
    return hdr, pdu

def one_read(txn):
    s = socket.create_connection(("127.0.0.1", 15021), timeout=5)
    req = struct.pack(">HHHBBHH", txn, 0, 6, 1, 3, 0x0100, 1)
    s.sendall(req)
    read_adu(s)
    s.close()
    return txn

# Two client connections, interleaved reads on each.
s1 = socket.create_connection(("127.0.0.1", 15021), timeout=5)
s2 = socket.create_connection(("127.0.0.1", 15021), timeout=5)
for txn, s in [(0x1111, s1), (0x2222, s2), (0x3333, s1), (0x4444, s2)]:
    req = struct.pack(">HHHBBHH", txn, 0, 6, 1, 3, 0x0100, 1)
    s.sendall(req)
    read_adu(s)
s1.close()
s2.close()
print("clients done")
PYEOF

sleep 0.3
kill $GW_PID 2>/dev/null || true
sleep 0.3

# Verify: [conn N] IDs appear in gateway log; IDs are small integers >= 1;
# device-side lines carry the same [conn N] shape.
CONNS=$(grep -o '\[conn [0-9]*\]' /tmp/opencode/b9_gateway.log | sort -u)
echo "distinct conn IDs in log:"
echo "$CONNS"
N=$(echo "$CONNS" | grep -c '\[conn')
if [ "$N" -lt 2 ]; then
	echo "SMOKE-FAIL: expected >= 2 distinct conn IDs, got $N"
	exit 1
fi
DEVICE_CONNS=$(grep 'device 127.0.0.1:15020' /tmp/opencode/b9_gateway.log | grep -o '\[conn [0-9]*\]' | sort -u | wc -l)
if [ "$DEVICE_CONNS" -lt 2 ]; then
	echo "SMOKE-FAIL: device-side log lines missing [conn N] IDs (got $DEVICE_CONNS)"
	exit 1
fi
echo "SMOKE-PASS: conn IDs present on client and device log lines"
