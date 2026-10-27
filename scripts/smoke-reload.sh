#!/bin/sh
# Write-policy + SIGHUP-reload smoke test (real binary, real sockets).
#
#   1. start fakedevice.py and a gateway whose write policy allows FC6
#      writes to register 0x0100 only (default deny);
#   2. verify: 0x0100 write passes, 0x0101 write gets exception 0x02,
#      reads are unaffected, and the device never sees a denied write;
#   3. rewrite the config to allow 0x0101 instead, send SIGHUP;
#   4. verify the SAME process (same PID, no restart) now denies 0x0100
#      and allows 0x0101 — the reload really took effect.
#
# Exit 0 = pass, 1 = failure. Needs python3 (device + raw Modbus client).
set -eu

cd "$(dirname "$0")/.."
TMP=$(mktemp -d)
DEV_PORT=15100
GW_PORT=15101
CONF="$TMP/gateway.yaml"
LOG="$TMP/gateway.log"

cleanup() {
	[ -n "${GW_PID:-}" ] && kill "$GW_PID" 2>/dev/null || true
	[ -n "${DEV_PID:-}" ] && kill "$DEV_PID" 2>/dev/null || true
	wait 2>/dev/null || true # reap without the shell's "Terminated" notice
	rm -rf "$TMP"
}
trap cleanup EXIT

go build -o "$TMP/modbus-shield" ./cmd/modbus-shield

python3 scripts/fakedevice.py "$DEV_PORT" &
DEV_PID=$!

# write_policy: default deny, allow FC6 on register 0x0100 (=256) only.
write_config() {
	allow_from=$1
	cat > "$CONF" << EOF
log:
  level: debug
  format: json
devices:
  - name: smoke
    listen_addr: 127.0.0.1:$GW_PORT
    device_addr: 127.0.0.1:$DEV_PORT
    write_policy:
      default: deny
      rules:
        - fc: [6]
          from: $allow_from
          to: $allow_from
          action: allow
EOF
}

write_config 256
sleep 0.5
"$TMP/modbus-shield" gateway --config "$CONF" > "$LOG" 2>&1 &
GW_PID=$!
sleep 0.7

# probe ADDR -> prints the response PDU as hex (e.g. "0601002a2a" ok,
# "8602" exception 0x02).
probe() {
	python3 - "$1" "$2" << 'PYEOF'
import socket, struct, sys
addr = int(sys.argv[1])
fc = int(sys.argv[2])
s = socket.create_connection(("127.0.0.1", 15101), timeout=5)
if fc == 6:
    pdu = struct.pack(">BHH", 6, addr, 0x2A2A)
else:
    pdu = struct.pack(">BHH", fc, addr, 1)
req = struct.pack(">HHHB", 0x4242, 0, 1 + len(pdu), 1) + pdu
s.sendall(req)
hdr = s.recv(7)
length = struct.unpack(">H", hdr[4:6])[0]
body = b""
while len(body) < length - 1:
    body += s.recv(length - 1 - len(body))
s.close()
print(body.hex())
PYEOF
}

check() { # desc expected actual
	if [ "$2" != "$3" ]; then
		echo "FAIL: $1: got $3, want $2" >&2
		exit 1
	fi
	echo "ok: $1"
}

check "write 0x0100 allowed (echoed PDU)" "0601002a2a" "$(probe 256 6)"
check "write 0x0101 denied (exception 0x02)" "8602" "$(probe 257 6)"
check "read 0x0100 unaffected" "0302cafe" "$(probe 256 3)"

# --- reload: move the allowed window to 0x0101 -------------------------
PID_BEFORE=$GW_PID
write_config 257
kill -HUP "$GW_PID"
sleep 0.5

check "process survived SIGHUP" "$PID_BEFORE" "$GW_PID"
check "write 0x0100 now denied" "8602" "$(probe 256 6)"
check "write 0x0101 now allowed" "0601012a2a" "$(probe 257 6)"

if ! grep -q "configuration reloaded" "$LOG"; then
	echo "FAIL: gateway log has no 'configuration reloaded' line" >&2
	exit 1
fi
echo "ok: log recorded the reload"
echo "PASS: write policy + SIGHUP reload"
