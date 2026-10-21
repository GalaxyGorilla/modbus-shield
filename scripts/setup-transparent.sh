#!/bin/sh
# setup-transparent.sh — netfilter rule for modbus-shield transparent
# mode (B3, Linux-only). NOT run automatically: this rewrites firewall
# rules and needs CAP_NET_ADMIN/root.
#
# Usage: setup-transparent.sh <ingress-iface> [listen-port] [modbus-port]
#
# What it does: steers inbound TCP/<modbus-port> arriving on
# <ingress-iface> into the local modbus-shield listener on
# <listen-port>. The gateway then recovers the ORIGINAL destination
# (device IP:502) per connection via conntrack SO_ORIGINAL_DST and
# forwards there.
#
# FAIL-OPEN reminder: if modbus-shield is not running (or the rule is
# removed), traffic on this port flows UNPROXIED straight to the device —
# all shielding is bypassed. Monitor accordingly.

set -eu

IFACE="${1:?usage: setup-transparent.sh <ingress-iface> [listen-port] [modbus-port]}"
LPORT="${2:-5020}"
MBPORT="${3:-502}"

# nftables backend (iptables >= 1.8) preferred; falls back to legacy.
if iptables -t nat -C PREROUTING -i "$IFACE" -p tcp --dport "$MBPORT" -j REDIRECT --to-port "$LPORT" 2>/dev/null; then
    echo "transparent redirect already in place (iface $IFACE, dport $MBPORT -> $LPORT)"
    exit 0
fi
iptables -t nat -A PREROUTING -i "$IFACE" -p tcp --dport "$MBPORT" -j REDIRECT --to-port "$LPORT"
echo "installed: nat PREROUTING -i $IFACE -p tcp --dport $MBPORT -j REDIRECT --to-port $LPORT"
echo
echo "next: run the gateway with the same listen port and 'transparent: true':"
echo "  modbus-shield gateway --listen :$LPORT --transparent --read-only [...]"
echo
echo "WARNING: traffic now depends on this box. If modbus-shield stops,"
echo "port $MBPORT on the device is UNREACHABLE through the box (and any"
echo "bridge path without the redirect flows unproxied = unshielded)."
