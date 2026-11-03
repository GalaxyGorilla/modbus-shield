#!/usr/bin/env python3
"""Independent TLS/mTLS client for the modbus-shield interop suite.

Uses Python's ssl module and a raw Modbus/TCP frame — not Go's crypto/tls,
not a Go test client — so the handshake, certificate chain and client-cert
requirement are judged by a second implementation.

Modes (--mode):
  tls                   server-auth TLS; verify the proxy certificate
  mtls                  TLS + a client certificate
  mtls-no-client-cert   expect the handshake to fail (mTLS is mandatory)
  plain                 expect a plain Modbus request to be refused

Exit 0 on the expected outcome, 1 otherwise.
"""

import argparse
import socket
import ssl
import struct
import sys


def modbus_read(sock):
    # FC3, start 0x0100, quantity 1 (the fake device answers 0xCAFE).
    pdu = bytes([0x03, 0x01, 0x00, 0x00, 0x01])
    sock.sendall(struct.pack(">HHHB", 0x1234, 0, len(pdu) + 1, 1) + pdu)
    hdr = b""
    while len(hdr) < 7:
        chunk = sock.recv(7 - len(hdr))
        if not chunk:
            raise RuntimeError("connection closed before an MBAP header")
        hdr += chunk
    txn, proto, length, unit = struct.unpack(">HHHB", hdr)
    if txn != 0x1234 or proto != 0 or unit != 1 or length < 3:
        raise RuntimeError(f"bad MBAP header: txn={txn} proto={proto} len={length} unit={unit}")
    body = b""
    while len(body) < length - 1:
        chunk = sock.recv(length - 1 - len(body))
        if not chunk:
            raise RuntimeError("connection closed mid-PDU")
        body += chunk
    if body[0] & 0x80:
        raise RuntimeError(f"device exception {body[1]}")
    value = struct.unpack(">H", body[2:4])[0]
    if value != 0xCAFE:
        raise RuntimeError(f"register = {value:#06x}, want 0xcafe")
    return value


def tls_context(args):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_verify_locations(cafile=args.ca)
    if args.cert:
        ctx.load_cert_chain(args.cert, args.key)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--server-name", default="localhost")
    p.add_argument("--mode", choices=("tls", "mtls", "mtls-no-client-cert", "plain"), required=True)
    p.add_argument("--ca")
    p.add_argument("--cert")
    p.add_argument("--key")
    args = p.parse_args()

    if args.mode == "plain":
        try:
            with socket.create_connection((args.host, args.port), timeout=3) as s:
                s.settimeout(2)
                try:
                    modbus_read(s)
                except (TimeoutError, OSError, RuntimeError) as exc:
                    print(f"plain client refused: {exc}")
                    return 0
            print("FAIL: plain client received a Modbus answer over TLS", file=sys.stderr)
            return 1
        except OSError as exc:
            print(f"plain client refused: {exc}")
            return 0

    ctx = tls_context(args)
    try:
        with socket.create_connection((args.host, args.port), timeout=3) as raw:
            with ctx.wrap_socket(raw, server_hostname=args.server_name) as s:
                value = modbus_read(s)
                print(f"{args.mode} read register 0x{value:04x}")
                return 0
    except (ssl.SSLError, OSError, RuntimeError) as exc:
        if args.mode == "mtls-no-client-cert":
            print(f"mTLS without a client certificate refused: {exc}")
            return 0
        print(f"FAIL: {args.mode}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
