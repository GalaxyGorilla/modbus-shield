#!/usr/bin/env python3
"""scripts/fakedevice.py — minimal fake Modbus TCP device for interop tests.

Serves any number of concurrent connections (a "well-behaved" device).
Behavior:
  - FC3/FC4 read: register 0x0100 (1-based ref 257), quantity 1 -> 0xCAFE;
    anything else -> exception 0x02 (Illegal Data Address).
  - FC5/6/15/16 writes: echo the request PDU back (success).
  - Everything else: exception 0x01 (Illegal Function).

Usage: fakedevice.py <port>
"""
import socket
import struct
import sys
import threading


def handle(c):
    while True:
        hdr = b""
        while len(hdr) < 7:
            chunk = c.recv(7 - len(hdr))
            if not chunk:
                return
            hdr += chunk
        txn, proto, length, unit = struct.unpack(">HHHB", hdr)
        if proto != 0 or length < 2 or length > 254:
            return
        pdu = b""
        while len(pdu) < length - 1:
            chunk = c.recv(length - 1 - len(pdu))
            if not chunk:
                return
            pdu += chunk
        fc = pdu[0]
        if fc == 3 or fc == 4:  # read holding/input registers
            addr, qty = struct.unpack(">HH", pdu[1:5])
            if addr == 0x0100 and qty == 1:
                body = bytes([fc, 2, 0xCA, 0xFE])
            else:
                body = bytes([fc | 0x80, 0x02])  # illegal data address
        elif fc in (5, 6, 15, 16):  # writes: echo success (echo request PDU)
            body = pdu
        else:
            body = bytes([fc | 0x80, 0x01])
        resp = struct.pack(">HHHB", txn, 0, 1 + len(body), unit) + body
        c.sendall(resp)


def main():
    port = int(sys.argv[1])
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(16)
    while True:
        c, _ = s.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()


if __name__ == "__main__":
    main()
