#!/usr/bin/env python3
"""Independent Modbus TCP client for the modbus-shield interop suite.

Uses pymodbus, not this project's Go client and not a hand-rolled frame, so
the front leg is judged by a second implementation. It exercises:

  - FC3/FC4 reads through the proxy
  - FC6 write + read-back
  - unit-ID addressing (the proxy must preserve the client's unit ID)
  - exception pass-through for an unmapped register
  - concurrent clients (fan-in) with per-client registers

Exit 0 = all checks passed, 1 = a failure.
"""
import argparse
import threading

from pymodbus.client import ModbusTcpClient

CAFE = 0xCAFE
UNIT = 1


def read_register(client, address, device_id=UNIT):
    r = client.read_holding_registers(address, count=1, device_id=device_id)
    if r.isError():
        raise RuntimeError(f"read {address:#06x} failed: {r}")
    return r.registers[0]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--clients", type=int, default=4)
    p.add_argument("--rounds", type=int, default=10)
    args = p.parse_args()

    client = ModbusTcpClient(args.host, port=args.port, timeout=3)
    if not client.connect():
        raise SystemExit(f"pymodbus client could not connect to {args.host}:{args.port}")
    try:
        if read_register(client, 0x0100) != CAFE:
            raise SystemExit("holding register 0x0100 did not return 0xCAFE")
        print("pymodbus FC3 read 0x0100 = 0xCAFE")

        if read_register(client, 0x0101) != 0x1234:
            raise SystemExit("holding register 0x0101 did not return 0x1234")

        w = client.write_register(0x0101, 0x4242, device_id=UNIT)
        if w.isError():
            raise SystemExit(f"FC6 write failed: {w}")
        if read_register(client, 0x0101) != 0x4242:
            raise SystemExit("FC6 read-back did not return 0x4242")
        print("pymodbus FC6 write/read-back 0x0101 = 0x4242")

        r = client.read_holding_registers(0x0200, count=1, device_id=UNIT)
        if not r.isError() or getattr(r, "exception_code", None) != 2:
            raise SystemExit(f"unmapped register did not return Illegal Data Address: {r}")
        print("pymodbus exception pass-through: 0x0200 -> Illegal Data Address")

        if read_register(client, 0x0100, device_id=17) != CAFE:
            raise SystemExit("unit-ID 17 read did not return 0xCAFE")
        print("pymodbus unit-ID addressing: unit 17 -> 0xCAFE")
    finally:
        client.close()

    errors = []
    lock = threading.Lock()

    def worker(idx):
        c = ModbusTcpClient(args.host, port=args.port, timeout=3)
        try:
            if not c.connect():
                raise RuntimeError("connect failed")
            reg = 0x0110 + idx
            for i in range(args.rounds):
                if read_register(c, 0x0100) != CAFE:
                    raise RuntimeError("shared read returned the wrong value")
                value = (idx << 8) | (i & 0xFF)
                w = c.write_register(reg, value, device_id=UNIT)
                if w.isError():
                    raise RuntimeError(f"write {reg:#06x} failed: {w}")
                if read_register(c, reg) != value:
                    raise RuntimeError(f"read-back {reg:#06x} returned the wrong value")
        except Exception as exc:  # noqa: BLE001 - reported below
            with lock:
                errors.append(f"client {idx}: {exc}")
        finally:
            c.close()

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(args.clients)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    if errors:
        raise SystemExit("concurrent pymodbus clients failed:\n  " + "\n  ".join(errors))
    print(
        f"pymodbus concurrent clients: {args.clients} clients x {args.rounds} "
        "write/read rounds"
    )
    print("pymodbus interop: PASS")


if __name__ == "__main__":
    main()
