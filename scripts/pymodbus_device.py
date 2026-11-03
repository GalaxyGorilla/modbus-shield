#!/usr/bin/env python3
"""scripts/pymodbus_device.py — an independent Modbus TCP device.

Uses pymodbus (not this project's Go code, not scripts/fakedevice.py) so the
gateway's device leg is judged by a second implementation. The register map
matches the rest of the interop suite:

  holding/input register 0x0100 = 0xCAFE
  holding/input register 0x0101 = 0x1234
  registers 0x0102..0x013F start at 0 and are writable
  anything outside the block -> Illegal Data Address (exception 0x02)

Usage: pymodbus_device.py --port <port> [--host 127.0.0.1]
"""
import argparse
import logging
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning)
# pymodbus 3.16 logs its v4 datastore deprecation notices at WARNING. They
# are useful upstream but noise in an interop transcript; the version is
# pinned by scripts/peers-setup.sh.
logging.getLogger("pymodbus").setLevel(logging.ERROR)

from pymodbus.datastore import (  # noqa: E402
    ModbusDeviceContext,
    ModbusSequentialDataBlock,
    ModbusServerContext,
)
from pymodbus.server import StartTcpServer  # noqa: E402


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, required=True)
    args = p.parse_args()

    # pymodbus treats the block address as one-based (it stores address-1),
    # so a block starting at 0x0101 covers request address 0x0100.
    values = [0xCAFE, 0x1234] + [0] * 62
    hr = ModbusSequentialDataBlock(0x0101, values)
    ir = ModbusSequentialDataBlock(0x0101, values)
    context = ModbusServerContext(
        devices=ModbusDeviceContext(hr=hr, ir=ir), single=True
    )
    StartTcpServer(context, address=(args.host, args.port))


if __name__ == "__main__":
    main()
