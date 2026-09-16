#!/usr/bin/env python3
"""
Lab Modbus/TCP PLC simulator  ---  FOR ISOLATED LAB USE ONLY.

Emulates a Schneider Electric Modicon M340 PLC on Modbus/TCP (port 502) so an
OT scanner can fingerprint it safely. This process holds no real-world I/O and
touches no production system. Bind address defaults to loopback; do NOT expose
it to a routable network.

Run:  python lab/modbus_plc_sim.py            # 127.0.0.1:502
      python lab/modbus_plc_sim.py 0.0.0.0 15020   # custom (lab VLAN only)
"""
import sys
import logging
from pymodbus.server import StartTcpServer
from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusDeviceContext,
    ModbusServerContext,
)
from pymodbus.pdu.device import ModbusDeviceIdentification

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("lab-plc")


def build_context() -> ModbusServerContext:
    # Register maps seeded with recognisable, non-sensitive dummy values.
    block = lambda: ModbusSequentialDataBlock(1, [0] * 200)
    device = ModbusDeviceContext(di=block(), co=block(), ir=block(), hr=block())
    return ModbusServerContext(devices=device, single=True)


def build_identity() -> ModbusDeviceIdentification:
    # Realistic device profile so the scanner's Read Device ID probe (FC 0x2B/0x0E)
    # returns vendor/product/version and CVE correlation can be exercised.
    ident = ModbusDeviceIdentification()
    ident.VendorName = "Schneider Electric"
    ident.ProductCode = "BMXP342020"
    ident.VendorUrl = "https://www.se.com"
    ident.ProductName = "Modicon M340"
    ident.ModelName = "BMX P34 2020"
    ident.MajorMinorRevision = "2.60"
    return ident


def main() -> None:
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 502
    log.info("Lab PLC simulator (Modicon M340 profile) starting on %s:%s", host, port)
    log.info("LAB USE ONLY - not a real controller, no physical I/O.")
    StartTcpServer(
        context=build_context(),
        identity=build_identity(),
        address=(host, port),
    )


if __name__ == "__main__":
    main()
