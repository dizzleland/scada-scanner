# OT Test Lab — Modbus/TCP PLC Simulator

**Isolated lab only. No production or third-party system is involved.**

This lab stands up a simulated Modbus/TCP controller so the scanner can be
exercised end to end without touching any real ICS/SCADA equipment. It exists
to demonstrate scanner operation, fingerprint parsing, and detection
engineering on ground I own.

## What it emulates

`modbus_plc_sim.py` presents a Modbus/TCP endpoint that answers the standard
Read Device Identification request (function code `0x2B` / MEI `0x0E`) with a
realistic profile:

| Object            | Value                |
|-------------------|----------------------|
| Vendor name       | Schneider Electric   |
| Product code      | BMXP342020           |
| Major/minor rev.  | 2.60                 |
| Device profile    | Modicon M340 (sim)   |

The device holds no physical I/O. The register maps are seeded with dummy
zeros. Nothing here connects to a real controller.

## Run it (loopback only)

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt   # Windows
python lab/modbus_plc_sim.py            # binds 127.0.0.1:502
```

Keep the bind address on loopback or an isolated lab VLAN. Do not expose it to
a routable network.

## Scan it

Safe mode (non-intrusive, the production default):

```bash
python scada_scanner.py -t 127.0.0.1 --safe-mode --i-am-authorized \
  --rate 5 --timeout 4 -o portfolio/lab_scan_results.json
```

Full fingerprint (adds the active Read Device ID probe; only ever against
equipment you own):

```bash
python scada_scanner.py -t 127.0.0.1 --i-am-authorized \
  --rate 10 --timeout 4 -o portfolio/lab_scan_full.json
```

The full scan resolves the device to `Schneider Electric BMXP342020 v2.60`.
