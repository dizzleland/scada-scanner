# OT Scanner Capability — Lab Demonstration Package

Hands-on evidence for OT/ICS security analyst work, produced entirely on an
isolated lab. **No production or third-party system was scanned, probed, or
contacted.** Every packet in this package went to a Modbus simulator I run on
loopback.

## What's here

| File | What it shows |
|------|---------------|
| `../lab/modbus_plc_sim.py` | Isolated Modbus/TCP PLC simulator (Modicon M340 profile) |
| `lab_scan_results.json` | Safe-mode scan (non-intrusive, production default) |
| `lab_scan_full.json` | Full fingerprint scan resolving vendor/product/version |
| `FINDINGS-scanner-bugs.md` | Two real bugs I found and fixed in the tool, with tests |
| `detection/modbus-anomalies.md` | Sigma + Zeek detection content for anomalous Modbus |
| `threat-model.md` | Purdue placement, ATT&CK for ICS, IEC 62443 remediation |

## The four analyst deliverables

1. **Discovery** — ran the scanner against the lab and produced machine-readable
   findings.
2. **Fingerprint integrity** — found the tool under-reporting, traced two
   protocol-parsing bugs to the byte level, fixed both, and added regression
   tests (suite now 12 passing).
3. **Detection** — wrote vendor-neutral rules for the reconnaissance and
   write-abuse behaviour on a Modbus segment.
4. **Remediation** — placed the asset in the Purdue model and mapped fixes to
   IEC 62443 zones/conduits and monitoring requirements.

## Safety and authorization

- Scans run only against `127.0.0.1` (the simulator).
- The tool's own authorization preflight is respected; `--i-am-authorized`
  asserts ownership of the lab target.
- `--safe-mode` is the responsible default for any real engagement and is only
  ever pointed at systems under written authorization.

## Reproduce

See `../lab/README.md`.
