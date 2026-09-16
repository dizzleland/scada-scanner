# Two Bugs Found and Fixed While Validating the Scanner

While standing up a Modbus lab to validate this scanner end to end, the tool
reported **zero services** against a controller that was plainly responding.
Rather than trust the output, I instrumented the probe path and traced two
real defects. Both are fixed in this fork, each with a regression test.

## Bug 1 — Probe selection keyed on the transport, not the protocol

**Symptom.** Every scan of a live Modbus device returned nothing.

**Root cause.** The `PortProtocol` dataclass is declared
`(port, protocol, service, description)`, but every table entry was written as
`PortProtocol(502, "TCP", "MODBUS", ...)`. The transport string `"TCP"` landed
in the `protocol` field and the real protocol name `"MODBUS"` landed in
`service`. Probe selection then did `_get_protocol_probe(port.protocol)` →
`_get_protocol_probe("TCP")`, which matched no key and fell through to an
**all-zero default packet**. A strict Modbus stack never answers a null frame,
so the read timed out and the host was recorded as dead.

**Fix.** Renamed the fields to what they hold — `transport` and `protocol` —
so probe selection and every reported protocol value use the true protocol
name. Four call sites that read the name from `service` were updated.

## Bug 2 — Modbus Device Identification parsed at the wrong offsets

**Symptom.** After Bug 1, the device was detected but vendor, product, and
version stayed `Unknown`.

**Root cause.** The Read Device Identification response parser read the object
count from byte 9 (the Read-Device-ID code) and started objects at byte 10.
The MBAP header is 7 bytes; the object count is at byte 13 and objects begin at
byte 14. The parser was reading the conformity level as an object and stopping.

**Fix.** Corrected the offsets, mapped the standard object IDs
(VendorName=0, ProductCode=1, MajorMinorRevision=2), and merged the recovered
identity into the fingerprint's vendor/product/version fields so downstream
CVE correlation can run.

## Result

The same lab scan now resolves cleanly:

```
protocol: MODBUS
vendor:   Schneider Electric
product:  BMXP342020
version:  2.60
```

Regression tests added in `tests/test_fingerprinting.py`:

- `test_portprotocol_transport_and_protocol_fields`
- `test_protocol_probe_selected_by_protocol_name`
- `test_parse_modbus_device_identification`

Full suite: 12 passing.

## Why this matters for OT defense

A scanner that silently under-reports is worse than no scanner: it produces a
false "all clear." Finding this took reading the protocol framing byte by byte
against the Modbus Application Protocol spec — the same discipline an OT
analyst needs to trust asset-inventory and monitoring tooling instead of taking
its output on faith.
