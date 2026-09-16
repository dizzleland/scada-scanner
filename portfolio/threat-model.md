# OT Lab Threat Model — Purdue Placement, ATT&CK for ICS, Remediation

A short threat model for the simulated Modbus controller, framed the way an OT
analyst would present it: where the asset sits, how it could be attacked, and
what reduces the risk. The device is a lab simulation; the reasoning is what
transfers to a real upstream oil & gas environment.

## Purdue-model placement

```
 Level 5  Enterprise / Internet
 Level 4  IT business network ....... email, laptops, VPN/ZTNA
 --------- IT -> OT boundary (firewall + monitored DMZ) ---------
 Level 3  Operations / DMZ .......... historian, jump host, patch, AV/EDR mgmt
 Level 2  Supervisory .............. HMI, SCADA server, engineering workstation
 Level 1  Control .................. [ PLC / RTU  <-- the simulated Modicon ]
 Level 0  Process .................. sensors, actuators, valves, pumps
```

The controller lives at **Level 1**. Its only legitimate peers are the HMI,
SCADA server, and engineering workstation at Level 2. Any Modbus conversation
that originates above the IT→OT boundary is by definition out of place — which
is exactly what the detection content keys on.

## Attack paths (ATT&CK for ICS)

| Stage | Technique | In this model |
|-------|-----------|---------------|
| Initial access | T0866 Exploitation of Remote Services; T0822 External Remote Services | Internet-facing remote access or a pivot from a phished IT laptop |
| Discovery | T0846 Remote System Discovery; T0888 Remote System Information Discovery | Modbus enumeration and Read Device ID fingerprinting |
| Collection | T0801 Monitor Process State | Reading holding/input registers to learn the process |
| Impair / Impact | T0836 Modify Parameter; T0855 Unauthorized Command Message; T0831 Manipulation of Control | Writing coils/registers to move field devices (the FrostyGoop pattern) |

## Consequence framing

Modbus/TCP has no authentication or encryption. Once an attacker can route to
Level 1, protocol-level controls offer little resistance, so the defensible
lines are **network position** and **monitoring**. In an environment with
safety-instrumented and injection systems, control is prioritised by
consequence, not just likelihood.

## Remediation (aligned to IEC 62443)

1. **Zones and conduits (SR/ZCR).** Place Level 1 controllers in a dedicated
   zone; permit Modbus only from the named Level 2 conduit. Deny IT→L1 outright.
2. **Least routes.** No direct Internet or IT path to control devices; remote
   access terminates at a monitored Level 3 DMZ jump host with MFA.
3. **Monitor the protocol (IEC 62443-3-3 SR 6.2).** Passive Modbus visibility
   with the detection content in `detection/modbus-anomalies.md`.
4. **Authoritative inventory (SR 7.8).** Passive asset discovery so every
   Modbus speaker is known; alert on new ones.
5. **Compensating controls for unpatchable devices.** Where firmware cannot be
   patched, wrap the device in tighter segmentation and stricter write-path
   monitoring rather than exposing it.

## What this demonstrates

The same four artifacts an OT analyst hands over after an assessment:
discovery (the scan), a placed asset (this model), detections (the rules), and
a remediation path tied to a recognised standard — produced on a safe lab, not
on anyone's live network.
