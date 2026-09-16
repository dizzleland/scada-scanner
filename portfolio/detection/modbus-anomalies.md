# Detection Content — Anomalous Modbus/TCP Activity

Lab-derived detections for the behaviour this scanner (and real adversaries)
generate on a Modbus segment. These are generic, vendor-neutral rules built and
tested against the lab simulator. They are not tuned to any specific network.

Modbus/TCP is unauthenticated and unencrypted, so detection leans on
**behaviour and context**: who is talking Modbus, from where, and which
function codes are used.

## What to alert on

| Behaviour | Why it matters | ATT&CK for ICS |
|-----------|----------------|----------------|
| Modbus function `0x2B/0x0E` (Read Device ID) from a non-engineering host | Reconnaissance / fingerprinting | T0888 Remote System Information Discovery |
| Write function codes (`0x05`,`0x06`,`0x0F`,`0x10`) from an unexpected source | Unauthorized control of field devices | T0836 Modify Parameter; T0855 Unauthorized Command Message |
| A single source touching many Modbus hosts in a short window | Network scanning / enumeration | T0846 Remote System Discovery |
| Modbus to/from an IT-subnet address | IT→OT boundary crossing | T0866 Exploitation of Remote Services |

## Sigma (Zeek `modbus.log` source)

```yaml
title: Modbus Write From Unauthorized Source
id: 8f1e2a10-0c3a-4d0e-9a1a-lab-derived-0001
status: experimental
description: Modbus write-class function code from a host not on the approved
  engineering-workstation allow-list. Modbus has no authentication, so source
  identity plus function code is the primary signal.
logsource:
  product: zeek
  service: modbus
detection:
  writes:
    func|contains:
      - 'WRITE_SINGLE_COIL'
      - 'WRITE_SINGLE_REGISTER'
      - 'WRITE_MULTIPLE_COILS'
      - 'WRITE_MULTIPLE_REGISTERS'
  known_engineers:
    id.orig_h:
      - '10.20.30.0/24'   # replace with the real engineering-WS range
  condition: writes and not known_engineers
level: high
falsepositives:
  - Legitimate engineering changes from a host missing from the allow-list
tags:
  - attack.t0836
  - attack.t0855
```

## Zeek scan-detection sketch

```zeek
# Flag any host that opens Modbus (502) to more than N distinct servers
# inside a short window — classic enumeration behaviour.
event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool) {
    if ( is_orig ) {
        local src = c$id$orig_h;
        add modbus_targets[src][c$id$resp_h];
        if ( |modbus_targets[src]| > 5 )
            NOTICE([$note=Modbus_Enumeration, $conn=c,
                    $msg=fmt("%s queried %d Modbus hosts", src,
                             |modbus_targets[src]|)]);
    }
}
```

## Deployment notes

- Feed a passive Modbus sensor (Zeek, or an OT platform such as Nozomi) from a
  SPAN/TAP at the IT→OT boundary and inside the control LAN.
- Maintain the engineering-workstation allow-list as data, not in the rule.
- Read Device ID from a non-engineering host is low-severity on its own but a
  strong pivot signal when correlated with new external access.
