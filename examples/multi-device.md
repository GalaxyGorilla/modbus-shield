# Multi-device box (one box, several listeners and devices)

One modbus-shield instance in front of **several** legacy devices — the
config-driven deployment. Each `devices:` entry couples exactly one
front-leg listener with one upstream device; all entries in one file
share the same log and metrics settings.

```
[SCADA] ──────► :5020 ──► modbus-shield ──► 10.0.0.42:502  (fragile PLC, read-only)
[Node-RED] ───► :5021 ──► (one instance)   ──► 10.0.0.43:502  (inverter, free RW)
[EV charger] ─► :5022 ──►                  ──► 10.0.0.44:502  (serial gateway w/ remap)
```

Typical scenario: one box at the edge of a cell/segment with three
legacy devices of different trust levels — a fragile PLC that must be
read-only and shielded, an inverter that engineers may write to, and a
serial converter behind which only one unit ID answers.

## 1. The config

```yaml
# /etc/modbus-shield/gateway.yaml
devices:
  # Device 1: fragile PLC — read-only, shielded, SCADA only.
  - name: legacy-plc
    listen_addr: ":5020"
    device_addr: "10.0.0.42:502"
    read_only: true
    allow:
      - "10.8.0.0/24"        # SCADA segment only
    max_clients: 8
    rate_per_sec: 50
    timeout_ms: 5000

  # Device 2: inverter — trusted engineering access, writes allowed.
  - listen_addr: ":5021"
    device_addr: "10.0.0.43:502"
    timeout_ms: 2000

  # Device 3: serial gateway — device answers only unit 17,
  # clients keep addressing unit 1 (or their own unit IDs).
  - name: serial-gw
    listen_addr: ":5022"
    device_addr: "10.0.0.44:502"
    device_unit_id: 17

log:
  level: info
  format: json

metrics_listen: ":9202"
```

Full field reference: [`configs/gateway.yaml`](../configs/gateway.yaml).

## 2. Validate and run

```bash
modbus-shield validate --config /etc/modbus-shield/gateway.yaml
modbus-shield gateway --config /etc/modbus-shield/gateway.yaml
```

`validate` reports a per-device summary (read-only, allow-list size,
unit remap) — checking all listeners at once before apply. One bad
device entry fails the whole file: the gateway refuses to run with a
partially valid config, so a fleet can rely on validate as the gate.

## 3. Point the clients

Each client points at the listener that serves **its** device — that is
the whole migration per device:

| Client | Points at | Effect |
|---|---|---|
| SCADA (10.8.0.x) | `<box>:5020` | reads the PLC, read-only, allow-listed |
| Node-RED / engineering | `<box>:5021` | full read/write to the inverter |
| Historic metering | `<box>:5022` unit 1 | proxy rewrites to unit 17 toward the device, responses back to unit 1 |

Each listener independently enforces its device's policy; one device
being down or flaky does not affect the others (separate listeners,
separate upstream connections, separate counters —
`modbus_shield_*_total{device=...}` label everything per device).

## 4. Verify

```bash
# per-listener end-to-end check:
mbpoll -1 -m tcp -p 5020 -a 1 -c 1 -t 4:hex <box-ip>   # PLC read (0xCAFE-style value)
mbpoll -1 -m tcp -p 5021 -a 1 -c 1 -t 4:hex <box-ip>   # inverter read
mbpoll -1 -m tcp -p 5022 -a 17 -c 1 -t 4:hex <box-ip>  # serial gw: unit 17

# or a write check on the unrestricted listener:
mbpoll -1 -m tcp -p 5021 -a 1 -r 257 -t 4:hex 0x0001 <box-ip>  # FC6 write

# selftest probes ALL devices directly:
modbus-shield selftest --config /etc/modbus-shield/gateway.yaml
```

`selftest` reports per-device: dial + read (or exception = alive) per
configured device, so one dead device is visible immediately without
taking down the others.

## Isolation properties

- **Per-device listeners** — one device entry cannot affect another's
  listener, upstream connection, or counters.
- **Per-device shielding** — `max_clients` and `rate_per_sec` are
  per-listener budgets: a polling storm on the inverter listener never
  reaches the fragile PLC.
- **Per-device observability** — every metric is labeled by `device`
  name (defaults to the device address when `name` is omitted); the
  `device_up` gauge tells you exactly which device is unreachable.
- **Shared process** — all listeners share one process, one systemd
  unit, one metrics endpoint. A crash takes down all listeners (systemd
  restarts them together); if you need blast-radius separation, run one
  instance per device — the flags mode makes that a two-line service
  each.
