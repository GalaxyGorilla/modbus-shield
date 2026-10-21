# Health via Modbus — monitor the box with the tooling you already have

The retrofit box sits between the plant network and a legacy device.
Plant SCADA can already speak Modbus — so the box exposes **its own
health as readable registers on a virtual unit-ID**. No Prometheus, no
extra port, no new tooling on site: point a health check at the box's
front leg with a unit-ID that the real device never uses.

```
[SCADA health poll] --Modbus TCP--> [modbus-shield] --Modbus TCP--> [legacy device]
        unit 200  (answered by the box)     |  unit 1 (forwarded)
```

## 1. Enable it

One setting — the virtual unit-ID health requests are addressed to.
Pick a unit-ID the real device does not answer (devices typically use
1..247; 250+ is usually safe):

```yaml
devices:
  - name: legacy-plc
    listen_addr: ":5020"
    device_addr: "10.0.0.42:502"
    health_unit_id: 200
```

Or on the command line:

```bash
modbus-shield gateway --listen :5020 --device 10.0.0.42:502 --health-unit-id 200
```

## 2. Read the registers

Health reads are ordinary FC3 (read holding registers) or FC4 requests
against the health unit-ID. Both return the same register image:

| Register | Meaning |
|---|---|
| 0 | magic `0x4D53` ("MS") — identifies the endpoint |
| 1 | register map version (bumped when the layout changes) |
| 2–3 | uptime seconds (uint32, high word first) |
| 4 | upstream state (1 = device connection up, 0 = down) |
| 5 | upstream reconnects (16-bit wrap) |
| 6 | upstream errors (16-bit wrap) |
| 7 | stale responses discarded (16-bit wrap) |
| 8 | front connections accepted (16-bit wrap) |
| 9 | front connections rejected (16-bit wrap) |
| 10 | current client connections |
| 11–14 | requests forwarded / exception_device / exception_policy / exception_rate (16-bit wrap) |
| 15 | read-only policy (1 = on) |
| 16 | max_clients |
| 17 | rate_per_sec (0 = unlimited) |

Example with mbpoll (register numbers are 1-based on the CLI, so
register 0 = `-r 1`):

```bash
mbpoll -1 -m tcp -a 200 -t 4 -c 4 -r 1 127.0.0.1 -p 5020
```

An SCADA health check only needs two registers: **4** (device
reachable through the box) and **2–3** (uptime — a reset box or a
crash-loop is visible as a jumping uptime).

## 3. What the device sees

Nothing. Requests to the health unit-ID are answered by the box itself
and never reach the legacy device — even when the device is down
(register 4 reads 0 instead of the box throwing a gateway exception).

## Protection semantics

- Health reads **bypass read-only policy and the rate limiter**: the
  endpoint stays responsive exactly when the box is shielding a polling
  storm — that is when you need it most.
- The front-leg gates still apply: the IP allow-list and the connection
  cap are enforced at accept time, so only permitted clients can read
  the health registers.
- Only reads (FC3/FC4) are valid; anything else gets a clean Modbus
  exception. The registers are read-only by design — there is no write
  path into the box.
- Out-of-range reads get exception 0x02 (Illegal Data Address); the
  register count is fixed at 18.

## Notes

- Counters wrap at 16 bits — the register map version (register 1)
  tells you how to interpret them; Prometheus on the ops side
  (`--metrics-addr`) carries the full-precision counters.
- The upstream state gauge flips to 0 the moment the device connection
  drops and back to 1 on the next successful dial; reconnects counts
  every successful dial, including the first one after start.
- `validate` shows the feature in its device summary
  (`modbus-shield validate --config ...`).
