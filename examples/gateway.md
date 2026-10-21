# Gateway box (one box in front of the legacy device)

A single modbus-shield box in front of a legacy Modbus TCP device — the
primary retrofit deployment. All clients multiplex onto exactly one
device connection; the box enforces who may connect, who may write, and
how hard the device is hammered.

```
[SCADA] --\
[Node-RED] ---> Modbus TCP --> [modbus-shield box] --Modbus TCP--> [legacy device]
[EV charger] --/                    (one upstream connection)
```

This is the deployment for the retrofit use case: the box **is** the
device's security gate — blocked writes and rejected clients never reach
the legacy device, and the device-side wire stays 100% plain Modbus TCP.
The device notices nothing.

## 1. Run it (paste two lines)

No config file needed for a single device:

```bash
modbus-shield gateway \
  --listen :5020 \
  --device 10.0.0.42:502 \
  --read-only \
  --allow 10.8.0.0/24 \
  --max-clients 8 \
  --rate-per-sec 50
```

- `--listen` — the front leg (clients repoint here once).
- `--device` — the legacy device (plain Modbus TCP, unmodified).
- `--read-only` — write function codes (5, 6, 15, 16, 21, 22, 23) are
  rejected with a Modbus exception (0x01 Illegal Function); the device
  never sees them.
- `--allow` — client allow-list (IP or CIDR, repeatable). Omit to allow
  any client.
- `--max-clients` / `--rate-per-sec` — shielding limits that protect
  fragile devices from connection and polling storms.

Point every client at the box IP instead of the device IP — that
repointing is the whole migration.

## 2. Or with a config file

For multi-device instances (one listener + device pair per entry), use
YAML — see [`configs/gateway.yaml`](../configs/gateway.yaml):

```bash
modbus-shield gateway --config /etc/modbus-shield/gateway.yaml
```

## 3. Verify on site

```bash
# pre-apply check (config syntax, addresses, allow-lists):
modbus-shield validate --config /etc/modbus-shield/gateway.yaml

# environment check: real Modbus read directly to each configured device
# (an exception response still proves liveness):
modbus-shield selftest --config /etc/modbus-shield/gateway.yaml

# machine-readable variants for web UIs:
modbus-shield validate --json --config ...
modbus-shield selftest --json --config ...
```

## 4. Wire a real client

Anything that speaks Modbus TCP works unchanged — only the target
address changes:

```bash
# mbpoll example: read holding register 0x0100 via the box
mbpoll -1 -m tcp -p 5020 -a 1 -c 1 -t 4:hex <box-ip>
```

The device keeps its unit IDs; register maps and data encodings flow
through untouched (the proxy parses only the 7-byte MBAP header).

## Protection semantics

- Write function codes on a `read_only` listener: **rejected** with a
  proxy-generated Modbus exception (0x01) — that rejection is the
  protection; the device never sees the write.
- Clients outside the `allow` list: **connection refused**.
- Bursts above `rate_per_sec`: rejected with exception 0x06 (Server
  Device Busy — the spec's "retry later" code), device untouched.
- Connections above `max_clients`: rejected at accept time.
- Device outage: clients get exception 0x0B (Gateway Target Device
  Failed To Respond); the box re-dials automatically with bounded
  backoff and recovers on its own — the retrofit box is the new network
  path, so it must never give up.

## Hardening options

- **Unit-ID remap** — for serial-gateway-style devices where clients
  must keep their unit IDs but the device only answers one:
  `--device-unit-id 17` (or `device_unit_id: 17` in YAML). Requests are
  rewritten toward the device, responses rewritten back to the client's
  original unit ID.
- **Prometheus metrics** — `--metrics-addr :9202` (or
  `metrics_listen:` in YAML) serves connection/request/error counters,
  device-up gauges and forwarding-latency histograms. Operations-side
  only; the device sees nothing.

## Shielding notes

- **One upstream connection** — all client traffic multiplexes over a
  single device connection (many legacy devices accept only one or very
  few concurrent TCP sessions and degrade under more). Requests are
  serialized first-come-first-served; each client's requests are
  correlated independently by transaction ID.
- **Fragile devices** — `max_clients` + `rate_per_sec` exist precisely
  for the fragile-device case; a misbehaving client cannot wedge the
  others (fair scheduling, per-request deadlines).
