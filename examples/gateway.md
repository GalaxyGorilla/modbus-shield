# Gateway box (one box in front of the legacy device)

A single modbus-shield box in front of a legacy Modbus TCP device — the
primary retrofit deployment. All clients multiplex onto exactly one
device connection; the box enforces who may connect, who may write, and
how hard the device is hammered.

**This is your walkthrough if:** you have one legacy device with Modbus
TCP (a PLC, inverter, power meter, EV charger, heat pump...), you cannot
or don't want to modify it, and you want it protected. Start at section 0
for the Modbus background, then paste two lines.

```
[SCADA] --\
[Node-RED] ---> Modbus TCP --> [modbus-shield box] --Modbus TCP--> [legacy device]
[EV charger] --/                    (one upstream connection)
```

This is the deployment for the retrofit use case: the box **is** the
device's security gate — blocked writes and rejected clients never reach
the legacy device, and the device-side wire stays 100% plain Modbus TCP.
The device notices nothing.

## 0. Two minutes of Modbus background

Everything else on this page assumes only this:

- **What Modbus is.** A network language from 1979 that industrial
  machines (PLCs, inverters, power meters, chargers) still speak today.
  A client asks, the device answers: "give me the value of register 40001"
  → "412". That's the whole protocol — reads and writes of numbered
  registers.
- **Why it matters here.** Modbus has **no passwords, no encryption, no
  permissions** — it was designed for a serial cable between two trusted
  machines, long before network security existed. Anyone who can reach
  the device can read it *and command it*.
- **"Register" and "unit ID".** A *register* is one numbered value in the
  device (a temperature, a setpoint, a fault code). The *unit ID* is a
  1-byte address — it matters when several devices share one line (see
  the unit-ID remap hardening option below).
- **Why old devices are fragile.** Many accept only **one network
  connection**; a second computer asking questions can freeze or crash
  them. And they never get updates — the firmware is what it is.
- **What the box changes.** Nothing about the device. It speaks Modbus
  toward the device exactly as clients did before, and speaks Modbus
  toward clients exactly as the device expected. Only now there is
  something in between that counts connections, rejects strangers and
  blocks writes.

You do not need more Modbus knowledge to deploy the box. Where a
walkthrough needs device-specific values (register numbers, unit IDs),
they come from your device's manual, not from this project.

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
- `--rate-per-client-per-sec` — optional per-connection cap (add it when
  several pollers share the box: one runaway client then gets 0x06
  itself instead of consuming the `--rate-per-sec` budget everyone else
  needs).

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

A successful read prints the register value (e.g. `[257]: 0xCAFE`); a
blocked write prints the rejection exception instead. The device keeps
its unit IDs; register maps and data encodings flow through untouched
(the proxy parses only the 7-byte MBAP header).

## Protection semantics

- Write function codes on a `read_only` listener: **rejected** with a
  proxy-generated Modbus exception (0x01) — that rejection is the
  protection; the device never sees the write.
- Clients outside the `allow` list: **connection refused**.
- Bursts above `rate_per_sec`: rejected with exception 0x06 (Server
  Device Busy — the spec's "retry later" code), device untouched.
- A single client above `rate_per_client_per_sec`: that client gets 0x06
  while the others keep their share of `rate_per_sec` (the per-client
  check runs first, so a rejected request never charges the shared
  budget).
- Connections above `max_clients`: rejected at accept time.
- Device outage: clients get exception 0x0B (Gateway Target Device
  Failed To Respond); the box re-dials automatically with bounded
  backoff and recovers on its own — the retrofit box is the new network
  path, so it must never give up.

## Hardening options

- **Unit-ID remap** — for devices behind a serial converter where the
  device only answers one fixed unit ID but your clients use another:
  `--device-unit-id 17` (or `device_unit_id: 17` in YAML). Requests are
  rewritten toward the device, responses rewritten back to the client's
  original unit ID.
- **Slower pacing for picky devices** — `request_delay_ms: 10` enforces
  a minimum gap between requests toward the device (some old devices
  degrade when asked too fast). `idle_timeout_ms: 60000` disconnects
  clients that went silent, freeing their slots.
- **Caching for very slow devices** — `read_cache_ttl_ms: 5000` makes
  the box answer repeated identical reads from memory for 5 s
  (off by default; writes always go through).
- **Speaking to serial-only converters** — `rtu_over_tcp: true` when the
  device sits behind a cheap converter that doesn't wrap Modbus TCP; the
  box translates both directions.
- **TLS / mTLS, roles, health, transparent splice** — see the
  [examples index](README.md); each has its own walkthrough.
- **Prometheus metrics** — `--metrics-addr :9202` (or
  `metrics_listen:` in YAML) serves connection/request/error counters,
  device-up gauges and forwarding-latency histograms. Operations-side
  only; the device sees nothing.

## Shielding notes

- **One upstream connection** — all client traffic multiplexes over a
  single device connection (many legacy devices accept only one or very
  few concurrent TCP sessions and degrade under more). Requests are
  serialized first-come-first-served (FIFO hand-over, so a quiet poller
  is never starved by a busy one); each client's requests are
  correlated independently by transaction ID.
- **Fragile devices** — `max_clients` + `rate_per_sec` exist precisely
  for the fragile-device case; a misbehaving client cannot wedge the
  others (fair scheduling, per-request deadlines).
- **Non-conforming devices** — if a converter or old gateway does not
  echo transaction IDs (or sets a non-zero MBAP protocol ID), every
  request ends in exception 0x0B under strict correlation. Set
  `lenient_correlation: true` (or `--lenient-correlation`) to accept
  those responses; framing stays strict and clients still see their own
  transaction ID.
