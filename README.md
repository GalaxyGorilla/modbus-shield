# modbus-shield

[![Go Reference](https://pkg.go.dev/badge/github.com/GalaxyGorilla/modbus-shield.svg)](https://pkg.go.dev/github.com/GalaxyGorilla/modbus-shield)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

A **Modbus TCP retrofit security proxy** for legacy devices. One static
binary, one box in front of the legacy device. The device keeps speaking
plain Modbus TCP; the proxy does all the security and shielding work.

```
[SCADA] ──┐
[Node-RED] ──► Modbus TCP ──►  ┌──────────────────────┐  ──Modbus TCP──►  ┌───────────────┐
[EV charger]─┘  N clients      │    modbus-shield     │   one connection  │ legacy device │
                               └──────────────────────┘                   └───────────────┘
                               ACLs · read-only · limits
```

## Why

Legacy Modbus TCP devices have no security and often no resilience:
the protocol itself provides none (no auth, no encryption, defined in
1979 and unchanged since), and many devices accept only one or very few
concurrent TCP connections — a second poller crashes or degrades them.
Replacing them is expensive or impossible; touching their firmware is
off the table.

modbus-shield is the box you put in front of them (retrofitting):

- **Zero-touch on the device** — it keeps speaking plain Modbus TCP;
  the proxy does all the security work. No firmware changes, no
  register-map changes.
- **One box is enough** — clients are repointed to the box IP once;
  that repointing is the whole migration.
- **The device sees one connection forever** — all clients multiplex
  onto a single upstream connection, fed through in a fair queue.
  Fragile single-connection devices are protected from connection
  storms by design.
- **Shielding limits** — connection cap and rate limit per listener
  defend the device from polling storms (Victron + Home Assistant + an
  EV charger polling one inverter is the canonical accident).
- **Access control** — client IP allow-lists and a read-only mode
  ("anyone may read the temperatures, nobody may write setpoints").
- **Deploy by paste** — two flags, done (see [examples/](examples/)).

The v1 essence: a **dumb-but-strict forwarder** — same data in and out,
only filtered and queued. The proxy parses the 7-byte MBAP header and
forwards the PDU as an opaque blob; vendor register maps, word-swap
encodings and data-type quirks flow through untouched between client
and device.

## Is modbus-shield the right tool?

Not always. Prefer the simplest boundary that solves the problem:

- **You need protocol translation or register remapping of data** —
  modbus-shield is a transport-level proxy; it does not convert
  registers (e.g. SunSpec models). Look at the device firmware or a
  protocol gateway instead.
- **Only the network path needs protection, and clients are trusted** —
  a firewall rule or VPN (WireGuard/IPsec) segmenting the SCADA network
  may be simpler.
- **You need a flexible programmable Modbus router** —
  [tiagocoutinho/modbus-proxy](https://github.com/tiagocoutinho/modbus-proxy)
  is an established Python multiplexer with the same transparent
  forwarding model (but no ACLs, no read-only mode, no metrics, and a
  Python runtime on the box).

Use modbus-shield when the legacy device cannot change and you need an
appliance-like security gate in front of it: multiplexing, shielding
limits, IP allow-lists, read-only policy, Prometheus metrics, config
validation and self-tests, a static binary and hardened systemd units.
It is intentionally opinionated about deployment and operations.

## Deployment shape

| Shape | Topology | Use when |
|---|---|---|
| [Gateway box](examples/gateway.md) (v1) | `[N clients] ⇄ modbus-shield ⇄ [legacy device]` | One box in front of the device; the retrofit use case |
| [TLS front leg](examples/tls.md) (B1) | `[TLS clients] ⇄ TLS ⇄ modbus-shield ⇄ plain ⇄ [device]` | Clients on an untrusted segment; encrypted, optionally cert-authenticated (mTLS) front door |
| [Two-proxy secured line](examples/two-proxy.md) (B2) | `[N clients] ⇄ plain ⇄ box ⇄ TLS/mTLS ⇄ box ⇄ plain ⇄ [device]` | Clients and device in different segments/sites; the untrusted link between the boxes carries only TLS |
| [Health via Modbus](examples/health.md) (B4) | `[SCADA] ⇄ modbus-shield ⇄ [device]` (health on a virtual unit-ID) | Plant SCADA monitors the box itself with the Modbus tooling it already has — no extra port or tooling |

Planned (see [BACKLOG.md](BACKLOG.md)): transparent bump-in-the-wire
(B3). Security note: the Modbus Organization publishes a TLS security
profile for Modbus/TCP ([MB-TCP-Security
spec](https://www.modbus.org/file/secure/modbussecurityprotocol.pdf),
"mbaps": TLS on port 802, mandatory mutual X.509 auth, role-based
authorization via certificate extensions). modbus-shield's TLS legs are
wire-compatible with that profile (TLS 1.2 minimum, standard X.509, the
mbap ADU untouched); full mbaps conformance — mandatory mutual auth and
role-based authorization — is a deliberate future option, not the
default, because retrofit clients and devices in the field don't speak
it.

## Quick start

Build (plain Go toolchain, no other dependencies):

```bash
make            # or: go build -o bin/modbus-shield ./cmd/modbus-shield
```

### Plug and play (no config file)

```bash
# the retrofit box: everyone may read, nobody may write,
# only the SCADA subnet may connect at all
modbus-shield gateway \
  --listen :5020 \
  --device 10.0.0.42:502 \
  --read-only \
  --allow 10.8.0.0/24 \
  --max-clients 8 \
  --rate-per-sec 50
```

Point the clients at the box IP instead of the device IP. Full
walkthrough: [examples/gateway.md](examples/gateway.md).

### Config files

Each instance is one YAML file; each `devices:` entry couples exactly
one front-leg listener with one upstream device. Template:
[`configs/gateway.yaml`](configs/gateway.yaml).

```bash
modbus-shield gateway --config /etc/modbus-shield/gateway.yaml
```

## Tools

```bash
# validate a config without running (pre-apply hook for tooling/web UIs;
# --json for machine-readable output):
modbus-shield validate --config /etc/modbus-shield/gateway.yaml

# validate + probe the environment (real FC3 Modbus read directly to
# each configured device; an exception response still proves liveness;
# --probe=false skips the network):
modbus-shield selftest --config /etc/modbus-shield/gateway.yaml

# other commands:
modbus-shield genpsk    # fresh random 32-byte hex key (tunnel milestone)
modbus-shield version
```

Both `validate` and `selftest` accept the same flags as the `gateway`
subcommand (or `--config`), so a web UI can build the form, validate
with `validate --json`, and offer a "test connection" button backed by
`selftest --json`.

## Features

- **Transparent MBAP proxying** — length-prefixed framing, protocol-ID
  validation, 260-byte ADU cap; requests correlated by transaction ID
  with per-request deadlines and stale-response discard (a device that
  echoes wrong transaction IDs cannot desynchronize the stream).
- **Multiplexing** — N client connections → one upstream connection,
  fair first-come-first-served scheduling, backpressure that never
  wedges (one stalled client cannot block the others).
- **Multi-device** — one listener + device pair per config entry.
- **Unit-ID remapping** — `device_unit_id` rewrites requests toward the
  device and responses back to the client's unit ID (serial-gateway
  style).
- **Access control** — per-listener IP allow-lists; read-only mode
  rejects write function codes (5, 6, 15, 16, 21, 22, 23) with a clean
  Modbus exception generated by the proxy — the device never sees the
  write.
- **Shielding** — connection cap and token-bucket rate limit per
  listener; rate-rejected requests get exception 0x06 (Server Device
  Busy) and never reach the device.
- **Never-down** — upstream reconnect with bounded backoff; client and
  listener errors never kill the listener; graceful SIGINT/SIGTERM
  shutdown.

## Metrics

Prometheus endpoint via `--metrics-addr` (or `metrics_listen` in YAML):

| Metric | Labels | Meaning |
|---|---|---|
| `modbus_shield_connections_accepted_total` | — | front-leg connections admitted |
| `modbus_shield_connections_rejected_total` | — | rejected by conn cap or allow-list |
| `modbus_shield_requests_total` | `device`, `outcome` | requests by outcome: `forwarded`, `exception_device`, `exception_policy`, `exception_rate` |
| `modbus_shield_request_errors_total` | — | upstream exchange errors |
| `modbus_shield_stale_responses_discarded_total` | — | stale/mismatched device responses discarded |
| `modbus_shield_reconnects_total` | — | successful upstream dials (initial connect counts) |
| `modbus_shield_device_up` | `device` | upstream connection state gauge |
| `modbus_shield_forward_latency_seconds` | `device` | per-device forwarding latency histogram |

## Appliance deployment

- **Static binary** — `make release` produces a stripped, cgo-free
  static binary suitable for any Linux appliance (Pi, DIN-rail SBC).
- **systemd unit** — [`deploy/`](deploy/) ships a hardened unit file
  (`Restart=on-failure`, `ProtectSystem=strict`,
  `CAP_NET_BIND_SERVICE` for privileged ports).
- **Supply chain** — `make sbom` produces SPDX + CycloneDX SBOMs of the
  release binary into `dist/`; `make vulnscan` matches them against
  NVD/GHSA/OSV and fails on HIGH-severity findings. Both exit 77 (skip)
  when syft/grype are not installed.
- **Operations** — reconnect with backoff, graceful shutdown, config
  validation and self-tests for on-site commissioning.

## Testing

```bash
make test      # vet + staticcheck + govulncheck + go test ./... -race -timeout 180s
make interop   # real-client interop (mbpoll) against a fake device; exit 77 = skip
```

The test suite includes an in-Go fake Modbus device, e2e multiplexing
and recovery tests under `-race`, goroutine-leak regression tests, fuzz
targets for the MBAP parser with committed regression corpora (re-run
in every `go test`), and a real-client interop script driving
[mbpoll](https://github.com/epsilonrt/mbpoll) through the gateway
(reads, writes, exception pass-through, unit-ID addressing, concurrent
clients). There is no Modbus conformance suite — this suite is the
anchor.

## Documentation

- [`examples/`](examples/) — copy-paste deployment walkthroughs
  (gateway, multi-device, production operations).
- [`configs/`](configs/) — YAML template.
- [`deploy/`](deploy/) — systemd unit file.
- [`BACKLOG.md`](BACKLOG.md) — things to implement later.
- [`AGENTS.md`](AGENTS.md) — architecture, wire-level details and the
  maintenance rules.

## License

[MIT](LICENSE)
