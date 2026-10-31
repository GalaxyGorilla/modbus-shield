<h1><a href="https://saschakattelmann.de"><img src="docs/assets/sascha-kattelmann-logo.png" alt="" height="42" align="absmiddle"></a>&#8202; Modbus Shield</h1>

[![Go Reference](https://pkg.go.dev/badge/github.com/GalaxyGorilla/modbus-shield.svg)](https://pkg.go.dev/github.com/GalaxyGorilla/modbus-shield)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

A **Modbus TCP security proxy** for legacy devices. One static binary.
The device keeps speaking plain Modbus TCP; the proxy does all the
security and shielding work.

**Status:** production-ready for the documented software scope. Physical-device
validation and site commissioning are still required; see
[Production readiness](#production-readiness).

**Never heard of Modbus?** Read the [two-minute primer](examples/gateway.md#2-two-minutes-of-modbus-background)
below the fold — everything else in this document assumes only that.

```mermaid
flowchart LR
    C["Existing clients<br/>SCADA · HMI · dashboards"]
    S["modbus-shield<br/>allow-list · write policy · limits"]
    D["Legacy Modbus device<br/>unchanged"]
    C -->|"Modbus TCP"| S
    S -->|"one shared connection"| D
```

**Most users start here:** follow the
[single-device gateway walkthrough](examples/gateway.md). It explains Modbus
from scratch, gives a minimal configuration, and ends with a real connection
test. Use the [scenario picker](#deployment-shape) only if you need TLS,
multiple devices, two boxes, certificate roles, or a transparent cable-splice
installation.

## Why

Legacy Modbus TCP devices have no security and often no resilience:
the protocol itself provides none (no auth, no encryption, defined in
1979 and unchanged since), and many devices accept only one or very few
concurrent TCP connections — a second poller crashes or degrades them.
Replacing them is expensive or impossible; touching their firmware is
off the table.

modbus-shield sits in front of them — commonly as a small dedicated box
in a retrofit install, but the software itself is just a proxy service
that runs anywhere:

- **Zero-touch on the device** — it keeps speaking plain Modbus TCP;
  the proxy does all the security work. No firmware changes, no
  register-map changes.
- **One hop is enough** — clients are repointed to the proxy once;
  that repointing is the whole migration.
- **The device sees one connection forever** — all clients multiplex
  onto a single upstream connection, fed through in a fair queue.
  Fragile single-connection devices are protected from connection
  storms by design.
- **Shielding limits** — connection cap, rate limit, optional request
  pacing (`request_delay_ms`) and idle-client reaping (`idle_timeout_ms`)
  per listener
  defend the device from polling storms (Victron + Home Assistant + an
  EV charger polling one inverter is the canonical accident).
- **Access control** — client IP allow-lists and a read-only mode
  ("anyone may read the temperatures, nobody may write setpoints"), an
  address-scoped write policy for the finer question ("this SCADA may
  write registers 0-99, that dashboard may only write 400-499"), or
  full per-role function-code rights via certificate roles (mbaps mode,
  [examples/mbaps.md](examples/mbaps.md)).
- **Change without downtime** — `SIGHUP` re-reads the config and swaps
  ACLs, write policy, limits and other per-request settings in place;
  client connections and the single device connection stay up.
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

## Production readiness

The documented gateway scope is feature-complete and production-ready as
software. The race suite exercises the built proxy, TLS/mTLS, RTU-over-TCP,
multi-device routing, policy reloads and failure recovery; `mbpoll`
independently drives reads, writes, exceptions, unit IDs and concurrent clients
through the gateway. The repository also supplies hardened service units,
health metrics, configuration validation, self-tests and an operations guide.

**Known validation boundary:** the project has not yet completed testing
against physical PLCs, meters, drives, converters or gateways. Before relying
on a specific installation, commission it with the real device and validate
vendor timing/framing quirks, sustained load, power and network interruption,
the target Linux host's transparent-netfilter path where used, and installation
failure modes. This is deployment validation, not unfinished functionality in
the documented scope. External security review and regulatory certification
remain separate work. See the [operations guide](examples/operations.md) for
commissioning and failure diagnosis.

The commercial value is the retrofit boundary: operators can add encryption,
identity, scoped writes and resilience without replacing the installed asset
or translating its register model. This also makes modbus-shield suitable as
the Modbus module in a broader multi-protocol critical-infrastructure
appliance; appliance-level orchestration remains outside this repository.

## Deployment shape

**Not sure which shape is yours?** The one-line picker:

- "I just want a proxy in front of the device" → [Gateway](examples/gateway.md)
- "Clients and device are on different sites/segments" → [Two-proxy secured line](examples/two-proxy.md)
- "The network between clients and the proxy is untrusted" → [TLS front leg](examples/tls.md)
- "Different people deserve different permissions" → [mbaps role authorization](examples/mbaps.md)
- "I can't reconfigure anything — cable splice only" → [Transparent bump-in-the-wire](examples/transparent.md) (Linux-only)
- "Plant SCADA should monitor the proxy itself" → [Health via Modbus](examples/health.md)

| Start here | Your situation | What changes |
|---|---|---|
| [Gateway](examples/gateway.md) | One or more clients poll one legacy device | Clients point at modbus-shield; the device stays unchanged |
| [TLS front leg](examples/tls.md) | The client-facing network is untrusted | Clients use TLS or mTLS to reach the same gateway |
| [Two-proxy secured line](examples/two-proxy.md) | Clients and device are in different sites or segments | Place one box at each end; only the middle link uses TLS |
| [Multi-device](examples/multi-device.md) | One box protects several devices | Give each device its own listener and policy |
| [mbaps roles](examples/mbaps.md) | Different certificate holders need different rights | Add mTLS certificates carrying operator/engineer roles |
| [Transparent mode](examples/transparent.md) | Clients cannot be repointed | Insert a Linux box in-path; clients keep dialing the device IP |
| [Health via Modbus](examples/health.md) | SCADA should monitor the box itself | Reserve one virtual unit ID for proxy health |

Planned (see [BACKLOG.md](BACKLOG.md)): none — all backlog items are done.
Security note: the Modbus Organization publishes a TLS security
profile for Modbus/TCP ([MB-TCP-Security
spec](https://www.modbus.org/file/secure/modbussecurityprotocol.pdf),
"mbaps": TLS on port 802, mandatory mutual X.509 auth, role-based
authorization via certificate extensions). modbus-shield's TLS legs are
wire-compatible with that profile (TLS 1.2 minimum, standard X.509, the
mbap ADU untouched), and the **role-authorization subset** is
implemented as the optional mbaps mode (B12) — mTLS plus per-role
function-code rights from the Modbus role certificate extension. Full
port-802 mbaps conformance remains out of scope: retrofit clients and
devices in the field don't speak it.

## Quick start

Build (plain Go toolchain, no other dependencies):

```bash
make            # or: go build -o bin/modbus-shield ./cmd/modbus-shield
```

### Plug and play (no config file)

```bash
# read-only gateway: everyone may read, nobody may write,
# only the SCADA subnet may connect at all
modbus-shield gateway \
  --listen :5020 \
  --device 10.0.0.42:502 \
  --read-only \
  --allow 10.8.0.0/24 \
  --max-clients 8 \
  --rate-per-sec 50 \
  --rate-per-client-per-sec 5
```

Point the clients at the proxy address instead of the device IP. Full
walkthrough: [examples/gateway.md](examples/gateway.md).

### Write policy instead of all-or-nothing

```bash
# reads open; FC6/FC16 writes only to registers 0-99 for unit 1
modbus-shield gateway \
  --listen :5020 --device 10.0.0.42:502 \
  --allow 10.8.0.0/24 \
  --write-range '*:6,16:0-99'
# '*' = any unit / any write FC / any address; a leading '!' makes it a
# deny rule (deny wins), and --write-default allow switches to deny-list
# mode. Denials are exception 0x02 and never reach the device.
```

### Config files

Each instance is one YAML file; each `devices:` entry couples exactly
one front-leg listener with one upstream device. Template:
[`configs/gateway.yaml`](configs/gateway.yaml).

```bash
modbus-shield gateway --config /etc/modbus-shield/gateway.yaml

# apply edited ACLs, write policy, limits, cache TTL, pacing, unit-ID
# remap or mbaps roles without dropping clients or the device link:
kill -HUP $(cat /run/modbus-shield.pid)   # or: systemctl reload modbus-shield-gateway
```

## Tools

```bash
# validate a config without running (pre-apply hook for tooling/web UIs;
# --json for machine-readable output):
modbus-shield validate --config /etc/modbus-shield/gateway.yaml

# validate + probe the environment (real FC3 read over each configured
# device transport: plain/TLS and MBAP/RTU-over-TCP; an exception still
# proves liveness; --probe=false skips the network):
modbus-shield selftest --config /etc/modbus-shield/gateway.yaml

# other commands:
modbus-shield genpsk    # reserved helper; TLS/mTLS deployments use X.509 certs
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
  first-come-first-served scheduling, backpressure that never
  wedges (one stalled client cannot block the others).
- **Multi-device** — one listener + device pair per config entry, plus
  optional `extra_listen` front doors sharing the same upstream
  connection and shielding limits (B10).
- **Unit-ID remapping** — `device_unit_id` rewrites requests toward the
  device and responses back to the client's unit ID (serial-gateway
  style).
- **RTU-over-TCP device side** — `rtu_over_tcp` makes the device leg
  speak bare Modbus RTU frames (unit address + PDU + CRC16) for cheap
  serial-to-TCP converters that don't wrap MBAP; the front leg stays
  Modbus TCP and clients notice nothing (B7).
- **Opt-in read cache** — `read_cache_ttl_ms` serves repeated FC 1-4
  reads from memory, shielding very slow devices from heavy polling;
  cached responses carry fresh transaction IDs. A cache hit generates no
  device traffic and is answered BEFORE the rate limiters — they exist to
  protect the device, so a free answer is never charged a token or turned
  into 0x06; writes and exceptions are never cached; 0 = fully
  transparent (B8).
- **Access control** — per-listener IP allow-lists; read-only mode
  rejects write function codes (5, 6, 15, 16, 21, 22, 23) with a clean
  Modbus exception generated by the proxy — the device never sees the
  write.
- **Address-scoped write policy** — `write_policy` answers *which* writes
  may pass instead of all-or-nothing: rules scope by client unit ID,
  function code and address range, with `default: deny` (allow-list) or
  `default: allow` (deny-list). Deny overrides allow, and an allow rule
  must COVER the whole write range, so a multi-register write can never
  straddle an allowed window; denials are exception 0x02 (Illegal Data
  Address) and never reach the device. Writes whose address range cannot
  be parsed (truncated PDU, quantity 0, 16-bit overflow) are denied.
- **Config reload** — `SIGHUP` re-reads `--config` and applies the
  per-request settings (ACLs, write policy, read-only, limits, cache TTL,
  pacing, idle timeout, unit-ID remap, health unit ID, mbaps roles) with
  no client disconnect and no device reconnect. Listener, device address
  and TLS changes need a restart and are logged as warnings. MBAPS role
  revocations affect the next request even on an established mTLS session.
- **Shielding** — connection cap, token-bucket rate limit (shared and
  per client), optional request pacing and idle-client timeout per
  listener; rate-rejected requests get exception 0x06 (Server Device
  Busy) and never reach the device; idle clients are reaped so dead
  pollers don't hold cap slots. `rate_per_sec` bounds total device
  traffic, `rate_per_client_per_sec` keeps one runaway poller from
  spending the budget the others need (its rejections don't charge the
  shared bucket), and the upstream queue serves clients in arrival order
  so a quiet poller is never starved.
- **Non-conforming devices** — `lenient_correlation` tolerates a device
  leg that does not echo transaction IDs or puts junk in the MBAP
  protocol-ID field (some converters/gateways do; strict mode rejects
  them, lenient mode accepts and rewrites the header so clients still see
  their own transaction ID). Framing stays strict either way; default
  off.
- **Never-down** — upstream reconnect with bounded backoff; client and
  listener errors never kill the listener; graceful SIGINT/SIGTERM
  shutdown that drains in-flight requests instead of cutting responses
  off mid-write, then closes idle connections (bounded, always
  terminates).

## Metrics

Prometheus endpoint via `--metrics-addr` (or `metrics_listen` in YAML):

| Metric | Labels | Meaning |
|---|---|---|
| `modbus_shield_connections_accepted_total` | — | front-leg connections admitted |
| `modbus_shield_connections_rejected_total` | — | rejected by conn cap or allow-list |
| `modbus_shield_requests_total` | `device`, `outcome` | requests by outcome: `forwarded`, `exception_device`, `exception_policy` (read-only/mbaps), `exception_rate`, `exception_authz` (mbaps role denied), `cache_hit` |
| `modbus_shield_request_errors_total` | — | upstream exchange errors |
| `modbus_shield_stale_responses_discarded_total` | — | stale/mismatched device responses discarded |
| `modbus_shield_reconnects_total` | — | successful upstream dials (initial connect counts) |
| `modbus_shield_device_up` | `device` | upstream connection state gauge |
| `modbus_shield_forward_latency_seconds` | `device` | per-device forwarding latency histogram |

## Appliance deployment

- **Static binary** — `make release` produces a stripped, cgo-free
  static binary suitable for any Linux appliance (Pi, DIN-rail SBC).
- **Cross-builds** — `make release-all` produces stripped static binaries
  for all appliance platforms into `dist/`: `linux-amd64`, `linux-arm64`,
  `linux-armv7`. Pure Go with CGO disabled — cross-compiling is exact.
- **systemd unit** — [`deploy/`](deploy/) ships a hardened unit file
  (`Type=notify`, `WatchdogSec=30`, `Restart=on-failure`,
  `ProtectSystem=strict`, `CAP_NET_BIND_SERVICE` for privileged ports).
- **systemd watchdog** — the binary speaks sd_notify: `READY=1` only after
  every configured front listener has bound, then `WATCHDOG=1` pings while
  running (internal/watchdog), so a bind failure is never advertised ready
  and a wedged process is restarted by the host. When deployed on an in-path
  box, it IS the device's network path — it must never hang silently. No-ops
  outside systemd.
- **Supply chain** — `make sbom` produces SPDX + CycloneDX SBOMs of the
  release binary into `dist/`; `make vulnscan` matches them against
  NVD/GHSA/OSV and fails on HIGH-severity findings. Both exit 77 (skip)
  when syft/grype are not installed.
- **Operations** — reconnect with backoff, graceful shutdown, config
  reload via `SIGHUP` (no restarts, no dropped clients), config
  validation and self-tests for on-site commissioning.

## Testing

```bash
make build        # bin/modbus-shield
make vet          # go vet ./...
make test         # gofmt gate + go test ./... -race -timeout 180s
make staticcheck  # staticcheck ./...
make govulncheck  # govulncheck ./...
make interop      # real-client mbpoll interop; exit 77 = skip
```

The test suite includes an in-Go fake Modbus device, e2e multiplexing
and recovery tests under `-race`, goroutine-leak regression tests, fuzz
targets for the MBAP parser with committed regression corpora (re-run
in every `go test`), fairness and shutdown-drain tests, multi-device
primary/extra-listener isolation, live MBAPS revocation, configured-transport
selftests, systemd readiness ordering, and a
real-client interop script driving
[mbpoll](https://github.com/epsilonrt/mbpoll) through the gateway
(reads, writes, exception pass-through, unit-ID addressing, concurrent
clients). The suite is green on Linux and macOS (the conntrack and
systemd tests are the only platform-specific parts); there is no Modbus
conformance suite — this suite is the anchor. The interop suite is
actually run locally (`brew install mbpoll`, `make interop` → PASS):
FC3/FC4 reads, FC6 write, exception pass-through, unit-ID addressing,
8 concurrent mbpoll clients through one upstream connection.
A real-binary smoke (`scripts/smoke-reload.sh`) drives the write policy
and a live `SIGHUP` reload over sockets.

## Documentation

- [`examples/`](examples/) — copy-paste deployment walkthroughs with a
  scenario picker: [gateway.md](examples/gateway.md) (start here; includes
  a two-minute Modbus primer), multi-device, TLS, two-proxy, mbaps roles,
  health-via-Modbus, transparent, and the production operations guide.
- [`configs/`](configs/) — YAML template.
- [`deploy/`](deploy/) — systemd unit file.
- [`BACKLOG.md`](BACKLOG.md) — all items done; kept as the decision record.
- [`AGENTS.md`](AGENTS.md) — architecture, wire-level details and the
  maintenance rules.

## License

[MIT](LICENSE)
