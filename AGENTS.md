# AGENTS.md — modbus-shield

> **Read this file first. Update it at the end of every task** — behavior,
> layout, commands, decisions. Treat it as documentation-as-code.

## 1. Mission

This project is a **Modbus TCP retrofit security proxy**. From the original
author:

> "What I want to do is basically 'retrofitting', e.g. adding security
> capabilities to legacy devices by adding a box in front of them, or even
> inside their casing."

Deployment model (v1, gateway reverse proxy):

```
[N clients] --Modbus TCP--> [modbus-shield box] --Modbus TCP--> [legacy device]
```

The device sees **one** connection forever; N clients are fed through in a
fair queue. The box is the device's security gate: ACLs, write protection,
connection/rate limits, and (later) TLS terminate at the proxy — the
device-side wire stays 100% plain Modbus TCP. The device notices nothing.

The v1 essence: a **dumb-but-strict forwarder** — same data in/out, only
filtered and queued. Deliberately NOT (yet): protocol translation, caching,
serial ports.

## 2. Decisions (do not re-litigate without strong reason)

| Topic | Decision |
|---|---|
| Language | **Go** (chosen deliberately: static single binary for appliance use, goroutines/channels map 1:1 onto the multiplexer, race detector + native fuzzing for the "well tested" bar; snmp-shield sibling synergy) |
| Protocol scope | **Modbus TCP only** (v1) — no RTU framing, no local serial ports; unit-ID remap covers serial converters that expose Modbus TCP |
| Primary shape | **Gateway reverse proxy** (clients repointed to the box IP); transparent bump-in-the-wire is backlog B3; two-proxy secured line is B2 |
| Security v1 | **IP ACLs + function-code policy (read-only) + shielding limits** (conn cap + rate limit); TLS front leg is B1 |
| Caching | **None** — exactly transparent semantics (opt-in TTL cache is B8) |
| Transport level | Parse the 7-byte MBAP header, forward the PDU as an **opaque blob** — vendor register-map/encoding chaos flows through untouched |
| Correlation posture | **Strict on framing, liberal on correlation** — real devices deviate (wonky txn-ID echo, unit-ID swaps) |
| Config | YAML per instance + no-YAML flags one-liner mode (field techs paste two lines) |
| Ground truth | Modbus Organization spec PDFs, NOT RFCs (none exist): MODBUS Application Protocol Specification V1.1b3 (Apr 2012) + MODBUS Messaging on TCP/IP Implementation Guide V1.0b |

## 3. Status / Roadmap

**Current state: milestone 4 — multiplexing proven. `internal/proxy`:
front-leg listener, per-client lock-step loop, upstream connection with
reconnect/backoff, stale-response discard, unit-ID remap, IP allow-list
gate, read-only policy, race-free connection cap. Concurrency e2e under
`-race` (11 tests): 8 clients × 25 reads multiplex onto exactly ONE
upstream connection (LockStep device), fairness under 100ms/request
device, idle/stalled client isolation, cap enforcement (2/2 split),
device-outage re-dial recovery, goroutine-leak regression.**

| Milestone | Status |
|---|---|
| Scaffold: dirs, go.mod, .gitignore, Makefile, AGENTS.md, BACKLOG.md | done |
| `internal/mbtcp`: MBAP header build/parse (single parser, fuzz-ready), ADU cap, unit-ID types | done |
| `internal/config`: YAML + flags, multi-device entries, ACL/policy config, validation | YAML done (flags mode lands with the CLI milestone) |
| Gateway core: listener, per-client lock-step loop, upstream conn + reconnect/backoff, stale-response discard | done |
| Multiplexing + fairness + backpressure (goroutine-leak regression test) | done (rate limit still open, tracked with ACL row) |
| ACLs + read-only policy + shielding limits (conn cap, rate limit) | conn cap + read-only done; rate limit pending |
| Observability (Prometheus + zap) | pending |
| CLI: `validate` / `selftest` / flags mode / `version` | pending |
| Fuzzing (`internal/mbtcp` targets + regression corpus) + mbpoll interop script | pending |
| Docs: README (why/deployment shapes/decision guidance), examples, systemd units | pending |

### Verification targets (from the plan)

- Milestone 4 acceptance met: **8 clients × 25 reads through the box onto
  a fragile single-connection device — exactly one upstream connection,
  all correct under `-race`.**
- Testing bar (every commit): build + vet + `go test ./... -race` clean.
- Adversarial: garbage datagrams never kill the listener, oversized ADUs
  rejected, late/duplicate/mismatched transaction responses discarded.
- In-Go fake Modbus device for all e2e; real-client interop (`mbpoll`)
  gated with exit 77; parser fuzz targets with committed regression corpus.

## 4. Repository Layout

```
cmd/modbus-shield/         main package; role via subcommand (gateway) + validate/selftest/genpsk/version
internal/mbtcp/            MBAP header build/parse (mbtcp.go, fuzz_test.go + unit tests)
internal/config/           YAML config (config.go + tests); flags overrides land with CLI
internal/proxy/            gateway core: gateway.go, upstream.go, runner.go, logger.go + fakedevice e2e
internal/acl/              client IP allow-list + write-FC classifier (acl.go + tests)
internal/observ/           zap logging + Prometheus metrics
configs/                   example YAML templates
scripts/                   smoke + interop scripts (mbpoll), SBOM entry point
deploy/                    hardened systemd unit files
examples/                  copy-paste deployment walkthroughs
```

(Planned; directories are created as milestones land. Empty for now:
internal/*, configs/, scripts/, deploy/, examples/.)

## 5. Build / Test

Go at `/usr/local/go/bin/go` (on PATH via `/etc/profile.d/go.sh`);
go.mod declares minimum **1.24.0** (CI-free project — tests run manually).

```bash
go build ./...
go vet ./...
go test ./... -race -timeout 180s
```

`make build` / `make test` / `make vet` / `make release` wrap the same
commands (`release` = stripped static binary, `CGO_ENABLED=0
-trimpath -ldflags "-s -w"`, for appliance deployment).

**Static analysis** (installed in `~/go/bin`, run after every dependency
change or parser edit — pragmatic: fix only meaningful findings):

```bash
~/go/bin/staticcheck ./...
~/go/bin/govulncheck ./...
```

**SBOM + vulnerability scan** (installed in `~/go/bin`, run after every
dependency change or before a release):

```bash
make sbom       # release binary -> syft -> dist/modbus-shield.{spdx,cdx}.json
make vulnscan   # grype db update + grype --fail-on high vs NVD/GHSA/OSV
```

Missing tools → exit 77 (skip), like the interop scripts.

**Acceptance for every commit**: build + vet + `go test -race ./...` clean.
Note: non-login shells may not have `go` on PATH — use `/usr/local/go/bin/go`
or set `-timeout` on `go test` (network tests would hang without one).

## 6. Key Dependencies (go.mod)

- `gopkg.in/yaml.v3 v3.0.1` (milestone 2; govulncheck-clean)
- planned: `prometheus/client_golang`, `spf13/pflag`, `go.uber.org/zap`
- Modbus protocol handling is implemented in-house on `encoding/binary`
  (full parser control for fuzzability); a client lib (e.g. grid-x/modbus)
  is only considered for the `selftest` probe — to be decided at that
  milestone.

## 7. Design Notes

- **MBAP header** (MODBUS Messaging on TCP/IP Implementation Guide V1.0b):
  transaction-ID 2B (client-chosen, echoed by server), protocol-ID 2B
  (always 0), length 2B (bytes following, incl. unit-ID), unit-ID 1B.
  Max ADU 260 B (max PDU 253 B). TCP/502 (IANA modbus/tcp). Strict
  lock-step request/response per connection.
- **Framing rule**: read 7-byte header, validate protocol-ID == 0, read
  `length - 1` more bytes (PDU incl. unit-ID already counted). Reject
  length > 254 (ADU cap) and length < 2 as malformed; never let a
  declared length index past the actually-read bytes.
- **Function codes** (V1.1b3): read = 1 (coils), 2 (discrete), 3 (holding),
  4 (input); write = 5, 6, 15, 16, 22, 23 (+ file 20/21, FIFO 24).
  Read-only policy blocks the write set with a Modbus exception response
  (FC|0x80, code 0x01 Illegal Function) so clients see a clean
  protocol-level rejection — the exception is generated by the proxy,
  the device never sees the write.
- **Exception codes**: 0x01 Illegal Function, 0x02 Illegal Data Address,
  0x03 Illegal Data Value, 0x04 Server Device Failure, 0x05 Acknowledge,
  0x06 Server Device Busy, 0x0A Gateway Path Unavailable, 0x0B Gateway
  Target Device Failed To Respond (0x0A/0x0B are the natural codes for
  proxy-generated upstream errors).
- **`internal/mbtcp` API contract**: parse entry points are `ParseADU(buf)`
  (strict: exactly one frame, no truncation/trailing) and `ReadADU(r)`
  (streaming: validates the header before reading the body, returns bare
  `io.EOF` on clean close at a frame boundary, wraps `io.ErrUnexpectedEOF`
  for truncated frames). All rejections are package sentinels
  (`ErrShortFrame`, `ErrTruncated`, `ErrTrailingBytes`, `ErrProtocolID`,
  `ErrLengthTooSmall`, `ErrLengthTooLarge`) — the fuzz target enforces
  this. `ADU.PDU` never contains the unit ID (`Header.UnitID` holds it) so
  unit-ID remapping can rewrite both independently. Build via `NewADU`/
  `AppendTo` (buffer-reusing). Proxy-generated exceptions use
  `ExceptionPDU(fc, code)` (FC|0x80 + code).
- **`internal/config` YAML schema** (one file = one instance, N
  `devices:` entries): `name` (opt; defaults to device_addr), `listen_addr`,
  `device_addr`, `read_only`, `allow` (IPs/CIDRs), `max_clients` (def 16),
  `rate_per_sec`, `timeout_ms` (def 5000), `device_unit_id` (opt remap),
  plus top-level `log.{level,format}` and `metrics_listen`. Validate
  enforces: ≥1 device, host:port syntax, unique listen addrs,
  non-negative limits, valid IP/CIDR entries. Accessors:
  `Device.RequestTimeout()`, `HasUnitRemap()`, `UpstreamUnitID()`.
- **`internal/proxy` gateway contract**: one `gateway` per config device
  = front-leg `Serve` loop + per-client `handleClient` lock-step loop
  (read one ADU -> forward -> write one ADU). All client traffic
  multiplexes over ONE `upstream` connection (legacy devices accept few
  connections); exchanges are serialized by `upstream.mu`, one in-flight
  request, responses matched by transaction ID, late/stale responses
  discarded (stream stays frame-aligned, skipping is safe). ANY exchange
  error drops the device connection (post-timeout stream state is
  unknown); next exchange re-dials with 100ms->1s bounded backoff and
  `ErrDeviceUnreachable` (clients get exception 0x0B) when the deadline
  expires. Client-side errors only kill that client's connection; the
  listener never dies. Proxy-generated exceptions carry the client's
  original txn-ID + unit ID. Unit-ID remap: request rewritten to
  `device_unit_id`, response rewritten back to the client's unit ID.
  `Runner` owns gateways: `NewRunner(cfg, log)` -> `Run()` (binds all,
  first bind error aborts) -> `Stop()`; `bound` channel signals when
  listeners are up (tests wait on it before dialing). `Logger` is a
  minimal zap-agnostic interface injected by main.
- **`internal/acl` contract**: `IsWrite(fc)` classifies write FCs
  (5, 6, 15, 16, 21, 22, 23; reads + diagnostics + FIFO 24 allowed).
  `NewList(entries)` returns nil for empty (no restriction); `Allowed(ip)`
  is nil-receiver safe (nil = allow all). Read-only rejection is a
  proxy-generated exception 0x01 — the device never sees the write.
- **Connection cap must be one atomic decision** (`gateway.admit`):
  `clients.Add(1)` IS the admission (allowed while new value <= cap);
  rejecting decrements. Never Load-then-Add across the decision or
  increment in the spawned handler goroutine — a burst of concurrent
  dials then slips past `max_clients` before handlers start (real race,
  caught by TestGatewayConnCapFriendly burst test). ACL check decrements
  on rejection too.
- **No RFCs exist for Modbus** — the spec PDFs above are the only ground
  truth, and there is no conformance suite: our adversarial test suite +
  mbpoll interop is the anchor. Real devices deviate (wonky txn-ID echo,
  unit-ID semantics); be strict on framing, liberal on correlation.
- **Vendor chaos stays out of the proxy**: register maps, word-swap
  encodings, data types are client↔device concerns; the PDU is opaque.
- **Multiplexing is the hard part** — the reference implementation
  (tiagocortinho/modbus-proxy) and its 5 years of issues prove it
  (freezes, fd exhaustion, pipe breaks, txn desync). Design accordingly:
  one in-flight transaction per upstream connection, responses matched by
  transaction-ID, per-request deadline, stale/late response discard,
  fair scheduling across clients, backpressure that never wedges.
- **Single-connection devices**: many legacy devices accept only one (or
  very few) TCP connections and crash or degrade under more — this is the
  reason the proxy exists; shielding limits (conn cap, rate limit) are a
  v1 feature, not an afterthought.
