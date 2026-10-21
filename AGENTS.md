# AGENTS.md — modbus-shield

> **Read this file first. Update it at the end of every task** — behavior,
> layout, commands, decisions. Treat it as documentation-as-code.

## 1. Mission

This project is a **Modbus TCP security proxy**. From the original
author, describing the deployment that motivated it:

> "What I want to do is basically 'retrofitting', e.g. adding security
> capabilities to legacy devices by adding a box in front of them, or even
> inside their casing."

Deployment model (v1, gateway reverse proxy):

```
[N clients] --Modbus TCP--> [modbus-shield] --Modbus TCP--> [legacy device]
```

The device sees **one** connection forever; N clients are fed through in a
fair queue. The proxy is the device's security gate: ACLs, write
protection, connection/rate limits, and TLS terminate at the proxy — the
device-side wire stays 100% plain Modbus TCP. The device notices nothing.
Commonly deployed as a small dedicated box in a retrofit install (the
motivation above), but the software itself is just a proxy service and
runs on any Linux host.

The v1 essence: a **dumb-but-strict forwarder** — same data in/out, only
filtered and queued. Deliberately NOT (yet): protocol translation, caching,
serial ports.

## 2. Decisions (do not re-litigate without strong reason)

| Topic | Decision |
|---|---|
| Language | **Go** (chosen deliberately: static single binary for appliance use, goroutines/channels map 1:1 onto the multiplexer, race detector + native fuzzing for the "well tested" bar; snmp-shield sibling synergy) |
| Protocol scope | **Modbus TCP only** (v1) — no RTU framing, no local serial ports; unit-ID remap covers serial converters that expose Modbus TCP |
| Primary shape | **Gateway reverse proxy** (clients repointed to the proxy); transparent bump-in-the-wire is backlog B3; two-proxy secured line is B2 |
| Security v1 | **IP ACLs + function-code policy (read-only) + shielding limits** (conn cap + rate limit); TLS front leg is B1; per-role FC rights over mTLS (mbaps mode) is B12 |
| Caching | **None** — exactly transparent semantics (opt-in TTL cache is B8) |
| Transport level | Parse the 7-byte MBAP header, forward the PDU as an **opaque blob** — vendor register-map/encoding chaos flows through untouched |
| Correlation posture | **Strict on framing, liberal on correlation** — real devices deviate (wonky txn-ID echo, unit-ID swaps) |
| Config | YAML per instance + no-YAML flags one-liner mode (field techs paste two lines) |
| Ground truth | Modbus Organization spec PDFs, NOT RFCs (none exist): MODBUS Application Protocol Specification V1.1b3 (Apr 2012) + MODBUS Messaging on TCP/IP Implementation Guide V1.0b. For security: MODBUS/TCP Security Protocol Specification MB-TCP-Security-v36 (2021-07-30) — the "mbaps" profile (port 802, mandatory mutual TLS, role-OID AuthZ). Our TLS legs are wire-compatible with it; full mbaps conformance (mandatory mTLS + role-based AuthZ) is a possible future mode, NOT adopted in v1 because retrofit clients/devices don't speak it |

## 3. Status / Roadmap

**Current state: BACKLOG COMPLETE + docs consistency pass + streamlining
pass + identity rewording.** The software is presented as what it is —
a **Modbus TCP security proxy**; the "box in front of the device" is a
deployment story (from the original motivation), not the identity.
README hero/Why/shape table, CLI usage + help text, and AGENTS.md
mission now say "proxy"/"host"; examples keep deployment-level box
phrasing where it describes a real dedicated-box install. All v1
milestones + B1–B12 + B15 done. B3 (transparent bump-in-the-wire,
Linux-only) landed after a design spike (docs/b3-transparent-mode.md):
`transparent: true` (or `--transparent`) forwards to the client's
ORIGINAL destination from netfilter conntrack (`SO_ORIGINAL_DST`) per
front-leg connection — cable-splice install with zero client/device
reconfiguration; `scripts/setup-transparent.sh` installs the idempotent
REDIRECT rule (never auto-run). **Fail-open by design**: a missing rule
/ bridging without redirecting flows traffic unproxied to the device
(shielding bypassed) — documented loudly. Docs audit (post-backlog):
README got a scenario picker + metric-table fixes (exception_authz,
cache_hit outcomes), gateway.md got a two-minute Modbus primer (section
0, no-modbus-knowledge requirement) + expanded hardening options,
examples/README.md got a use-when index (stale "Planned" line removed),
health.md register count corrected to 19 (B8), pymodbus snippets made
functional, configs/gateway.yaml transparent block moved to top level +
Run: path fixed. Full suite green under `-race`; staticcheck +
govulncheck clean.**

| Milestone | Status |
|---|---|
| Scaffold: dirs, go.mod, .gitignore, Makefile, AGENTS.md, BACKLOG.md | done |
| `internal/mbtcp`: MBAP header build/parse (single parser, fuzz-ready), ADU cap, unit-ID types | done |
| `internal/config`: YAML + flags, multi-device entries, ACL/policy config, validation | done (YAML + single-device flags mode) |
| Gateway core: listener, per-client lock-step loop, upstream conn + reconnect/backoff, stale-response discard | done |
| Multiplexing + fairness + backpressure (goroutine-leak regression test) | done |
| ACLs + read-only policy + shielding limits (conn cap, rate limit) | done (all: read-only, conn cap, rate limit) |
| Observability (Prometheus + zap) | done |
| CLI: `validate` / `selftest` / flags mode / `version` | done (gateway/validate/selftest/genpsk/version) |
| Fuzzing (`internal/mbtcp` targets + regression corpus) + mbpoll interop script | done (FuzzParseADU + FuzzReadADU, corpora committed; interop PASS rc=0) |
| Docs: README (why/deployment shapes/decision guidance), examples, systemd units | done (README + examples: gateway/multi-device/operations + deploy unit + make interop) |
| B1: TLS front leg (per-device `tls:` block + flags, mTLS) | done (config/proxy/CLI/tests + examples/tls.md) |
| B2: two-proxy secured line (`device_tls:` upstream leg + flags) | done (config/proxy/CLI/tests + examples/two-proxy.md) |
| B4: health-via-Modbus virtual unit-ID (`health_unit_id`) | done (proxy/health.go + tests + examples/health.md) |
| B5: inter-request pacing (`request_delay_ms`) | done (upstream timer + tests) |
| B6: idle client timeout (`idle_timeout_ms`) | done (handleClient read deadline + tests) |
| B9: connection-ID logging (`[conn N]` in client + device log lines) | done (connSeq counter, exchange takes connID, smoke-connid.sh) |
| B10: multiple listeners per device (`extra_listen` + `--extra-listen`) | done (config/proxy/CLI/tests; one upstream shared by all doors) |
| B11: systemd watchdog (`Type=notify` + `WatchdogSec`, sd_notify pings) | done (internal/watchdog + tests + real-binary smoke; deploy unit updated) |
| B12: mbaps role authorization (`mbaps:` block + `--mbaps-role`, per-role FC rights over mTLS) | done (config/proxy/CLI/tests + examples/mbaps.md + real-binary smoke) |
| B7: RTU-over-TCP device side (`rtu_over_tcp` + `--rtu-over-tcp`) | done (mbtcp RTU framing + upstream translation + tests + real-binary smoke) |
| B8: opt-in TTL read cache (`read_cache_ttl_ms` + `--read-cache-ttl-ms`) | done (proxy/cache.go + tests + real-binary smoke; health register 18, map v2) |
| B3: transparent bump-in-the-wire (`transparent: true` + `--transparent`, Linux-only) | done (origdst_linux.go + upstream per-conn target + tests + examples/transparent.md; design spike in docs/) |

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
internal/mbtcp/            MBAP + RTU framing (mbtcp.go, rtu.go + tests + FuzzParseADU/FuzzReadADU + corpora)
internal/config/           YAML config + single-device flags mode (config.go + tests)
internal/proxy/            gateway core: gateway.go, upstream.go, runner.go, logger.go, ratelimit.go, health.go, cache.go, origdst_linux.go/origdst_other.go + fakedevice e2e
internal/acl/              client IP allow-list + write-FC classifier (acl.go + tests)
internal/observ/           zap logging + Prometheus metrics (observ.go + tests; implements proxy.Metrics)
internal/watchdog/         sd_notify wrapper (READY + watchdog pings; no-ops outside systemd)
configs/                   example YAML templates
scripts/                   interop-modbus.sh (real mbpoll), gen-certs.sh (throwaway PKI incl. mbaps role certs), fakedevice.py, smoke scripts, SBOM entry point
deploy/                    hardened systemd unit files
examples/                  copy-paste walkthroughs: gateway.md, multi-device.md, operations.md (production guide), tls.md, two-proxy.md, mbaps.md, health.md, transparent.md
```

(All directories populated as of v1 feature-complete; see individual
milestone sections above for file inventories.)

## 5. Build / Test

Go at `/usr/local/go/bin/go` (on PATH via `/etc/profile.d/go.sh`);
go.mod declares minimum **1.26.0** (CI-free project — tests run manually).

**Latest local verification (2026-10-21):** `go build ./...`, `go vet
./...`, and `go test ./... -race -timeout 180s` passed under Go 1.27.3
(pinned via the `toolchain` directive in go.mod — GO-2026-6809 in the
Go 1.27.2 `crypto/x509` stdlib made 1.27.2 unusable for TLS-enabled
releases; with 1.27.3 `govulncheck ./...` reports no vulnerabilities).
`make release-all` produced valid static Linux amd64/arm64/armv7
binaries under 1.27.3; the amd64 binary ran `version`. `staticcheck
./...` passed. The optional `make interop` suite was not run because
`mbpoll` is absent (the script exits 77 by design).

**Read-cache + rate-limiter ordering (pinned by
TestGatewayRateLimitBeforeCache):** the rate limiter runs BEFORE the
cache lookup — a cache hit avoids device traffic but still consumes a
rate token and is rejected with 0x06 when the limit is exhausted.
All cache-ordering claims (config.go field comment, cache.go package
doc, BACKLOG.md B8 entry, README bullet) were re-audited and now state
this consistently; the B3 spike doc's "if we build it" / "decision
required" sections are explicitly framed as historical notes.

```bash
go build ./...
go vet ./...
go test ./... -race -timeout 180s
```

`make build` / `make test` / `make vet` / `make release` wrap the same
commands (`release` = stripped static binary, `CGO_ENABLED=0
-trimpath -ldflags "-s -w"`, for appliance deployment). `make release-all`
cross-builds stripped static binaries for all appliance platforms into
`dist/`: `linux-amd64`, `linux-arm64`, `linux-armv7` (pure Go + CGO
disabled = cross-compiling is exact; verified: all three build and the
amd64 binary runs). `make interop`
runs the real-client mbpoll interop suite (exit 77 = skip when mbpoll
is missing; see the Interop design note).

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
- `github.com/prometheus/client_golang v1.23.2` (milestone 5; govulncheck-clean)
- `go.uber.org/zap v1.27.0` (milestone 5; govulncheck-clean)
- `github.com/spf13/pflag v1.0.10` (milestone 6 CLI; snmp-shield-pinned)
- `github.com/coreos/go-systemd/v22 v22.7.0` (B11 watchdog; only the
  `daemon` package — sd_notify; govulncheck-clean)
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
- **Multiple listeners per device (B10)**: `extra_listen` (YAML list) +
  repeatable `--extra-listen` flag add front doors to the SAME gateway.
  `Runner.Run` binds `listen_addr` + every `extra_listen` entry and
  serves each listener with the same `gateway.Serve` — all doors share
  ONE upstream connection, one conn cap, one allow-list, one rate
  limiter, one TLS config (shielding stays per-device, which is the
  point: the fragile device sees one connection no matter how many
  doors). Validate enforces host:port syntax, no duplicate of the
  device's own listen_addr, and no collision with other devices'
  addresses (shared `seen` map). `r.lns` is in bind order: for gateway
  i, its listeners occupy a contiguous slice of length
  `len(1 + ExtraListen)` — tests use `startGatewayExtra` returning
  addresses in bind order.
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
- **`internal/proxy` rate limiter contract** (`ratelimit.go`): token
  bucket, capacity = 1 second's worth of `rate_per_sec` tokens, continuous
  refill, burst absorbed without rejection. `newRateLimiter(0|negative)`
  returns nil = unlimited; ALL checks are nil-guarded (same pattern as
  the nil allow-list). `last` initializes lazily on first Allow() so test
  clock injection (`nowFn`) is exact — never read the wall clock at
  construction. Order in `serve()`: read-only check first (blocked writes
  never consume rate tokens), then rate limit, then remap + exchange.
  Rate-rejected requests get exception 0x06 Server Device Busy (spec:
  "client should retry later") and the device never sees them.
- **Pacing + idle timeout contracts (B5/B6)**: `request_delay_ms` is
  enforced in `upstream.exchange` under `u.mu` (before `ensureConn`) —
  the gap is measured across ALL client requests multiplexed onto the
  one device connection, which is exactly the serialization point a
  picky device sees; the sleep is charged against the exchange deadline
  (a slow-paced device = a slow exchange, deadline still bounds it).
  `lastRequest` records when each exchange starts (send/attempt time),
  set even when the delay is 0 so enabling pacing mid-run is coherent.
  `idle_timeout_ms` bounds ONLY the read waiting for the next request in
  `handleClient` (deadline reset each iteration; cleared explicitly with
  a zero Time when unset) — in-flight exchanges keep their own upstream
  deadline and response writes keep `writeTimeout`; a reaped client just
  loses its connection, the next one works immediately. Both fields
  default to 0 = disabled; Validate rejects negatives.
- **Connection-ID logging contract (B9)**: `gateway.connSeq`
  (atomic.Uint64) hands out per-gateway connection IDs in
  `handleClient` (`connID := g.connSeq.Add(1)`, assigned once per
  connection, never per request). Client-side log lines (closing,
  write-failed, read-only, rate-limit, upstream error, health) and
  device-side log lines all carry `[conn N]`. `upstream` holds
  `connSeq *atomic.Uint64` — a POINTER shared with the owning gateway
  (set after construction), so exchange-time device lines (pacing,
  stale discard) use the same ID space; never copy the counter.
  `exchange(req, timeout, connID)` takes the ID as a parameter.
  Device-side lines only appear on per-exchange events (pacing/stale) —
  connection-scoped lines like "connected" do not carry `[conn N]`.
  Verified by `scripts/smoke-connid.sh` (JSON log, asserts >= 2 distinct
  IDs on client AND device lines).
- **`proxy.Metrics` interface contract** (logger.go, implemented by
  `internal/observ.Metrics`): every method nil-safe — call sites never
  check for nil; `metricsOrNop(met)` normalizes nil to `nopMetrics{}` at
  construction. Outcome labels on `requests_total`: forwarded |
  exception_device (upstream error) | exception_policy (read-only) |
  exception_rate (rate limiter). Connection counters increment in the
  Serve loop (not admit), so rejections by cap AND ACL both count.
  device_up/reconnects/latency live in `upstream` (reconnects counts
  every successful dial, so the initial connect counts too). Per-device
  latency histograms register lazily (map + mutex) — Prometheus
  AlreadyRegisteredError avoided by pre-map registration.
- **`internal/observ` wiring**: `Log(level, format)` maps config
  console→zap development config, json→production config;
  `AsProxyLogger(l *zap.Logger)` returns `l.Sugar()` — *zap.SugaredLogger
  satisfies `proxy.Logger` directly (its formatted methods match the
  signature exactly); do NOT wrap it again (infinite recursion risk).
  Never name a struct field after a method you also delegate (`Debugf`
  field + `Debugf` method = recursion).
- **CLI contract** (cmd/modbus-shield): every subcommand registers the
  same flag set (role flags never trip unknown-flag errors on
  validate/selftest). `--config` XOR direct flags; direct flags build a
  single-device `config.Device` + `cfg.Defaults()` + `cfg.Validate()`.
  `probeDevice` (selftest) builds the FC3 probe on `internal/mbtcp`
  directly (unit = device_unit_id remap or 1) — no client library. An
  exception response PASSES the probe with a note (device answered on
  the wire = alive); only dial/read/txn-mismatch fail. `gateway` holds
  `*http.Server` for metrics in a plain local var; nil-safe
  `ShutdownMetrics(nil)`. Tests set flag values through the flag
  pointers (exactly as pflag Parse would), never via reflection.
- **Fuzz targets** (`internal/mbtcp`): `FuzzParseADU` (strict single-frame
  parser) and `FuzzReadADU` (`fuzz_stream_test.go`, streaming entry point
  with pipelined frames + chunked delivery via io.MultiReader). Invariants
  for both: rejections must be documented sentinels (or bare
  io.EOF/io.ErrUnexpectedEOF wrappers for the streaming target), accepted
  frames must re-frame and re-parse byte-exactly. Regression corpora live
  in `internal/mbtcp/testdata/fuzz/<FuzzName>/` (go test fuzz v1 format)
  and re-run in every plain `go test`. Fuzzing locally: `go test
  ./internal/mbtcp/ -run '^$' -fuzz <Name> -fuzztime 15s`; interesting
  new seeds land in the build cache — copy them into testdata to commit.
- **Interop** (`scripts/interop-modbus.sh`): drives the built gateway with
  real mbpoll (epsilonrt/mbpoll + libmodbus) against
  `scripts/fakedevice.py`. Covers FC3/FC4 reads, FC6 write, exception
  pass-through (mbpoll prints "Illegal data address" and exits 1 on a
  device exception — the script requires that), unit-ID addressing
  (`-a 17`), 8 concurrent mbpolls (multiplexing), and a chain-alive check.
  Exit 77 when mbpoll is missing (`MBPOLL_BIN` overrides the binary path).
  mbpoll refs are 1-based: register 0x0100 = `-r 257`.
- **Graceful shutdown**: `gateway.Serve` returns **nil** on
  `errors.Is(err, net.ErrClosed)` (Stop() closed the listener = clean
  shutdown, not an error). Any other Accept error is fatal to Run. Without
  this, every SIGTERM logged an ERROR stack trace from main.
- **TLS front-leg contract (B1)**: per-device `config.TLSConfig`
  (`tls.cert`/`tls.key`/`tls.client_ca`) — Validate enforces
  cert+key both-or-neither, client_ca requires cert/key, all files
  readable at validate time. `tlsConfigFor` builds TLS 1.2 minimum +
  `RequireAndVerifyClientCert` when client_ca set. `Serve` wraps the
  listener with `tls.NewListener`; the handshake is **lazy** in the
  handler goroutine (never in the accept loop — a hanging client must
  not block accept). `tls.Conn.RemoteAddr()` delegates to the inner TCP
  conn, so the IP allow-list and conn-cap keep working unchanged.
  Plain client against TLS listener = lazy handshake error in
  handleClient, listener never dies. mTLS test lesson: under TLS 1.3 the
  client's Dial may return before the server's client-cert rejection
  arrives — force the alert with a write+read before asserting failure.
- **Two-proxy secured line contract (B2)**: per-device
  `config.DeviceTLSConfig` (`device_tls.ca_cert`/`server_name`/`cert`/
  `key`) — the box dials `device_addr` over TLS instead of plain TCP
  (client role on the upstream leg). The far side is a second
  modbus-shield gateway with a front-leg `tls:` block in front of the
  local device — no new subcommand needed. Validate: client cert+key
  both-or-neither, all files readable. `deviceTLSConfigFor` builds TLS
  1.2 minimum + custom CA pool (empty `ca_cert` = system roots) +
  optional server_name override + optional client cert (mTLS toward the
  far box). Upstream dialing is **eager** (`tls.DialWithDialer`, handshake
  inside the dial deadline) — a half-open TLS conn must not look "up";
  reconnect/backoff/stale-discard logic unchanged. Bad CA → exchange
  error → exception 0x0B; the device never sees rejected TLS.
  Test-lesson reuse: `tlsChain` PKI helper shared; second `tlsChain`
  call yields an unrelated CA for bad-CA tests.
- **mbaps role-authorization contract (B12)** (`internal/proxy/mbaps.go`
  + `config.MBAPSConfig`): per-device `mbaps:` block with `roles:` map
  (role name -> allowed function codes) + repeatable
  `--mbaps-role ROLE=FC,FC,...` flag. **mTLS is mandatory**: Validate
  rejects `mbaps` without `tls:` + `client_ca` (spec R-02/R-06). The
  role lives in the client cert's Modbus role extension (OID
  1.3.6.1.4.1.50316.802.1, value ASN.1 UTF8String, R-21/R-22; one role
  per cert R-65) — extracted once per connection in `handleClient` via
  an EAGER, deadline-bounded `tc.Handshake()` in the handler goroutine
  (safe: never in the accept loop), then
  `ConnectionState().PeerCertificates[0]`. Rights resolution: role not
  in the map or malformed/missing extension → nil set = deny every
  device request (NULL role, R-23). Enforcement in `serve()` sits AFTER
  the health check (health/monitoring bypasses role rights, same
  posture as read-only/rate-limit) and BEFORE read-only; denial =
  exception 0x01 Illegal Function (R-31), metric outcome
  `exception_authz`, health counter `incPolicy()` (register map
  unchanged). Test PKI: `tlsChainMulti(t, []clientSpec{{CN, Role}})`
  builds certs with `ExtraExtensions` carrying
  `asn1.Marshal(role)` (UTF8String); `tlsChain` wraps it for the
  single-no-role-client case. Verified by e2e tests (role policy,
  unconfigured role, health bypass) + real-binary smoke with OpenSSL
  certs (`1.3.6.1.4.1.50316.802.1=ASN1:UTF8String:operator` ext line).
  Full port-802 mbaps conformance stays out of scope.
- **RTU-over-TCP contract (B7)** (`internal/mbtcp/rtu.go` +
  `upstream.exchangeRTU`): `rtu_over_tcp: true` (or `--rtu-over-tcp`)
  switches the DEVICE leg to bare Modbus RTU framing (unit address +
  PDU + CRC16, MODBUS over Serial Line V1.02) — for cheap serial-to-TCP
  converters without MBAP. In-house CRC-16/MODBUS (`CRC16`, poly 0xA001
  reflected, init 0xFFFF, low byte first on the wire; catalog check
  "123456789" -> 0x4B37). RTU has no length field, so response frames
  are read by predicting their shape from the RESPONSE's function code
  (fc|0x80 = code+CRC; FC 1/2/3/4/23 = bytecount+data+CRC; FC
  5/6/15/16 = fixed 6; FC 22 = fixed 8; anything else = idle-gap
  framing: read until a quiet gap, clamped by the exchange deadline).
  `upstream.exchange` branches to `exchangeRTU` after ensureConn:
  MBAP ADU -> `RTUFrame(req unit, pdu)`, response -> `NewADU(req txn,
  resp unit, resp pdu)` — transaction/protocol IDs are reconstructed
  (RTU has none); stale-RTU-response discard correlates by UNIT ADDRESS.
  The front leg stays Modbus TCP (clients notice nothing); pacing (B5)
  wraps RTU exchanges; works with `device_tls` (RTU bytes ride inside
  the TLS tunnel). **Request shapes have NO bytecount for FC 1-6** (the
  bytecount is a response-only field — real bug caught in the fake
  device: FC3 request = addr,fc,reg(2),qty(2),CRC fixed 6-byte body);
  response shapes DO carry it. Verified by unit tests (CRC known
  answers, round-trips, gap fallback via net.Pipe, deadline clamp) +
  e2e (read/exception/unit-ID/remap) + real-binary smoke.
- **Read-cache contract (B8)** (`internal/proxy/cache.go`):
  `read_cache_ttl_ms: N` (or `--read-cache-ttl-ms N`) enables an opt-in
  TTL cache for read responses; 0 = disabled (nil-guard, same pattern
  as the rate limiter/allow-list). Cache key = CLIENT unit ID + request
  PDU (pre-remap; per-client, remap-independent since the unit ID lives
  in the header). Only non-exception responses to FC 1-4 (`isReadFC`)
  are stored; writes, exceptions, health reads never cached. In
  `serve()` the lookup sits AFTER the rate limiter (a hit consumes no
  rate token and generates NO device traffic; outcome label
  `cache_hit`, health register 18 via `incCacheHit`); the store sits
  after a successful exchange, guarded by `isReadFC` &&
  `!resp.IsException()`. Cached responses are rebuilt with
  `NewADU(client txn, client unit, cached pdu)` — clients always see
  their own fresh transaction ID. Entry values are copied on insert and
  return; mutex-guarded map, lazy TTL expiry. 0 = fully transparent
  semantics.
- **systemd watchdog contract (B11)** (`internal/watchdog`, wrapper on
  coreos/go-systemd/v22 `daemon`): `Interval()` = `SdWatchdogEnabled`
  (0 when not under systemd), `NotifyReady()` sends `READY=1`,
  `Start(interval, done)` pings `WATCHDOG=1` every interval/2 until done.
  `runGateway` logs "systemd watchdog enabled" when `Interval() > 0`,
  starts the ping goroutine with the shared `done` channel, and calls
  `NotifyReady()` right before `r.Run()` (READY only means "serving").
  All functions no-op outside systemd (no NOTIFY_SOCKET env). sd_notify
  uses **SOCK_DGRAM** — tests fake systemd with `net.ListenUnixgram` +
  `ReadFromUnix` (NOT stream sockets; `Accept` does not exist there).
  Real caught bug: READY=1 was initially missing (only pings were sent)
  — the smoke test with a fake systemd socket caught it; always verify
  BOTH READY and pings. Deploy unit: `Type=notify`, `WatchdogSec=30`.
- **Transparent mode contract (B3)** (`internal/proxy/origdst_linux.go`,
  build tag `linux`): `transparent: true` replaces the static
  `device_addr` dial target with the client's ORIGINAL destination
  recovered per front-leg connection via
  `getsockopt(SOL_IP, SO_ORIGINAL_DST)` on the accepted socket
  (`unix.Syscall6` + raw sockaddr parsing; `x/sys` was already in the
  dep tree — no new dependency). `upstream` gains `origDST
  func(net.Conn)(string,error)` + `origDSTConn`: `exchange(req, timeout,
  connID, clientConn)` resolves the target under `u.mu` before
  `ensureConn`; a changed client connection drops the previously dialed
  device connection (one client conn ⇄ one device conn). Non-Linux
  builds get a stub that errors cleanly (binary stays cross-platform).
  `parseOrigDst` (sockaddr parsing) is unit-tested; `getsockoptOrigDst`
  is the only untestable-without-netfilter part — e2e tests inject a
  fake resolver into `up.origDST` (transparent gateway, per-connection
  target re-dial, resolver-error → exception 0x0B + recovery).
  **FAIL-OPEN by design**: missing rule = unproxied traffic; documented
  in examples/transparent.md + docs/b3-transparent-mode.md (NFQUEUE
  userspace mangling and eBPF rejected there). Requires CAP_NET_ADMIN;
  rule script is idempotent and never auto-run.
- **No RFCs exist for Modbus** — the spec PDFs above are the only ground
  truth, and there is no conformance suite: our adversarial test suite +
  mbpoll interop is the anchor. Real devices deviate (wonky txn-ID echo,
  unit-ID semantics); be strict on framing, liberal on correlation.
- **MODBUS/TCP Security ("mbaps", MB-TCP-Security-v36, 2021-07-30)**:
  the Modbus Organization's security profile — MBAP ADU encapsulated in
  TLS on **port 802** (IANA mbap/TLS/TCP), TLS 1.2 minimum (R-01/R-34),
  **mandatory mutual** X.509 auth (R-02/R-06/R-44), role-based AuthZ via
  the registered OID 1.3.6.1.4.1.50316.802.1 in the client cert
  (R-21/R-22, ASN1 UTF8String), AuthZ checked on **every request**,
  rejection = exception 0x01 Illegal Function (R-31), no change to mbap
  (R-05), TLS-PSK deliberately unused. modbus-shield's TLS legs are
  wire-compatible (TLS 1.2 min, stdlib X.509, PDU opaque); full mbaps
  conformance (mandatory mTLS + role AuthZ) is a possible future mode,
  NOT v1 — retrofit clients/devices don't speak mbaps, which is exactly
  why the box speaks plain Modbus TCP to both ends.
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
