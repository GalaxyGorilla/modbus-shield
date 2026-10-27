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
| Security v1 | **IP ACLs + write policy (read-only OR address-scoped rules) + shielding limits** (conn cap + rate limit); TLS front leg is B1; per-role FC rights over mTLS (mbaps mode) is B12 |
| Caching | **None** — exactly transparent semantics (opt-in TTL cache is B8) |
| Config changes | Live reload via **SIGHUP** for everything per-request (ACLs, write policy, limits, cache TTL, pacing, timeouts, remap, mbaps roles); listeners/device address/TLS need a restart and are reported as reload warnings |
| Transport level | Parse the 7-byte MBAP header, forward the PDU as an **opaque blob** — vendor register-map/encoding chaos flows through untouched |
| Correlation posture | **Strict on framing, liberal on correlation** — real devices deviate (wonky txn-ID echo, unit-ID swaps) |
| Config | YAML per instance + no-YAML flags one-liner mode (field techs paste two lines) |
| Ground truth | Modbus Organization spec PDFs, NOT RFCs (none exist): MODBUS Application Protocol Specification V1.1b3 (Apr 2012) + MODBUS Messaging on TCP/IP Implementation Guide V1.0b. For security: MODBUS/TCP Security Protocol Specification MB-TCP-Security-v36 (2021-07-30) — the "mbaps" profile (port 802, mandatory mutual TLS, role-OID AuthZ). Our TLS legs are wire-compatible with it; full mbaps conformance (mandatory mTLS + role-based AuthZ) is a possible future mode, NOT adopted in v1 because retrofit clients/devices don't speak it |

## 3. Status / Roadmap

**Current state: BACKLOG COMPLETE + docs consistency pass + streamlining
pass + identity rewording + portability/shielding hardening pass +
write-policy/reload pass (B14).**

Write-policy + reload pass (2026-10-27), the follow-up to the hardening
pass (still no CI — user decision):

- **Address-scoped write policy (B14):** `write_policy:` (YAML) /
  `--write-range` + `--write-default` (flags). Rules scope by client unit
  ID, write function code and inclusive address range. Evaluation is
  deny-overrides + allow-must-cover (an allow must CONTAIN the whole
  request range, so a multi-register write cannot straddle an allowed
  window); order-independent; unparseable ranges denied; `read_only` and
  `write_policy` are mutually exclusive. Denial = exception 0x02, metric
  outcome `exception_policy`, health `incPolicy()`; the device never sees
  it. Engine in `internal/acl/writepolicy.go`, compilation in
  `internal/proxy/runtime.go`, e2e in
  `internal/proxy/writepolicy_test.go`.
- **SIGHUP config reload:** `internal/proxy/runtime.go` +
  `reload.go`. Every config-derived per-request knob lives in a
  `gatewayRuntime` struct swapped under an `RWMutex`; a reload compiles a
  whole new snapshot and swaps it atomically (never a half-applied mix).
  Applied: `allow`, `read_only`/`write_policy`, `max_clients`, both rate
  limits, cache TTL, pacing, `lenient_correlation`, idle + request
  timeouts, `device_unit_id`, `health_unit_id`, mbaps roles. Restart-only
  (listener/device/TLS/transparent/RTU, added/removed devices): reported
  as warnings, never silently ignored. A config that fails to load keeps
  the running one. Handler loops re-read the snapshot AFTER the blocking
  read — reading it before would delay every reload by one request for a
  busy client and forever for an idle keeper (real bug caught by
  `TestReloadWritePolicy`).
- **Cache ordering reversed (deliberate):** the cache lookup now runs
  BEFORE both rate limiters. The limiters protect the DEVICE; a hit never
  touches it, so charging it a token only turned a free answer into 0x06.
  Pinned by `TestGatewayCacheHitBypassesRateLimit` (was
  `TestGatewayRateLimitBeforeCache`, which pinned the old behavior and
  was rewritten, not deleted).
- **`make interop` finally runs:** mbpoll installed on this machine;
  the full real-client suite passes (see section 5).

Hardening pass (2026-10-27), all driven by a self-review rather than new
features — no CI was added (deliberate: this project stays CI-free and
the checks run manually via `make`):

- **Portability fixed (real bugs):** the `internal/proxy` test binary did
  not compile off Linux (`transparent_test.go` used the Linux-only
  `parseOrigDst` without a build tag — the parse tests now live in
  `origdst_linux_test.go`), and the watchdog's fake systemd socket used
  `t.TempDir()`, whose macOS path exceeds `sun_path` (bind EINVAL — now
  `shortTempDir`). `go test ./... -race` is green on darwin/arm64.
- **Lenient device-leg correlation** (`lenient_correlation` /
  `--lenient-correlation`): the doc posture "strict framing, liberal
  correlation" was untrue in code — strict txn-ID echo plus a mandatory
  protocol ID of 0 on the DEVICE leg made non-conforming
  converters/gateways fail 100% of requests with 0x0B. Now opt-in
  tolerated, framing unchanged, response header normalized so clients
  always see their own txn ID.
- **Per-client rate limit** (`rate_per_client_per_sec` /
  `--rate-per-client-per-sec`): the shared bucket let one runaway
  poller starve every other client with 0x06.
- **FIFO upstream gate**: the "fair queue" claim was a plain mutex; the
  slot is now handed over through a cap-1 channel, and a test pins the
  observable fairness property.
- **Shutdown drain**: `Stop` used to cut in-flight responses off; it now
  drains `inFlight` first and then closes idle connections (bounded,
  prompt).
- `gofmt -l` drift in `health.go`/`rtu_test.go` fixed; `make test` now
  gates on gofmt too.

The software is presented as what it is —
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
| B14: address-scoped write policy (`write_policy:` + `--write-range`/`--write-default`) | done (acl/writepolicy.go + proxy/runtime.go + e2e tests + examples/gateway.md + smoke-reload.sh) |
| B14: SIGHUP config reload (`Runner.Reload` + gatewayRuntime snapshot) | done (proxy/runtime.go + reload.go + tests + deploy ExecReload + examples/operations.md) |

### Verification targets (from the plan)

- Milestone 4 acceptance met: **8 clients × 25 reads through the box onto
  a fragile single-connection device — exactly one upstream connection,
  all correct under `-race`.**
- Testing bar (every commit): build + vet + `go test ./... -race` clean.
- Adversarial: garbage datagrams never kill the listener, oversized ADUs
  rejected, late/duplicate/mismatched transaction responses discarded.
- In-Go fake Modbus device for all e2e; real-client interop (`mbpoll`)
  now RUN and passing on this machine (`make interop`; still exits 77
  where mbpoll is absent — that skip path is unchanged); parser fuzz
  targets with committed regression corpus.
- Real-binary smokes: `scripts/smoke-connid.sh` (B9), and
  `scripts/smoke-reload.sh` (write policy + live SIGHUP, 2026-10-27).

## 4. Repository Layout

```
cmd/modbus-shield/         main package; role via subcommand (gateway) + validate/selftest/genpsk/version
internal/mbtcp/            MBAP + RTU framing (mbtcp.go, rtu.go + tests + FuzzParseADU/FuzzReadADU + corpora)
internal/config/           YAML config + single-device flags mode (config.go + tests)
internal/proxy/            gateway core: gateway.go, upstream.go, runner.go, reload.go, runtime.go, logger.go, ratelimit.go, health.go, cache.go, mbaps.go, origdst_linux.go/origdst_other.go + fakedevice e2e
internal/acl/              client IP allow-list + write-FC classifier + address-scoped write policy (acl.go, writepolicy.go + tests)
internal/observ/           zap logging + Prometheus metrics (observ.go + tests; implements proxy.Metrics)
internal/watchdog/         sd_notify wrapper (READY + watchdog pings; no-ops outside systemd)
configs/                   example YAML templates (write_policy + reload notes in gateway.yaml)
scripts/                   interop-modbus.sh (real mbpoll), gen-certs.sh (throwaway PKI incl. mbaps role certs), fakedevice.py, smoke-connid.sh, smoke-reload.sh (write policy + live SIGHUP), SBOM entry point
deploy/                    hardened systemd unit files
examples/                  copy-paste walkthroughs: gateway.md, multi-device.md, operations.md (production guide), tls.md, two-proxy.md, mbaps.md, health.md, transparent.md
```

(All directories populated as of v1 feature-complete; see individual
milestone sections above for file inventories.)

## 5. Build / Test

Go 1.27.3 (the exact toolchain is pinned by the `toolchain` directive in
go.mod; this dev machine has it at `/opt/homebrew/bin/go`, Linux boxes
usually at `/usr/local/go/bin/go`);
go.mod declares minimum **1.26.0** (CI-free project — tests run manually).

**Latest local verification (2026-10-27, macOS/darwin arm64):** `go
build ./...`, `go vet ./...`, `GOOS=linux go vet ./...`, `gofmt -l .`
(clean) and `go test ./... -race -timeout 240s` pass under Go 1.27.3;
`staticcheck ./...` and `govulncheck ./...` pass (the latter reinstalled
into `~/go/bin` during this pass). The suite is green OFF Linux too —
two real defects were found and fixed in the earlier hardening pass (see
below): `transparent_test.go` called the Linux-only `parseOrigDst`
without a build tag (the whole `internal/proxy` test binary failed to
compile on macOS), and the watchdog's fake-systemd socket used
`t.TempDir()`, whose macOS `/var/folders/...` path exceeds the 104-byte
`sun_path` limit (bind EINVAL). Both are recorded because the previous
verification ran only on Linux and therefore could not see them.

**`make interop` NOW RUNS (2026-10-27):** mbpoll was installed via
`brew install mbpoll` (1.5.4 / libmodbus 3.2.0) and the suite PASSES —
FC3/FC4 reads, FC6 write, exception pass-through, unit-ID addressing, 8
concurrent mbpolls over the single upstream connection, chain alive
after the burst. This closes the long-standing "never actually run" gap;
the earlier exit-77 skip note no longer applies on this machine.

**Write policy + reload + cache-ordering reversal (B14, 2026-10-27):**
`write_policy` (YAML) / `--write-range` + `--write-default` (flags) scope
writes by client unit ID, function code and address range; evaluation is
deny-overrides / allow-must-cover, unparseable ranges are denied, denials
are exception 0x02 with the `exception_policy` metric outcome and
`health.incPolicy()`. `SIGHUP` swaps a compiled `gatewayRuntime` snapshot
in place. The cache lookup was **moved BEFORE both rate limiters** — a
deliberate reversal of the earlier B8 ordering (a hit protects the
device, so it costs no token; now pinned by
`TestGatewayCacheHitBypassesRateLimit`). All docs/comments that stated
the old ordering (config.go, cache.go, BACKLOG.md B8, README, AGENTS)
were re-audited and now state the new one; the B3 spike doc's "if we
build it" / "decision required" sections are explicitly framed as
historical notes.

```bash
go build ./...
go vet ./...
go test ./... -race -timeout 180s
```

`make build` / `make test` / `make vet` / `make release` wrap the same
commands (`make test` also fails on non-empty `gofmt -l` output — the
only formatting gate in this CI-free project; `release` = stripped
static binary, `CGO_ENABLED=0
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
  this. `ReadADUWith(r, ReadOptions{AllowForeignProtocolID: true})` is
  the DEVICE-leg-only relaxation (lenient correlation): it tolerates a
  foreign protocol ID but keeps every framing rule, because the length
  field sizes the read in all modes. Strict entry points are the
  default and are what the front leg + both fuzz targets use.
  `ADU.PDU` never contains the unit ID (`Header.UnitID` holds it) so
  unit-ID remapping can rewrite both independently. Build via `NewADU`/
  `AppendTo` (buffer-reusing). Proxy-generated exceptions use
  `ExceptionPDU(fc, code)` (FC|0x80 + code).
- **`internal/config` YAML schema** (one file = one instance, N
  `devices:` entries): `name` (opt; defaults to device_addr), `listen_addr`,
  `device_addr`, `read_only`, `allow` (IPs/CIDRs), `max_clients` (def 16),
  `rate_per_sec`, `rate_per_client_per_sec`, `lenient_correlation`,
  `timeout_ms` (def 5000), `device_unit_id` (opt remap),
  `write_policy.{default,rules[]}` (mutually exclusive with `read_only`),
  plus top-level `log.{level,format}` and `metrics_listen`. Validate
  enforces: ≥1 device, host:port syntax, unique listen addrs,
  non-negative limits (both rates included), valid IP/CIDR entries,
  write-policy defaults/actions ∈ {allow, deny}, rule FCs are WRITE
  function codes, from/to present together and ordered (0..65535), and
  no empty default-deny policy.
  Accessors: `Device.RequestTimeout()`, `HasUnitRemap()`,
  `UpstreamUnitID()`, `HasLenientCorrelation()`, `HasWritePolicy()`,
  `WritePolicyDefaultAllow()`.
- **`internal/proxy` gateway contract**: one `gateway` per config device
  = front-leg `Serve` loop + per-client `handleClient` lock-step loop
  (read one ADU -> forward -> write one ADU). All client traffic
  multiplexes over ONE `upstream` connection (legacy devices accept few
  connections); exchanges are serialized by a cap-1 FIFO gate
  (`upstream.gate`) plus `upstream.mu`, one in-flight request, responses
  matched by transaction ID, late/stale responses discarded (stream stays
  frame-aligned, skipping is safe). ANY exchange
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
- **Scheduling fairness contract**: the upstream slot is handed over
  through `upstream.gate` (cap-1 channel), which releases waiters in the
  order they blocked; a plain mutex makes no ordering promise. Because
  every client loop is lock-step, at most ONE request per client is ever
  queued, so the FIFO gate yields round-robin-ish service and a quiet
  poller is never starved by a busy one. `TestGatewayFairScheduling`
  pins the observable property (the device never sees one client three
  times in a row) — it passes on the mutex too, so it verifies the
  property, not the mechanism; keep the gate because it makes the
  guarantee explicit instead of relying on Go's mutex starvation mode.
- **Lenient device-leg correlation (`lenient_correlation`, opt-in)**:
  set on `upstream.lenient` from `Device.HasLenientCorrelation()`. The
  device leg then reads with `mbtcp.ReadADUWith(...,
  AllowForeignProtocolID: true)` and accepts a response whose
  transaction ID does not match the request (exactly one request is in
  flight, so that frame IS the answer). The response header is
  normalized on every path — `resp.Header.TransactionID =
  req.Header.TransactionID`, `ProtocolID = 0` — so a non-conforming
  device can never leak a wrong transaction ID or protocol ID to a
  client. Framing stays strict: length bounds, ADU cap, truncated frames
  still fail and drop the connection. Default off; the front leg is
  never lenient. Pinned by `TestStrictCorrelationRejectsForeignTxn`,
  `TestLenientCorrelationAcceptsForeignTxn`, `TestForeignProtocolID`
  (fake-device knobs `MangleTxn` + `ForeignProtocolID`) and
  `TestReadADUWithForeignProtocolID` (framing rules still enforced).
- **Shutdown drain contract (`Runner.Stop`)**: close listeners -> wait
  for the `Serve` goroutines -> `gateway.drain(5s)`: poll
  `gateway.inFlight` (incremented around `serve` + `writeADU`) until no
  request is being served, then close the tracked client connections
  (`gateway.conns`) and wait for the handler `WaitGroup`. Idle handlers
  are parked in a read and never finish on their own, so closing them is
  what makes shutdown prompt (`TestShutdownDrainsInFlightRequest`
  asserts both: the response survives, and Stop stays under 2s). Do NOT
  reintroduce a plain `wg.Wait()` before closing connections — that
  makes every shutdown with an idle keeper cost the full grace period.
  `inFlight` covers the write, not just the exchange, so a response is
  never cut off mid-write.
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
  bucket, capacity = 1 second's worth of the configured rate tokens,
  continuous refill, burst absorbed without rejection.
  `newRateLimiter(0|negative)` returns nil = unlimited; ALL checks are
  nil-guarded (same pattern as the nil allow-list). `last` initializes
  lazily on first Allow() so test clock injection (`nowFn`) is exact —
  never read the wall clock at construction. TWO buckets exist: the
  shared `rate_per_sec` (`gateway.lim`, one per device, bounds total
  device traffic) and the per-connection `rate_per_client_per_sec`
  (`clientLim`, created in `handleClient`, so a reconnect starts with a
  full bucket — a burst damper, not a quota). Order in `serve()`:
  read-only check first (blocked writes never consume tokens), then the
  PER-CLIENT bucket, then the SHARED bucket, then the cache lookup, then
  remap + exchange. The per-client check MUST come before the shared one:
  otherwise a runaway client's rejections drain the shared budget and
  starve everybody else — that bug was real and is pinned by
  `TestGatewayPerClientRateLimit` (hog gets 0x06, quiet client still
  works). Rate-rejected requests get exception 0x06 Server Device Busy
  (spec: "client should retry later") and the device never sees them;
  both rejections count as outcome `exception_rate` + `incRate()`.
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
  `ShutdownMetrics(nil)`. `--write-range` entries are parsed into
  `config.WriteRule`s by `parseWriteRangeSpec` (grammar
  `[!]UNIT:FCS:FROM[-TO]`, `*` wildcards, default deny when rules are
  given) and then validated by `cfg.Validate()` like a YAML policy.
  `gateway` handles SIGHUP separately from SIGINT/SIGTERM: the signal
  goroutine loops (reload → continue), so the first HUP cannot consume
  the shutdown watcher. Tests set flag values through the flag
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
  `serve()` the lookup sits BEFORE both rate limiters — a hit generates
  NO device traffic and therefore costs no rate token (ordering reversed
  in B14; outcome label `cache_hit`, health register 18 via
  `incCacheHit`); the store sits
  after a successful exchange, guarded by `isReadFC` &&
  `!resp.IsException()`. Cached responses are rebuilt with
  `NewADU(client txn, client unit, cached pdu)` — clients always see
  their own fresh transaction ID. Entry values are copied on insert and
  return; mutex-guarded map, lazy TTL expiry. 0 = fully transparent
  semantics.
- **Write-policy contract (B14)** (`internal/acl/writepolicy.go` +
  `config.WritePolicyConfig` + `newGatewayRuntime`): governs WRITES only
  (reads always pass); `nil` policy = allow every write (nil-guard
  pattern). `Allowed(unit, pdu)` evaluates the rule SET: a deny rule
  matches on range INTERSECTION (touching any forbidden address rejects),
  an allow rule only when it CONTAINS the whole request range; any
  matching deny wins, then any matching allow, else `default`. Rule
  order is irrelevant. `WriteRange(fc, pdu)` extracts the affected range
  (FC5/6 one address; FC15/16 address+qty; FC22 one address; FC23 uses
  the WRITE half, not the read half; FC21 has no address and needs an
  unscoped rule) and returns ok=false for truncated PDUs, quantity 0 or
  16-bit overflow — unparseable = denied. In `serve()` the check sits
  after the health endpoint and mbaps, and after `read_only` (which stays
  the coarse switch; the two are mutually exclusive in config), BEFORE
  the cache and both rate limits (a denied write costs no token).
  Denial = exception 0x02 Illegal Data Address + outcome
  `exception_policy` + `health.incPolicy()`; the device never sees it.
  Flags: `--write-range '[!]UNIT:FCS:FROM[-TO]'` (`*` wildcards, leading
  `!` = deny) + `--write-default deny|allow` (default deny when rules are
  given), parsed by `parseWriteRangeSpec`/`parseAddrRange`.
- **Reload contract (B14)** (`internal/proxy/runtime.go` +
  `reload.go`): everything config-derived that a request needs lives in
  `gatewayRuntime` (readOnly, writePol, allow, maxClients, lim,
  sharedRate, clientRate, cache, mbaps, healthUnit, idleTimeout, timeout,
  unitRemap). `gateway.runtime()` copies it under `rtMu.RLock` (no I/O
  under the lock); `setRuntime` swaps it whole, so a request sees ONE
  coherent configuration, never a half-applied reload. `handleClient`
  re-reads the snapshot AFTER `mbtcp.ReadADU` returns — reading it before
  the blocking read would delay a reload by one request for a busy
  client and indefinitely for an idle one (real bug; the idle deadline
  still uses the pre-read snapshot). `Runner.Reload(cfg)` matches
  gateways by `dev.Name`, compiles a new runtime, applies
  `up.setRequestDelay`/`up.setLenient` (atomics — never take the exchange
  mutex) and returns warnings for: restart-only fields (listen_addr,
  extra_listen, device_addr, tls, device_tls, transparent, rtu_over_tcp),
  enabling the health endpoint (disabling it is reloadable), devices
  removed from the config
  (still serving) and devices added (not running). A failed compile keeps
  the previous runtime. A reload creates a FRESH read cache (entries do
  not survive — a reload is also a cache flush), and the shared rate
  bucket is rebuilt (full burst); the PER-CLIENT bucket is created per
  connection, so a changed `rate_per_client_per_sec` applies to NEW
  connections only. main handles SIGHUP only
  with `--config` (flags
  mode = logged no-op) and keeps running on a bad file. Deploy unit:
  `ExecReload=/bin/kill -HUP $MAINPID`. Pinned by `TestReload*`,
  `TestGatewayWritePolicy*` and `scripts/smoke-reload.sh` (real binary,
  live SIGHUP).
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
