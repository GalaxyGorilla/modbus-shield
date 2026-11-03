# BACKLOG — modbus-shield

The protocol and proxy backlog is complete. The open items below concern
turnkey integration into a managed appliance with a web UI.

## Open — appliance management integration

- **A1 Versioned configuration schema:** expose a stable JSON Schema for every
  YAML field, default, constraint, description, secret, and restart/reload
  behavior. Generate or test it against the Go configuration types so UI forms
  cannot silently drift from the daemon.
- **A2 Restricted local management API:** provide a Unix-socket interface (or a
  small shared management sidecar) for validate, self-test, apply, reload,
  restart, status, and rollback. The web process must not run arbitrary shell
  commands or require unrestricted root access. Keep the protocol data plane
  independent from the management plane.
- **A3 Transactional configuration:** stage a revision, run `validate --json`
  and optional `selftest --json`, install it atomically, reload or restart as
  required, verify health, and automatically restore the previous known-good
  revision on failure. Preserve an auditable revision history.
- **A4 Unified structured status:** expose the active configuration revision
  and hash, readiness, configured and connected devices, reload result,
  restart-required fields, and relevant counters as a stable JSON response.
  Never include credentials or private-key material.
- **A5 Secret and certificate lifecycle:** define safe upload, ownership,
  permissions, validation, rotation, expiry reporting, backup, and redaction
  behavior. Encryption at rest and master-key custody belong to the appliance
  layer, not the protocol daemon.
- **A6 Appliance-level acceptance tests:** exercise the complete web UI/API →
  staged YAML → validation/self-test → systemd reload/restart → real Modbus
  traffic path. Cover invalid configuration, interrupted apply, failed
  self-test, rollback, secret rotation, power loss, and all supported appliance
  architectures.

Completion means an unprivileged management UI can safely configure and
operate the service without duplicating undocumented daemon behavior.

## Post-backlog correctness fixes

- **Multi-device `extra_listen` routing (2026-10-31):** listener ownership is
  tracked explicitly. The old flat-slice indexing overlapped gateways after an
  earlier device added an extra listener, leaving a later primary port
  unserved and allowing the wrong gateway to accept the extra port.
- **MBAPS rights reload on live sessions (2026-10-31):** the authenticated
  certificate role stays fixed for the TLS session, but its rights are looked
  up from the current SIGHUP runtime snapshot per request. Revocations now
  affect established clients immediately.
- **Configured-transport selftest (2026-10-31):** commissioning probes now use
  the production device-side TLS, RTU-over-TCP and lenient-correlation path
  instead of always sending plain MBAP. The documented front-box mTLS selftest
  now actually validates the certificate chain and far-box handshake.
- **Accurate systemd readiness (2026-10-31):** `READY=1` is sent only after
  every configured listener binds. A startup bind failure now exits without
  briefly advertising a ready service.

## Done (kept for reference)

- ~~B14 address-scoped write policy + SIGHUP config reload~~ — **done**
  (2026-10-27): `write_policy` (YAML) / `--write-range` + `--write-default`
  (flags) replace the all-or-nothing `read_only` switch with rules scoped
  by client unit ID, function code and inclusive address range. Evaluation
  is deny-overrides and allow-must-cover (an allow rule must contain the
  WHOLE request range, so a multi-register write can never straddle an
  allowed window); rule order is irrelevant. Unparseable write ranges
  (truncated PDU, quantity 0, 16-bit overflow) are denied. Denials are
  exception 0x02 (Illegal Data Address), reuse the `exception_policy`
  metric outcome + `health.incPolicy()`, and never reach the device.
  `read_only` + `write_policy` is a config error. `SIGHUP` re-reads
  `--config` and swaps a compiled `gatewayRuntime` snapshot (ACLs, write
  policy, read-only, conn cap, rate limits, cache TTL, pacing, lenient
  correlation, idle timeout, request timeout, unit-ID remap, health unit
  ID, mbaps roles) in place — no client disconnect, no device reconnect;
  restart-only changes (listen_addr, extra_listen, device_addr, tls,
  device_tls, transparent, rtu_over_tcp, added/removed devices) are
  reported as warnings. A config that fails validation on SIGHUP is
  rejected and the running configuration stays. Cache ordering was
  **reversed** in the same pass: a cache hit is now answered BEFORE the
  rate limiters (they protect the device; a hit never touches it).
  Pinned by `TestWritePolicy*` (acl), `TestGatewayWritePolicy*`,
  `TestReload*`, `TestGatewayCacheHitBypassesRateLimit`, cmd flag tests
  and `scripts/smoke-reload.sh` (real binary + SIGHUP).

- ~~B13 hardening pass: portability, lenient correlation, per-client
  limits, fairness, drain~~ — **done** (2026-10-27, self-review driven,
  no new protocol surface): the test suite now compiles and passes off
  Linux (Linux-only `parseOrigDst` tests moved behind a build tag; the
  watchdog fake-systemd socket moved off the too-long macOS TMPDIR path);
  `lenient_correlation` accepts a device leg that does not echo
  transaction IDs or sets a foreign MBAP protocol ID (framing stays
  strict, responses are normalized so clients always see their own txn
  ID); `rate_per_client_per_sec` adds a per-connection bucket that is
  checked BEFORE the shared `rate_per_sec` bucket so a runaway poller's
  rejections cannot drain everybody else's budget; the upstream slot is
  handed over through a cap-1 FIFO gate instead of relying on mutex
  ordering; `Runner.Stop` drains in-flight requests before closing idle
  connections. Pinned by `TestReadADUWithForeignProtocolID`,
  `TestStrictCorrelationRejectsForeignTxn`,
  `TestLenientCorrelationAcceptsForeignTxn`, `TestForeignProtocolID`,
  `TestGatewayPerClientRateLimit`, `TestGatewayFairScheduling` and
  `TestShutdownDrainsInFlightRequest`. `make test` now also gates on
  `gofmt -l`. The three items left open here (register-range write
  policy, config reload without a restart, CI) were followed up as:
  write policy + reload landed in B14 below; CI stays out deliberately
  (user decision — checks run manually via `make`).

- ~~B3 Transparent bump-in-the-wire mode~~ — **done**: `transparent: true`
  (or `--transparent`, Linux-only). The gateway forwards to the client's
  ORIGINAL destination recovered from netfilter conntrack
  (`SO_ORIGINAL_DST`) per front-leg connection instead of a static
  `device_addr` (which stays the label). A netfilter rule
  (`scripts/setup-transparent.sh`, idempotent, never auto-run) steers
  inbound TCP/502 into the listener. Zero client/device reconfiguration
  — cable-splice install. Build-tagged `origdst_linux.go` (non-Linux
  errors cleanly). **FAIL-OPEN by design**: a missing rule / bridging
  without redirecting flows traffic unproxied to the device (shielding
  bypassed) — documented loudly; a blocking inline firewall would
  fail-closed by taking the device down with the box. Design spike +
  options (NFQUEUE userspace mangling and eBPF rejected) in
  docs/b3-transparent-mode.md. Verified by unit tests (sockaddr
  parsing) + e2e with an injected fake resolver (transparent gateway,
  per-connection target re-dial, resolver-error recovery); the
  netfilter path needs manual validation on target hardware with
  CAP_NET_ADMIN. See examples/transparent.md.

- ~~B8 opt-in TTL read cache~~ — **done**: `read_cache_ttl_ms: N`
  (or `--read-cache-ttl-ms N`) serves repeated FC 1-4 reads from memory,
  shielding very slow devices from heavy polling. Cache key = client
  unit ID + request PDU (per-client, remap-independent); only
  non-exception read responses are stored; cached responses carry the
  client's fresh transaction ID and generate NO device traffic. Ordering
  was REVERSED in B14: the lookup now runs BEFORE both rate limiters, so
  a hit costs no rate token and is never rejected with 0x06 (pinned by
  `TestGatewayCacheHitBypassesRateLimit`); writes and exceptions are
  never cached; mutex-guarded
  map with lazy TTL expiry. Metric outcome `cache_hit` + health register
  18 (cache hits, 16-bit wrap; register map version bumped to 2). 0 =
  disabled (fully transparent semantics). Verified by unit tests
  (nil-guard, hit/expiry/key isolation, concurrent access) + e2e
  (device sees 1 of 2 identical reads; different register reaches
  device; writes never cached) + real-binary smoke.
- ~~B7 RTU-over-TCP device side~~ — **done**: `rtu_over_tcp: true`
  (or `--rtu-over-tcp`) makes the device leg speak bare Modbus RTU
  frames (unit address + PDU + CRC16, MODBUS over Serial Line V1.02) for
  cheap serial-to-TCP converters without MBAP. In-house CRC-16/MODBUS +
  RTU framing in `internal/mbtcp` (`RTUFrame`, `ReadRTUResponse`,
  `VerifyRTUFrame`); response frames are read by predicting their shape
  from the response's function code (byte-count / fixed / exception
  shapes per V1.1b3) with an idle-gap fallback for unlisted codes;
  CRC-verified. The proxy translates MBAP ADU ↔ RTU frame (txn/protocol
  IDs reconstructed — RTU has none); the front leg stays Modbus TCP;
  works with `device_tls` (RTU bytes ride inside the TLS tunnel);
  stale-RTU-response discard by unit address. Request shapes on the
  device side have NO bytecount for FC 1–6 (response-only field) — the
  fake-device lesson. Verified by unit tests + e2e + real-binary smoke
  (read 0xCAFE + write echo through the box).
- ~~B12 mbaps conformance mode~~ — **done** (role-authorization subset
  of the MODBUS/TCP Security profile on the front leg): per-device
  `mbaps:` block (`roles:` map role-name -> allowed function codes) +
  repeatable `--mbaps-role ROLE=FC,FC,...` flag; mTLS mandatory
  (requires `tls:` with `client_ca`, spec R-02/R-06); role extracted at
  handshake from the Modbus role cert extension (OID
  1.3.6.1.4.1.50316.802.1, ASN.1 UTF8String, R-21/R-22); every request
  checked against the role's rights (R-31), denial = exception 0x01,
  device never sees it; NULL role (no extension, R-23) and unconfigured
  roles denied; health reads bypass role rights; new metric outcome
  `exception_authz`. Full port-802 mbaps conformance stays out of scope
  (retrofit clients don't speak it). See examples/mbaps.md.

- ~~B11 systemd watchdog~~ — **done**: `internal/watchdog` (wrapper on
  coreos/go-systemd/v22 `daemon`); the gateway sends `READY=1` on
  startup and pings `WATCHDOG=1` every interval/2 while running; deploy
  unit now `Type=notify` + `WatchdogSec=30`. No-ops outside systemd
  (no NOTIFY_SOCKET env). Verified by unit tests against a fake
  unixgram systemd socket + real-binary smoke test.

- ~~B10 Multiple listeners per device~~ — **done**: `extra_listen` (per
  device YAML list + repeatable `--extra-listen` flag); every extra
  front door is served by the same gateway, so all listeners share ONE
  upstream device connection, the connection cap, allow-list, rate
  limit and TLS config — shielding stays per-device. Validate enforces
  unique, non-duplicate addresses across all devices.
- ~~B4 Health via Modbus~~ — **done**: `health_unit_id` (per device +
  `--health-unit-id`); the proxy answers requests to a virtual unit-ID
  with 18 readable health registers (magic, map version, uptime,
  upstream state, reconnects, errors, stale discards, conn counters,
  request outcomes, read-only/max_clients/rate); health reads bypass
  read-only + rate limiting; FC3/FC4 only; device never sees health
  traffic.
- ~~B5 Inter-request delay~~ — **done**: `request_delay_ms` +
  `--request-delay-ms`; minimum gap between consecutive requests on the
  upstream connection, enforced under the upstream mutex (measured
  across ALL multiplexed clients); charged against the exchange
  deadline.
- ~~B6 Idle client timeout~~ — **done**: `idle_timeout_ms` +
  `--idle-timeout-ms`; the idle wait for the next request is
  deadline-bounded; idle clients lose their connection (reclaims
  connection-cap slots from dead/hung pollers); exchange/writes keep
  their own deadlines.
- ~~B9 Connection-ID in logs~~ — **done**: per-gateway `connSeq`
  counter; every client-side and device-side log line carries
  `[conn N]` (pacing/stale-discard device lines included); verified by
  `scripts/smoke-connid.sh`.
- ~~B1 TLS front leg~~ — **done**: per-device `tls:` config block
  (`cert`/`key`/`client_ca`) + `--tls-cert/--tls-key/--tls-client-ca`
  flags; TLS 1.2 minimum, mTLS via `RequireAndVerifyClientCert`; lazy
  handshake in the handler goroutine; e2e tests (TLS, mTLS
  reject/accept, plain-client resilience).
- ~~B2 Two-proxy secured line~~ — **done**: per-device `device_tls:`
  config block (`ca_cert`/`server_name`/`cert`/`key`) +
  `--device-tls-*` flags; the front box dials the device over TLS, the
  far side is a second gateway with front-leg `tls:` (no new
  subcommand); eager TLS dial with handshake inside the dial deadline;
  mTLS toward the far box via stdlib X.509; e2e two-box chain tests
  (mTLS hops, server_name override, bad-CA rejection).
- ~~B15 Interop test client~~ — **done**: `scripts/interop-modbus.sh` +
  `make interop` drive the gateway with real mbpoll (reads, writes,
  exception pass-through, unit-ID addressing, concurrent clients); the same
  script starts TLS and mTLS front legs and drives them with
  `scripts/interop_tls_client.py` (Python `ssl`): server-auth TLS, mTLS with
  a client certificate, a plain client refused, and an mTLS client without a
  certificate refused. Exit 77 when mbpoll is missing.

## Done — testing (kept for reference)

- **TCP fault injection:** a frame-aware relay
  (`internal/proxy/faulttcp_test.go`) truncates a response, resets the
  device connection, or drops a request. Each case must produce a
  gateway-target-failure exception (code 11), then the next request on the
  same client connection reconnects and succeeds.
- **Soak coverage:** `make soak` (opt-in, 10 min) runs
  `TestSoakMultiDeviceSteadyState`: two co-hosted `devices:` entries with
  distinct unit-ID remaps under continuous reads — zero unanswered, flat
  goroutines, bounded live heap. The normal `make test` skips it; the full
  run is a release-checklist item. A 20s quick pass is green (3,252 rounds,
  goroutines 11→11, live heap 0.3→0.3 MiB).

## Out of scope (do not re-litigate)

- SunSpec/register conversion or any data-model translation — transport-level
  proxy only; the PDU stays opaque.
- Caching by default (see B8: opt-in only).
- Local serial ports in v1 (RTU directly on the box's serial port).
