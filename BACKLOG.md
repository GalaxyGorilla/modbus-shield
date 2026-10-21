# BACKLOG — modbus-shield

Things to implement later, in rough priority order. Each item names the
technology researched for it (verified healthy on GitHub, Oct 2026).

| # | Item | Technology / notes |
|---|---|---|
| B3 | **Transparent bump-in-the-wire mode** — L2 splice, zero client/device reconfiguration, cable-splice install; intercept port 502 inline, pass other traffic | **florianl/go-nfqueue** first candidate (MIT, netfilter queue API, needs CAP_NET_ADMIN); cilium/ebpf = later performance path (linux amd64/arm64 only). Design spike needed; Linux-only |

## Done (kept for reference)

- ~~B8 opt-in TTL read cache~~ — **done**: `read_cache_ttl_ms: N`
  (or `--read-cache-ttl-ms N`) serves repeated FC 1-4 reads from memory,
  shielding very slow devices from heavy polling. Cache key = client
  unit ID + request PDU (per-client, remap-independent); only
  non-exception read responses are stored; cached responses carry the
  client's fresh transaction ID, skip the rate limiter and generate NO
  device traffic; writes and exceptions are never cached; mutex-guarded
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
  exception pass-through, unit-ID addressing, concurrent clients); exit 77
  when mbpoll is missing.

## Out of scope (do not re-litigate)

- SunSpec/register conversion or any data-model translation — transport-level
  proxy only; the PDU stays opaque.
- Caching by default (see B8: opt-in only).
- Local serial ports in v1 (RTU directly on the box's serial port).
