# BACKLOG — modbus-shield

Things to implement later, in rough priority order. Each item names the
technology researched for it (verified healthy on GitHub, Oct 2026).

| # | Item | Technology / notes |
|---|---|---|
| B3 | **Transparent bump-in-the-wire mode** — L2 splice, zero client/device reconfiguration, cable-splice install; intercept port 502 inline, pass other traffic | **florianl/go-nfqueue** first candidate (MIT, netfilter queue API, needs CAP_NET_ADMIN); cilium/ebpf = later performance path (linux amd64/arm64 only). Design spike needed; Linux-only |
| B4 | **Health via Modbus itself** — expose proxy health (connections, request/error counters, upstream state) as a virtual unit-ID with readable registers | in-house on `internal/mbtcp`; plant SCADA monitors the box with tooling it already has (analog of snmp-shield's SNMP metrics interface) |
| B5 | **Inter-request delay** — optional pacing toward picky legacy devices | trivial timer in the upstream loop |
| B6 | **Idle client timeout / TTL** — close front connections idle too long | per-conn deadline |
| B7 | **RTU-over-TCP device side** — speak RTU framing (no MBAP) toward cheap converters that bridge raw serial over TCP | framing module extension |
| B8 | **Opt-in TTL read cache** — serve repeated reads from memory to shield very slow devices from heavy polling | per-listener, TTL-based, OFF by default (staleness surprises in SCADA) |
| B9 | **Connection-ID in logs** — correlate client-side and device-side log lines | observ package |
| B10 | **Multiple listeners per device** — one upstream, several front listeners | config schema extension |
| B11 | **systemd watchdog** — `WatchdogSec`/`sd_notify` so a wedged process is restarted by the host | coreos/go-systemd/v22 `daemon` package |

## Done (kept for reference)

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
