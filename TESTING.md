# Testing Modbus Shield

The suite is organized around security properties and failure modes, not only
successful request forwarding.

| Layer | Evidence |
| --- | --- |
| Parsers | MBAP and RTU framing, lengths, malformed/oversized input, committed fuzz corpora |
| Policy | Allow-lists, read-only and address-scoped writes, MBAPS role rights, live revocation |
| Shielding | Connection caps, shared/per-client rates, fair serialization, pacing and idle eviction |
| Transport | Plain TCP, TLS/mTLS, upstream TLS, RTU-over-TCP and transparent routing |
| End to end | Real proxy sockets, fake devices, reads/writes/exceptions, multiplexing, reconnect and stale-response discard |
| Fault injection | A frame-aware TCP relay truncates a response, resets the device connection, or drops a request; the gateway returns a gateway-target-failure exception, reconnects, and serves the next request |
| Lifecycle | Invalid/valid reloads, graceful drain, listener ownership, systemd readiness and watchdog |
| Independent client | `mbpoll` drives the built gateway through reads, writes, exceptions, unit IDs and concurrent clients; a Python `ssl` client validates TLS and mTLS (including a client without a certificate) |
| Real binary | Reload and connection-identity smoke scripts exercise the compiled command |

## Commands

```sh
make test          # gofmt + complete race suite
make verify        # build + race suite + vet
make acceptance    # verify + mbpoll + real-binary smokes
make security      # verify + staticcheck + govulncheck + SBOM vulnerability gate
make soak          # opt-in long multi-device soak (SOAK_DURATION=90s for a quick pass)
```

Individual release checks remain available as `make staticcheck`,
`make govulncheck`, `make sbom` and `make vulnscan`.

## Security regressions pinned explicitly

- A listener can serve only the device gateway that owns it.
- Removing MBAPS rights takes effect on the next request of an existing mTLS
  connection.
- Denied writes never reach the device.
- An invalid reload cannot replace the active policy.
- Device TLS and RTU-over-TCP commissioning use the production transport path.
- An independent Python `ssl` client completes TLS and mTLS, while a plain
  client and an mTLS client without a certificate are refused.
- A truncated response, a device reset and a dropped request each become a
  gateway-target-failure exception; the next request reconnects and succeeds.
- A listener bind failure cannot emit systemd `READY=1`.
- Shutdown drains in-flight requests, while stale or mismatched responses are
  never delivered to another client.
- Cache hits and rate limits follow the documented device-protection ordering.

## Soak

`make soak` runs `TestSoakMultiDeviceSteadyState` for ten minutes per test
(`SOAK_DURATION` overrides it, e.g. `make soak SOAK_DURATION=90s`). It is
skipped unless `MODBUS_SHIELD_SOAK=1`, which `make soak` sets, so a normal
`make test` stays fast. The test drives two co-hosted `devices:` entries with
distinct unit-ID remaps over persistent client connections and asserts zero
unanswered rounds, flat goroutines, and a live heap that does not track the
request count. It is a release-checklist item, not a CI one.

A full 10-minute run on 2026-11-03: 95,656 rounds, worst round trip 38 ms,
goroutines `11 → 11`, live heap `0.3 → 0.3 MiB`.

## Focused mutation checks

Not full mutation testing. Each row was applied to a clean tree, the named
test failed, and the file was restored. The stale-response row found a test
that passed for the wrong reason: it checked only the normalized transaction
ID (which `exchange` rewrites even when it accepts the stale frame), so it now
checks the payload and the stale-discard counter as well.

| Invariant broken | Mutation | Test that caught it |
|---|---|---|
| Read-only write block | `if rt.readOnly && acl.IsWrite(...)` → `false` | `TestGatewayReadOnly` |
| mTLS client-certificate requirement | `RequireAndVerifyClientCert` → `NoClientCert` | `TestGatewayMTLS` |
| Stale-response discard | transaction-ID comparison → `false` | `TestUpstreamStaleDiscardUnit` |

## Remaining hardware boundary

The single-machine suite cannot reproduce every PLC, meter, converter, switch
or target kernel. Hardware commissioning must still cover vendor timing and
framing deviations, sustained polling, cable/network interruption, device
reboots, certificate lifecycle, transparent netfilter behavior and appliance
resource exhaustion. Missing hardware is documented as a validation boundary,
not silently converted into a passing test.
