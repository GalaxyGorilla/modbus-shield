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
| Lifecycle | Invalid/valid reloads, graceful drain, listener ownership, systemd readiness and watchdog |
| Independent client | `mbpoll` drives the built gateway through reads, writes, exceptions, unit IDs and concurrent clients |
| Real binary | Reload and connection-identity smoke scripts exercise the compiled command |

## Commands

```sh
make test          # gofmt + complete race suite
make verify        # build + race suite + vet
make acceptance    # verify + mbpoll + real-binary smokes
make security      # verify + staticcheck + govulncheck + SBOM vulnerability gate
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
- A listener bind failure cannot emit systemd `READY=1`.
- Shutdown drains in-flight requests, while stale or mismatched responses are
  never delivered to another client.
- Cache hits and rate limits follow the documented device-protection ordering.

## Remaining hardware boundary

The single-machine suite cannot reproduce every PLC, meter, converter, switch
or target kernel. Hardware commissioning must still cover vendor timing and
framing deviations, sustained polling, cable/network interruption, device
reboots, certificate lifecycle, transparent netfilter behavior and appliance
resource exhaustion. Missing hardware is documented as a validation boundary,
not silently converted into a passing test.
