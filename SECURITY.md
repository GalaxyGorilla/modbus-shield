# Modbus Shield security model

Modbus Shield is a security boundary in front of legacy Modbus TCP devices. It
reduces exposure; it does not make an untrusted device, host, or clear network
segment trustworthy.

Start with [`README.md`](README.md) for deployment shapes,
[`examples/operations.md`](examples/operations.md) for day-2 operation, and
[`TESTING.md`](TESTING.md) for the evidence and release gates.

## Protected assets

- Availability of fragile devices and their single upstream connection.
- Register and coil writes governed by read-only or address-scoped policy.
- Client/device traffic confidentiality and peer authentication where TLS or
  mTLS is configured.
- Per-role function-code authorization in MBAPS mode.
- Integrity of the running policy across configuration reloads.

## Trust boundaries

The appliance host, configuration file, administrators, private keys and
issuing CAs are trusted. A one-box gateway normally leaves the final
proxy-to-device Modbus leg clear; physically protect or isolate that segment.
Use the two-proxy TLS deployment when the middle network is untrusted.

Client IP allow-lists are network policy, not cryptographic identity. Use mTLS
when identity must survive NAT, shared hosts, or an untrusted client network.
The legacy device and all wire input are treated as malformed or hostile, but a
compromised device can still return plausible false process data.

## Enforced controls

- Strict MBAP/RTU framing and bounded ADU sizes.
- Connection caps, shared and per-client request rates, pacing and idle
  eviction.
- Client allow-lists, read-only mode and address-scoped write policy.
- TLS/mTLS front and upstream legs with normal certificate verification.
- Mandatory mTLS and certificate-role function-code rights in MBAPS mode.
- Request/response correlation, stale-response discard and bounded timeouts.
- Atomic runtime-policy snapshots on `SIGHUP`; invalid reloads keep the last
  valid policy.
- Hardened systemd service, readiness ordering, watchdog, graceful draining,
  structured logs, health endpoints and security-policy metrics.

Security denials are enforced before device forwarding. Cached reads, health
traffic, transparent mode and lenient device correlation have documented,
tested ordering and scope; none bypass write authorization.

## Deliberate limits

- Modbus Shield is not a firewall, IDS, malware scanner, safety PLC or
  end-to-end process-data authenticator.
- TLS is optional outside MBAPS mode. A plain listener provides policy and
  shielding but no cryptographic client identity or confidentiality.
- One-box deployments do not encrypt the legacy device leg.
- Rate limits reduce abuse but cannot guarantee availability under host,
  network or upstream-device exhaustion.
- Transparent mode depends on Linux netfilter/original-destination behavior and
  requires target-host commissioning.
- Certificate issuance, revocation, rotation and hardware key protection are
  deployment responsibilities.
- Real hardware, external review and regulatory certification remain separate
  validation work.

## Release security gate

```sh
make verify       # format, race suite, build and vet
make acceptance   # independent mbpoll + real-binary policy smokes
make security     # staticcheck, govulncheck, SBOM and HIGH+ vulnerability gate
```

`make sbom` writes SPDX and CycloneDX documents to `dist/`.
`scripts/sbom.sh --sbom-only` provides the same standalone artifact flow.

## Reporting vulnerabilities

Please use GitHub's private **Report a vulnerability** function for this
repository. Include the affected mode, configuration shape, reproduction,
expected policy and observed wire behavior. Do not attach production
certificates, keys, packet captures containing process data, or proprietary
register maps.
