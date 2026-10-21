# examples/

Copy-paste deployment walkthroughs for every modbus-shield shape.

| Walkthrough | Shape |
|---|---|
| [gateway.md](gateway.md) | Gateway box — one box in front of the legacy device (the v1 retrofit deployment) |
| [multi-device.md](multi-device.md) | Multi-device box — one instance, several listeners and devices with per-device policies |
| [operations.md](operations.md) | Production operations — systemd install, commissioning, monitoring, config changes, troubleshooting, upgrades |
| [health.md](health.md) | Health via Modbus — monitor the box itself from plant SCADA via a virtual unit-ID (no extra port or tooling) |
| [tls.md](tls.md) | TLS front leg — encrypted, optionally mTLS-authenticated client-facing side |
| [two-proxy.md](two-proxy.md) | Two-proxy secured line — two boxes, TLS/mTLS across the untrusted link between them |
| [mbaps.md](mbaps.md) | mbaps role authorization — per-role function-code rights from certificate roles (mTLS mandatory) |
| [transparent.md](transparent.md) | Transparent bump-in-the-wire (Linux-only) — cable-splice install, zero reconfiguration, netfilter REDIRECT + conntrack |

Planned (see [../BACKLOG.md](../BACKLOG.md)): transparent bump-in-the-wire.
