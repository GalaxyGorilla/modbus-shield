# examples/

Copy-paste deployment walkthroughs for every modbus-shield shape.

| Walkthrough | Shape |
|---|---|
| [gateway.md](gateway.md) | Gateway box — one box in front of the legacy device (the v1 retrofit deployment) |
| [multi-device.md](multi-device.md) | Multi-device box — one instance, several listeners and devices with per-device policies |
| [operations.md](operations.md) | Production operations — systemd install, commissioning, monitoring, config changes, troubleshooting, upgrades |
| [tls.md](tls.md) | TLS front leg — encrypted, optionally mTLS-authenticated client-facing side |

Planned (see [../BACKLOG.md](../BACKLOG.md)): TLS front leg, two-proxy
secured line, transparent bump-in-the-wire.
