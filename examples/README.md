# examples/

Copy-paste deployment walkthroughs for every modbus-shield shape.

**New here?** Start with [gateway.md](gateway.md) — the primary retrofit
deployment. It includes a two-minute Modbus background section, so no
prior Modbus knowledge is needed.

| Walkthrough | Use this when |
|---|---|
| [gateway.md](gateway.md) | You have one legacy device and want it protected — the standard retrofit deployment |
| [multi-device.md](multi-device.md) | One box, several devices, different rules per device |
| [operations.md](operations.md) | The box is deployed — day-2: install as a service, commission, monitor, troubleshoot, upgrade |
| [health.md](health.md) | You want to monitor the box itself from plant SCADA with the Modbus tooling you already have |
| [tls.md](tls.md) | Clients sit on an untrusted network segment and the traffic to the box must be encrypted (optionally mTLS) |
| [two-proxy.md](two-proxy.md) | Clients and device are in different sites/segments — the link between two boxes carries only TLS |
| [mbaps.md](mbaps.md) | Different users deserve different permissions — per-role function-code rights from certificate roles (mTLS mandatory) |
| [transparent.md](transparent.md) | You cannot reconfigure clients or device at all — cable-splice install, zero reconfiguration (Linux-only) |
