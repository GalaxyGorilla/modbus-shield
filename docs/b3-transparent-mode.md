# B3 design spike: transparent bump-in-the-wire mode

Status: DONE — implemented and shipped (commit 7bfa663). This document
records the design spike that preceded the implementation; see
examples/transparent.md for the operator walkthrough and
internal/proxy/origdst_linux.go for the code.

## 1. Goal

Deploy modbus-shield as a **cable splice**: the box sits physically between
the network and the legacy device (two NICs / bridge / default-gateway role)
and intercepts Modbus TCP inline — **zero client reconfiguration, zero
device reconfiguration**. Clients keep dialing the device's IP:502; the box
answers for it. Other traffic passes through untouched.

This is the strongest retrofit story ("unplug cable from device, plug both
ends into the box, done") but the largest engineering risk of any backlog
item. This spike exists to pick the mechanism before writing code.

## 2. What transparency requires

The proxy must, per accepted connection, learn **where the client was
originally headed** (the device's real IP:502) and forward there, while
pretending to be that destination. Linux provides this via netfilter +
conntrack:

- A netfilter rule steers inbound TCP/502 into the local proxy.
- The ORIGINAL pre-redirect destination is stored in conntrack and
  recoverable with `getsockopt(SO_ORIGINAL_DST)`.
- Everything else (non-502) is forwarded/bridged by the kernel — the proxy
  never sees it.

Key platform facts (verified Oct 2026):

- `golang.org/x/sys/unix` (already in the dependency tree) exposes both
  `SO_ORIGINAL_DST` and `IP_TRANSPARENT` — **no new dependency needed**.
- `florianl/go-nfqueue` v2 (MIT, 114★, healthy) is the userspace
  netfilter-queue API — only relevant for the rejected option A2 below.
- The whole feature is **Linux-only** (iptables/nft + conntrack).

## 3. Options considered

### A1 — TPROXY/REDIRECT + userspace proxying (RECOMMENDED)

```
iptables -t nat -A PREROUTING -i <ingress> -p tcp --dport 502 -j REDIRECT --to-port 5020
```

Kernel terminates the client's TCP at the box; the gateway accepts on
`5020` and recovers the real destination per connection via
`getsockopt(SO_ORIGINAL_DST)`; the existing upstream path
(`ensureConn`/`exchange`, incl. TLS/RTU options) dials the **original
destination**. Nothing about the data plane changes — multiplexing,
shielding, ACLs, read-only, health all keep working unchanged, because a
transparent connection is just a client connection whose upstream address
came from conntrack instead of config.

- Pros: kernel handles the entire TCP state machine; reuses 100% of the
  existing, race-tested gateway core; ~1 new file (original-dst resolution)
  + config plumbing + rule helper; smallest possible delta.
- Cons/risks:
  - Needs `CAP_NET_ADMIN` (install the iptables rule) and, for true
    transparent binding on the same IP, `IP_TRANSPARENT`.
  - REDIRECT requires traffic to be *routed through* the box (default
    gateway / bridge role); the box becomes the device's network path.
  - **The dev box has no root** (verified: iptables permission denied) —
    the netfilter path can only be unit-tested with mocks + a documented
    manual test on target hardware.
  - Per-connection upstream address breaks `device_tls`/`rtu_over_tcp`
    assumptions only in the sense that the target is per-connection — both
    flags still apply per gateway (traffic profile stays one device).

### A2 — NFQUEUE userspace packet mangling (REJECTED)

Intercept raw IP/TCP packets in userspace (go-nfqueue), re-inject a
proxied flow. Rejected: requires implementing a userspace TCP state machine
(windows, retransmits, keepalives, fragmentation) — a CVE factory and a
maintenance burden with zero benefit over A1, where the kernel does this
for free.

### A3 — eBPF (SK_LOOKUP / XDP) (REJECTED for now)

Elegant but: cilium/ebpf supports only linux amd64/arm64 (excludes the
armv7 Pi-class devices central to the appliance story), adds toolchain
complexity (clang/llvm for CO:RE), and Modbus traffic volumes (KB/s) give
eBPF's performance advantage nothing to do. Revisit only if a customer
deployment demands wire-rate on 10G+.

## 4. Implementation sketch (if we build it)

1. `internal/config`: per-device `transparent: true` (mutually exclusive
   with `device_addr`; `rtu_over_tcp`/`device_tls` keep working per
   gateway).
2. `internal/proxy/origdst_linux.go`: `originalDST(conn) (string, error)`
   via `unix.GetsockoptIP`/`SO_ORIGINAL_DST` on the accepted socket;
   build-tag `!linux` stub returning an error (binary stays cross-platform,
   transparent mode errors cleanly elsewhere).
3. `gateway`: when transparent, per accepted connection resolve orig-dst
   lazily on first exchange (upstream target becomes per-connection;
   `upstream.addr` turns into a resolver func — the only structural
   change).
4. `scripts/setup-transparent.sh`: idempotent iptables/nft rule + bridge
   setup for the two-NIC splice (documented manual step, not auto-run —
   the box must never silently rewrite firewall rules).
5. Docs: `examples/transparent.md` with the hardware role (bridge or
   default gateway), capability requirements, failure mode (rule missing =
   traffic flows unproxied straight to the device — fail-OPEN by design,
   called out loudly; ACLs/shielding are bypassed in that state).

## 5. Decision required before coding

The blocker is **testability**: no root on the dev box means the netfilter
mechanism itself ships untested here (unit-tested with mocks only; manual
test on real hardware required before any customer claim). Options:

- **Build now**: A1 as sketched, mocks + smoke scripts included, README
  marks it "requires manual validation on target hardware".
- **Ship the design, defer code**: keep this doc + the script skeleton as
  the B3 deliverable; revisit when hardware with CAP_NET_ADMIN is
  available for a proper integration test.

Either way, A2/A3 stay rejected and A1 is the only mechanism worth
building.
