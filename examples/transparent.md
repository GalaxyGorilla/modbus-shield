# Transparent bump-in-the-wire mode (B3, Linux-only)

Deploy the box as a **cable splice**: clients keep dialing the device's
real IP:502 — the box intercepts the traffic inline. Zero client
reconfiguration, zero device reconfiguration. Unplug the device's cable,
plug both ends into the box, install one netfilter rule, done.

```
                        +--------------------+
 [clients] ----splice---| two-NIC Linux box  |---splice---- [legacy device]
     (unchanged)        |   modbus-shield    |             (unchanged)
                        +--------------------+
        netfilter REDIRECT: tcp/502 -> gateway; gateway forwards to the
        ORIGINAL destination recovered from conntrack (SO_ORIGINAL_DST)
```

## Requirements

- **Linux only** (netfilter + conntrack; the binary still builds
  elsewhere but transparent mode errors cleanly).
- **CAP_NET_ADMIN** (or root) to install the redirect rule.
- The box must be **in the traffic path**: default gateway for the
  clients, or a bridge. The netfilter rule only sees traffic that is
  routed through the box.

## 1. Install the redirect rule

```sh
sudo scripts/setup-transparent.sh eth0        # clients arrive on eth0
# or manually:
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 502 -j REDIRECT --to-port 5020
```

The script is idempotent and NOT run automatically (it rewrites firewall
rules — an appliance should never do that silently).

## 2. Run the gateway

```sh
modbus-shield gateway --listen :5020 --transparent --read-only \
  --rate-per-sec 20 --allow 10.8.0.0/24
```

`--transparent` tells the gateway to forward to the client's **original
destination** (from conntrack) instead of a configured `device_addr`.
The YAML form:

```yaml
devices:
  - name: legacy-plc
    listen_addr: ":5020"
    device_addr: "legacy-plc:502"   # label only in transparent mode
    transparent: true
    read_only: true
    allow: ["10.8.0.0/24"]
    rate_per_sec: 20
```

## 3. Verify

```sh
modbus-shield validate --config /etc/modbus-shield/gateway.yaml --json
mbpoll -m tcp -a 1 -r 257 -t 4:hex -1 <device-ip>   # through the box
```

Every feature keeps working unchanged — ACLs, read-only, rate limit,
health unit-ID, metrics: a transparent connection is just a client
connection whose upstream address comes from conntrack instead of config.

## Protection semantics

- **Denied = the protection**: out-of-allow-list clients are refused at
  accept; writes get exception 0x01 (read-only); pollers get 0x06 when
  the rate limit trips.
- **Fail-OPEN by design**: if the redirect rule is missing, or the box
  bridges traffic without redirecting it, packets flow **unproxied
  straight to the device** — all shielding is bypassed. This is the
  inherent property of an inline splice (a blocking inline firewall
  would fail-closed, at the cost of taking the device down with the
  box). Monitor the rule's presence; alert if it disappears.
- If the box routes but modbus-shield dies: the REDIRECT has no
  listener → connections to port 502 through the box are refused (the
  device is unreachable through the box until the process returns).

## Notes

- The upstream target is resolved **per client connection**; the gateway
  multiplexes one client connection's traffic onto its own device
  connection as usual (the shielding model is unchanged).
- `device_addr` is still required — it is the device's name/label in
  logs and metrics (and the connection target in case the resolver is
  never consulted, e.g. health-only traffic).
- TLS front leg (`tls:` block) is independent of transparent mode; mTLS
  clients keep working. The original-destination lookup happens on the
  accepted socket before/after TLS termination — it reads conntrack, not
  the stream.
- Tested here by unit tests (sockaddr parsing) + e2e tests with an
  injected fake resolver (transparent gateway, per-connection target
  re-dial, resolver-error recovery). The netfilter path itself needs a
  manual validation on target hardware with CAP_NET_ADMIN (see
  docs/b3-transparent-mode.md).
