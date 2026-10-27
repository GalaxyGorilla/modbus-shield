# Running modbus-shield in production (operations)

Day-2 operations for a deployed retrofit box: install as a service,
commission it on site, monitor it, change its configuration, and
troubleshoot it. The deployment itself is
[examples/gateway.md](gateway.md) — this guide starts where that one ends.

```
[clients] ──Modbus TCP──► [modbus-shield] ──Modbus TCP──► [legacy device]
                          (systemd service,      (plain, unmodified)
                           metrics + logs)
```

The box **is** the device's network path now — everything in this guide
follows from that: it must come back up on its own, its state must be
observable, and a restart must be boring.

## 1. Install as a service

The release binary is static — the box needs nothing but the binary and
a config file:

```bash
# build + ship (any Linux, no runtime dependencies):
make release
scp bin/modbus-shield box:/usr/local/bin/

# on the box: dedicated user + config
sudo useradd --system --no-create-home --shell /usr/sbin/nologin modbus-shield
sudo mkdir -p /etc/modbus-shield
sudo cp configs/gateway.yaml /etc/modbus-shield/gateway.yaml

# hardened systemd unit (shipped in deploy/):
sudo cp deploy/modbus-shield-gateway.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now modbus-shield-gateway
```

The unit runs as the `modbus-shield` user with `Type=notify` and
`WatchdogSec=30`: the binary sends `READY=1` on startup and pings
`WATCHDOG=1` every 15 s, so systemd restarts a wedged process instead of
leaving the device unreachable. `Restart=on-failure` (restarts forever
with 5 s pause), `ProtectSystem=strict` (read-only
filesystem), no new privileges, and `CAP_NET_BIND_SERVICE` as the only
capability — so it may bind port 502 and nothing else. Tuning the
listener address is a config change, not a unit change.

## 2. Commissioning checklist (on site)

Do this once after cabling, before pointing real clients at the box:

```bash
# 1. config is valid (syntax, addresses, allow-lists):
modbus-shield validate --config /etc/modbus-shield/gateway.yaml

# 2. the legacy device answers (real FC3 Modbus read directly to the
#    device; an exception response still proves liveness):
modbus-shield selftest --config /etc/modbus-shield/gateway.yaml

# 3. the chain works end to end (mbpoll through the box):
mbpoll -1 -m tcp -p 5020 -a 1 -c 1 -t 4:hex <box-ip>

# 4. wire the metrics scrape (see section 3), then:
systemctl status modbus-shield-gateway
```

`validate` and `selftest` both support `--json` for tooling and web UIs.
If `selftest` fails, the problem is between box and device (wiring,
power, device config) — clients are not involved yet.

## 3. Monitoring and alerting

Enable the Prometheus endpoint via `--metrics-addr :9202` (or
`metrics_listen: ":9202"` in YAML) and scrape it from your monitoring
system. Suggested alerts, in order of operational importance:

| Alert | Condition (suggest) | Meaning |
|---|---|---|
| Device unreachable | `modbus_shield_device_up == 0` for >1 min | box cannot reach the legacy device — power, wire, or device down |
| Upstream errors reaching clients | `rate(modbus_shield_requests_total{outcome="exception_device"}[5m]) > 0` | clients are seeing exception 0x0B |
| Write attempts blocked | `rate(modbus_shield_requests_total{outcome="exception_policy"}[5m]) > 0` | someone is trying to write to a read-only listener — a **security signal**, page or log it |
| Reconnect flapping | `increase(modbus_shield_reconnects_total[10m]) > 5` | flaky link or crashing device |
| Clients rejected | `increase(modbus_shield_connections_rejected_total[10m]) > 0` | allow-list misses or `max_clients` too low for the real client fleet |
| Device too slow | p99 of `modbus_shield_forward_latency_seconds` approaching `timeout_ms` | device or wire degraded; clients will start seeing timeouts next |

Rate limiting (exception 0x06) is usually **not** alert-worthy — it is
the shield doing its job. Watch `requests_total{outcome="exception_rate"}`
only if clients complain.

Logs: `log.format: json` ships cleanly into log collectors;
`log.level: debug` is for diagnosis only (verbose, not for steady
state). `journalctl -u modbus-shield-gateway -f` is enough on a
systemd appliance.

## 4. Changing configuration

There is no hot reload — the config is read once at startup:

```bash
# edit, then ALWAYS validate before applying:
modbus-shield validate --config /etc/modbus-shield/gateway.yaml
sudo cp gateway.yaml /etc/modbus-shield/gateway.yaml
sudo systemctl restart modbus-shield-gateway
```

A restart is boring by design:

- the front-leg listener rebinds and waits; clients reconnect on their
  next poll (SCADA systems retry automatically),
- requests already at the device are drained before shutdown completes
  (a response is not cut off mid-write); idle client connections are
  then closed so the stop stays prompt,
- the device sees the same thing it always sees: one plain Modbus TCP
  connection,
- blocked writes and rejected clients keep being rejected — there is no
  window where the device is exposed.

For fleet deployments, `validate --json` is the pre-apply gate: a web
UI or config pipeline can validate every candidate config before it
ever touches a box.

## 5. Troubleshooting playbook

Symptoms as the **client** sees them, with the box-side diagnosis:

| Client sees | Likely cause | Verify on the box | Fix |
|---|---|---|---|
| exception 0x0B (Gateway Target Device Failed To Respond) | device down or wire broken | `selftest`; `modbus_shield_device_up` gauge; `reconnects_total` climbing | restore device power/wiring; the box recovers on its own once the device answers |
| exception 0x06 (Server Device Busy) | rate limit hit — more polling than `rate_per_sec` (shared) or `rate_per_client_per_sec` (one client) allows | `requests_total{outcome="exception_rate"}`; a per-client hit logs `per-client rate limit` with the `[conn N]` ID | raise the limit, reduce pollers, or accept the shielding — if only ONE client sees 0x06, set/raise `rate_per_client_per_sec` instead of the shared budget |
| connection refused / dropped | client not on the `allow` list, or `max_clients` exhausted | `connections_rejected_total`; log line `connection rejected` | fix the allow-list entry (IP/CIDR) or raise `max_clients` |
| everything slow | device busy or slow wire | `forward_latency_seconds` p99 vs `timeout_ms` | check device load; tune `timeout_ms` so it exceeds the device's real worst-case RTT |
| reads fine, writes always fail with 0x01 | listener is `read_only` — working as intended | config `read_only: true` | that is the protection; remove `read_only` only deliberately |
| garbage/timeout on one client only | that client connection wedged | other clients fine; `stale_responses_discarded_total` flat | reconnect the client — the box isolates stuck clients by design |
| box not listening at all | process down or config invalid | `systemctl status`, `journalctl -u modbus-shield-gateway` | `validate` the config; check the unit's `ExecStart` path |

Two counters that look alarming but usually are not:

- `stale_responses_discarded_total` — a device that echoes wrong
  transaction IDs makes this climb; the proxy absorbs it and clients
  see correct answers. Investigate only if it grows while clients
  report errors.
- `reconnects_total` counting upward slowly — every successful dial
  counts (including the first). Trend matters, not the absolute value.

## 6. Upgrading the binary

The binary is static and stateless — an upgrade is replace + restart:

```bash
make release
make sbom && make vulnscan   # supply-chain check before shipping
scp bin/modbus-shield box:/usr/local/bin/modbus-shield.new
ssh box 'sudo mv /usr/local/bin/modbus-shield.new /usr/local/bin/modbus-shield \
         && sudo systemctl restart modbus-shield-gateway'
modbus-shield version        # confirm on the box
```

Nothing persists between restarts: no state directory, no sessions, no
queues. The new binary starts from the same config and behaves
identically.

## 7. What the device sees

Worth restating for operations planning: the legacy device experiences
exactly one plain Modbus TCP connection, forever. Box restarts,
client storms, and config changes are invisible to it apart from that
connection briefly dropping and re-dialing. The device cannot be
overwhelmed by the front leg: `max_clients` and `rate_per_sec` bound
what reaches it, and read-only listeners never let a write through.
