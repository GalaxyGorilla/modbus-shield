# Example: TLS front leg (encrypted client-facing side)

Terminate TLS on the client-facing listener while the device-side wire
stays plain Modbus TCP. The legacy device notices nothing — it still sees
one plain connection from the box.

```
[TLS clients] --TLS--> [modbus-shield] --plain Modbus TCP--> [legacy device]
```

Use this when clients are on an untrusted network segment (plant office,
remote access) and the Modbus wire between them and the box must be
encrypted. Add a client CA for mTLS: only clients holding a certificate
signed by your CA may connect at all.

## 1. Create certificates

For production, use your PKI. For a quick start, one self-signed CA with
a server and a client certificate (ECDSA, IP SAN for the box):

```bash
mkdir -p /etc/modbus-shield/tls && cd /etc/modbus-shield/tls

# CA (signs both certs below)
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -x509 -new -key ca.key -sha256 -days 3650 \
    -subj "/CN=modbus-shield CA" -out ca.crt

# Server certificate for the box (clients verify this; SAN must match
# the address clients dial — here 10.8.0.1 and localhost)
openssl ecparam -name prime256v1 -genkey -noout -out server.key
openssl req -new -key server.key -subj "/CN=modbus-shield" -out server.csr
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -days 825 \
    -sha256 -extfile <(printf "subjectAltName=IP:10.8.0.1,DNS:localhost\nextendedKeyUsage=serverAuth") \
    -out server.crt

# Client certificate (SCADA presents this; signed by the same CA)
openssl ecparam -name prime256v1 -genkey -noout -out client.key
openssl req -new -key client.key -subj "/CN=scada-1" -out client.csr
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -days 825 \
    -sha256 -extfile <(printf "extendedKeyUsage=clientAuth") \
    -out client.crt

chmod 600 *.key
```

## 2. Run it

Config file (per-device `tls:` block):

```yaml
devices:
  - name: legacy-plc
    listen_addr: ":5020"
    device_addr: "10.0.0.42:502"
    read_only: true
    tls:
      cert: /etc/modbus-shield/tls/server.crt
      key: /etc/modbus-shield/tls/server.key
      # client_ca turns on mTLS: clients MUST present a signed cert.
      client_ca: /etc/modbus-shield/tls/ca.crt
```

```bash
modbus-shield validate --config gateway.yaml   # pre-apply check (also checks the files)
modbus-shield gateway --config gateway.yaml
```

Or flags (single device, plug and play):

```bash
modbus-shield gateway --listen :5020 --device 10.0.0.42:502 --read-only \
    --tls-cert /etc/modbus-shield/tls/server.crt \
    --tls-key /etc/modbus-shield/tls/server.key \
    --tls-client-ca /etc/modbus-shield/tls/ca.crt
```

TLS is terminated on the front leg only; ACLs, read-only policy, shielding
limits and unit-ID remapping apply exactly as on plain TCP. The handshake
is lazy per connection — a hanging client cannot block new connections,
and a plain (non-TLS) client costs its connection only; the box keeps
serving.

## 3. Verify

With a TLS-capable client. `mbpoll` does not speak TLS, so use Python
(`pymodbus` v3 wraps an SSLContext) or any TLS-capable Modbus client you
already have:

```python
import ssl
from pymodbus.client import ModbusTcpClient

ctx = ssl.create_default_context(cafile="/etc/modbus-shield/tls/ca.crt")
ctx.load_cert_chain("/etc/modbus-shield/tls/client.crt",
                    "/etc/modbus-shield/tls/client.key")
# check_hostname=False because the CA below signs an IP-SAN cert;
# prefer a DNS SAN + hostname check in production.
ctx.check_hostname = False

c = ModbusTcpClient("10.8.0.1", port=5020, sslctx=ctx)
c.connect()
rr = c.read_holding_registers(0x0100, count=1, slave=1)
print(rr.registers)
c.close()
```

Or a bare-socket check with the client cert (no Modbus client needed):

```bash
openssl s_client -connect 10.8.0.1:5020 \
    -cert /etc/modbus-shield/tls/client.crt \
    -key /etc/modbus-shield/tls/client.key \
    -CAfile /etc/modbus-shield/tls/ca.crt </dev/null | head -5
```

A client without a certificate is rejected during the handshake when
`client_ca` is set (mTLS). A plain Modbus client against the TLS listener
gets a failed connection, not a protocol downgrade.

## Protection semantics

- **Encryption**: the client-facing wire is TLS 1.2+ (Go stdlib
  `crypto/tls`); Modbus traffic is not readable on that segment.
- **mTLS**: with `client_ca`, only clients with a CA-signed certificate
  pass the handshake — certificate-based access control independent of
  IP addresses.
- **Device-side stays plain**: TLS ends at the box. The legacy device
  keeps speaking unmodified Modbus TCP on one connection.
- **Everything else unchanged**: read-only, allow-lists, connection cap,
  rate limit and metrics work identically on TLS listeners.

## Hardening notes

- Set `log.format: json` in production and ship logs; handshake failures
  appear at debug level.
- Watch `modbus_shield_requests_total{outcome="exception_policy"}` and
  connection metrics — unchanged by TLS.
- Point `metrics_listen` at a loopback or management address (metrics
  are served over plain HTTP, not on the Modbus listener).
- Keep `ca.crt` as the only trust anchor your clients need; rotate
  `server.crt`/`client.crt` independently.
