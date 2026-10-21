# mbaps role authorization (MODBUS/TCP Security profile)

Restrict what each client may do by issuing it a certificate with a
**role**: the mbaps role authorization mode (backlog B12) implements the
role-based part of the [MODBUS/TCP Security Protocol Specification]
(MB-TCP-Security-v36, the "mbaps" profile) on the front leg.

```
[operator client] --mTLS, role "operator"--> \
[engineer client] --mTLS, role "engineer"-->  [modbus-shield] --plain--> [legacy device]
[unknown client]  --mTLS, no role--------->  /
```

How it works:

- `mbaps` **requires mTLS** (`tls.cert` + `tls.key` + `tls.client_ca` —
  mutual authentication is mandatory per spec R-02/R-06).
- The client certificate carries a role in the **Modbus role extension**,
  OID `1.3.6.1.4.1.50316.802.1`, value ASN.1 UTF8String (spec R-21/R-22;
  one role per certificate, R-65).
- The box extracts the role at handshake and checks **every request**
  against the role's allowed function codes (spec R-31). A denied request
  gets a clean Modbus exception **0x01 Illegal Function** — the device
  never sees it.
- A certificate **without** a role extension gets the NULL role (R-23)
  and is denied every device request. A role missing from the configured
  table is likewise denied. Health reads (`health_unit_id`) bypass the
  check so monitoring stays responsive.
- The Roles-to-Rights mapping is vendor-specific per the spec (R-24/R-25);
  here it is a simple role-name -> function-codes table.

## 1. Create the PKI (one CA, server + per-role client certs)

For a quick start, `scripts/gen-certs.sh` generates the whole PKI
(CA + server + client + operator/engineer role certs with the mbaps
role extension) into `certs/`. The walkthrough below uses a `pki/`
directory with production-shaped names.

```sh
mkdir pki && cd pki
# CA
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -new -x509 -key ca.key -subj "/CN=plant CA" -days 365 -out ca.crt
# server certificate (the box)
openssl ecparam -name prime256v1 -genkey -noout -out server.key
openssl req -new -key server.key -subj "/CN=127.0.0.1" -out server.csr
printf "subjectAltName=IP:127.0.0.1,DNS:modbus-shield\nextendedKeyUsage=serverAuth\n" > server.ext
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -extfile server.ext -days 365 -out server.crt
# operator client: may READ only (FC 1,2,3,4)
openssl ecparam -name prime256v1 -genkey -noout -out operator.key
openssl req -new -key operator.key -subj "/CN=operator" -out operator.csr
printf "extendedKeyUsage=clientAuth\n1.3.6.1.4.1.50316.802.1=ASN1:UTF8String:operator\n" > operator.ext
openssl x509 -req -in operator.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -extfile operator.ext -days 365 -out operator.crt
# engineer client: may READ and WRITE (adds FC 5,6,15,16)
openssl ecparam -name prime256v1 -genkey -noout -out engineer.key
openssl req -new -key engineer.key -subj "/CN=engineer" -out engineer.csr
printf "extendedKeyUsage=clientAuth\n1.3.6.1.4.1.50316.802.1=ASN1:UTF8String:engineer\n" > engineer.ext
openssl x509 -req -in engineer.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -extfile engineer.ext -days 365 -out engineer.crt
```

The `1.3.6.1.4.1.50316.802.1=ASN1:UTF8String:<role>` line in the
extension file is the mbaps role (OpenSSL syntax).

## 2. Configure the box

```yaml
devices:
  - name: legacy-plc
    listen_addr: ":502"
    device_addr: "10.0.0.42:502"
    tls:
      cert: /etc/modbus-shield/pki/server.crt
      key: /etc/modbus-shield/pki/server.key
      client_ca: /etc/modbus-shield/pki/ca.crt
    mbaps:
      roles:
        operator: [1, 2, 3, 4]              # reads only
        engineer: [1, 2, 3, 4, 5, 6, 15, 16] # reads + writes
```

Or as a one-liner (repeatable `--mbaps-role ROLE=FC,FC,...`):

```sh
modbus-shield gateway --listen :502 --device 10.0.0.42:502 \
  --tls-cert pki/server.crt --tls-key pki/server.key --tls-client-ca pki/ca.crt \
  --mbaps-role "operator=1,2,3,4" \
  --mbaps-role "engineer=1,2,3,4,5,6,15,16"
```

## 3. Verify

```sh
modbus-shield validate --config gateway.yaml
modbus-shield selftest --config gateway.yaml   # probes the device directly
```

Then point an mbaps-capable client at the box. `mbpoll` does not speak
TLS; with pymodbus (v3), hand it an SSLContext carrying the role
certificate:

```python
import ssl
from pymodbus.client import ModbusTcpClient

ctx = ssl.create_default_context(cafile="pki/ca.crt")
ctx.load_cert_chain("pki/operator.crt", "pki/operator.key")
ctx.check_hostname = False  # IP-SAN test cert; use DNS SAN in production

c = ModbusTcpClient("modbus-shield-host", port=502, sslctx=ctx)
c.connect()
rr = c.read_holding_registers(0x0100, count=1, slave=1)   # allowed
wr = c.write_register(0x0100, 1, slave=1)                 # denied: exception 0x01
print(rr, wr)
c.close()
```

Any TLS-capable Modbus client works; the client presents its role
certificate and every request is authorized per the table above.

## Protection semantics

- **mTLS is mandatory**: a client without a certificate signed by
  `client_ca` fails the TLS handshake — it never reaches the proxy loop.
- **Role enforced on every request** (spec R-31): a denied request gets
  exception 0x01 Illegal Function generated by the proxy; the device
  never sees it. The deny is visible in the logs
  (`mbaps denied FC 6 (not authorized)`) and in Prometheus as
  `modbus_shield_requests_total{outcome="exception_authz"}`.
- **NULL role denied**: a valid client certificate without a role
  extension (or with an unconfigured role) can connect but is denied
  every device request (R-23).
- **Health stays monitorable**: reads to `health_unit_id` bypass role
  rights, so plant SCADA can watch the box even as a NULL-role client.
- **Stacks with everything else**: read-only, allow-list, rate limit,
  connection cap and pacing apply on top of role authorization.

## Notes

- TLS 1.2 minimum (spec R-01/R-34); the Go stdlib negotiates newer.
- One role per certificate (R-65) — the whole extension string is the
  role name.
- Spec-conformant client certs use `extendedKeyUsage=clientAuth`; the
  TLS layer already requires CA-signed client certs in this mode.
- `mbpoll` does not speak TLS; use a TLS-capable Modbus client to test.
- This implements the **role-authorization subset** of the mbaps
  profile on the front leg. It is not a full mbaps server (the spec's
  port-802 profile with its own session semantics); the device-side wire
  stays plain Modbus TCP.
