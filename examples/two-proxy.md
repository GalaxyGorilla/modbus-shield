# Two-proxy secured line (device side over TLS)

When the clients and the legacy device live in different network segments
(plant floor vs. control room, different sites, a DMZ between them), one
box is not enough: the *link between the boxes* must be secured. Two
modbus-shield instances form a secured line — the front box accepts plain
Modbus TCP from local clients, encrypts everything across the untrusted
link, and the far box terminates TLS in front of the device:

```
[clients]                          untrusted link                        [device]
   |                                      |                                 |
   |-- plain Modbus TCP --> [front box] --TLS/mTLS--> [far box] -- plain -->|
                            modbus-shield              modbus-shield
                            gateway with               gateway with
                            device_tls:                tls: (front leg)
```

Both boxes run the **same binary** with the same `gateway` role — the far
box is just a normal front-leg TLS gateway (see `tls.md`); the front box
adds a `device_tls:` block that dials the device over TLS.

## 1. Generate certificates

The far box needs a server certificate for the names it is reached by
(here: `192.168.40.2`); the front box needs a client certificate so the
far box can require mTLS. One CA signs both:

```sh
# CA
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -x509 -new -key ca.key -subj "/CN=line CA" -days 365 -out ca.crt

# Far box server certificate (IP SAN for the device-side address)
openssl ecparam -name prime256v1 -genkey -noout -out far.key
openssl req -new -key far.key -subj "/CN=farbox" -out far.csr
printf "subjectAltName=IP:192.168.40.2,DNS:farbox.internal\nextendedKeyUsage=serverAuth\n" > far.ext
openssl x509 -req -in far.csr -CA ca.crt -CAkey ca.key -extfile far.ext -days 365 -out far.crt

# Front box client certificate (mTLS toward the far box)
openssl ecparam -name prime256v1 -genkey -noout -out front.key
openssl req -new -key front.key -subj "/CN=frontbox" -out front.csr
printf "extendedKeyUsage=clientAuth\n" > front.ext
openssl x509 -req -in front.csr -CA ca.crt -CAkey ca.key -extfile front.ext -days 365 -out front.crt
```

## 2. Run the far box (device side)

```sh
modbus-shield gateway \
  --listen 0.0.0.0:5020 \
  --device 10.0.0.42:502 \
  --tls-cert far.crt --tls-key far.key \
  --tls-client-ca ca.crt
```

The far box only accepts TLS connections presenting a certificate signed
by `ca.crt`; the device-side wire stays plain Modbus TCP.

## 3. Run the front box (client side)

```sh
modbus-shield gateway \
  --listen 0.0.0.0:502 \
  --device 192.168.40.2:5020 \
  --device-tls-ca ca.crt \
  --device-tls-server-name farbox.internal \
  --device-tls-cert front.crt --device-tls-key front.key
```

The front box dials the far box over TLS, verifies its certificate
against `ca.crt` (expecting the name `farbox.internal`), and presents its
own client certificate. Clients talk plain Modbus TCP to `:502` as always.

Equivalent YAML (front box):

```yaml
devices:
  - name: line-front
    listen_addr: "0.0.0.0:502"
    device_addr: "192.168.40.2:5020"
    read_only: false
    device_tls:
      ca_cert: "ca.crt"
      server_name: "farbox.internal"
      cert: "front.crt"
      key: "front.key"
```

## 4. Verify

```sh
# Front box
modbus-shield validate --config front.yaml && modbus-shield selftest --config front.yaml

# Far box
modbus-shield validate --config far.yaml && modbus-shield selftest --config far.yaml

# End to end through both boxes (mbpoll, plain Modbus TCP)
mbpoll -1 -m tcp -a 1 -t 4:hex -r 257 -c 1 -p 502 <front-box-ip>
```

`selftest` on the front box probes over the TLS leg — a green probe
proves the certificate chain, the mTLS handshake, and the far box.

## Protection semantics

- The untrusted link carries **only TLS**; a wiretap sees ciphertext.
- The far box rejects any TLS client **without a certificate signed by
  the CA** (mTLS) — the device never sees rejected attempts.
- A name mismatch (wrong `server_name` / missing SAN) fails the dial and
  surfaces to clients as a Modbus gateway exception (0x0B) — the front
  box keeps retrying with backoff, so a recovering far box needs no
  client action.
- All shielding (read-only, allow-lists, rate limits, connection caps)
  applies independently per box; typically the front box enforces client
  policies and the far box enforces `allow` limited to the front box's
  address.

## Notes

- `device_tls.ca_cert` may be omitted when the far box's certificate
  chains to a CA in the system trust store (e.g. an internal PKI).
- `device_tls.server_name` is only needed when the certificate's SAN does
  not match the dialed address (IP-dialed box with a DNS-name cert).
- The boxes reconnect independently; bring up the far box first and the
  front box will connect on its next retry.
- PSK-TLS is deliberately not used: Go's stdlib lacks external PSK
  support, and mutual X.509 covers the rotated-credential story better.
