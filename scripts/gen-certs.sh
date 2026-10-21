#!/bin/sh
# Generate a throwaway PKI for TLS/mbaps testing and small deployments:
#   certs/ca.{crt,key}, certs/{server,client}.{crt,key}
#   certs/client-operator.{crt,key} / certs/client-engineer.{crt,key} (mbaps)
# Server SANs: localhost, 127.0.0.1
# Client SANs: modbus-shield-client(-operator / -engineer)
# Role certs carry the Modbus role extension (mbaps):
#   OID 1.3.6.1.4.1.50316.802.1 = UTF8String "operator" / "engineer"
#
# Output lands in certs/ (gitignored). For testing only.
# POSIX sh (no bashisms): works under sh, bash, and direct exec.
set -eu

cd "$(dirname "$0")/.."
mkdir -p certs

DAYS=825
CA_CN="modbus-shield test CA"
SRV_CN="localhost"
CLI_CN="modbus-shield-client"
ROLE_OID="1.3.6.1.4.1.50316.802.1"

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout certs/ca.key -out certs/ca.crt -days "$DAYS" -nodes \
  -subj "/CN=${CA_CN}" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout certs/server.key -out certs/server.csr -nodes \
  -subj "/CN=${SRV_CN}"

openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout certs/client.key -out certs/client.csr -nodes \
  -subj "/CN=${CLI_CN}"

# ext files (POSIX: no process substitution)
printf '%s\n' \
  "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  "extendedKeyUsage=serverAuth" > certs/server.ext
printf '%s\n' \
  "subjectAltName=DNS:${CLI_CN}" \
  "extendedKeyUsage=clientAuth" > certs/client.ext

openssl x509 -req -in certs/server.csr -CA certs/ca.crt -CAkey certs/ca.key \
  -CAcreateserial -out certs/server.crt -days "$DAYS" \
  -extfile certs/server.ext

openssl x509 -req -in certs/client.csr -CA certs/ca.crt -CAkey certs/ca.key \
  -CAcreateserial -out certs/client.crt -days "$DAYS" \
  -extfile certs/client.ext

# mbaps role certs (one role per cert, UTF8String role extension).
for role in operator engineer; do
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout "certs/client-${role}.key" -out "certs/client-${role}.csr" -nodes \
    -subj "/CN=${CLI_CN}-${role}"

  printf '%s\n' \
    "subjectAltName=DNS:${CLI_CN}-${role}" \
    "extendedKeyUsage=clientAuth" \
    "${ROLE_OID}=ASN1:UTF8String:${role}" > "certs/client-${role}.ext"

  openssl x509 -req -in "certs/client-${role}.csr" -CA certs/ca.crt -CAkey certs/ca.key \
    -CAcreateserial -out "certs/client-${role}.crt" -days "$DAYS" \
    -extfile "certs/client-${role}.ext"

  rm -f "certs/client-${role}.csr" "certs/client-${role}.ext"
done

rm -f certs/server.csr certs/client.csr certs/server.ext certs/client.ext
chmod 600 certs/*.key

echo "wrote certs/ca.{crt,key} certs/server.{crt,key} certs/client.{crt,key}"
echo "     certs/client-operator.{crt,key} certs/client-engineer.{crt,key} (mbaps role certs)"
