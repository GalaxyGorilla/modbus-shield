package proxy

import (
	"crypto/x509"
	"encoding/asn1"
)

// mbapsRoleOID is the Modbus.org private-enterprise OID for the mbaps
// client role certificate extension (MB-TCP-Security-v36, R-21). The
// extension value is an ASN.1 UTF8String (R-22); the entire string is one
// role (R-65).
var mbapsRoleOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 50316, 802, 1}

// mbapsRole extracts the mbaps role from a client certificate: the value
// of the first extension matching the Modbus.org role OID, decoded as an
// ASN.1 UTF8String. ok=false when the certificate carries no (or a
// malformed) role extension — the NULL role per spec R-23.
func mbapsRole(cert *x509.Certificate) (role string, ok bool) {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(mbapsRoleOID) {
			continue
		}
		var r string
		if _, err := asn1.Unmarshal(ext.Value, &r); err != nil {
			return "", false
		}
		return r, true
	}
	return "", false
}

// mbapsRightsFor resolves the allowed function codes for a connection's
// role. A role without an entry (or the NULL role) yields a nil set =
// deny every device request.
func mbapsRightsFor(roles map[string]map[uint8]bool, role string, ok bool) map[uint8]bool {
	if !ok {
		return nil
	}
	return roles[role]
}
