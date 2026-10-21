//go:build !linux

package proxy

import (
	"errors"
	"net"
)

// originalDST is not implemented off Linux: transparent mode (B3) relies
// on netfilter conntrack (SO_ORIGINAL_DST), which is Linux-only.
func originalDST(conn net.Conn) (string, error) {
	return "", errors.New("original-dst: transparent mode is Linux-only (netfilter conntrack)")
}
