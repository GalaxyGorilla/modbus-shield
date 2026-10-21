package acl

import (
	"net"
	"testing"
)

func TestIsWrite(t *testing.T) {
	cases := []struct {
		fc   uint8
		want bool
	}{
		{1, false}, {2, false}, {3, false}, {4, false}, // reads
		{5, true}, {6, true}, {15, true}, {16, true}, // writes
		{21, true}, {22, true}, {23, true}, // file/mask/rw
		{7, false}, {8, false}, {17, false}, {24, false}, // diagnostics/fifo
		{0x81, false}, // exception responses are not writes
	}
	for _, c := range cases {
		if got := IsWrite(c.fc); got != c.want {
			t.Errorf("IsWrite(%d) = %v, want %v", c.fc, got, c.want)
		}
	}
}

func TestNewListEmpty(t *testing.T) {
	l, err := NewList(nil)
	if err != nil || l != nil {
		t.Fatalf("NewList(nil) = %v, %v; want nil, nil", l, err)
	}
	l, err = NewList([]string{})
	if err != nil || l != nil {
		t.Fatalf("NewList(empty) = %v, %v; want nil, nil", l, err)
	}
}

func TestNewListInvalid(t *testing.T) {
	if _, err := NewList([]string{"not-an-ip"}); err == nil {
		t.Fatal("expected error for invalid entry")
	}
}

func TestListAllowed(t *testing.T) {
	l, err := NewList([]string{"10.0.0.5", "192.168.1.0/24"})
	if err != nil {
		t.Fatalf("NewList: %v", err)
	}
	cases := []struct {
		ip   string
		want bool
	}{
		{"10.0.0.5", true},
		{"10.0.0.6", false},
		{"192.168.1.1", true},
		{"192.168.1.254", true},
		{"192.168.2.1", false},
		{"8.8.8.8", false},
	}
	for _, c := range cases {
		if got := l.Allowed(net.ParseIP(c.ip)); got != c.want {
			t.Errorf("Allowed(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestNilListAllowsAll(t *testing.T) {
	var l *List
	if !l.Allowed(net.ParseIP("1.2.3.4")) {
		t.Fatal("nil list must allow all")
	}
}
