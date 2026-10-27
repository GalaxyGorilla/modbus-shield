package watchdog

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// shortTempDir returns a temp directory whose path still fits in a Unix
// socket address. t.TempDir() is unusable for that on macOS: TMPDIR lives
// under /var/folders/... and the resulting sun_path exceeds the 104-byte
// (macOS/BSD) kernel limit, so bind fails with EINVAL. Short system temp
// roots are tried first; the test skips if none is short enough.
func shortTempDir(t *testing.T) string {
	t.Helper()
	const maxSunPath = 100 // conservative: macOS limits sun_path to 104 bytes
	for _, base := range []string{"/tmp", os.TempDir()} {
		if base == "" {
			continue
		}
		dir, err := os.MkdirTemp(base, "wd")
		if err != nil {
			continue
		}
		if len(dir)+len("/notify.sock") >= maxSunPath {
			os.RemoveAll(dir)
			continue
		}
		t.Cleanup(func() { os.RemoveAll(dir) })
		return dir
	}
	t.Skip("no temp directory short enough for a Unix socket path")
	return "" // unreachable
}

// startFakeSystemd starts a Unix-socket fake of systemd's NOTIFY_SOCKET
// and returns the socket path plus a channel delivering every received
// state string.
func startFakeSystemd(t *testing.T) (string, <-chan string) {
	t.Helper()
	sockPath := filepath.Join(shortTempDir(t), "notify.sock")
	ln, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sockPath, Net: "unixgram"})
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	states := make(chan string, 32)
	go func() {
		defer close(states)
		buf := make([]byte, 512)
		for {
			n, _, err := ln.ReadFromUnix(buf)
			if err != nil {
				return
			}
			if n > 0 {
				states <- string(buf[:n])
			}
		}
	}()
	return sockPath, states
}

// withFakeSystemd points NOTIFY_SOCKET and WATCHDOG_USEC at the fake
// socket for the duration of fn.
func withFakeSystemd(t *testing.T, sockPath, usec string, fn func()) {
	t.Helper()
	oldSock, oldUsec := os.Getenv("NOTIFY_SOCKET"), os.Getenv("WATCHDOG_USEC")
	os.Setenv("NOTIFY_SOCKET", sockPath)
	if usec != "" {
		os.Setenv("WATCHDOG_USEC", usec)
	} else {
		os.Unsetenv("WATCHDOG_USEC")
	}
	defer func() {
		os.Setenv("NOTIFY_SOCKET", oldSock)
		if oldUsec != "" {
			os.Setenv("WATCHDOG_USEC", oldUsec)
		} else {
			os.Unsetenv("WATCHDOG_USEC")
		}
	}()
	fn()
}

func TestNoopWithoutSystemd(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	os.Unsetenv("NOTIFY_SOCKET")
	os.Unsetenv("WATCHDOG_USEC")
	if d := Interval(); d != 0 {
		t.Fatalf("Interval() = %v, want 0 without systemd", d)
	}
	if ok, err := NotifyReady(); ok || err != nil {
		t.Fatalf("NotifyReady() = (%v, %v), want (false, nil) without systemd", ok, err)
	}
}

func TestWatchdogEnabledAndPing(t *testing.T) {
	sockPath, states := startFakeSystemd(t)
	withFakeSystemd(t, sockPath, "1000000", func() { // WatchdogSec = 1s
		d := Interval()
		if d != time.Second {
			t.Fatalf("Interval() = %v, want 1s", d)
		}
		if ok, err := NotifyReady(); !ok || err != nil {
			t.Fatalf("NotifyReady() = (%v, %v), want (true, nil)", ok, err)
		}
		done := make(chan struct{})
		go Start(d, done)
		select {
		case s := <-states:
			if s != "READY=1" {
				t.Fatalf("first notification = %q, want READY=1", s)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for READY=1")
		}
		select {
		case s := <-states:
			if s != "WATCHDOG=1" {
				t.Fatalf("ping = %q, want WATCHDOG=1", s)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for WATCHDOG=1")
		}
		close(done)
	})
}

func TestWatchdogDisabledWhenUsecMissing(t *testing.T) {
	sockPath, states := startFakeSystemd(t)
	withFakeSystemd(t, sockPath, "", func() {
		if d := Interval(); d != 0 {
			t.Fatalf("Interval() = %v with NOTIFY_SOCKET but no WATCHDOG_USEC, want 0", d)
		}
		if ok, err := NotifyReady(); !ok || err != nil {
			t.Fatalf("NotifyReady() = (%v, %v), want (true, nil) — ready still notifiable", ok, err)
		}
		// SdNotify must have delivered READY=1 to the socket even though
		// the watchdog is off.
		select {
		case s := <-states:
			if s != "READY=1" {
				t.Fatalf("notification = %q, want READY=1", s)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for READY=1")
		}
	})
}
