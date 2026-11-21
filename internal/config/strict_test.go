package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestShippedConfigPassesStrictLoad(t *testing.T) {
	file := filepath.Join("..", "..", "configs", "gateway.yaml")
	if _, err := Load(file); err != nil {
		t.Fatalf("shipped config rejected: %v", err)
	}
}

func TestStrictLoadRejectsUnknownFields(t *testing.T) {
	tests := []struct {
		name string
		body string
		path string
	}{
		{
			name: "top level",
			body: "devices:\n  - name: plc\n    listen_addr: 192.0.2.10:802\n    device_addr: 198.51.100.20:502\nread_onyl: true\n",
			path: "read_onyl",
		},
		{
			name: "device",
			body: "devices:\n  - name: plc\n    listen_addr: 192.0.2.10:802\n    device_addr: 198.51.100.20:502\n    read_onyl: true\n",
			path: "devices[0].read_onyl",
		},
		{
			name: "tls",
			body: "devices:\n  - name: plc\n    listen_addr: 192.0.2.10:802\n    device_addr: 198.51.100.20:502\n    tls:\n      cert: a.crt\n      key: a.key\n      client_caa: ca.crt\n",
			path: "devices[0].tls.client_caa",
		},
		{
			name: "device tls",
			body: "devices:\n  - name: plc\n    listen_addr: 192.0.2.10:802\n    device_addr: 198.51.100.20:502\n    device_tls:\n      ca_sert: ca.crt\n",
			path: "devices[0].device_tls.ca_sert",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writeConfig(t, tc.body))
			if err == nil {
				t.Fatal("unknown field was accepted")
			}
			var se *SchemaError
			if !errors.As(err, &se) {
				t.Fatalf("want *SchemaError, got %T: %v", err, err)
			}
			if se.ID != ErrorUnknownField || se.Path != tc.path {
				t.Fatalf("issue = %+v, want %s at %s", se, ErrorUnknownField, tc.path)
			}
			if !strings.Contains(err.Error(), tc.path) {
				t.Fatalf("error text lacks the path: %v", err)
			}
		})
	}
}

func TestStrictLoadRejectsTypeMismatch(t *testing.T) {
	_, err := Load(writeConfig(t, "devices: not-a-list\n"))
	var se *SchemaError
	if !errors.As(err, &se) || se.ID != ErrorTypeMismatch || se.Path != "devices" {
		t.Fatalf("err = %v", err)
	}
}

func TestSchemaVersionHandling(t *testing.T) {
	valid := "schema_version: 1\ndevices:\n  - name: plc\n    listen_addr: 192.0.2.10:802\n    device_addr: 198.51.100.20:502\n"
	cfg, err := Load(writeConfig(t, valid))
	if err != nil {
		t.Fatalf("explicit version 1 rejected: %v", err)
	}
	if cfg.SchemaVersion != 1 {
		t.Fatalf("schema version = %d", cfg.SchemaVersion)
	}

	cfg, err = Load(writeConfig(t, "devices:\n  - name: plc\n    listen_addr: 192.0.2.10:802\n    device_addr: 198.51.100.20:502\n"))
	if err != nil {
		t.Fatalf("absent version rejected: %v", err)
	}
	if cfg.SchemaVersion != CurrentSchemaVersion {
		t.Fatalf("absent version = %d", cfg.SchemaVersion)
	}

	_, err = Load(writeConfig(t, "schema_version: 99\ndevices:\n  - name: plc\n    listen_addr: 192.0.2.10:802\n    device_addr: 198.51.100.20:502\n"))
	var se *SchemaError
	if !errors.As(err, &se) || se.ID != ErrorVersionUnsupported || se.Path != "schema_version" {
		t.Fatalf("unsupported version err = %v", err)
	}
}
