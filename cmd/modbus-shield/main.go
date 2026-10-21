// Command modbus-shield runs one gateway instance of the Modbus TCP
// retrofit security proxy. The instance is configured either by a YAML
// file (--config) or entirely by flags for plug-and-play deployments
// without config files.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/GalaxyGorilla/modbus-shield/internal/config"
	"github.com/GalaxyGorilla/modbus-shield/internal/mbtcp"
	"github.com/GalaxyGorilla/modbus-shield/internal/observ"
	"github.com/GalaxyGorilla/modbus-shield/internal/proxy"
	"github.com/spf13/pflag"
	"go.uber.org/zap"
)

// version is overridden for releases via ldflags.
var version = "0.1.0"

func main() {
	os.Exit(run())
}

func run() int {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		return 2
	}
	switch os.Args[1] {
	case "version", "--version", "-v":
		fmt.Printf("modbus-shield %s\n", version)
		return 0
	case "gateway":
		return runGateway(os.Args[2:])
	case "validate":
		return runValidate(os.Args[2:])
	case "selftest":
		return runSelftest(os.Args[2:])
	case "genpsk":
		return genPSK()
	case "help", "--help", "-h":
		usage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage(os.Stderr)
		return 2
	}
}

// genPSK prints a fresh random 32-byte pre-shared key in hex form
// (reserved for the future secured-line milestone).
func genPSK() int {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		fmt.Fprintf(os.Stderr, "genpsk: %v\n", err)
		return 1
	}
	fmt.Println(hex.EncodeToString(buf))
	return 0
}

// cliFlags bundles every flag the gateway/validate/selftest subcommands
// accept (all subcommands register the same set, so role flags never
// trip unknown-flag errors).
type cliFlags struct {
	fs *pflag.FlagSet

	configPath   *string
	listen       *string
	device       *string
	readOnly     *bool
	allow        *[]string
	maxClients   *int
	ratePerSec   *int
	timeoutMs    *int
	deviceUnitID *string
	tlsCert      *string
	tlsKey       *string
	tlsClientCA  *string
	devTLSCA     *string
	devTLSSNI    *string
	devTLSCert   *string
	devTLSKey    *string
	metricsAddr  *string
	logLevel     *string
	logFormat    *string
	jsonOut      *bool
	selftestProbe *bool
}

// register defines the full flag set shared by gateway, validate and
// selftest.
func register(fs *pflag.FlagSet) cliFlags {
	var c cliFlags
	c.fs = fs
	c.configPath = fs.String("config", "", "path to YAML config file (either --config or direct flags)")
	c.listen = fs.String("listen", "", "front-leg listener address clients connect to, ip:port")
	c.device = fs.String("device", "", "upstream legacy device address, ip:port")
	c.readOnly = fs.Bool("read-only", false, "block all write function codes (device never sees writes)")
	c.allow = fs.StringArray("allow", nil, "client allow-list entry, IP or CIDR (repeatable; empty = any client)")
	c.maxClients = fs.Int("max-clients", 0, "max concurrent client connections (0 = default 16)")
	c.ratePerSec = fs.Int("rate-per-sec", 0, "max accepted requests per second (0 = unlimited)")
	c.timeoutMs = fs.Int("timeout-ms", 0, "per-request upstream deadline in ms (0 = default 5000)")
	c.deviceUnitID = fs.String("device-unit-id", "", "unit ID sent upstream (serial-gateway remap; responses rewritten back)")
	c.tlsCert = fs.String("tls-cert", "", "front-leg TLS server certificate (PEM; enables TLS termination)")
	c.tlsKey = fs.String("tls-key", "", "front-leg TLS server key (PEM)")
	c.tlsClientCA = fs.String("tls-client-ca", "", "client certificate CA (PEM; enables mTLS: clients must present a signed cert)")
	c.devTLSCA = fs.String("device-tls-ca", "", "upstream TLS CA (PEM; verifies the far box's certificate; empty = system roots)")
	c.devTLSSNI = fs.String("device-tls-server-name", "", "upstream TLS server-name override (when the far box presents a different name)")
	c.devTLSCert = fs.String("device-tls-cert", "", "upstream TLS client certificate (PEM; mTLS toward the far box)")
	c.devTLSKey = fs.String("device-tls-key", "", "upstream TLS client key (PEM)")
	c.metricsAddr = fs.String("metrics-addr", "", "Prometheus metrics listen address (e.g. 127.0.0.1:9202)")
	c.logLevel = fs.String("log-level", "info", "log level: debug, info, warn, error")
	c.logFormat = fs.String("log-format", "console", "log format: console or json")
	c.jsonOut = fs.Bool("json", false, "validate/selftest: machine-readable JSON output (for tooling / web UIs)")
	c.selftestProbe = fs.Bool("probe", true, "selftest: run network probes (Modbus read to each device); --probe=false checks config only")
	return c
}

// flagsConfig assembles a validated single-device Config from direct
// flags (plug-and-play deployment without a YAML file).
func flagsConfig(c cliFlags) (*config.Config, error) {
	if *c.listen == "" {
		return nil, fmt.Errorf("--listen is required (front-leg listener ip:port)")
	}
	if *c.device == "" {
		return nil, fmt.Errorf("--device is required (upstream legacy device ip:port)")
	}
	dev := config.Device{
		ListenAddr: *c.listen,
		DeviceAddr: *c.device,
		ReadOnly:   *c.readOnly,
		Allow:      *c.allow,
		MaxClients: *c.maxClients,
		RatePerSec: *c.ratePerSec,
		TimeoutMs:  *c.timeoutMs,
	}
	if *c.deviceUnitID != "" {
		u, err := strconv.ParseUint(*c.deviceUnitID, 10, 8)
		if err != nil {
			return nil, fmt.Errorf("--device-unit-id must be 0-255, got %q", *c.deviceUnitID)
		}
		id := uint8(u)
		dev.DeviceUnitID = &id
	}
	if *c.tlsCert != "" || *c.tlsKey != "" || *c.tlsClientCA != "" {
		dev.TLS = &config.TLSConfig{
			Cert:     *c.tlsCert,
			Key:      *c.tlsKey,
			ClientCA: *c.tlsClientCA,
		}
	}
	if *c.devTLSCA != "" || *c.devTLSSNI != "" || *c.devTLSCert != "" || *c.devTLSKey != "" {
		dev.DeviceTLS = &config.DeviceTLSConfig{
			CACert:     *c.devTLSCA,
			ServerName: *c.devTLSSNI,
			Cert:       *c.devTLSCert,
			Key:        *c.devTLSKey,
		}
	}
	cfg := &config.Config{
		Devices: []config.Device{dev},
		Log:     config.LogConfig{Level: *c.logLevel, Format: *c.logFormat},
	}
	cfg.Defaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// loadChecked builds a validated Config the same way the gateway
// subcommand does: --config YAML or direct flags.
func loadChecked(c cliFlags) (*config.Config, error) {
	if *c.configPath != "" {
		return config.Load(*c.configPath)
	}
	return flagsConfig(c)
}

// check is one selftest/validate result line.
type check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// report is the JSON document printed by validate --json and
// selftest --json (for tooling / web UIs).
type report struct {
	OK      bool    `json:"ok"`
	Error   string  `json:"error,omitempty"`
	Devices []check `json:"devices,omitempty"`
	Checks  []check `json:"checks,omitempty"`
}

// deviceChecks summarizes the configured devices for validate output.
func deviceChecks(cfg *config.Config) []check {
	out := make([]check, 0, len(cfg.Devices))
	for _, d := range cfg.Devices {
		feats := []string{}
		if d.ReadOnly {
			feats = append(feats, "read-only")
		}
		if len(d.Allow) > 0 {
			feats = append(feats, fmt.Sprintf("allowlist(%d)", len(d.Allow)))
		}
		if d.HasUnitRemap() {
			feats = append(feats, fmt.Sprintf("unit-remap->%d", d.UpstreamUnitID()))
		}
		detail := fmt.Sprintf("%s -> %s", d.ListenAddr, d.DeviceAddr)
		if len(feats) > 0 {
			detail += " (" + strings.Join(feats, ", ") + ")"
		}
		out = append(out, check{Name: d.Name, OK: true, Detail: detail})
	}
	return out
}

func finishReport(rep report, jsonOut bool, kind string) int {
	rep.OK = rep.Error == ""
	if jsonOut {
		out, _ := json.Marshal(rep)
		fmt.Println(string(out))
	}
	if !rep.OK {
		if !jsonOut {
			fmt.Fprintf(os.Stderr, "invalid: %s\n", rep.Error)
		}
		return 1
	}
	if !jsonOut {
		fmt.Printf("%s ok\n", kind)
	}
	return 0
}

// runValidate loads and validates a configuration without running the
// proxy. Exit 0 = valid, 1 = invalid. This is the pre-apply hook for
// tooling and appliance commissioning.
func runValidate(args []string) int {
	fs := pflag.NewFlagSet("validate", pflag.ContinueOnError)
	c := register(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	var rep report
	cfg, err := loadChecked(c)
	if err != nil {
		rep.Error = err.Error()
		return finishReport(rep, *c.jsonOut, "validate")
	}
	rep.Devices = deviceChecks(cfg)
	return finishReport(rep, *c.jsonOut, "validate")
}

// runSelftest validates the configuration and then probes each
// configured device with a real Modbus read (FC3) directly from this
// box — proving the legacy device is reachable and speaks Modbus.
// Designed for appliance commissioning and health checks. Exit 0 = all
// checks passed.
func runSelftest(args []string) int {
	fs := pflag.NewFlagSet("selftest", pflag.ContinueOnError)
	c := register(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	var rep report
	cfg, err := loadChecked(c)
	if err != nil {
		rep.Error = "config: " + err.Error()
		return finishSelftest(rep, *c.jsonOut)
	}
	rep.Devices = deviceChecks(cfg)

	if *c.selftestProbe {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		for _, d := range cfg.Devices {
			rep.Checks = append(rep.Checks, probeDevice(ctx, d))
		}
	}

	for _, ch := range rep.Checks {
		if !ch.OK {
			rep.Error = ch.Name + ": " + ch.Detail
			break
		}
	}
	return finishSelftest(rep, *c.jsonOut)
}

func finishSelftest(rep report, jsonOut bool) int {
	rep.OK = rep.Error == ""
	if jsonOut {
		out, _ := json.Marshal(rep)
		fmt.Println(string(out))
	} else {
		for _, d := range rep.Devices {
			fmt.Printf("  %-16s %-4s %s\n", d.Name, "ok", d.Detail)
		}
		for _, ch := range rep.Checks {
			status := "ok"
			if !ch.OK {
				status = "FAIL"
			}
			if ch.Detail != "" {
				fmt.Printf("  %-16s %-4s %s\n", ch.Name, status, ch.Detail)
			} else {
				fmt.Printf("  %-16s %-4s\n", ch.Name, status)
			}
		}
		if rep.OK {
			fmt.Println("selftest passed")
		}
	}
	if !rep.OK {
		fmt.Fprintf(os.Stderr, "selftest FAILED: %s\n", rep.Error)
		return 1
	}
	return 0
}

// probeDevice sends one Modbus FC3 read (holding register 0, quantity 1)
// directly to the device and waits for a response — proves the legacy
// device is reachable from this box and speaks Modbus TCP. An exception
// response still proves liveness (the device answered on the wire), so
// it passes with a note. Two attempts (some devices drop the first query
// after ARP resolution).
func probeDevice(ctx context.Context, d config.Device) check {
	name := "device " + d.DeviceAddr
	unit := uint8(1)
	if d.HasUnitRemap() {
		unit = d.UpstreamUnitID()
	}
	adu, err := mbtcp.NewADU(1, unit, []byte{3, 0x00, 0x00, 0x00, 0x01})
	if err != nil {
		return check{Name: name, OK: false, Detail: err.Error()}
	}
	var lastErr string
	for attempt := 0; attempt < 2; attempt++ {
		if err := ctx.Err(); err != nil {
			return check{Name: name, OK: false, Detail: lastErr}
		}
		ok, detail := probeAttempt(ctx, d.DeviceAddr, adu)
		if ok {
			return check{Name: name, OK: true, Detail: detail}
		}
		lastErr = detail
	}
	return check{Name: name, OK: false, Detail: lastErr}
}

// probeAttempt performs one dial + read exchange with a 2s deadline.
func probeAttempt(ctx context.Context, addr string, adu mbtcp.ADU) (bool, string) {
	dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return false, err.Error()
	}
	defer conn.Close()
	deadline := time.Now().Add(2 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write(adu.Frame()); err != nil {
		return false, err.Error()
	}
	resp, err := mbtcp.ReadADU(conn)
	if err != nil {
		return false, err.Error()
	}
	if resp.Header.TransactionID != adu.Header.TransactionID {
		return false, fmt.Sprintf("response transaction ID %d does not match request", resp.Header.TransactionID)
	}
	if resp.IsException() {
		code, _ := resp.ExceptionCode()
		return true, fmt.Sprintf("device alive (exception code 0x%02x, unit %d)", code, resp.Header.UnitID)
	}
	return true, fmt.Sprintf("read ok (unit %d, function 0x%02x)", resp.Header.UnitID, resp.FunctionCode())
}

// runGateway runs the proxy until a signal arrives.
func runGateway(args []string) int {
	fs := pflag.NewFlagSet("gateway", pflag.ContinueOnError)
	c := register(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	log, err := observ.Log(*c.logLevel, *c.logFormat)
	if err != nil {
		fmt.Fprintf(os.Stderr, "logger: %v\n", err)
		return 1
	}
	defer func() { _ = log.Sync() }()

	var cfg *config.Config
	if *c.configPath != "" {
		cfg, err = config.Load(*c.configPath)
		if err != nil {
			log.Error("load config", zap.Error(err))
			return 1
		}
	} else {
		cfg, err = flagsConfig(c)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			return 2
		}
	}

	metricsAddr := *c.metricsAddr
	if metricsAddr == "" {
		metricsAddr = cfg.MetricsListenAddr
	}
	var met proxy.Metrics
	var metricsSrv *http.Server
	if metricsAddr != "" {
		m := observ.NewMetrics()
		met = m
		metricsSrv = observ.ServeMetrics(metricsAddr, m.Handler(), log)
	}
	log.Info("starting modbus-shield", zap.Int("devices", len(cfg.Devices)))

	r, err := proxy.NewRunner(cfg, observ.AsProxyLogger(log), met)
	if err != nil {
		log.Error("build runner", zap.Error(err))
		observ.ShutdownMetrics(metricsSrv)
		return 1
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		select {
		case <-sigCh:
			log.Info("shutdown signal received")
			r.Stop()
		case <-done:
		}
	}()
	err = r.Run()
	close(done)
	observ.ShutdownMetrics(metricsSrv)
	if err != nil {
		log.Error("proxy exited", zap.Error(err))
		return 1
	}
	return 0
}

func usage(w *os.File) {
	fmt.Fprintf(w, `modbus-shield — Modbus TCP retrofit security proxy

Usage (config file):
  modbus-shield gateway --config <file> [--metrics-addr <addr>]

Usage (flags, no config file — plug and play):
  modbus-shield gateway --listen <ip:port> --device <legacy-device:port> \
      [--read-only] [--allow <ip|cidr>]... [--max-clients <n>] \
      [--rate-per-sec <n>] [--timeout-ms <ms>] [--device-unit-id <id>] \
      [--tls-cert <pem> --tls-key <pem> [--tls-client-ca <pem>]] \
      [--device-tls-ca <pem> [--device-tls-server-name <name>] \
       [--device-tls-cert <pem> --device-tls-key <pem>]] \
      [--metrics-addr <addr>] [--log-level <lvl>] [--log-format <fmt>]

The gateway is a single box in front of the legacy device: N clients are
multiplexed over ONE connection to the device (many legacy devices accept
only one), writes can be blocked (--read-only), clients restricted
(--allow) and the device shielded from polling storms (--rate-per-sec).
With --tls-cert/--tls-key the front leg terminates TLS (add
--tls-client-ca for mTLS); the device-side wire stays plain Modbus TCP.
With --device-tls-* the upstream leg is secured instead: the box dials
the device over TLS — the far side is a second modbus-shield gateway
whose front leg terminates TLS in front of the local device (two-proxy
secured line). Plain Modbus TCP on both end wires — the device notices
nothing.

Other commands:
  modbus-shield validate [--config <file> | same flags as gateway] [--json]
      check a configuration without running (pre-apply for tooling)
  modbus-shield selftest [--config <file> | same flags as gateway]
      [--probe=false] [--json]
      validate + probe each configured device with a real Modbus read
      (FC3) directly from this box
  modbus-shield genpsk   print a fresh random pre-shared key (hex; reserved for the future secured line)
  modbus-shield version
`)
}
