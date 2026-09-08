package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"arpsponge/internal/engine"
)

var version = "dev"

func main() {
	opts, cmd, cmdArgs, err := parseGlobalArgs(os.Args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage()
			return
		}
		fmt.Fprintln(os.Stderr, err)
		usage()
		os.Exit(2)
	}
	if opts.version {
		fmt.Println(version)
		return
	}
	if cmd == "" {
		usage()
		os.Exit(2)
	}
	if opts.socket == "" {
		if opts.interfaceName == "" {
			fmt.Fprintln(os.Stderr, "--interface required unless --socket is set")
			os.Exit(2)
		}
		opts.socket = filepath.Join(opts.rundir, opts.interfaceName, "control.sock")
	}

	client := newUnixClient(opts.socket)

	switch cmd {
	case "status":
		resp, err := doRequest(client, http.MethodGet, "/v1/status", nil)
		mustPrint(resp, err, opts.json)
	case "ip":
		handleIP(client, cmdArgs, opts.json)
	case "arp":
		handleARP(client, cmdArgs, opts.json)
	case "config":
		handleConfig(client, cmdArgs, opts.json)
	case "log":
		handleLog(client, newUnixStreamingClient(opts.socket), cmdArgs, opts.json)
	default:
		usage()
		os.Exit(2)
	}
}

type globalOptions struct {
	socket        string
	rundir        string
	interfaceName string
	json          bool
	version       bool
}

func parseGlobalArgs(args []string) (globalOptions, string, []string, error) {
	fs := flag.NewFlagSet("global", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	opts := globalOptions{}
	fs.StringVar(&opts.socket, "socket", "", "control socket path")
	fs.StringVar(&opts.rundir, "rundir", "/run/arpsponge", "runtime directory")
	fs.StringVar(&opts.interfaceName, "interface", "", "interface name")
	fs.BoolVar(&opts.json, "json", false, "json output")
	fs.BoolVar(&opts.version, "version", false, "print version")
	if err := fs.Parse(args); err != nil {
		return globalOptions{}, "", nil, err
	}
	remaining := fs.Args()
	if len(remaining) == 0 {
		return opts, "", nil, nil
	}
	return opts, remaining[0], remaining[1:], nil
}

func handleIP(client *http.Client, args []string, jsonOut bool) {
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}
	sub := args[0]
	switch sub {
	case "list":
		fs := flag.NewFlagSet("ip list", flag.ExitOnError)
		state := fs.String("state", "", "state filter")
		_ = fs.Parse(args[1:])
		path := "/v1/ip"
		if *state != "" {
			path += "?state=" + *state
		}
		resp, err := doRequest(client, http.MethodGet, path, nil)
		mustPrint(resp, err, jsonOut)
	case "show":
		if len(args) < 2 {
			usage()
			os.Exit(2)
		}
		resp, err := doRequest(client, http.MethodGet, "/v1/ip/"+args[1], nil)
		mustPrint(resp, err, jsonOut)
	case "set":
		if len(args) < 3 {
			usage()
			os.Exit(2)
		}
		payload := map[string]any{"state": args[2]}
		fs := flag.NewFlagSet("ip set", flag.ExitOnError)
		mac := fs.String("mac", "", "mac address")
		count := fs.Int("count", -1, "pending count")
		_ = fs.Parse(args[3:])
		if *mac != "" {
			payload["mac"] = *mac
		}
		if *count >= 0 {
			payload["count"] = *count
		}
		resp, err := doRequest(client, http.MethodPost, "/v1/ip/"+args[1]+"/state", payload)
		mustPrint(resp, err, jsonOut)
	case "clear":
		if len(args) == 1 {
			resp, err := doRequest(client, http.MethodPost, "/v1/ip/clear", nil)
			mustPrint(resp, err, jsonOut)
			return
		}
		resp, err := doRequest(client, http.MethodPost, "/v1/ip/"+args[1]+"/clear", nil)
		mustPrint(resp, err, jsonOut)
	default:
		usage()
		os.Exit(2)
	}
}

func handleARP(client *http.Client, args []string, jsonOut bool) {
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}
	sub := args[0]
	switch sub {
	case "list":
		resp, err := doRequest(client, http.MethodGet, "/v1/arp", nil)
		mustPrint(resp, err, jsonOut)
	case "show":
		if len(args) < 2 {
			usage()
			os.Exit(2)
		}
		resp, err := doRequest(client, http.MethodGet, "/v1/arp/"+args[1], nil)
		mustPrint(resp, err, jsonOut)
	case "clear":
		resp, err := doRequest(client, http.MethodPost, "/v1/arp/clear", nil)
		mustPrint(resp, err, jsonOut)
	default:
		usage()
		os.Exit(2)
	}
}

func handleConfig(client *http.Client, args []string, jsonOut bool) {
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}
	switch args[0] {
	case "get":
		resp, err := doRequest(client, http.MethodGet, "/v1/config", nil)
		mustPrint(resp, err, jsonOut)
	case "set":
		payload, err := parseConfigSet(args[1:])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		resp, err := doRequest(client, http.MethodPost, "/v1/config", payload)
		mustPrint(resp, err, jsonOut)
	default:
		usage()
		os.Exit(2)
	}
}

func parseConfigSet(args []string) (map[string]any, error) {
	cfg := engine.DefaultConfig()
	fs := flag.NewFlagSet("config set", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	logLevel := ""
	logMask := ""
	dummy := ""
	passive := ""
	static := ""
	gratuitous := ""
	spongeNet := ""
	arpUpdateMethod := ""
	sweepSkipAlive := ""
	fs.IntVar(&cfg.QueueDepth, "queue_depth", cfg.QueueDepth, "queue depth")
	fs.Float64Var(&cfg.MaxRate, "max_rate", cfg.MaxRate, "maximum request rate")
	fs.IntVar(&cfg.ArpAge, "arp_age", cfg.ArpAge, "ARP expiry age")
	fs.IntVar(&cfg.MaxPending, "max_pending", cfg.MaxPending, "maximum pending probes")
	fs.Float64Var(&cfg.Proberate, "proberate", cfg.Proberate, "probe rate")
	fs.Float64Var(&cfg.FloodProtection, "flood_protection", cfg.FloodProtection, "flood protection rate")
	fs.IntVar(&cfg.LearnSeconds, "learning", cfg.LearnSeconds, "learning duration")
	fs.StringVar(&logLevel, "log_level", "", "log level")
	fs.StringVar(&logMask, "log_mask", "", "log mask")
	fs.StringVar(&dummy, "dummy", "", "dummy mode true/false")
	fs.StringVar(&passive, "passive", "", "passive mode true/false")
	fs.StringVar(&static, "static", "", "static mode true/false")
	fs.StringVar(&gratuitous, "gratuitous", "", "gratuitous ARP updates true/false")
	fs.StringVar(&spongeNet, "sponge_network", "", "sponge network true/false")
	fs.StringVar(&arpUpdateMethod, "arp_update_method", "", "ARP update methods")
	fs.IntVar(&cfg.SweepPeriod, "sweep_period", cfg.SweepPeriod, "sweep period")
	fs.IntVar(&cfg.SweepAge, "sweep_age", cfg.SweepAge, "sweep age")
	fs.StringVar(&sweepSkipAlive, "sweep_skip_alive", "", "skip alive sweep targets true/false")
	if err := fs.Parse(args); err != nil {
		return nil, fmt.Errorf("parse config set: %w", err)
	}
	if fs.NArg() != 0 {
		return nil, fmt.Errorf("unexpected config set arguments: %s", strings.Join(fs.Args(), " "))
	}

	seen := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) { seen[f.Name] = true })
	for _, field := range []struct {
		name  string
		raw   string
		value *bool
	}{
		{"dummy", dummy, &cfg.Dummy},
		{"passive", passive, &cfg.Passive},
		{"static", static, &cfg.Static},
		{"gratuitous", gratuitous, &cfg.Gratuitous},
		{"sponge_network", spongeNet, &cfg.SpongeNet},
		{"sweep_skip_alive", sweepSkipAlive, &cfg.SweepSkipAlive},
	} {
		if !seen[field.name] {
			continue
		}
		parsed, err := strconv.ParseBool(field.raw)
		if err != nil {
			return nil, fmt.Errorf("invalid %s boolean %q: %w", field.name, field.raw, err)
		}
		*field.value = parsed
	}
	if err := engine.ValidateConfig(cfg); err != nil {
		return nil, err
	}

	payload := make(map[string]any)
	for name := range seen {
		switch name {
		case "queue_depth":
			payload[name] = cfg.QueueDepth
		case "max_rate":
			payload[name] = cfg.MaxRate
		case "arp_age":
			payload[name] = cfg.ArpAge
		case "max_pending":
			payload[name] = cfg.MaxPending
		case "proberate":
			payload[name] = cfg.Proberate
		case "flood_protection":
			payload[name] = cfg.FloodProtection
		case "learning":
			payload[name] = cfg.LearnSeconds
		case "dummy":
			payload[name] = cfg.Dummy
		case "passive":
			payload[name] = cfg.Passive
		case "static":
			payload[name] = cfg.Static
		case "gratuitous":
			payload[name] = cfg.Gratuitous
		case "sponge_network":
			payload[name] = cfg.SpongeNet
		case "sweep_period":
			payload[name] = cfg.SweepPeriod
		case "sweep_age":
			payload[name] = cfg.SweepAge
		case "sweep_skip_alive":
			payload[name] = cfg.SweepSkipAlive
		case "log_level":
			payload[name] = logLevel
		case "log_mask":
			payload[name] = logMask
		case "arp_update_method":
			payload[name] = arpUpdateMethod
		}
	}
	return payload, nil
}

func handleLog(client *http.Client, streamClient *http.Client, args []string, jsonOut bool) {
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}
	switch args[0] {
	case "tail":
		fs := flag.NewFlagSet("log tail", flag.ExitOnError)
		n := fs.Int("n", 100, "number of entries")
		_ = fs.Parse(args[1:])
		path := fmt.Sprintf("/v1/log?tail=%d", *n)
		resp, err := doRequest(client, http.MethodGet, path, nil)
		mustPrint(resp, err, jsonOut)
	case "follow":
		if err := streamLogsContext(context.Background(), streamClient, jsonOut, os.Stdout); err != nil && !errors.Is(err, context.Canceled) {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	default:
		usage()
		os.Exit(2)
	}
}

func streamLogsContext(ctx context.Context, client *http.Client, jsonOut bool, output io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/v1/log/stream", nil)
	if err != nil {
		return fmt.Errorf("create log stream request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("open log stream: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("log stream returned %s", resp.Status)
	}

	reader := bufio.NewReader(resp.Body)
	for {
		line, readErr := reader.ReadString('\n')
		if strings.HasPrefix(line, "data:") {
			data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			if err := emitLogEvent(output, data, jsonOut); err != nil {
				return err
			}
		}
		if readErr != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(readErr, io.EOF) {
				return errors.New("log stream ended unexpectedly")
			}
			return fmt.Errorf("read log stream: %w", readErr)
		}
	}
}

type streamLogEntry struct {
	Time  int64  `json:"time"`
	Level string `json:"level"`
	Event string `json:"event"`
	PID   int    `json:"pid"`
	Msg   string `json:"msg"`
}

func emitLogEvent(output io.Writer, data string, jsonOut bool) error {
	if jsonOut {
		if !json.Valid([]byte(data)) {
			return fmt.Errorf("decode log stream event: invalid JSON")
		}
		_, err := fmt.Fprintln(output, data)
		return err
	}
	var entry streamLogEntry
	if err := json.Unmarshal([]byte(data), &entry); err != nil {
		return fmt.Errorf("decode log stream event: %w", err)
	}
	timestamp := time.Unix(entry.Time, 0).Format("2006-01-02 15:04:05")
	_, err := fmt.Fprintf(output, "%s [%s] %s\n", timestamp, entry.Level, entry.Msg)
	return err
}

func newUnixClient(socketPath string) *http.Client {
	return &http.Client{
		Transport: newUnixTransport(socketPath, 0),
		Timeout:   10 * time.Second,
	}
}

func newUnixStreamingClient(socketPath string) *http.Client {
	return &http.Client{
		Transport: newUnixTransport(socketPath, 10*time.Second),
	}
}

func newUnixTransport(socketPath string, responseHeaderTimeout time.Duration) *http.Transport {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	return &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socketPath)
		},
		ResponseHeaderTimeout: responseHeaderTimeout,
	}
}

func doRequest(client *http.Client, method, path string, payload any) ([]byte, error) {
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, "http://unix"+path, body)
	if err != nil {
		return nil, err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s", strings.TrimSpace(string(data)))
	}
	return data, nil
}

func mustPrint(data []byte, err error, jsonOut bool) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if jsonOut {
		fmt.Println(string(data))
		return
	}
	var out any
	if err := json.Unmarshal(data, &out); err != nil {
		fmt.Println(string(data))
		return
	}
	pretty, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(pretty))
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: arpspongectl [--socket PATH|--interface IFACE] <command> [args]")
	fmt.Fprintln(os.Stderr, "commands:")
	fmt.Fprintln(os.Stderr, "  status")
	fmt.Fprintln(os.Stderr, "  ip list|show|set|clear")
	fmt.Fprintln(os.Stderr, "  arp list|show|clear")
	fmt.Fprintln(os.Stderr, "  config get|set")
	fmt.Fprintln(os.Stderr, "  log tail|follow")
}
