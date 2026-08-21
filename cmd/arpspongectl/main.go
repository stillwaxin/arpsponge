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
		handleLog(client, cmdArgs, opts.json)
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
	sub := args[0]
	switch sub {
	case "get":
		resp, err := doRequest(client, http.MethodGet, "/v1/config", nil)
		mustPrint(resp, err, jsonOut)
	case "set":
		fs := flag.NewFlagSet("config set", flag.ExitOnError)
		payload := map[string]any{}
		queue := fs.Int("queue_depth", -1, "queue depth")
		maxRate := fs.Float64("max_rate", -1, "max rate")
		pending := fs.Int("max_pending", -1, "max pending")
		proberate := fs.Float64("proberate", -1, "proberate")
		flood := fs.Float64("flood_protection", -1, "flood protection")
		logLevel := fs.String("log_level", "", "log level")
		logMask := fs.String("log_mask", "", "log mask")
		dummy := fs.String("dummy", "", "dummy true/false")
		passive := fs.String("passive", "", "passive true/false")
		static := fs.String("static", "", "static true/false")
		gratuitous := fs.String("gratuitous", "", "gratuitous true/false")
		spongeNet := fs.String("sponge_network", "", "sponge network true/false")
		arpUpdate := fs.String("arp_update_method", "", "arp update method")
		sweepPeriod := fs.Int("sweep_period", -1, "sweep period")
		sweepAge := fs.Int("sweep_age", -1, "sweep age")
		sweepSkip := fs.String("sweep_skip_alive", "", "sweep skip alive true/false")
		_ = fs.Parse(args[1:])

		setInt(payload, "queue_depth", *queue)
		setFloat(payload, "max_rate", *maxRate)
		setInt(payload, "max_pending", *pending)
		setFloat(payload, "proberate", *proberate)
		setFloat(payload, "flood_protection", *flood)
		setInt(payload, "sweep_period", *sweepPeriod)
		setInt(payload, "sweep_age", *sweepAge)
		setString(payload, "log_level", *logLevel)
		setString(payload, "log_mask", *logMask)
		setString(payload, "arp_update_method", *arpUpdate)
		setBoolString(payload, "dummy", *dummy)
		setBoolString(payload, "passive", *passive)
		setBoolString(payload, "static", *static)
		setBoolString(payload, "gratuitous", *gratuitous)
		setBoolString(payload, "sponge_network", *spongeNet)
		setBoolString(payload, "sweep_skip_alive", *sweepSkip)

		resp, err := doRequest(client, http.MethodPost, "/v1/config", payload)
		mustPrint(resp, err, jsonOut)
	default:
		usage()
		os.Exit(2)
	}
}

func handleLog(client *http.Client, args []string, jsonOut bool) {
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}
	sub := args[0]
	switch sub {
	case "tail":
		fs := flag.NewFlagSet("log tail", flag.ExitOnError)
		n := fs.Int("n", 100, "lines")
		_ = fs.Parse(args[1:])
		path := fmt.Sprintf("/v1/log?tail=%d", *n)
		resp, err := doRequest(client, http.MethodGet, path, nil)
		mustPrint(resp, err, jsonOut)
	case "follow":
		streamLogs(client)
	default:
		usage()
		os.Exit(2)
	}
}

func streamLogs(client *http.Client) {
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://unix/v1/log/stream", nil)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	defer resp.Body.Close()
	reader := bufio.NewReader(resp.Body)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				fmt.Fprintln(os.Stderr, err)
			}
			return
		}
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		payload := strings.TrimPrefix(line, "data: ")
		var entry struct {
			Time  int64  `json:"time"`
			Level string `json:"level"`
			Event string `json:"event"`
			PID   int    `json:"pid"`
			Msg   string `json:"msg"`
		}
		if err := json.Unmarshal([]byte(payload), &entry); err != nil {
			continue
		}
		ts := time.Unix(entry.Time, 0).Format("2006-01-02 15:04:05")
		fmt.Printf("%s [%s] %s\n", ts, entry.Level, entry.Msg)
	}
}

func newUnixClient(socketPath string) *http.Client {
	transport := &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", socketPath)
		},
	}
	return &http.Client{Transport: transport, Timeout: 10 * time.Second}
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

func setInt(payload map[string]any, key string, v int) {
	if v >= 0 {
		payload[key] = v
	}
}

func setFloat(payload map[string]any, key string, v float64) {
	if v >= 0 {
		payload[key] = v
	}
}

func setString(payload map[string]any, key string, v string) {
	if v != "" {
		payload[key] = v
	}
}

func setBoolString(payload map[string]any, key string, v string) {
	if v == "" {
		return
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return
	}
	payload[key] = b
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
