package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestMainHelpExitsSuccessfully(t *testing.T) {
	if helpArg := os.Getenv("ARPSPONGECTL_HELPER_ARG"); helpArg != "" {
		os.Args = []string{"arpspongectl", helpArg}
		main()
		return
	}

	for _, helpArg := range []string{"--help", "-h"} {
		t.Run(helpArg, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestMainHelpExitsSuccessfully$")
			cmd.Env = append(os.Environ(), "ARPSPONGECTL_HELPER_ARG="+helpArg)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("arpspongectl %s exited with %v:\n%s", helpArg, err, output)
			}
			if !strings.Contains(string(output), "usage: arpspongectl") {
				t.Fatalf("arpspongectl %s output missing usage:\n%s", helpArg, output)
			}
			if strings.Contains(string(output), "flag: help requested") {
				t.Fatalf("arpspongectl %s leaked flag.ErrHelp:\n%s", helpArg, output)
			}
		})
	}
}

func TestMainConfigSetHelper(t *testing.T) {
	encoded := os.Getenv("ARPSPONGECTL_CONFIG_SET_ARGS")
	if encoded == "" {
		return
	}
	var args []string
	if err := json.Unmarshal([]byte(encoded), &args); err != nil {
		t.Fatalf("decode helper arguments: %v", err)
	}
	os.Args = append([]string{"arpspongectl"}, args...)
	main()
}

func TestMainLogFollowHelper(t *testing.T) {
	encoded := os.Getenv("ARPSPONGECTL_LOG_FOLLOW_ARGS")
	if encoded == "" {
		return
	}
	var args []string
	if err := json.Unmarshal([]byte(encoded), &args); err != nil {
		t.Fatalf("decode helper arguments: %v", err)
	}
	os.Args = append([]string{"arpspongectl"}, args...)
	main()
}

func TestParseGlobalArgsAcceptsSeparatedInterfaceBeforeCommand(t *testing.T) {
	opts, cmd, cmdArgs, err := parseGlobalArgs([]string{"--interface", "eth0", "status"})
	if err != nil {
		t.Fatalf("parseGlobalArgs() error = %v", err)
	}
	if opts.interfaceName != "eth0" {
		t.Fatalf("interface = %q, want eth0", opts.interfaceName)
	}
	if cmd != "status" {
		t.Fatalf("command = %q, want status", cmd)
	}
	if len(cmdArgs) != 0 {
		t.Fatalf("command args = %q, want none", cmdArgs)
	}
}

func TestParseGlobalArgsParsesVersionOnceWithRemainingArguments(t *testing.T) {
	opts, cmd, cmdArgs, err := parseGlobalArgs([]string{"--version", "status"})
	if err != nil {
		t.Fatalf("parseGlobalArgs() error = %v", err)
	}
	if !opts.version {
		t.Fatal("version = false, want true")
	}
	if cmd != "status" {
		t.Fatalf("command = %q, want status", cmd)
	}
	if len(cmdArgs) != 0 {
		t.Fatalf("command args = %q, want none", cmdArgs)
	}
}

func TestStreamLogsSurvivesIdleStreamPastOrdinaryClientTimeout(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "arpspongectl-")
	if err != nil {
		t.Fatalf("create temporary socket directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "control.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/log/stream" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		select {
		case <-time.After(11 * time.Second):
			_, _ = w.Write([]byte("data: {\"event\":\"probe\",\"message\":\"still connected\"}\n\n"))
			w.(http.Flusher).Flush()
		case <-r.Context().Done():
		}
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		_ = server.Close()
	})

	done := make(chan struct{})
	go func() {
		_ = streamLogsContext(context.Background(), newUnixStreamingClient(path), false, io.Discard)
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("stream ended before an idle period longer than the ordinary client timeout")
	case <-time.After(10*time.Second + 500*time.Millisecond):
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stream did not receive the post-idle event")
	}
}

func TestOrdinaryClientStillTimesOutWhileReadingResponseBody(t *testing.T) {
	path := newUnixTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))

	started := time.Now()
	_, err := doRequest(newUnixClient(path), http.MethodGet, "/slow", nil)
	if err == nil {
		t.Fatal("ordinary request unexpectedly succeeded")
	}
	if elapsed := time.Since(started); elapsed < 9*time.Second || elapsed > 12*time.Second {
		t.Fatalf("ordinary request timed out after %s, want about 10s", elapsed)
	}
}

func TestParseConfigSetPreservesExplicitZeroAndFalse(t *testing.T) {
	payload, err := parseConfigSet([]string{
		"--max_pending=0",
		"--proberate=0",
		"--learning=0",
		"--passive", "false",
	})
	if err != nil {
		t.Fatalf("parse config set: %v", err)
	}
	for key, want := range map[string]any{
		"max_pending": 0,
		"proberate":   0.0,
		"learning":    0,
		"passive":     false,
	} {
		if got, ok := payload[key]; !ok || got != want {
			t.Fatalf("payload[%q] = %#v (present %t), want %#v", key, got, ok, want)
		}
	}
}

func TestMainConfigSetFailuresExitNonzeroAndMalformedInputSkipsHTTP(t *testing.T) {
	var requests atomic.Int32
	path := newUnixTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))

	for _, args := range [][]string{
		{"--passive", "treu"},
		{"--max_rate", "-1"},
		{"--max_rate", "not-a-number"},
		{"--passive", "false", "unexpected"},
	} {
		if err := runConfigSetMain(t, path, args...); err == nil {
			t.Fatalf("invalid config set %q exited successfully", args)
		}
		if got := requests.Load(); got != 0 {
			t.Fatalf("invalid config set %q made %d HTTP requests, want 0", args, got)
		}
	}

	if err := runConfigSetMain(t, path, "--passive", "false"); err == nil {
		t.Fatal("HTTP 500 exited successfully")
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("HTTP failure made %d HTTP requests, want 1", got)
	}

	missing := filepath.Join(t.TempDir(), "missing.sock")
	if err := runConfigSetMain(t, missing, "--passive", "false"); err == nil {
		t.Fatal("refused Unix socket connection exited successfully")
	}
}

func TestMainLogFollowFailuresExitNonzero(t *testing.T) {
	for _, handler := range []http.HandlerFunc{
		func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		},
		func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
		},
	} {
		path := newUnixTestServer(t, handler)
		if err := runLogFollowMain(t, path); err == nil {
			t.Fatal("log follow failure exited successfully")
		}
	}
	if err := runLogFollowMain(t, filepath.Join(t.TempDir(), "missing.sock")); err == nil {
		t.Fatal("refused log follow connection exited successfully")
	}
}

func runConfigSetMain(t *testing.T, socket string, configArgs ...string) error {
	t.Helper()
	args := append([]string{"--socket", socket, "config", "set"}, configArgs...)
	encoded, err := json.Marshal(args)
	if err != nil {
		t.Fatalf("marshal helper arguments: %v", err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestMainConfigSetHelper$")
	cmd.Env = append(os.Environ(), "ARPSPONGECTL_CONFIG_SET_ARGS="+string(encoded))
	return cmd.Run()
}

func runLogFollowMain(t *testing.T, socket string) error {
	t.Helper()
	encoded, err := json.Marshal([]string{"--socket", socket, "log", "follow"})
	if err != nil {
		t.Fatalf("marshal helper arguments: %v", err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestMainLogFollowHelper$")
	cmd.Env = append(os.Environ(), "ARPSPONGECTL_LOG_FOLLOW_ARGS="+string(encoded))
	return cmd.Run()
}

func TestParseConfigSetRejectsInvalidInputBeforeHTTP(t *testing.T) {
	for _, args := range [][]string{
		{"--passive=treu"},
		{"--max_pending=-1"},
		{"--max_rate=NaN"},
		{"--proberate=Inf"},
		{"--learning=9223372037"},
		{"--queue_depth=0"},
		{"--passive=false", "unexpected"},
	} {
		if _, err := parseConfigSet(args); err == nil {
			t.Fatalf("parse config set %q succeeded", args)
		}
	}
}

func TestStreamLogsContextReportsHTTPFailureCancellationAndJSON(t *testing.T) {
	for _, tt := range []struct {
		name string
		h    http.HandlerFunc
		call func(t *testing.T, client *http.Client) (string, error)
	}{
		{
			name: "http status",
			h: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusServiceUnavailable)
				w.(http.Flusher).Flush()
				<-r.Context().Done()
			},
			call: func(_ *testing.T, client *http.Client) (string, error) {
				var output bytes.Buffer
				return output.String(), streamLogsContext(context.Background(), client, false, &output)
			},
		},
		{
			name: "cancellation",
			h: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				<-r.Context().Done()
			},
			call: func(t *testing.T, client *http.Client) (string, error) {
				ctx, cancel := context.WithCancel(context.Background())
				done := make(chan error, 1)
				go func() { done <- streamLogsContext(ctx, client, false, io.Discard) }()
				time.AfterFunc(20*time.Millisecond, cancel)
				return "", <-done
			},
		},
		{
			name: "json event",
			h: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = w.Write([]byte("data: {\"time\":1,\"level\":\"info\",\"event\":\"probe\",\"pid\":1,\"msg\":\"ok\"}\n\n"))
				w.(http.Flusher).Flush()
			},
			call: func(_ *testing.T, client *http.Client) (string, error) {
				var output bytes.Buffer
				err := streamLogsContext(context.Background(), client, true, &output)
				return output.String(), err
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := newUnixTestServer(t, tt.h)
			output, err := tt.call(t, newUnixStreamingClient(path))
			switch tt.name {
			case "http status":
				if err == nil || !strings.Contains(err.Error(), "503") {
					t.Fatalf("stream error = %v, want HTTP status", err)
				}
			case "cancellation":
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("stream error = %v, want context.Canceled", err)
				}
			case "json event":
				if err == nil || !strings.Contains(err.Error(), "ended unexpectedly") {
					t.Fatalf("stream error = %v, want unexpected EOF", err)
				}
				if !json.Valid(bytes.TrimSpace([]byte(output))) {
					t.Fatalf("JSON output = %q, want parseable event", output)
				}
			}
		})
	}
}

func newUnixTestServer(t *testing.T, handler http.Handler) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "arpspongectl-")
	if err != nil {
		t.Fatalf("create temporary socket directory: %v", err)
	}
	path := filepath.Join(dir, "control.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &http.Server{Handler: handler}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		_ = server.Close()
		_ = os.RemoveAll(dir)
	})
	return path
}
