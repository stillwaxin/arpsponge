package main

import (
	"bytes"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"arpsponge/internal/engine"
)

func TestNewControlHTTPServerSetsFiniteTimeouts(t *testing.T) {
	srv := newControlHTTPServer(http.NotFoundHandler())
	if srv.ReadHeaderTimeout <= 0 {
		t.Fatalf("ReadHeaderTimeout = %s, want a positive timeout", srv.ReadHeaderTimeout)
	}
	if srv.ReadTimeout <= 0 {
		t.Fatalf("ReadTimeout = %s, want a positive timeout", srv.ReadTimeout)
	}
	if srv.WriteTimeout <= 0 {
		t.Fatalf("WriteTimeout = %s, want a positive timeout", srv.WriteTimeout)
	}
}

func TestShutdownControlHTTPServerStopsServing(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := newControlHTTPServer(http.NotFoundHandler())
	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve(listener) }()

	if err := shutdownControlHTTPServer(srv); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	select {
	case err := <-serveDone:
		if !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("Serve() error = %v, want http.ErrServerClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not stop after shutdown")
	}
}

func TestRunPrintsHelpAndReturnsSuccess(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := runWithIO([]string{"--help"}, &stdout, &stderr); err != nil {
		t.Fatalf("runWithIO(--help) error = %v, want nil", err)
	}
	if !strings.Contains(stdout.String(), "Usage of arpsponge:") || !strings.Contains(stdout.String(), "-rate") {
		t.Fatalf("help output missing usage or flags:\n%s", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("help wrote stderr: %s", stderr.String())
	}
}

func TestRunInvalidFlagPointsToHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := runWithIO([]string{"--not-a-real-flag"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("runWithIO(invalid flag) error = nil, want failure")
	}
	if !strings.Contains(err.Error(), "--help") {
		t.Fatalf("invalid flag error = %q, want concise --help guidance", err)
	}
}

func TestRunAcceptsDeprecatedDaemonFlagAsNoOp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := runWithIO([]string{"--daemon", "--version"}, &stdout, &stderr)
	if !errors.Is(err, errVersionRequested) {
		t.Fatalf("runWithIO(--daemon --version) error = %v, want version request", err)
	}
	if !strings.Contains(stderr.String(), "--daemon is deprecated and ignored") {
		t.Fatalf("daemon warning missing: %s", stderr.String())
	}
}

func TestParseInitStateRejectsInvalidValue(t *testing.T) {
	if _, err := parseInitState("BOGUS"); err == nil {
		t.Fatal("parseInitState(BOGUS) error = nil")
	}
	state, err := parseInitState("pending")
	if err != nil || state != engine.Pending(0) {
		t.Fatalf("parseInitState(pending) = %v, %v; want PENDING(0), nil", state, err)
	}
}

func TestParseSweepRejectsMalformedValues(t *testing.T) {
	for _, spec := range []string{"nonsense", "10/nope", "-1/10", "10/-1", "1/2/3"} {
		if _, _, err := parseSweep(spec); err == nil {
			t.Fatalf("parseSweep(%q) error = nil", spec)
		}
	}
	period, age, err := parseSweep("900/3600")
	if err != nil || period != 900 || age != 3600 {
		t.Fatalf("parseSweep(valid) = %d, %d, %v; want 900, 3600, nil", period, age, err)
	}
}

func TestRunRejectsInvalidConfigBeforeOpeningInterface(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
		want string
	}{
		{
			name: "init",
			args: []string{"--network", "192.0.2.0/24", "--interface", "eth0", "--init", "BOGUS"},
			want: "invalid init state",
		},
		{
			name: "sweep",
			args: []string{"--network", "192.0.2.0/24", "--interface", "eth0", "--sweep", "nonsense"},
			want: "invalid sweep",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			err := runWithIO(tt.args, &stdout, &stderr)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("runWithIO() error = %v, want %q", err, tt.want)
			}
		})
	}
}
