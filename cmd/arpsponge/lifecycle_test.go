package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"arpsponge/internal/engine"
	"arpsponge/internal/packet"
)

type lifecycleCapture struct {
	canceled chan struct{}
	release  chan struct{}
	closed   chan struct{}
}

func (c *lifecycleCapture) Run(ctx context.Context, _ func(packet.Packet)) error {
	<-ctx.Done()
	close(c.canceled)
	<-c.release
	return ctx.Err()
}
func (c *lifecycleCapture) Close() { close(c.closed) }

func TestCaptureShutdownJoinsAllUsersBeforeClose(t *testing.T) {
	capture := &lifecycleCapture{make(chan struct{}), make(chan struct{}), make(chan struct{})}
	engineStopping, engineStopped := make(chan struct{}), make(chan struct{})
	worker := newCaptureWorker(capture, func(packet.Packet) {}, func() { close(engineStopping); <-engineStopped })
	worker.Start()
	shutdown := make(chan struct{})
	go func() { worker.Stop(); close(shutdown) }()
	select {
	case <-capture.canceled:
	case <-time.After(time.Second):
		t.Fatal("capture not canceled")
	}
	select {
	case <-engineStopping:
	case <-time.After(time.Second):
		t.Fatal("engine not stopped")
	}
	select {
	case <-capture.closed:
		t.Fatal("capture closed before engine stopped")
	default:
	}
	close(engineStopped)
	select {
	case <-capture.closed:
		t.Fatal("capture closed before reader joined")
	case <-time.After(20 * time.Millisecond):
	}
	close(capture.release)
	select {
	case <-shutdown:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not join capture")
	}
	select {
	case <-capture.closed:
	default:
		t.Fatal("capture not closed after workers joined")
	}
	worker.Stop()
}

func TestCaptureSetupFailureClosesHandleWithoutStartingReader(t *testing.T) {
	capture := &lifecycleCapture{make(chan struct{}), make(chan struct{}), make(chan struct{})}
	engineStopped := false
	worker := newCaptureWorker(capture, func(packet.Packet) { t.Error("handler ran before setup completed") }, func() { engineStopped = true })
	// A failed listener or permission setup runs deferred cleanup before Start.
	done := make(chan struct{})
	go func() { worker.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cleanup waited for an unstarted reader")
	}
	if !engineStopped {
		t.Fatal("engine cleanup skipped")
	}
	select {
	case <-capture.closed:
	default:
		t.Fatal("unstarted handle was not closed")
	}
	select {
	case <-capture.canceled:
		t.Fatal("reader ran before successful setup")
	default:
	}
	worker.Start()
	worker.mu.Lock()
	started := worker.started
	worker.mu.Unlock()
	if started {
		t.Fatal("reader started after failed setup closed its handle")
	}
}

func TestDaemonSupervisesCaptureCompletion(t *testing.T) {
	failure := errors.New("terminal capture failure")
	for _, result := range []error{failure, nil} {
		captureErrors := make(chan error, 1)
		captureErrors <- result
		err := superviseDaemon(nil, nil, captureErrors, nil, func(time.Time) {}, func() {})
		if err == nil || !strings.Contains(err.Error(), "capture") {
			t.Fatalf("unexpected capture result %v returned %v", result, err)
		}
		if result != nil && !errors.Is(err, failure) {
			t.Fatalf("capture error not preserved: %v", err)
		}
	}
}

func TestDaemonSupervisionPreservesSignalShutdown(t *testing.T) {
	signals := make(chan os.Signal, 1)
	signals <- os.Interrupt
	if err := superviseDaemon(nil, nil, nil, signals, func(time.Time) {}, func() {}); err != nil {
		t.Fatalf("signal shutdown: %v", err)
	}
}

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
