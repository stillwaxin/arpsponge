//go:build !windows

package main

import (
	"os"
	"reflect"
	"syscall"
	"testing"
)

func TestSignalSetIncludesUnixShutdownAndDumpSignals(t *testing.T) {
	want := []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGUSR1}
	if got := signalSet(); !reflect.DeepEqual(got, want) {
		t.Fatalf("signal set = %v, want %v", got, want)
	}
}

func TestIsDumpSignalRecognizesOnlyUnixDumpSignals(t *testing.T) {
	for _, tt := range []struct {
		signal os.Signal
		want   bool
	}{
		{signal: syscall.SIGHUP, want: true},
		{signal: syscall.SIGUSR1, want: true},
		{signal: os.Interrupt, want: false},
		{signal: syscall.SIGTERM, want: false},
	} {
		if got := isDumpSignal(tt.signal); got != tt.want {
			t.Errorf("isDumpSignal(%v) = %t, want %t", tt.signal, got, tt.want)
		}
	}
}
