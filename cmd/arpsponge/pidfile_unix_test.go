//go:build !windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestAcquirePIDFileLocksWritesAndRemovesPIDFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "arpsponge.pid")
	if err := os.WriteFile(path, []byte("12345678901234567890\n"), 0o644); err != nil {
		t.Fatalf("seed pidfile: %v", err)
	}

	pidFile, err := acquirePIDFile(path)
	if err != nil {
		t.Fatalf("acquire pidfile: %v", err)
	}
	t.Cleanup(func() { _ = pidFile.Close() })

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read pidfile: %v", err)
	}
	want := strconv.Itoa(os.Getpid()) + "\n"
	if string(data) != want {
		t.Fatalf("pidfile content = %q, want %q", data, want)
	}

	second, err := acquirePIDFile(path)
	if err == nil {
		_ = second.Close()
		t.Fatal("second acquire succeeded while first pidfile is locked")
	}

	if err := pidFile.Close(); err != nil {
		t.Fatalf("close pidfile: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pidfile remains after close: %v", err)
	}
}

func TestPIDFileCloseDoesNotRemoveReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "arpsponge.pid")
	pidFile, err := acquirePIDFile(path)
	if err != nil {
		t.Fatalf("acquire pidfile: %v", err)
	}

	if err := os.Remove(path); err != nil {
		t.Fatalf("replace pidfile: remove old: %v", err)
	}
	if err := os.WriteFile(path, []byte("other process\n"), 0o644); err != nil {
		t.Fatalf("replace pidfile: write new: %v", err)
	}
	if err := pidFile.Close(); err != nil {
		t.Fatalf("close pidfile: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read replacement: %v", err)
	}
	if string(data) != "other process\n" {
		t.Fatalf("replacement content = %q, want it preserved", data)
	}
}
