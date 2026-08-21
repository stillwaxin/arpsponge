//go:build !windows

package unixsocket

import (
	"errors"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"testing"
)

func TestListenPreservesExistingNonSocketPaths(t *testing.T) {
	for _, tt := range []struct {
		name  string
		setup func(t *testing.T, path string)
		check func(t *testing.T, path string)
	}{
		{
			name: "directory",
			setup: func(t *testing.T, path string) {
				t.Helper()
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatalf("create directory: %v", err)
				}
			},
			check: func(t *testing.T, path string) {
				t.Helper()
				info, err := os.Lstat(path)
				if err != nil {
					t.Fatalf("lstat directory: %v", err)
				}
				if !info.IsDir() {
					t.Fatalf("path mode = %v, want directory", info.Mode())
				}
			},
		},
		{
			name: "regular file",
			setup: func(t *testing.T, path string) {
				t.Helper()
				if err := os.WriteFile(path, []byte("operator-owned\\n"), 0o600); err != nil {
					t.Fatalf("write file: %v", err)
				}
			},
			check: func(t *testing.T, path string) {
				t.Helper()
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("read file: %v", err)
				}
				if string(data) != "operator-owned\\n" {
					t.Fatalf("file content = %q, want preserved operator content", data)
				}
			},
		},
		{
			name: "symlink",
			setup: func(t *testing.T, path string) {
				t.Helper()
				target := filepath.Join(filepath.Dir(path), "operator-owned")
				if err := os.WriteFile(target, []byte("operator-owned\\n"), 0o600); err != nil {
					t.Fatalf("write symlink target: %v", err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatalf("create symlink: %v", err)
				}
			},
			check: func(t *testing.T, path string) {
				t.Helper()
				info, err := os.Lstat(path)
				if err != nil {
					t.Fatalf("lstat symlink: %v", err)
				}
				if info.Mode()&os.ModeSymlink == 0 {
					t.Fatalf("path mode = %v, want symlink", info.Mode())
				}
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := newSocketTestPath(t)
			tt.setup(t, path)

			listener, err := Listen(path, "", "", 0o600)
			if listener != nil {
				_ = listener.Close()
				_ = os.Remove(path)
				t.Fatal("Listen returned a listener for an existing non-socket path")
			}
			if err == nil {
				t.Fatal("Listen succeeded for an existing non-socket path")
			}
			tt.check(t, path)
		})
	}
}

func TestListenReplacesStaleSocket(t *testing.T) {
	path := newSocketTestPath(t)
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatalf("create stale socket: %v", err)
	}
	stale.SetUnlinkOnClose(false)
	if err := stale.Close(); err != nil {
		t.Fatalf("close stale socket listener: %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat stale socket: %v", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("stale path mode = %v, want socket", info.Mode())
	}

	listener, err := Listen(path, "", "", 0o600)
	if err != nil {
		t.Fatalf("replace stale socket: %v", err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
		_ = os.Remove(path)
	})
	info, err = os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat replacement socket: %v", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("replacement path mode = %v, want socket", info.Mode())
	}
}

func newSocketTestPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "arpsponge-socket-")
	if err != nil {
		t.Fatalf("create socket temp directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "control.sock")
}

func TestListenCleansSocketAfterConfigurationFailure(t *testing.T) {
	path := newSocketTestPath(t)
	listener, err := Listen(path, "arpsponge-test-user-that-does-not-exist", "", 0o600)
	if err == nil {
		if listener != nil {
			_ = listener.Close()
		}
		t.Fatal("Listen succeeded with an unknown owner")
	}
	if listener != nil {
		t.Fatal("Listen returned a listener after configuration failure")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket remains after configuration failure: Lstat error = %v", err)
	}

	reopened, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("socket path cannot be reused after configuration failure: %v", err)
	}
	t.Cleanup(func() {
		_ = reopened.Close()
		_ = os.Remove(path)
	})
}

func TestConfigureSocketPropagatesChmodAndChownErrors(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.sock")
	if err := configureSocket(missing, "", "", 0o600); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("configureSocket chmod error = %v, want os.ErrNotExist", err)
	}

	current, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	if err := configureSocket(missing, current.Username, "", 0); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("configureSocket chown error = %v, want os.ErrNotExist", err)
	}
}
