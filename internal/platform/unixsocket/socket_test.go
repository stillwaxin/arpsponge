//go:build !windows

package unixsocket

import (
	"errors"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"sync"
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

func TestListenRefusesActiveSocketAndPreservesFirstListener(t *testing.T) {
	path := newSocketTestPath(t)
	first, err := Listen(path, "", "", 0o600)
	if err != nil {
		t.Fatalf("create first listener: %v", err)
	}
	t.Cleanup(func() { _ = first.Close() })

	second, err := Listen(path, "", "", 0o600)
	if second != nil {
		_ = second.Close()
		t.Fatal("second listener unexpectedly succeeded")
	}
	if err == nil {
		t.Fatal("second listener unexpectedly succeeded")
	}

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial first listener after failed second start: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close client connection: %v", err)
	}

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat first listener path: %v", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("path mode = %v, want socket", info.Mode())
	}
}

func TestListenRefusesUnlockedLegacyListenerAndPreservesItsSocket(t *testing.T) {
	path := newSocketTestPath(t)
	legacy, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatalf("create legacy listener: %v", err)
	}
	t.Cleanup(func() { _ = legacy.Close() })
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat legacy socket: %v", err)
	}

	listener, err := Listen(path, "", "", 0o600)
	if listener != nil {
		_ = listener.Close()
		t.Fatal("Listen replaced an unlocked legacy listener")
	}
	if err == nil {
		t.Fatal("Listen succeeded against an unlocked legacy listener")
	}
	after, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat legacy socket after failed replacement: %v", err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("failed replacement changed the legacy listener socket inode")
	}
}

func TestListenRefusesUncertainSocketLivenessAndPreservesItsSocket(t *testing.T) {
	path := newSocketTestPath(t)
	legacy, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatalf("create Unix datagram socket: %v", err)
	}
	t.Cleanup(func() { _ = legacy.Close() })
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat Unix datagram socket: %v", err)
	}

	listener, err := Listen(path, "", "", 0o600)
	if listener != nil {
		_ = listener.Close()
		t.Fatal("Listen replaced a socket with uncertain liveness")
	}
	if err == nil {
		t.Fatal("Listen succeeded against a socket with uncertain liveness")
	}
	after, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat Unix datagram socket after failed replacement: %v", err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("failed replacement changed the Unix datagram socket inode")
	}
}

func TestListenConcurrentStartsHaveOneWinner(t *testing.T) {
	path := newSocketTestPath(t)
	const starters = 8

	start := make(chan struct{})
	listeners := make(chan net.Listener, starters)
	errs := make(chan error, starters)
	var workers sync.WaitGroup
	for i := 0; i < starters; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			listener, err := Listen(path, "", "", 0o600)
			listeners <- listener
			errs <- err
		}()
	}
	close(start)
	workers.Wait()
	close(listeners)
	close(errs)

	winners := 0
	for listener := range listeners {
		if listener == nil {
			continue
		}
		winners++
		winner := listener
		t.Cleanup(func() { _ = winner.Close() })
	}
	if winners != 1 {
		t.Fatalf("successful listeners = %d, want 1", winners)
	}
	for err := range errs {
		if err == nil {
			continue
		}
	}
}

func TestListenCloseIsIdempotentAndReleasesSocketOwnership(t *testing.T) {
	path := newSocketTestPath(t)
	listener, err := Listen(path, "", "", 0o600)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket path remains after close: %v", err)
	}

	replacement, err := Listen(path, "", "", 0o600)
	if err != nil {
		t.Fatalf("listen after close: %v", err)
	}
	t.Cleanup(func() { _ = replacement.Close() })
}

func TestListenRetainsRestrictiveSidecarLockInode(t *testing.T) {
	path := newSocketTestPath(t)
	listener, err := Listen(path, "", "", 0o600)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	lockPath := path + ".lock"
	firstInfo, err := os.Lstat(lockPath)
	if err != nil {
		t.Fatalf("lstat sidecar lock: %v", err)
	}
	if !firstInfo.Mode().IsRegular() || firstInfo.Mode().Perm() != 0o600 {
		t.Fatalf("sidecar lock mode = %v, want regular 0600", firstInfo.Mode())
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}

	afterClose, err := os.Lstat(lockPath)
	if err != nil {
		t.Fatalf("lstat retained sidecar lock: %v", err)
	}
	if !os.SameFile(firstInfo, afterClose) {
		t.Fatal("close replaced or removed the sidecar lock inode")
	}

	replacement, err := Listen(path, "", "", 0o600)
	if err != nil {
		t.Fatalf("listen using retained sidecar lock: %v", err)
	}
	t.Cleanup(func() { _ = replacement.Close() })
	afterReuse, err := os.Lstat(lockPath)
	if err != nil {
		t.Fatalf("lstat reused sidecar lock: %v", err)
	}
	if !os.SameFile(firstInfo, afterReuse) {
		t.Fatal("new listener replaced the sidecar lock inode")
	}
}

func TestListenRejectsUnsafeSidecarLockPaths(t *testing.T) {
	for _, tt := range []struct {
		name  string
		setup func(t *testing.T, lockPath string)
		check func(t *testing.T, lockPath string)
	}{
		{
			name: "symlink",
			setup: func(t *testing.T, lockPath string) {
				t.Helper()
				target := filepath.Join(filepath.Dir(lockPath), "lock-target")
				if err := os.WriteFile(target, []byte("operator-owned\n"), 0o600); err != nil {
					t.Fatalf("write lock target: %v", err)
				}
				if err := os.Symlink(target, lockPath); err != nil {
					t.Fatalf("create lock symlink: %v", err)
				}
			},
			check: func(t *testing.T, lockPath string) {
				t.Helper()
				info, err := os.Lstat(lockPath)
				if err != nil {
					t.Fatalf("lstat lock symlink: %v", err)
				}
				if info.Mode()&os.ModeSymlink == 0 {
					t.Fatalf("lock path mode = %v, want symlink", info.Mode())
				}
			},
		},
		{
			name: "directory",
			setup: func(t *testing.T, lockPath string) {
				t.Helper()
				if err := os.Mkdir(lockPath, 0o700); err != nil {
					t.Fatalf("create lock directory: %v", err)
				}
			},
			check: func(t *testing.T, lockPath string) {
				t.Helper()
				info, err := os.Lstat(lockPath)
				if err != nil {
					t.Fatalf("lstat lock directory: %v", err)
				}
				if !info.IsDir() {
					t.Fatalf("lock path mode = %v, want directory", info.Mode())
				}
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := newSocketTestPath(t)
			lockPath := path + ".lock"
			tt.setup(t, lockPath)

			listener, err := Listen(path, "", "", 0o600)
			if listener != nil {
				_ = listener.Close()
				t.Fatal("Listen returned a listener for an unsafe lock path")
			}
			if err == nil {
				t.Fatal("Listen succeeded with an unsafe lock path")
			}
			tt.check(t, lockPath)
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unsafe lock path created socket: %v", err)
			}
		})
	}
}
