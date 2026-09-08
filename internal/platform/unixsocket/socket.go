//go:build !windows

// Package unixsocket creates Unix-domain control sockets with configured
// ownership permissions.
package unixsocket

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"strconv"
	"sync"
	"syscall"
	"time"
)

const socketProbeTimeout = 250 * time.Millisecond

// syscall.Umask is process-global, so socket creation must be serialized even
// when different control paths are started concurrently.
var listenMu sync.Mutex

// Listen creates a Unix socket with restrictive creation permissions before
// applying its requested ownership mode. It owns path with a persistent
// sidecar lock for the returned listener's lifetime.
func Listen(path string, owner string, group string, perm os.FileMode) (net.Listener, error) {
	lock, err := acquireSocketLock(path)
	if err != nil {
		return nil, err
	}

	if err := removeExistingSocket(path); err != nil {
		return nil, errors.Join(err, releaseSocketLock(lock))
	}

	listenMu.Lock()
	oldMask := syscall.Umask(0o077)
	ln, err := net.Listen("unix", path)
	syscall.Umask(oldMask)
	listenMu.Unlock()
	if err != nil {
		return nil, errors.Join(fmt.Errorf("listen on socket %s: %w", path, err), releaseSocketLock(lock))
	}

	unixListener, ok := ln.(*net.UnixListener)
	if !ok {
		_ = ln.Close()
		return nil, errors.Join(fmt.Errorf("unix listen returned %T", ln), releaseSocketLock(lock))
	}
	// Cleanup below verifies the inode before unlinking. This prevents a close
	// from removing a path replaced outside this process.
	unixListener.SetUnlinkOnClose(false)

	info, err := os.Lstat(path)
	if err != nil {
		_ = ln.Close()
		return nil, errors.Join(fmt.Errorf("lstat created socket %s: %w", path, err), releaseSocketLock(lock))
	}
	listener := &ownedListener{Listener: ln, path: path, socketInfo: info, lock: lock}
	if err := configureSocket(path, owner, group, perm); err != nil {
		return nil, errors.Join(fmt.Errorf("configure socket: %w", err), listener.Close())
	}
	return listener, nil
}

type ownedListener struct {
	net.Listener

	path       string
	socketInfo os.FileInfo
	lock       *os.File

	once     sync.Once
	closeErr error
}

func (l *ownedListener) Close() error {
	l.once.Do(func() {
		l.closeErr = errors.Join(
			closeListener(l.Listener),
			removeOwnedSocket(l.path, l.socketInfo),
			releaseSocketLock(l.lock),
		)
		l.lock = nil
	})
	return l.closeErr
}

func closeListener(listener net.Listener) error {
	if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("close socket listener: %w", err)
	}
	return nil
}

func acquireSocketLock(path string) (*os.File, error) {
	lockPath := path + ".lock"
	info, err := os.Lstat(lockPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("lstat socket lock: %w", err)
	}
	if err == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
		return nil, fmt.Errorf("refusing non-regular socket lock path %s", lockPath)
	}

	lock, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open socket lock: %w", err)
	}
	lockInfo, err := lock.Stat()
	if err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("stat socket lock: %w", err)
	}
	pathInfo, err := os.Lstat(lockPath)
	if err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("recheck socket lock path: %w", err)
	}
	if !lockInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(lockInfo, pathInfo) {
		_ = lock.Close()
		return nil, fmt.Errorf("refusing replaced socket lock path %s", lockPath)
	}
	if err := lock.Chmod(0o600); err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("restrict socket lock permissions: %w", err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("lock socket path %s: %w", path, err)
	}
	pathInfo, err = os.Lstat(lockPath)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(lockInfo, pathInfo) {
		_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
		_ = lock.Close()
		if err != nil {
			return nil, fmt.Errorf("recheck locked socket path: %w", err)
		}
		return nil, fmt.Errorf("refusing replaced socket lock path %s", lockPath)
	}
	return lock, nil
}

func releaseSocketLock(lock *os.File) error {
	if lock == nil {
		return nil
	}
	return errors.Join(flockUnlock(lock), closeSocketLock(lock))
}

func flockUnlock(lock *os.File) error {
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); err != nil {
		return fmt.Errorf("unlock socket lock: %w", err)
	}
	return nil
}

func closeSocketLock(lock *os.File) error {
	if err := lock.Close(); err != nil {
		return fmt.Errorf("close socket lock: %w", err)
	}
	return nil
}

func removeExistingSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("lstat socket path %s: %w", path, err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to replace non-socket path %s", path)
	}

	conn, err := (&net.Dialer{Timeout: socketProbeTimeout}).Dial("unix", path)
	if err == nil {
		if closeErr := conn.Close(); closeErr != nil {
			return fmt.Errorf("close liveness probe for socket %s: %w", path, closeErr)
		}
		return fmt.Errorf("refusing to replace active socket %s", path)
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		return fmt.Errorf("refusing to replace socket %s: liveness is uncertain: %w", path, err)
	}
	current, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("recheck stale socket path %s: %w", path, err)
	}
	if current.Mode()&os.ModeSocket == 0 || !os.SameFile(info, current) {
		return fmt.Errorf("refusing to replace changed socket path %s", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale socket path %s: %w", path, err)
	}
	return nil
}

func removeOwnedSocket(path string, socketInfo os.FileInfo) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("lstat socket path during cleanup %s: %w", path, err)
	}
	if info.Mode()&os.ModeSocket == 0 || !os.SameFile(socketInfo, info) {
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove socket path %s: %w", path, err)
	}
	return nil
}

func configureSocket(path string, owner string, group string, perm os.FileMode) error {
	if perm != 0 {
		if err := os.Chmod(path, perm); err != nil {
			return fmt.Errorf("chmod socket %s: %w", path, err)
		}
	}
	if owner == "" && group == "" {
		return nil
	}

	uid := -1
	gid := -1
	if owner != "" {
		u, err := user.Lookup(owner)
		if err != nil {
			return fmt.Errorf("unknown user %s: %w", owner, err)
		}
		uid, err = strconv.Atoi(u.Uid)
		if err != nil {
			return fmt.Errorf("parse user ID for %s: %w", owner, err)
		}
	}
	if group != "" {
		g, err := user.LookupGroup(group)
		if err != nil {
			return fmt.Errorf("unknown group %s: %w", group, err)
		}
		gid, err = strconv.Atoi(g.Gid)
		if err != nil {
			return fmt.Errorf("parse group ID for %s: %w", group, err)
		}
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return fmt.Errorf("chown socket %s: %w", path, err)
	}
	return nil
}
