//go:build !windows

// Package unixsocket creates Unix-domain control sockets with configured
// ownership and permissions. Listen changes the process-global umask while
// creating the socket and must only be called during single-threaded startup.
package unixsocket

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// Listen creates a Unix socket with restrictive creation permissions before
// applying its requested ownership and mode. Because syscall.Umask is
// process-global, callers must not invoke Listen concurrently.
func Listen(path string, owner string, group string, perm os.FileMode) (net.Listener, error) {
	if err := removeExistingSocket(path); err != nil {
		return nil, err
	}

	oldMask := syscall.Umask(0o077)
	ln, err := net.Listen("unix", path)
	syscall.Umask(oldMask)
	if err != nil {
		return nil, err
	}
	cleanup := func(cause error) (net.Listener, error) {
		var cleanupErr error
		if err := ln.Close(); err != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("close socket listener: %w", err))
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("remove socket path: %w", err))
		}
		return nil, errors.Join(cause, cleanupErr)
	}

	if err := configureSocket(path, owner, group, perm); err != nil {
		return cleanup(err)
	}
	return ln, nil
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
			return fmt.Errorf("invalid uid for user %s: %w", owner, err)
		}
	}
	if group != "" {
		g, err := user.LookupGroup(group)
		if err != nil {
			return fmt.Errorf("unknown group %s: %w", group, err)
		}
		gid, err = strconv.Atoi(g.Gid)
		if err != nil {
			return fmt.Errorf("invalid gid for group %s: %w", group, err)
		}
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return fmt.Errorf("chown socket %s: %w", path, err)
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
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale socket path %s: %w", path, err)
	}
	return nil
}
