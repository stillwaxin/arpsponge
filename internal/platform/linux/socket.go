//go:build linux

package linux

import (
	"fmt"
	"net"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// linux-only: Unix socket ownership and permission handling.
func ListenUnix(path string, owner string, group string, perm os.FileMode) (net.Listener, error) {
	if err := os.RemoveAll(path); err != nil {
		return nil, err
	}

	// Securely create socket with restricted permissions to prevent race condition
	oldMask := syscall.Umask(0o077)
	ln, err := net.Listen("unix", path)
	syscall.Umask(oldMask)

	if err != nil {
		return nil, err
	}
	if perm != 0 {
		_ = os.Chmod(path, perm)
	}
	if owner != "" || group != "" {
		uid := -1
		gid := -1
		if owner != "" {
			u, err := user.Lookup(owner)
			if err != nil {
				return nil, fmt.Errorf("unknown user %s: %w", owner, err)
			}
			uid, _ = strconv.Atoi(u.Uid)
		}
		if group != "" {
			g, err := user.LookupGroup(group)
			if err != nil {
				return nil, fmt.Errorf("unknown group %s: %w", group, err)
			}
			gid, _ = strconv.Atoi(g.Gid)
		}
		_ = os.Chown(path, uid, gid)
	}
	return ln, nil
}
