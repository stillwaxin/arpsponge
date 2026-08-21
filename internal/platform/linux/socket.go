//go:build linux

package linux

import (
	"net"
	"os"

	"arpsponge/internal/platform/unixsocket"
)

// linux-only: Unix socket ownership and permission handling.
func ListenUnix(path string, owner string, group string, perm os.FileMode) (net.Listener, error) {
	return unixsocket.Listen(path, owner, group, perm)
}
