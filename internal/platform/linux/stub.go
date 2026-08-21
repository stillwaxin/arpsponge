//go:build !linux

package linux

import (
	"context"
	"errors"
	"net"
	"os"
	"time"

	"arpsponge/internal/packet"
)

// ErrUnsupportedPlatform reports that arpsponge's capture and control socket
// support require Linux.
var ErrUnsupportedPlatform = errors.New("unsupported platform: Linux is required")

// InterfaceInfo describes an interface on Linux.
type InterfaceInfo struct {
	Name      string
	MAC       packet.MAC
	PrimaryIP uint32
	AllIPs    []uint32
}

// Capture is unavailable outside Linux.
type Capture struct{}

func GetInterfaceInfo(string) (InterfaceInfo, error) {
	return InterfaceInfo{}, ErrUnsupportedPlatform
}

func OpenCapture(string, int, bool, time.Duration) (*Capture, error) {
	return nil, ErrUnsupportedPlatform
}

func (c *Capture) Close() {}

func (c *Capture) Run(context.Context, func(packet.Packet)) error {
	return ErrUnsupportedPlatform
}

func (c *Capture) SendARP(packet.ARP, packet.MAC, packet.MAC) error {
	return ErrUnsupportedPlatform
}

func ListenUnix(string, string, string, os.FileMode) (net.Listener, error) {
	return nil, ErrUnsupportedPlatform
}
