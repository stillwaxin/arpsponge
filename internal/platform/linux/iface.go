//go:build linux

package linux

import (
	"fmt"
	"net"

	"arpsponge/internal/netutil"
	"arpsponge/internal/packet"
)

// linux-only: uses net.Interface to resolve MAC and IPv4 addresses.
type InterfaceInfo struct {
	Name      string
	MAC       packet.MAC
	PrimaryIP uint32
	AllIPs    []uint32
}

func GetInterfaceInfo(name string) (InterfaceInfo, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return InterfaceInfo{}, err
	}
	mac, err := packet.MACFromBytes(iface.HardwareAddr)
	if err != nil {
		return InterfaceInfo{}, fmt.Errorf("invalid mac for %s: %w", name, err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return InterfaceInfo{}, err
	}
	var ips []uint32
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil || ip.To4() == nil {
			continue
		}
		ipU, err := netutil.IPv4ToUint32(ip)
		if err != nil {
			continue
		}
		ips = append(ips, ipU)
	}
	primary := uint32(0)
	if len(ips) > 0 {
		primary = ips[0]
	}
	return InterfaceInfo{
		Name:      name,
		MAC:       mac,
		PrimaryIP: primary,
		AllIPs:    ips,
	}, nil
}
