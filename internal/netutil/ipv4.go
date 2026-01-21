package netutil

import (
	"encoding/binary"
	"errors"
	"net"
)

var ErrInvalidIPv4 = errors.New("invalid IPv4 address")

func IPv4ToUint32(ip net.IP) (uint32, error) {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return 0, ErrInvalidIPv4
	}
	return binary.BigEndian.Uint32(ipv4), nil
}

func Uint32ToIPv4(u uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, u)
	return ip
}

func IPv4String(u uint32) string {
	return Uint32ToIPv4(u).String()
}

func ParseIPv4String(s string) (uint32, error) {
	ip := net.ParseIP(s)
	if ip == nil {
		return 0, ErrInvalidIPv4
	}
	return IPv4ToUint32(ip)
}

func ParseCIDRString(s string) (*net.IPNet, uint32, uint32, int, error) {
	ip, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		return nil, 0, 0, 0, err
	}
	ipv4 := ip.To4()
	if ipv4 == nil {
		return nil, 0, 0, 0, ErrInvalidIPv4
	}
	prefixLen, _ := ipNet.Mask.Size()
	mask := MaskToUint32(ipNet.Mask)
	netU, _ := IPv4ToUint32(ipNet.IP)
	bcast := netU | ^mask
	ipNet.IP = ipv4
	return ipNet, netU, bcast, prefixLen, nil
}

func MaskToUint32(mask net.IPMask) uint32 {
	if len(mask) == 16 {
		mask = mask[12:16]
	}
	if len(mask) != 4 {
		return 0
	}
	return binary.BigEndian.Uint32(mask)
}

func InNet(ip uint32, network uint32, prefixLen int) bool {
	if prefixLen <= 0 {
		return true
	}
	if prefixLen >= 32 {
		return ip == network
	}
	mask := uint32(0xffffffff) << (32 - prefixLen)
	return (ip & mask) == (network & mask)
}

func Range(network uint32, broadcast uint32) (uint32, uint32) {
	return network, broadcast
}
