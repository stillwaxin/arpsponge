package packet

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
)

type MAC [6]byte

var ErrInvalidMAC = errors.New("invalid MAC address")

func ParseMAC(s string) (MAC, error) {
	var m MAC
	hw, err := net.ParseMAC(s)
	if err != nil {
		return m, err
	}
	if len(hw) != 6 {
		return m, ErrInvalidMAC
	}
	copy(m[:], hw)
	return m, nil
}

func MACFromBytes(b []byte) (MAC, error) {
	var m MAC
	if len(b) != 6 {
		return m, ErrInvalidMAC
	}
	copy(m[:], b)
	return m, nil
}

func (m MAC) String() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5])
}

func (m MAC) HardwareAddr() net.HardwareAddr {
	return net.HardwareAddr(m[:])
}

func (m MAC) IsZero() bool {
	return m == MAC{}
}

func MustParseMAC(s string) MAC {
	m, err := ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return m
}

func (m MAC) MarshalText() ([]byte, error) {
	return []byte(m.String()), nil
}

func (m *MAC) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		*m = MAC{}
		return nil
	}
	if len(text) == 12 {
		raw := make([]byte, 6)
		_, err := hex.Decode(raw, text)
		if err != nil {
			return err
		}
		return m.fromBytes(raw)
	}
	mac, err := ParseMAC(string(text))
	if err != nil {
		return err
	}
	*m = mac
	return nil
}

func (m *MAC) fromBytes(b []byte) error {
	if len(b) != 6 {
		return ErrInvalidMAC
	}
	copy(m[:], b)
	return nil
}

type Packet struct {
	SrcMAC    MAC
	DstMAC    MAC
	EtherType uint16
	IPv4      *IPv4
	ARP       *ARP
}

type IPv4 struct {
	SrcIP uint32
	DstIP uint32
}

type ARP struct {
	Opcode    uint16
	SenderMAC MAC
	SenderIP  uint32
	TargetMAC MAC
	TargetIP  uint32
}

const (
	EtherTypeIPv4 = 0x0800
	EtherTypeARP  = 0x0806
)

const (
	ARPOpRequest = 1
	ARPOpReply   = 2
)
