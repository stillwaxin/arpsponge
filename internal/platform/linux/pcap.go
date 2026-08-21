//go:build linux

package linux

import (
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"arpsponge/internal/netutil"
	"arpsponge/internal/packet"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// linux-only: uses libpcap for capture and injection.
type Capture struct {
	handle *pcap.Handle
	sendMu sync.Mutex
}

func OpenCapture(device string, snaplen int, promisc bool, timeout time.Duration) (*Capture, error) {
	handle, err := pcap.OpenLive(device, int32(snaplen), promisc, timeout)
	if err != nil {
		return nil, err
	}
	if err := handle.SetBPFFilter("arp or ip"); err != nil {
		handle.Close()
		return nil, err
	}
	return &Capture{handle: handle}, nil
}

func (c *Capture) Close() {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	if c.handle != nil {
		c.handle.Close()
		c.handle = nil
	}
}

func (c *Capture) Run(ctx context.Context, handler func(packet.Packet)) error {
	source := gopacket.NewPacketSource(c.handle, c.handle.LinkType())
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case pkt, ok := <-source.Packets():
			if !ok {
				return errors.New("pcap source closed")
			}
			decoded, ok := decodePacket(pkt)
			if ok {
				handler(decoded)
			}
		}
	}
}

func (c *Capture) SendARP(arp packet.ARP, srcMAC packet.MAC, dstMAC packet.MAC) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	if c.handle == nil {
		return errors.New("pcap handle not open")
	}
	eth := layers.Ethernet{
		SrcMAC:       srcMAC.HardwareAddr(),
		DstMAC:       dstMAC.HardwareAddr(),
		EthernetType: layers.EthernetTypeARP,
	}
	arpLayer := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         arp.Opcode,
		SourceHwAddress:   arp.SenderMAC[:],
		SourceProtAddress: netutil.Uint32ToIPv4(arp.SenderIP).To4(),
		DstHwAddress:      arp.TargetMAC[:],
		DstProtAddress:    netutil.Uint32ToIPv4(arp.TargetIP).To4(),
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &arpLayer); err != nil {
		return err
	}
	return c.handle.WritePacketData(buf.Bytes())
}

func decodePacket(pkt gopacket.Packet) (packet.Packet, bool) {
	ethLayer := pkt.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return packet.Packet{}, false
	}
	eth := ethLayer.(*layers.Ethernet)
	srcMAC, err := packet.MACFromBytes(eth.SrcMAC)
	if err != nil {
		return packet.Packet{}, false
	}
	dstMAC, err := packet.MACFromBytes(eth.DstMAC)
	if err != nil {
		return packet.Packet{}, false
	}
	out := packet.Packet{
		SrcMAC:    srcMAC,
		DstMAC:    dstMAC,
		EtherType: uint16(eth.EthernetType),
	}

	if ip4Layer := pkt.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
		ip4 := ip4Layer.(*layers.IPv4)
		srcIP, err := netutil.IPv4ToUint32(ip4.SrcIP)
		if err == nil {
			dstIP, err := netutil.IPv4ToUint32(ip4.DstIP)
			if err == nil {
				out.IPv4 = &packet.IPv4{SrcIP: srcIP, DstIP: dstIP}
			}
		}
	}

	if arpLayer := pkt.Layer(layers.LayerTypeARP); arpLayer != nil {
		arp := arpLayer.(*layers.ARP)
		senderMAC, err := packet.MACFromBytes(arp.SourceHwAddress)
		if err != nil {
			return out, true
		}
		targetMAC, err := packet.MACFromBytes(arp.DstHwAddress)
		if err != nil {
			return out, true
		}
		senderIP := ipFromBytes(arp.SourceProtAddress)
		targetIP := ipFromBytes(arp.DstProtAddress)
		out.ARP = &packet.ARP{
			Opcode:    arp.Operation,
			SenderMAC: senderMAC,
			SenderIP:  senderIP,
			TargetMAC: targetMAC,
			TargetIP:  targetIP,
		}
	}

	return out, true
}

func ipFromBytes(b []byte) uint32 {
	if len(b) != 4 {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}
