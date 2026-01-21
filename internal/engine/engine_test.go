package engine

import (
	"testing"

	"arpsponge/internal/control"
	"arpsponge/internal/netutil"
	"arpsponge/internal/packet"
)

type fakeSender struct {
	sent int
	last packet.ARP
}

func (f *fakeSender) SendARP(arp packet.ARP, _ packet.MAC, _ packet.MAC) error {
	f.sent++
	f.last = arp
	return nil
}

func newTestEngine(t *testing.T) (*Engine, *fakeSender) {
	t.Helper()
	netCIDR, netIP, broadcast, prefixLen, err := netutil.ParseCIDRString("10.0.0.0/24")
	if err != nil {
		t.Fatalf("parse cidr: %v", err)
	}
	myIP, _ := netutil.ParseIPv4String("10.0.0.1")
	mac := packet.MustParseMAC("aa:bb:cc:dd:ee:ff")
	cfg := DefaultConfig()
	cfg.InitState = StateNone
	logger := control.NewLogger(64, LevelDebug, EventAll)
	sender := &fakeSender{}
	eng := New(cfg, "eth0", netCIDR, netIP, broadcast, prefixLen, myIP, mac, []uint32{myIP}, sender, logger)
	return eng, sender
}

func TestHandleARPSetPending(t *testing.T) {
	eng, _ := newTestEngine(t)
	request := packet.Packet{
		SrcMAC:    packet.MustParseMAC("00:11:22:33:44:55"),
		DstMAC:    packet.MustParseMAC("ff:ff:ff:ff:ff:ff"),
		EtherType: packet.EtherTypeARP,
		ARP: &packet.ARP{
			Opcode:    packet.ARPOpRequest,
			SenderMAC: packet.MustParseMAC("00:11:22:33:44:55"),
			SenderIP:  mustIP(t, "10.0.0.2"),
			TargetMAC: packet.MustParseMAC("00:00:00:00:00:00"),
			TargetIP:  mustIP(t, "10.0.0.5"),
		},
	}
	eng.HandlePacket(request)

	state, ok := eng.GetIPState(mustIP(t, "10.0.0.5"))
	if !ok {
		t.Fatalf("expected state to be set")
	}
	if state.State != "PENDING(0)" {
		t.Fatalf("expected pending state, got %s", state.State)
	}
}

func TestHandleARPReplyForDead(t *testing.T) {
	eng, sender := newTestEngine(t)
	ip := mustIP(t, "10.0.0.9")
	if err := eng.SetIPState(ip, StateDead, packet.MAC{}); err != nil {
		t.Fatalf("set dead: %v", err)
	}

	request := packet.Packet{
		SrcMAC:    packet.MustParseMAC("00:11:22:33:44:55"),
		DstMAC:    packet.MustParseMAC("ff:ff:ff:ff:ff:ff"),
		EtherType: packet.EtherTypeARP,
		ARP: &packet.ARP{
			Opcode:    packet.ARPOpRequest,
			SenderMAC: packet.MustParseMAC("00:11:22:33:44:55"),
			SenderIP:  mustIP(t, "10.0.0.2"),
			TargetMAC: packet.MustParseMAC("00:00:00:00:00:00"),
			TargetIP:  ip,
		},
	}
	eng.HandlePacket(request)

	if sender.sent == 0 {
		t.Fatalf("expected a reply to be sent")
	}
	if sender.last.Opcode != packet.ARPOpReply {
		t.Fatalf("expected reply opcode, got %d", sender.last.Opcode)
	}
}

func mustIP(t *testing.T, s string) uint32 {
	ip, err := netutil.ParseIPv4String(s)
	if err != nil {
		t.Fatalf("parse ip: %v", err)
	}
	return ip
}
