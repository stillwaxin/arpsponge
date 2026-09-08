//go:build linux

package linux

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"arpsponge/internal/packet"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type packetReaderFunc func() (gopacket.Packet, error)

func (f packetReaderFunc) NextPacket() (gopacket.Packet, error) { return f() }

func TestCaptureReturnsTerminalReaderErrors(t *testing.T) {
	for _, failure := range []error{errors.New("injected capture failure"), pcap.NextErrorNoMorePackets} {
		capture := &Capture{reader: packetReaderFunc(func() (gopacket.Packet, error) { return nil, failure })}
		if err := capture.Run(context.Background(), func(packet.Packet) { t.Fatal("handler invoked on failed read") }); !errors.Is(err, failure) {
			t.Fatalf("Run error=%v, want %v", err, failure)
		}
	}
}

func TestCaptureTimeoutsContinueUntilCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reads := 0
	capture := &Capture{reader: packetReaderFunc(func() (gopacket.Packet, error) {
		reads++
		if reads == 3 {
			cancel()
		}
		return nil, pcap.NextErrorTimeoutExpired
	})}
	if err := capture.Run(ctx, func(packet.Packet) {}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error=%v", err)
	}
	if reads != 3 {
		t.Fatalf("timeout reader calls=%d, want 3", reads)
	}
}

func TestCaptureCanceledBeforeRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	capture := &Capture{reader: packetReaderFunc(func() (gopacket.Packet, error) { t.Fatal("read after cancellation"); return nil, nil })}
	if err := capture.Run(ctx, func(packet.Packet) {}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error=%v", err)
	}
}

func TestCaptureDeliversDecodedPacketSynchronously(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	buffer := gopacket.NewSerializeBuffer()
	eth := &layers.Ethernet{SrcMAC: []byte{2, 0, 0, 0, 0, 1}, DstMAC: []byte{255, 255, 255, 255, 255, 255}, EthernetType: layers.EthernetTypeARP}
	arp := &layers.ARP{AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4, HwAddressSize: 6, ProtAddressSize: 4, Operation: layers.ARPRequest, SourceHwAddress: eth.SrcMAC, SourceProtAddress: []byte{192, 0, 2, 1}, DstHwAddress: make([]byte, 6), DstProtAddress: []byte{192, 0, 2, 2}}
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true}, eth, arp); err != nil {
		t.Fatal(err)
	}
	reads, handled := 0, 0
	capture := &Capture{reader: packetReaderFunc(func() (gopacket.Packet, error) {
		reads++
		return gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default), nil
	})}
	err := capture.Run(ctx, func(pkt packet.Packet) {
		handled++
		if pkt.ARP == nil || pkt.ARP.TargetIP != 0xc0000202 {
			t.Fatalf("unexpected decoded packet: %+v", pkt)
		}
		cancel()
	})
	if !errors.Is(err, context.Canceled) || reads != 1 || handled != 1 {
		t.Fatalf("err=%v reads=%d handled=%d", err, reads, handled)
	}
}

func TestLiveCaptureIdleCancellation(t *testing.T) {
	if os.Getenv("ARPSPONGE_TEST_LIVE_CAPTURE") != "1" {
		t.Skip("set ARPSPONGE_TEST_LIVE_CAPTURE=1 with capture privileges")
	}
	capture, err := OpenCapture("lo", 512, false, 5*time.Millisecond)
	if err != nil {
		t.Fatalf("open live capture: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	var once sync.Once
	source := gopacket.NewPacketSource(capture.handle, capture.handle.LinkType())
	capture.reader = packetReaderFunc(func() (gopacket.Packet, error) {
		once.Do(func() { close(started) })
		return source.NextPacket()
	})
	done := make(chan error, 1)
	go func() { done <- capture.Run(ctx, func(packet.Packet) {}) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("live reader never started")
	}
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		capture.Close()
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("idle capture returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("idle capture failed to cancel; handle deliberately left open while reader is active")
	}
}
